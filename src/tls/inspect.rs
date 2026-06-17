use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use quinn::crypto::rustls::{HandshakeData, QuicClientConfig};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    DigitallySignedStruct, ProtocolVersion, RootCertStore, SignatureScheme, SupportedCipherSuite,
};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::Url;

use crate::cli::{Cli, HttpVersion};
use crate::core::{self, Printer, Sequence};
use crate::duration::{TimeoutBudget, duration_from_seconds};
use crate::error::{FetchError, write_warning_with_separator_with_color};

pub async fn execute(cli: &Cli, ignored_flags: &[&'static str]) -> Result<i32, FetchError> {
    let request_start = Instant::now();
    let url = tls_url(cli.url.as_deref().expect("URL checked by app"))?;
    super::validate_client_auth_for_tls(cli.cert.as_deref(), cli.key.as_deref())?;
    if !ignored_flags.is_empty() && !cli.silent {
        write_warning_with_separator_with_color(
            format!(
                "No HTTP request will be sent; these flags have no effect: {}",
                ignored_flags.join(", ")
            ),
            cli.color.as_deref(),
        );
    }

    let http_version = crate::cli::selected_http_version(cli).map_err(FetchError::Message)?;

    let request_timeout = inspection_request_timeout(cli)?;
    let connect_timeout = inspection_connect_timeout(cli, request_timeout, request_start)?;
    let inspection = TimeoutBudget::started_at(request_timeout, request_start)
        .run(inspect(cli, &url, http_version, connect_timeout))
        .await?;

    if !cli.silent {
        let mut printer = core::stdio().stderr_printer(cli.color.as_deref());
        render_to(&inspection, &mut printer);
        printer.flush_to(&mut std::io::stderr())?;
    }
    Ok(0)
}

fn inspection_request_timeout(cli: &Cli) -> Result<Option<Duration>, FetchError> {
    cli.timeout
        .map(|seconds| duration_from_seconds("timeout", seconds))
        .transpose()
}

fn inspection_connect_timeout(
    cli: &Cli,
    request_timeout: Option<Duration>,
    request_start: Instant,
) -> Result<TimeoutBudget, FetchError> {
    let connect_timeout = cli
        .connect_timeout
        .map(|seconds| duration_from_seconds("connect-timeout", seconds))
        .transpose()?;
    TimeoutBudget::for_connect(connect_timeout, request_timeout, request_start)
}

fn tls_url(raw: &str) -> Result<Url, FetchError> {
    if raw.contains("://") {
        let url = Url::parse(raw)?;
        return match url.scheme() {
            "https" | "wss" => Ok(url),
            _ => Err("--inspect-tls requires an HTTPS URL".into()),
        };
    }

    let host = raw.split('/').next().unwrap_or(raw);
    let host = host.split('@').next_back().unwrap_or(host);
    let host = host.trim_matches(['[', ']']);
    let host = host.split(':').next().unwrap_or(host);
    if host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
    {
        return Err("--inspect-tls requires an HTTPS URL".into());
    }
    Url::parse(&format!("https://{raw}")).map_err(Into::into)
}

async fn inspect(
    cli: &Cli,
    url: &Url,
    http_version: Option<HttpVersion>,
    timeout: TimeoutBudget,
) -> Result<Inspection, FetchError> {
    if http_version == Some(HttpVersion::Http3) {
        inspect_quic(cli, url, timeout).await
    } else {
        inspect_tcp(cli, url, http_version, timeout).await
    }
}

async fn inspect_tcp(
    cli: &Cli,
    url: &Url,
    http_version: Option<HttpVersion>,
    timeout: TimeoutBudget,
) -> Result<Inspection, FetchError> {
    let host = tls_host(url)?;
    let port = url.port_or_known_default().unwrap_or(443);

    let ca_certs = load_ca_certs(&cli.ca_cert)?;
    let native_roots = load_native_root_certs();
    let trusted_roots = trusted_root_certs(&ca_certs, &native_roots);
    let ocsp_capture = OcspCapture::default();
    let mut config = build_client_config(cli, &ca_certs, &native_roots, ocsp_capture.clone())?;
    config.alpn_protocols = alpn_protocols(http_version)
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();

    let server_name = ServerName::try_from(host.clone())
        .map_err(|_| FetchError::Message(format!("invalid server name '{host}'")))?;
    let stream = connect_tcp_host(&host, port, cli.dns_server.as_deref(), timeout).await?;
    let connector = TlsConnector::from(Arc::new(config));
    let stream = timeout
        .run(async move {
            connector
                .connect(server_name, stream)
                .await
                .map_err(go_style_tls_inspect_error)
        })
        .await?;
    let (_, conn) = stream.get_ref();

    let mut peer_chain = Vec::new();
    if let Some(certs) = conn.peer_certificates() {
        peer_chain.extend(
            certs
                .iter()
                .filter_map(|cert| ParsedCert::parse(cert.as_ref())),
        );
    }
    let chain = certificate_chain_for_display(peer_chain, &trusted_roots, !cli.insecure);

    Ok(Inspection {
        version: conn.protocol_version(),
        cipher_suite: conn.negotiated_cipher_suite(),
        alpn: conn
            .alpn_protocol()
            .map(|protocol| String::from_utf8_lossy(protocol).into_owned()),
        chain,
        ocsp_response: ocsp_capture.get(),
    })
}

async fn connect_tcp_host(
    host: &str,
    port: u16,
    dns_server: Option<&str>,
    timeout: TimeoutBudget,
) -> Result<TcpStream, FetchError> {
    let addrs = resolve_tls_host(host, port, dns_server, timeout).await?;
    let mut last_err = None;

    for addr in addrs {
        match timeout
            .run(async move { TcpStream::connect(addr).await.map_err(FetchError::from) })
            .await
        {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }

    Err(last_err.unwrap_or_else(|| FetchError::Message("no addresses found".to_string())))
}

async fn resolve_tls_host(
    host: &str,
    port: u16,
    dns_server: Option<&str>,
    timeout: TimeoutBudget,
) -> Result<Vec<SocketAddr>, FetchError> {
    let Some(dns_server) = dns_server else {
        return timeout
            .run(async {
                tokio::net::lookup_host((host, port))
                    .await
                    .map(|addrs| addrs.collect())
                    .map_err(FetchError::from)
            })
            .await;
    };
    if host.parse::<IpAddr>().is_ok() {
        return timeout
            .run(async {
                tokio::net::lookup_host((host, port))
                    .await
                    .map(|addrs| addrs.collect())
                    .map_err(FetchError::from)
            })
            .await;
    }

    let dns_timeout = timeout.remaining()?;
    let addrs = timeout
        .run(crate::dns::custom::lookup_ips(
            dns_server,
            host,
            dns_timeout,
        ))
        .await?;
    Ok(crate::dns::custom::socket_addrs_with_port(addrs, port))
}

async fn inspect_quic(
    cli: &Cli,
    url: &Url,
    timeout: TimeoutBudget,
) -> Result<Inspection, FetchError> {
    let host = tls_host(url)?;
    ensure_quic_protocol_versions(cli)?;
    let port = url.port_or_known_default().unwrap_or(443);
    let addrs = resolve_tls_host(&host, port, cli.dns_server.as_deref(), timeout).await?;

    let ca_certs = load_ca_certs(&cli.ca_cert)?;
    let native_roots = load_native_root_certs();
    let trusted_roots = trusted_root_certs(&ca_certs, &native_roots);
    let ocsp_capture = OcspCapture::default();
    let mut config = build_client_config(cli, &ca_certs, &native_roots, ocsp_capture.clone())?;
    config.alpn_protocols = alpn_protocols(Some(HttpVersion::Http3))
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();
    let quic_config = quic_client_config(config)?;

    let mut last_err: Option<FetchError> = None;
    for addr in addrs {
        ocsp_capture.clear();
        match inspect_quic_addr(
            addr,
            &host,
            quic_config.clone(),
            &trusted_roots,
            !cli.insecure,
            &ocsp_capture,
            timeout,
        )
        .await
        {
            Ok(inspection) => return Ok(inspection),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| FetchError::Message("no addresses found".to_string())))
}

fn tls_host(url: &Url) -> Result<String, FetchError> {
    match url.host() {
        Some(url::Host::Domain(host)) => Ok(host.to_string()),
        Some(url::Host::Ipv4(host)) => Ok(host.to_string()),
        Some(url::Host::Ipv6(host)) => Ok(host.to_string()),
        None => Err(FetchError::Message(
            "--inspect-tls requires an HTTPS URL".to_string(),
        )),
    }
}

async fn inspect_quic_addr(
    addr: SocketAddr,
    host: &str,
    quic_config: quinn::ClientConfig,
    trusted_roots: &[ParsedCert],
    verified: bool,
    ocsp_capture: &OcspCapture,
    timeout: TimeoutBudget,
) -> Result<Inspection, FetchError> {
    let bind_addr = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let bind_addr: SocketAddr = bind_addr
        .parse()
        .expect("hard-coded QUIC client bind address is valid");
    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(quic_config);

    let connecting = endpoint
        .connect(addr, host)
        .map_err(|err| FetchError::Message(err.to_string()))?;
    let connection = timeout
        .run(async {
            connecting
                .await
                .map_err(|err| FetchError::Message(err.to_string()))
        })
        .await?;
    let alpn = quic_alpn(&connection);
    let chain =
        certificate_chain_for_display(quic_peer_certificates(&connection), trusted_roots, verified);

    connection.close(0_u32.into(), b"");
    endpoint.close(0_u32.into(), b"");
    endpoint.wait_idle().await;

    Ok(Inspection {
        version: Some(ProtocolVersion::TLSv1_3),
        cipher_suite: None,
        alpn,
        chain,
        ocsp_response: ocsp_capture.get(),
    })
}

fn quic_client_config(config: rustls::ClientConfig) -> Result<quinn::ClientConfig, FetchError> {
    QuicClientConfig::try_from(config)
        .map(|config| quinn::ClientConfig::new(Arc::new(config)))
        .map_err(|err| FetchError::Message(format!("invalid QUIC TLS configuration: {err}")))
}

fn quic_alpn(connection: &quinn::Connection) -> Option<String> {
    let data = connection
        .handshake_data()?
        .downcast::<HandshakeData>()
        .ok()?;
    data.protocol
        .as_deref()
        .map(|protocol| String::from_utf8_lossy(protocol).into_owned())
}

fn quic_peer_certificates(connection: &quinn::Connection) -> Vec<ParsedCert> {
    let Some(certs) = connection
        .peer_identity()
        .and_then(|identity| identity.downcast::<Vec<CertificateDer<'static>>>().ok())
    else {
        return Vec::new();
    };
    certs
        .iter()
        .filter_map(|cert| ParsedCert::parse(cert.as_ref()))
        .collect()
}

fn go_style_tls_inspect_error(err: impl fmt::Display) -> FetchError {
    let message = err.to_string();
    if message.starts_with("tls:") {
        FetchError::Message(message)
    } else {
        FetchError::Message(format!("tls: {message}"))
    }
}

fn build_client_config(
    cli: &Cli,
    ca_certs: &[ParsedCert],
    native_roots: &[ParsedCert],
    ocsp_capture: OcspCapture,
) -> Result<rustls::ClientConfig, FetchError> {
    super::install_default_crypto_provider();

    let versions = inspection_protocol_versions(cli)?;
    let builder = rustls::ClientConfig::builder_with_protocol_versions(&versions);
    let builder = if cli.insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification { ocsp_capture }))
    } else {
        let verifier = WebPkiServerVerifier::builder(Arc::new(root_store(ca_certs, native_roots)?))
            .build()
            .map_err(|err| FetchError::Message(err.to_string()))?;
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(CapturingServerVerifier {
                inner: verifier,
                ocsp_capture,
            }))
    };

    if let Some((certs, key)) = super::rustls_client_auth(cli.cert.as_deref(), cli.key.as_deref())?
    {
        builder
            .with_client_auth_cert(certs, key)
            .map_err(|err| FetchError::Message(err.to_string()))
    } else {
        Ok(builder.with_no_client_auth())
    }
}

fn inspection_protocol_versions(
    cli: &Cli,
) -> Result<Vec<&'static rustls::SupportedProtocolVersion>, FetchError> {
    let min_tls = cli.min_tls.as_deref().or(cli.tls.as_deref()).map(|value| {
        (
            if cli.min_tls.is_some() {
                "min-tls"
            } else {
                "tls"
            },
            value,
        )
    });
    super::rustls_protocol_versions(min_tls, cli.max_tls.as_deref())
}

fn ensure_quic_protocol_versions(cli: &Cli) -> Result<(), FetchError> {
    let versions = inspection_protocol_versions(cli)?;
    if versions
        .iter()
        .any(|version| version.version == ProtocolVersion::TLSv1_3)
    {
        Ok(())
    } else {
        Err("HTTP/3 TLS inspection requires TLS 1.3".into())
    }
}

fn root_store(
    ca_certs: &[ParsedCert],
    native_roots: &[ParsedCert],
) -> Result<RootCertStore, FetchError> {
    let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let _ = roots.add_parsable_certificates(
        native_roots
            .iter()
            .map(|cert| CertificateDer::from(cert.raw.clone())),
    );
    for cert in ca_certs {
        roots
            .add(CertificateDer::from(cert.raw.clone()))
            .map_err(|err| FetchError::Message(format!("invalid CA certificate: {err}")))?;
    }
    Ok(roots)
}

fn load_native_root_certs() -> Vec<ParsedCert> {
    // Native roots give us the full certificate metadata that rustls' webpki
    // trust anchors intentionally omit, including NotAfter for display.
    rustls_native_certs::load_native_certs()
        .certs
        .into_iter()
        .filter_map(|cert| ParsedCert::parse(cert.as_ref()))
        .collect()
}

fn trusted_root_certs(ca_certs: &[ParsedCert], native_roots: &[ParsedCert]) -> Vec<ParsedCert> {
    let mut roots = Vec::new();
    for cert in ca_certs.iter().chain(native_roots) {
        if !roots.iter().any(|existing: &ParsedCert| {
            (!existing.raw.is_empty() && existing.raw == cert.raw)
                || (!existing.subject_der.is_empty()
                    && existing.subject_der == cert.subject_der
                    && !existing.spki_der.is_empty()
                    && existing.spki_der == cert.spki_der)
        }) {
            roots.push(cert.clone());
        }
    }
    roots
}

fn certificate_chain_for_display(
    mut peer_chain: Vec<ParsedCert>,
    trusted_roots: &[ParsedCert],
    verified: bool,
) -> Vec<ParsedCert> {
    if !verified || peer_chain.is_empty() {
        return peer_chain;
    }

    let Some(last) = peer_chain.last().cloned() else {
        return peer_chain;
    };

    if let Some(root) = trusted_roots
        .iter()
        .find(|root| same_trust_anchor_identity(&last, root))
    {
        if last.raw != root.raw
            && let Some(last) = peer_chain.last_mut()
        {
            *last = root.clone();
        }
        return peer_chain;
    }

    if let Some(root) = trusted_roots
        .iter()
        .find(|root| issued_by_trusted_root(&last, root))
        && !peer_chain.iter().any(|cert| cert.raw == root.raw)
    {
        peer_chain.push(root.clone());
    }

    peer_chain
}

fn same_trust_anchor_identity(cert: &ParsedCert, root: &ParsedCert) -> bool {
    !cert.subject_der.is_empty()
        && cert.subject_der == root.subject_der
        && !cert.spki_der.is_empty()
        && cert.spki_der == root.spki_der
}

fn issued_by_trusted_root(cert: &ParsedCert, root: &ParsedCert) -> bool {
    if cert.issuer_der.is_empty()
        || root.subject_der.is_empty()
        || cert.issuer_der != root.subject_der
    {
        return false;
    }

    match (&cert.authority_key_id, &root.subject_key_id) {
        (Some(authority), Some(subject)) => authority == subject,
        _ => true,
    }
}

fn load_ca_certs(paths: &[String]) -> Result<Vec<ParsedCert>, FetchError> {
    let mut certs = Vec::new();
    for path in paths {
        let data = super::read_pem_file(path)?;
        let blocks = super::pem_certificates(&data).map_err(|err| {
            FetchError::Message(format!("invalid CA certificate '{path}': {err}"))
        })?;
        if blocks.is_empty() {
            return Err(format!("invalid CA certificate '{path}': no certificates found").into());
        }
        for block in blocks {
            let parsed = ParsedCert::parse(&block)
                .ok_or_else(|| FetchError::Message(format!("invalid CA certificate '{path}'")))?;
            certs.push(parsed);
        }
    }
    Ok(certs)
}

fn alpn_protocols(http_version: Option<HttpVersion>) -> &'static [&'static str] {
    match http_version {
        Some(HttpVersion::Http1) => &["http/1.1"],
        Some(HttpVersion::Http3) => &["h3"],
        Some(HttpVersion::Http2) | None => &["h2", "http/1.1"],
    }
}

pub(crate) fn ignored_inspection_flags(cli: &Cli) -> Vec<&'static str> {
    let mut ignored = Vec::new();
    crate::inspection::append_shared_ignored_request_flags(cli, &mut ignored);
    crate::inspection::append_shared_ignored_auth_flags(cli, &mut ignored);
    crate::inspection::append_shared_ignored_response_flags(cli, &mut ignored);
    ignored
}

#[cfg(test)]
fn render(inspection: &Inspection) -> String {
    render_with_color(inspection, false)
}

#[cfg(test)]
fn render_with_color(inspection: &Inspection, use_color: bool) -> String {
    let mut out = Printer::new(use_color);
    render_to(inspection, &mut out);
    out.into_string().expect("TLS inspection output is UTF-8")
}

fn render_to(inspection: &Inspection, out: &mut Printer) {
    out.write_info_prefix();
    out.write_styled(
        version_label(inspection.version),
        &[Sequence::Bold, Sequence::Yellow],
    );
    if let Some(cipher) = inspection.cipher_suite {
        out.push_str(": ");
        out.push_str(&cipher_suite_label(cipher));
    }
    out.push('\n');

    if let Some(alpn) = &inspection.alpn {
        out.write_info_prefix();
        out.push_str("ALPN: ");
        out.write_styled(alpn, &[Sequence::Italic]);
        out.push('\n');
    }

    if !inspection.chain.is_empty() {
        out.write_info_prefix();
        out.push_str("\n");
        render_cert_chain(out, &inspection.chain);
        render_sans(out, &inspection.chain[0]);
    }
    render_ocsp_status(out, &inspection.ocsp_response);
}

fn render_cert_chain(out: &mut Printer, chain: &[ParsedCert]) {
    out.write_info_prefix();
    out.write_styled("Certificate chain", &[Sequence::Bold]);
    out.push_str(":\n");
    for (index, cert) in chain.iter().enumerate() {
        out.write_info_prefix();
        out.push_str(&"   ".repeat(index));
        out.write_styled("└─ ", &[Sequence::Dim]);
        out.write_styled(&cert.display_name(), &[Sequence::Bold]);
        let (expiry_text, expiry_color) = cert_expiry_info_and_color(cert.not_after);
        out.push_str(" (");
        out.write_styled(&expiry_text, &[expiry_color]);
        out.push_str(")\n");
    }
}

fn render_sans(out: &mut Printer, cert: &ParsedCert) {
    let mut sans = cert.dns_names.clone();
    sans.extend(cert.ip_addresses.iter().map(ToString::to_string));
    if sans.is_empty() {
        return;
    }
    out.write_info_prefix();
    out.push_str("\n");
    out.write_info_prefix();
    out.push_str("SANs: ");
    out.write_styled(&sans.join(", "), &[Sequence::Italic]);
    out.push('\n');
}

fn render_ocsp_status(out: &mut Printer, raw_ocsp: &[u8]) {
    let Some(status) = parse_ocsp_status(raw_ocsp) else {
        return;
    };
    out.write_info_prefix();
    out.push_str("OCSP: ");
    out.write_styled(status.label(), &[status.color()]);
    out.push_str(" (stapled)\n");
}

#[cfg(test)]
fn cert_expiry_info(not_after: Option<time::OffsetDateTime>) -> String {
    cert_expiry_info_and_color(not_after).0
}

fn cert_expiry_info_and_color(not_after: Option<time::OffsetDateTime>) -> (String, Sequence) {
    let Some(not_after) = not_after else {
        return ("expiry unknown".to_string(), Sequence::Yellow);
    };
    let now = time::OffsetDateTime::now_utc();
    if now > not_after {
        return ("expired".to_string(), Sequence::Red);
    }

    let remaining = not_after - now;
    let days = remaining.whole_days();
    let text = match days {
        0 => "expires in <1 day".to_string(),
        1 => "expires in 1 day".to_string(),
        days => format!("expires in {days} days"),
    };
    let color = match days {
        days if days < 7 => Sequence::Red,
        days if days < 30 => Sequence::Yellow,
        _ => Sequence::Green,
    };
    (text, color)
}

fn version_label(version: Option<ProtocolVersion>) -> &'static str {
    match version {
        Some(ProtocolVersion::TLSv1_3) => "TLS 1.3",
        Some(ProtocolVersion::TLSv1_2) => "TLS 1.2",
        Some(ProtocolVersion::TLSv1_1) => "TLS 1.1",
        Some(ProtocolVersion::TLSv1_0) => "TLS 1.0",
        _ => "TLS",
    }
}

fn cipher_suite_label(cipher: SupportedCipherSuite) -> String {
    format!("{:?}", cipher.suite())
}

#[derive(Clone)]
struct Inspection {
    version: Option<ProtocolVersion>,
    cipher_suite: Option<SupportedCipherSuite>,
    alpn: Option<String>,
    chain: Vec<ParsedCert>,
    ocsp_response: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OcspStatus {
    Good,
    Revoked,
    Unknown,
}

impl OcspStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Good => "good",
            Self::Revoked => "revoked",
            Self::Unknown => "unknown",
        }
    }

    fn color(self) -> Sequence {
        match self {
            Self::Good => Sequence::Green,
            Self::Revoked => Sequence::Red,
            Self::Unknown => Sequence::Yellow,
        }
    }
}

fn parse_ocsp_status(raw: &[u8]) -> Option<OcspStatus> {
    if raw.is_empty() {
        return None;
    }
    let mut top = DerReader::new(raw);
    let response = top.read_tlv()?;
    if response.tag != 0x30 {
        return None;
    }

    let mut response = DerReader::new(response.value);
    let status = response.read_tlv()?;
    if status.tag != 0x0a || status.value != [0] {
        return None;
    }

    let response_bytes_explicit = response.read_tlv()?;
    if response_bytes_explicit.tag != 0xa0 {
        return None;
    }
    let mut explicit = DerReader::new(response_bytes_explicit.value);
    let response_bytes = explicit.read_tlv()?;
    if response_bytes.tag != 0x30 {
        return None;
    }

    let mut response_bytes = DerReader::new(response_bytes.value);
    let response_type = response_bytes.read_tlv()?;
    if response_type.tag != 0x06
        || response_type.value != [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01]
    {
        return None;
    }
    let basic_response = response_bytes.read_tlv()?;
    if basic_response.tag != 0x04 {
        return None;
    }
    parse_basic_ocsp_response_status(basic_response.value)
}

fn parse_basic_ocsp_response_status(raw: &[u8]) -> Option<OcspStatus> {
    let mut top = DerReader::new(raw);
    let basic = top.read_tlv()?;
    if basic.tag != 0x30 {
        return None;
    }

    let mut basic = DerReader::new(basic.value);
    let tbs_response = basic.read_tlv()?;
    if tbs_response.tag != 0x30 {
        return None;
    }
    if basic.read_tlv()?.tag != 0x30 {
        return None;
    }
    if basic.read_tlv()?.tag != 0x03 {
        return None;
    }

    let mut tbs = DerReader::new(tbs_response.value);
    if tbs.peek_tag() == Some(0xa0) {
        tbs.read_tlv()?;
    }
    tbs.read_tlv()?; // responderID
    tbs.read_tlv()?; // producedAt
    let responses = tbs.read_tlv()?;
    if responses.tag != 0x30 {
        return None;
    }
    let mut responses = DerReader::new(responses.value);
    let single = responses.read_tlv()?;
    if single.tag != 0x30 {
        return None;
    }

    let mut single = DerReader::new(single.value);
    single.read_tlv()?; // certID
    let status = single.read_tlv()?;
    match status.tag {
        0x80 | 0xa0 => Some(OcspStatus::Good),
        0x81 | 0xa1 => Some(OcspStatus::Revoked),
        0x82 | 0xa2 => Some(OcspStatus::Unknown),
        _ => None,
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ParsedCert {
    raw: Vec<u8>,
    common_name: Option<String>,
    organization: Option<String>,
    dns_names: Vec<String>,
    ip_addresses: Vec<IpAddr>,
    not_after: Option<time::OffsetDateTime>,
    issuer_der: Vec<u8>,
    subject_der: Vec<u8>,
    spki_der: Vec<u8>,
    subject_key_id: Option<Vec<u8>>,
    authority_key_id: Option<Vec<u8>>,
    subject: String,
}

impl ParsedCert {
    fn parse(raw: &[u8]) -> Option<Self> {
        let cert = CertDer::parse(raw)?;
        let tbs = cert.tbs_certificate()?;
        let mut fields = TbsFields::parse(tbs)?;
        parse_extensions(fields.extensions, &mut fields);
        Some(Self {
            raw: raw.to_vec(),
            common_name: fields.subject.common_name,
            organization: fields.subject.organization,
            dns_names: fields.dns_names,
            ip_addresses: fields.ip_addresses,
            not_after: fields.not_after,
            issuer_der: fields.issuer_der,
            subject_der: fields.subject_der,
            spki_der: fields.spki_der,
            subject_key_id: fields.subject_key_id,
            authority_key_id: fields.authority_key_id,
            subject: fields.subject.display,
        })
    }

    fn display_name(&self) -> String {
        match (&self.common_name, &self.organization) {
            (Some(cn), Some(org)) if cn != org => format!("{cn}, {org}"),
            (Some(cn), _) => cn.clone(),
            (None, _) if !self.dns_names.is_empty() => self.dns_names[0].clone(),
            (None, Some(org)) => org.clone(),
            _ => self.subject.clone(),
        }
    }
}

struct TbsFields<'a> {
    subject: NameFields,
    not_after: Option<time::OffsetDateTime>,
    dns_names: Vec<String>,
    ip_addresses: Vec<IpAddr>,
    issuer_der: Vec<u8>,
    subject_der: Vec<u8>,
    spki_der: Vec<u8>,
    subject_key_id: Option<Vec<u8>>,
    authority_key_id: Option<Vec<u8>>,
    extensions: Option<&'a [u8]>,
}

impl<'a> TbsFields<'a> {
    fn parse(tbs: &'a [u8]) -> Option<Self> {
        let mut reader = DerReader::new(tbs);
        if reader.peek_tag()? == 0xa0 {
            reader.read_tlv()?;
        }
        reader.read_tlv()?; // serial
        reader.read_tlv()?; // signature
        let issuer = reader.read_tlv()?;
        let validity = reader.read_tlv()?;
        let not_after = parse_validity(validity.value);
        let subject_tlv = reader.read_tlv()?;
        let subject = parse_name(subject_tlv.value);
        let spki = reader.read_tlv()?;

        let mut extensions = None;
        while !reader.is_empty() {
            let tlv = reader.read_tlv()?;
            if tlv.tag == 0xa3 {
                extensions = Some(tlv.value);
            }
        }

        Some(Self {
            subject,
            not_after,
            dns_names: Vec::new(),
            ip_addresses: Vec::new(),
            issuer_der: issuer.value.to_vec(),
            subject_der: subject_tlv.value.to_vec(),
            spki_der: spki.raw.to_vec(),
            subject_key_id: None,
            authority_key_id: None,
            extensions,
        })
    }
}

fn parse_validity(validity: &[u8]) -> Option<time::OffsetDateTime> {
    let mut reader = DerReader::new(validity);
    reader.read_tlv()?;
    let not_after = reader.read_tlv()?;
    parse_time(not_after.tag, not_after.value)
}

fn parse_time(tag: u8, value: &[u8]) -> Option<time::OffsetDateTime> {
    let text = std::str::from_utf8(value).ok()?;
    let (year, rest) = match tag {
        0x17 => {
            let yy: i32 = text.get(0..2)?.parse().ok()?;
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            (year, text.get(2..)?)
        }
        0x18 => {
            let year: i32 = text.get(0..4)?.parse().ok()?;
            (year, text.get(4..)?)
        }
        _ => return None,
    };
    let month: u8 = rest.get(0..2)?.parse().ok()?;
    let day: u8 = rest.get(2..4)?.parse().ok()?;
    let hour: u8 = rest.get(4..6)?.parse().ok()?;
    let minute: u8 = rest.get(6..8)?.parse().ok()?;
    let second: u8 = rest.get(8..10)?.parse().ok()?;
    let date =
        time::Date::from_calendar_date(year, time::Month::try_from(month).ok()?, day).ok()?;
    let time = time::Time::from_hms(hour, minute, second).ok()?;
    Some(time::OffsetDateTime::new_utc(date, time))
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
struct NameFields {
    common_name: Option<String>,
    organization: Option<String>,
    display: String,
}

fn parse_name(name: &[u8]) -> NameFields {
    let mut parts = Vec::new();
    let mut fields = NameFields::default();
    let mut reader = DerReader::new(name);
    while let Some(set) = reader.read_tlv() {
        let mut set_reader = DerReader::new(set.value);
        while let Some(attr) = set_reader.read_tlv() {
            if let Some((oid, value)) = parse_attribute(attr.value) {
                match oid.as_slice() {
                    [0x55, 0x04, 0x03] => {
                        fields.common_name = Some(value.clone());
                        parts.push(format!("CN={value}"));
                    }
                    [0x55, 0x04, 0x0a] => {
                        fields.organization = Some(value.clone());
                        parts.push(format!("O={value}"));
                    }
                    [0x55, 0x04, 0x06] => parts.push(format!("C={value}")),
                    _ => {}
                }
            }
        }
    }
    fields.display = parts.join(", ");
    fields
}

fn parse_attribute(attr: &[u8]) -> Option<(Vec<u8>, String)> {
    let mut reader = DerReader::new(attr);
    let oid = reader.read_tlv()?;
    let value = reader.read_tlv()?;
    Some((
        oid.value.to_vec(),
        parse_der_string(value.tag, value.value)?,
    ))
}

fn parse_der_string(tag: u8, value: &[u8]) -> Option<String> {
    match tag {
        0x0c | 0x13 | 0x16 => String::from_utf8(value.to_vec()).ok(),
        0x1e => {
            let mut units = Vec::new();
            for chunk in value.chunks_exact(2) {
                units.push(u16::from_be_bytes([chunk[0], chunk[1]]));
            }
            String::from_utf16(&units).ok()
        }
        _ => None,
    }
}

fn parse_extensions(extensions: Option<&[u8]>, fields: &mut TbsFields<'_>) {
    let Some(extensions) = extensions else {
        return;
    };
    let mut outer = DerReader::new(extensions);
    let Some(seq) = outer.read_tlv() else {
        return;
    };
    let mut reader = DerReader::new(seq.value);
    while let Some(extension) = reader.read_tlv() {
        let mut ext = DerReader::new(extension.value);
        let Some(oid) = ext.read_tlv() else {
            continue;
        };
        if ext.peek_tag() == Some(0x01) {
            ext.read_tlv();
        }
        let Some(value) = ext.read_tlv() else {
            continue;
        };
        match oid.value {
            [0x55, 0x1d, 0x11] => parse_subject_alt_name(value.value, fields),
            [0x55, 0x1d, 0x0e] => {
                fields.subject_key_id = parse_subject_key_identifier(value.value);
            }
            [0x55, 0x1d, 0x23] => {
                fields.authority_key_id = parse_authority_key_identifier(value.value);
            }
            _ => {}
        }
    }
}

fn parse_subject_key_identifier(octets: &[u8]) -> Option<Vec<u8>> {
    let mut reader = DerReader::new(octets);
    let key_id = reader.read_tlv()?;
    if key_id.tag == 0x04 {
        Some(key_id.value.to_vec())
    } else {
        None
    }
}

fn parse_authority_key_identifier(octets: &[u8]) -> Option<Vec<u8>> {
    let mut reader = DerReader::new(octets);
    let seq = reader.read_tlv()?;
    if seq.tag != 0x30 {
        return None;
    }
    let mut fields = DerReader::new(seq.value);
    while let Some(field) = fields.read_tlv() {
        if field.tag == 0x80 {
            return Some(field.value.to_vec());
        }
    }
    None
}

fn parse_subject_alt_name(octets: &[u8], fields: &mut TbsFields<'_>) {
    let mut octet_reader = DerReader::new(octets);
    let Some(seq) = octet_reader.read_tlv() else {
        return;
    };
    let mut names = DerReader::new(seq.value);
    while let Some(name) = names.read_tlv() {
        match name.tag {
            0x82 => {
                if let Ok(dns) = std::str::from_utf8(name.value) {
                    fields.dns_names.push(dns.to_string());
                }
            }
            0x87 => match name.value {
                [a, b, c, d] => fields.ip_addresses.push(IpAddr::from([*a, *b, *c, *d])),
                bytes if bytes.len() == 16 => {
                    let mut octets = [0_u8; 16];
                    octets.copy_from_slice(bytes);
                    fields.ip_addresses.push(IpAddr::from(octets));
                }
                _ => {}
            },
            _ => {}
        }
    }
}

struct CertDer<'a> {
    value: &'a [u8],
}

impl<'a> CertDer<'a> {
    fn parse(raw: &'a [u8]) -> Option<Self> {
        let mut reader = DerReader::new(raw);
        let cert = reader.read_tlv()?;
        if cert.tag == 0x30 {
            Some(Self { value: cert.value })
        } else {
            None
        }
    }

    fn tbs_certificate(&self) -> Option<&'a [u8]> {
        let mut reader = DerReader::new(self.value);
        let tbs = reader.read_tlv()?;
        if tbs.tag == 0x30 {
            Some(tbs.value)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    raw: &'a [u8],
}

struct DerReader<'a> {
    data: &'a [u8],
}

impl<'a> DerReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn peek_tag(&self) -> Option<u8> {
        self.data.first().copied()
    }

    fn read_tlv(&mut self) -> Option<Tlv<'a>> {
        if self.data.len() < 2 {
            return None;
        }
        let original = self.data;
        let tag = self.data[0];
        let first_len = self.data[1];
        let mut offset = 2;
        let len = if first_len & 0x80 == 0 {
            usize::from(first_len)
        } else {
            let count = usize::from(first_len & 0x7f);
            if count == 0 || count > 4 || self.data.len() < offset + count {
                return None;
            }
            let mut len = 0_usize;
            for byte in &self.data[offset..offset + count] {
                len = (len << 8) | usize::from(*byte);
            }
            offset += count;
            len
        };
        if self.data.len() < offset + len {
            return None;
        }
        let value = &self.data[offset..offset + len];
        self.data = &self.data[offset + len..];
        Some(Tlv {
            tag,
            value,
            raw: &original[..offset + len],
        })
    }
}

#[derive(Clone, Debug, Default)]
struct OcspCapture {
    response: Arc<Mutex<Vec<u8>>>,
}

impl OcspCapture {
    fn set(&self, value: &[u8]) {
        if value.is_empty() {
            return;
        }
        *self.response.lock().expect("OCSP capture lock poisoned") = value.to_vec();
    }

    fn get(&self) -> Vec<u8> {
        self.response
            .lock()
            .expect("OCSP capture lock poisoned")
            .clone()
    }

    fn clear(&self) {
        self.response
            .lock()
            .expect("OCSP capture lock poisoned")
            .clear();
    }
}

#[derive(Debug)]
struct CapturingServerVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    ocsp_capture: OcspCapture,
}

impl ServerCertVerifier for CapturingServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.ocsp_capture.set(ocsp_response);
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[derive(Debug)]
struct NoCertificateVerification {
    ocsp_capture: OcspCapture,
}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.ocsp_capture.set(ocsp_response);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

impl fmt::Debug for Inspection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inspection")
            .field("version", &self.version)
            .field("alpn", &self.alpn)
            .field("chain_len", &self.chain.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use quinn::crypto::rustls::QuicServerConfig;

    const TEST_QUIC_CERT_PEM: &[u8] = br#"-----BEGIN CERTIFICATE-----
MIICzTCCAbWgAwIBAgIJALgQEfpjYIDxMA0GCSqGSIb3DQEBCwUAMBYxFDASBgNV
BAMMC3F1aWMtc2VydmVyMB4XDTI2MDUyMzIxMjc0NloXDTM2MDUyMDIxMjc0Nlow
FjEUMBIGA1UEAwwLcXVpYy1zZXJ2ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDMo8AZjwo8Hc0KbyQZyOsJggdY8UcUufcjdZCgSri/OKLivtzQU5K5
rJ2ESQjkv0M1ux9mrtYLsKSL2YXiVszVCOaUUEXqwT7+BNahs1lpLh99zzkOnwPk
Eiho7/m1zgr1oCwcCoOFkyKpNGxfPm9tFkraDkAmaCKzOElh8Gn/El9RU7sqvbdT
OSnvjJojY8S5Slag1YcFW0RAtw4uLV3cbGM6CGV891LjqUlSqUILAAHAgAwT4iU1
g8IjMzu+5LbKUUCSiGs1adHN5Wnp1gpmuIyKZpQVbagSmNgRrRNTZtrhta/zn9sS
Beqe/7w+IcUXz9t2HaxeTTUOb64X4YkvAgMBAAGjHjAcMBoGA1UdEQQTMBGHBH8A
AAGCCWxvY2FsaG9zdDANBgkqhkiG9w0BAQsFAAOCAQEAqDpnCjPQfp1EtJk28XKC
FHgv+26x5ENYpnsjfm/9qqdg9xkaW8yMm7UrNeTxwRhNDrLQFP5O39ZdlJkP+Gvt
q786Ru0946iuSTkbDHS2earZM469pccO4EUxp9SlT8vP0ifUMOLaq8wPsIl/iDig
bO33nq739GmwBfwaxk++MPNPsVYxkj5fzK9RZW9lVw1cj96jtVU9dvfGiGF/YoII
ECAmjQTnmdKXNAHKynrklkeo+Tj8fKYmc8HlHMLkFEf0kVYP2ITB+zCDcypu/M5y
PcC5pDIyMwOkVh3PkbEjfNs02H+MBT+04w0gF+LcKYH6c3q//+uZaAnlWkNf8j3C
hg==
-----END CERTIFICATE-----
"#;

    const TEST_QUIC_KEY_PEM: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDMo8AZjwo8Hc0K
byQZyOsJggdY8UcUufcjdZCgSri/OKLivtzQU5K5rJ2ESQjkv0M1ux9mrtYLsKSL
2YXiVszVCOaUUEXqwT7+BNahs1lpLh99zzkOnwPkEiho7/m1zgr1oCwcCoOFkyKp
NGxfPm9tFkraDkAmaCKzOElh8Gn/El9RU7sqvbdTOSnvjJojY8S5Slag1YcFW0RA
tw4uLV3cbGM6CGV891LjqUlSqUILAAHAgAwT4iU1g8IjMzu+5LbKUUCSiGs1adHN
5Wnp1gpmuIyKZpQVbagSmNgRrRNTZtrhta/zn9sSBeqe/7w+IcUXz9t2HaxeTTUO
b64X4YkvAgMBAAECggEAJEYuihlJ5igeLWhQDOYJi7Dp3oE+aVUhkr6HOXKlVvgS
H4FXoPH/gzwu28Eae3nPzxlxUoFRXdcdA9E2I03hly2xub6U9iz1Ho/6/8TL55IO
cP2njojvZqE1WoyXRfvVA3818m6Gq8nODhJF14g4tiyKbiayhlxVMlGa6Gp2T4k/
v5VWkgqDxsAh963IYuTKaCUTHIyavjUpmHraSbkeXH6g05VWpc+EXe9Aq/204asS
EpDOXP80NTQkY5WIneOfNv1kCBMGhD574UqV+6iqevYXrYDZdPiGItk1NPnTKwH1
X6DXldNHmp/GDoWdLGph1mkbIIKHOwOf9Ucaqrl80QKBgQD4+nInMLxRqBaM4W0w
BBQMzuQBx5vHlAud5+0x1pLbOgdZUZQnGvLZUfAzDuBcOLnOYRhAUUvc6WzqDmIu
Fx9otsLE888zOoi6JVCclyqbN9XaRfw+LIzAUYgPMJBwcOjwIRMWN2VqnyaXBx5t
LOWs0plyb7J1nGR3+9BCTjPu+QKBgQDSaTEVPD7tc96GwhoJQZi4Iy14n1HIjEOZ
nhV+5N8nFJxo50hRyz0r26RygUI8BUSkS+1+dbXsLMoZbRM/QCYnY3hhMBN9aV8B
2OAYZX8o2a3cQYn7KqiOH3DoTLG2D3GiWV3XZrT5yIrpPOA8W4e4FbmJ4+UavKVD
TN1B1XE7ZwKBgQDutKcXPdl/bGlaXpKhk3dppD3kGu0W1rCgjwjRXIjmGGeNUfJ5
35Nvmehx+1RN9rDl1h87IvZZ8Y5ThMDKsa6SZY6s55gC5J7L4RS9XQ0jTdABelHR
hkLX7BNHhOcmdopOF1fGWAwqwjVsXQ3l3ELDhBJMLhzqN6v3gPz1ZSbTeQKBgQCW
ldAZ6YcDu9Q7T3kAvOCGkC5/0E3goHnU3C14JmaKepbCARxh5Xl/BO+5P0be28pX
ZzuuMKIlR5zP+581ujxUHj1OGPEp5RqooMUo0KLj4n4qTwFoLwx4wom0xwa8TGtA
DIM7oHbO+TZpXDcDG2KTXYDu7ZnOu8nu03jaH96s6wKBgQDRap6lM8cpocvpURcx
97vZOfzDwrQP1rJ24E7sGa1ZneVgLG4ltSdm5ycK9Kx9BKIApOQN8+6glC6XSWGR
Lu1+IOUvo1N/eYFCBdRyC8cpVqZcElCCpYG5kXJQomSm9uyIntNhgoHj4XFFsbLR
TQt+xSSOMTZFrHhhVqsL9JQlHg==
-----END PRIVATE KEY-----
"#;

    #[test]
    fn alpn_protocols_match_go_defaults() {
        assert_eq!(alpn_protocols(None), ["h2", "http/1.1"]);
        assert_eq!(alpn_protocols(Some(HttpVersion::Http2)), ["h2", "http/1.1"]);
        assert_eq!(alpn_protocols(Some(HttpVersion::Http1)), ["http/1.1"]);
        assert_eq!(alpn_protocols(Some(HttpVersion::Http3)), ["h3"]);
    }

    #[test]
    fn inspection_protocol_versions_apply_go_min_max_bounds() {
        let cli = Cli::try_parse_from(["fetch", "--inspect-tls", "https://example.com"]).unwrap();
        assert_eq!(
            inspection_protocol_versions(&cli)
                .unwrap()
                .iter()
                .map(|version| version.version)
                .collect::<Vec<_>>(),
            vec![ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2]
        );

        let cli = Cli::try_parse_from([
            "fetch",
            "--inspect-tls",
            "--min-tls",
            "1.3",
            "--max-tls",
            "1.3",
            "https://example.com",
        ])
        .unwrap();
        assert_eq!(
            inspection_protocol_versions(&cli)
                .unwrap()
                .iter()
                .map(|version| version.version)
                .collect::<Vec<_>>(),
            vec![ProtocolVersion::TLSv1_3]
        );

        let cli = Cli::try_parse_from([
            "fetch",
            "--inspect-tls",
            "--tls",
            "1.2",
            "--max-tls",
            "1.2",
            "https://example.com",
        ])
        .unwrap();
        assert_eq!(
            inspection_protocol_versions(&cli)
                .unwrap()
                .iter()
                .map(|version| version.version)
                .collect::<Vec<_>>(),
            vec![ProtocolVersion::TLSv1_2]
        );
    }

    #[test]
    fn inspection_protocol_versions_reject_legacy_tls_versions() {
        let cli = Cli::try_parse_from([
            "fetch",
            "--inspect-tls",
            "--min-tls",
            "1.0",
            "https://example.com",
        ])
        .unwrap();

        let err = inspection_protocol_versions(&cli).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid value '1.0' for option '--min-tls': must be one of [1.2, 1.3]"
        );

        let cli = Cli::try_parse_from([
            "fetch",
            "--inspect-tls",
            "--max-tls",
            "1.1",
            "https://example.com",
        ])
        .unwrap();

        let err = inspection_protocol_versions(&cli).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid value '1.1' for option '--max-tls': must be one of [1.2, 1.3]"
        );
    }

    #[test]
    fn inspect_http3_rejects_tls12_only_config_like_quic_tls() {
        let cli = Cli::try_parse_from([
            "fetch",
            "--inspect-tls",
            "--http",
            "3",
            "--max-tls",
            "1.2",
            "https://example.com",
        ])
        .unwrap();

        let err = ensure_quic_protocol_versions(&cli).unwrap_err();

        assert_eq!(err.to_string(), "HTTP/3 TLS inspection requires TLS 1.3");
    }

    #[test]
    fn tls_url_rejects_plain_http() {
        let err = tls_url("http://localhost:8080").unwrap_err();

        assert_eq!(err.to_string(), "--inspect-tls requires an HTTPS URL");
    }

    #[test]
    fn tls_url_defaults_non_loopback_to_https() {
        let url = tls_url("example.com/path").unwrap();

        assert_eq!(url.as_str(), "https://example.com/path");
    }

    #[test]
    fn ignored_flags_match_go_inspect_tls_order() {
        let cli = Cli::try_parse_from([
            "fetch",
            "https://example.com",
            "--inspect-tls",
            "-d",
            "body",
            "--grpc",
            "--proto-file",
            "Cargo.toml",
            "--proto-import",
            ".",
            "--output",
            "out.txt",
            "--copy",
            "--clobber",
            "--compress",
            "off",
            "--image",
            "off",
            "--pager",
            "off",
            "--ignore-status",
            "--timing",
            "--proxy",
            "http://proxy.test",
            "--redirects",
            "1",
            "--retry-delay",
            "0.1",
            "--sort-headers",
            "--bearer",
            "token",
            "--format",
            "off",
            "--ws-interactive",
            "off",
            "--ws-message-mode",
            "text",
            "--dry-run",
        ])
        .unwrap();

        assert_eq!(
            ignored_inspection_flags(&cli),
            [
                "--data/--json/--xml",
                "--grpc",
                "--proto-file",
                "--proto-import",
                "--output",
                "--copy",
                "--clobber",
                "--retry-delay",
                "--redirects",
                "--timing",
                "--proxy",
                "--bearer",
                "--compress/--no-encode",
                "--format",
                "--image",
                "--pager",
                "--ignore-status",
                "--sort-headers",
                "--ws-interactive",
                "--ws-message-mode",
                "--dry-run",
            ]
        );
    }

    #[test]
    fn cert_display_name_prefers_common_name_and_org() {
        let cert = ParsedCert {
            raw: Vec::new(),
            common_name: Some("example.com".to_string()),
            organization: Some("Example Inc".to_string()),
            dns_names: vec!["alt.example".to_string()],
            ip_addresses: Vec::new(),
            not_after: None,
            issuer_der: Vec::new(),
            subject_der: Vec::new(),
            spki_der: Vec::new(),
            subject_key_id: None,
            authority_key_id: None,
            subject: "CN=example.com, O=Example Inc".to_string(),
        };

        assert_eq!(cert.display_name(), "example.com, Example Inc");
    }

    #[test]
    fn verified_display_chain_replaces_cross_signed_peer_root() {
        let root_not_after = time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(24_000);
        let peer_not_after = time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(21_000);
        let mut root = chain_test_cert(
            9,
            "GTS Root R4",
            b"root-subject",
            b"root-subject",
            b"root-spki",
            root_not_after,
        );
        root.subject_key_id = Some(b"root-key".to_vec());
        let mut peer_cross_signed_root = chain_test_cert(
            3,
            "GTS Root R4",
            b"root-subject",
            b"legacy-root-subject",
            b"root-spki",
            peer_not_after,
        );
        peer_cross_signed_root.subject_key_id = Some(b"root-key".to_vec());
        peer_cross_signed_root.authority_key_id = Some(b"legacy-key".to_vec());

        let chain = certificate_chain_for_display(
            vec![
                {
                    let mut cert = chain_test_cert(
                        1,
                        "example.com",
                        b"leaf-subject",
                        b"intermediate-subject",
                        b"leaf-spki",
                        peer_not_after,
                    );
                    cert.authority_key_id = Some(b"intermediate-key".to_vec());
                    cert
                },
                {
                    let mut cert = chain_test_cert(
                        2,
                        "WE1",
                        b"intermediate-subject",
                        b"root-subject",
                        b"intermediate-spki",
                        peer_not_after,
                    );
                    cert.subject_key_id = Some(b"intermediate-key".to_vec());
                    cert.authority_key_id = Some(b"root-key".to_vec());
                    cert
                },
                peer_cross_signed_root,
            ],
            &[root],
            true,
        );

        assert_eq!(chain.len(), 3);
        assert_eq!(chain[2].raw, vec![9]);
        assert_eq!(chain[2].not_after, Some(root_not_after));
    }

    #[test]
    fn verified_display_chain_appends_omitted_trusted_root() {
        let root_not_after = time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(24_000);
        let peer_not_after = time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(21_000);
        let mut root = chain_test_cert(
            9,
            "Test CA",
            b"root-subject",
            b"root-subject",
            b"root-spki",
            root_not_after,
        );
        root.subject_key_id = Some(b"root-key".to_vec());

        let chain = certificate_chain_for_display(
            vec![{
                let mut cert = chain_test_cert(
                    1,
                    "test-server",
                    b"leaf-subject",
                    b"root-subject",
                    b"leaf-spki",
                    peer_not_after,
                );
                cert.authority_key_id = Some(b"root-key".to_vec());
                cert
            }],
            &[root],
            true,
        );

        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1].display_name(), "Test CA");
        assert_eq!(chain[1].not_after, Some(root_not_after));
    }

    #[test]
    fn insecure_display_chain_keeps_peer_chain_without_trusted_root() {
        let root_not_after = time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(24_000);
        let peer_not_after = time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(21_000);
        let mut root = chain_test_cert(
            9,
            "Test CA",
            b"root-subject",
            b"root-subject",
            b"root-spki",
            root_not_after,
        );
        root.subject_key_id = Some(b"root-key".to_vec());

        let chain = certificate_chain_for_display(
            vec![{
                let mut cert = chain_test_cert(
                    1,
                    "test-server",
                    b"leaf-subject",
                    b"root-subject",
                    b"leaf-spki",
                    peer_not_after,
                );
                cert.authority_key_id = Some(b"root-key".to_vec());
                cert
            }],
            &[root],
            false,
        );

        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].display_name(), "test-server");
    }

    #[test]
    fn cert_expiry_info_matches_go_less_than_one_day_case() {
        let not_after = time::OffsetDateTime::now_utc() + time::Duration::hours(1);

        assert_eq!(cert_expiry_info(Some(not_after)), "expires in <1 day");
    }

    #[test]
    fn render_contains_tls_alpn_chain_and_sans() {
        let inspection = Inspection {
            version: Some(ProtocolVersion::TLSv1_3),
            cipher_suite: None,
            alpn: Some("h2".to_string()),
            chain: vec![ParsedCert {
                raw: vec![1],
                common_name: Some("example.com".to_string()),
                organization: None,
                dns_names: vec!["example.com".to_string()],
                ip_addresses: vec![IpAddr::from([127, 0, 0, 1])],
                not_after: Some(time::OffsetDateTime::now_utc() + time::Duration::hours(1)),
                issuer_der: Vec::new(),
                subject_der: Vec::new(),
                spki_der: Vec::new(),
                subject_key_id: None,
                authority_key_id: None,
                subject: "CN=example.com".to_string(),
            }],
            ocsp_response: Vec::new(),
        };

        let out = render(&inspection);

        assert!(out.contains("TLS 1.3"));
        assert!(out.contains("ALPN: h2"));
        assert!(out.contains("Certificate chain"));
        assert!(out.contains("SANs: example.com, 127.0.0.1"));
    }

    #[test]
    fn render_with_color_colors_tls_metadata_like_go() {
        let inspection = Inspection {
            version: Some(ProtocolVersion::TLSv1_3),
            cipher_suite: None,
            alpn: Some("h2".to_string()),
            chain: vec![ParsedCert {
                raw: vec![1],
                common_name: Some("example.com".to_string()),
                organization: None,
                dns_names: vec!["example.com".to_string()],
                ip_addresses: Vec::new(),
                not_after: Some(time::OffsetDateTime::now_utc() + time::Duration::hours(1)),
                issuer_der: Vec::new(),
                subject_der: Vec::new(),
                spki_der: Vec::new(),
                subject_key_id: None,
                authority_key_id: None,
                subject: "CN=example.com".to_string(),
            }],
            ocsp_response: Vec::new(),
        };

        let out = render_with_color(&inspection, true);

        assert!(out.contains("\x1b[1m\x1b[33mTLS 1.3\x1b[0m"));
        assert!(out.contains("ALPN: \x1b[3mh2\x1b[0m"));
        assert!(out.contains("\x1b[1mCertificate chain\x1b[0m"));
        assert!(out.contains("\x1b[2m└─ \x1b[0m"));
        assert!(out.contains("\x1b[1mexample.com\x1b[0m"));
        assert!(out.contains("\x1b[31mexpires in <1 day\x1b[0m"));
        assert!(out.contains("SANs: \x1b[3mexample.com\x1b[0m"));
    }

    #[test]
    fn parse_ocsp_status_reads_basic_response_statuses() {
        for (tag, want) in [
            (0x80, OcspStatus::Good),
            (0xa1, OcspStatus::Revoked),
            (0x82, OcspStatus::Unknown),
        ] {
            let response = test_ocsp_response(tag);
            assert_eq!(parse_ocsp_status(&response), Some(want), "tag {tag:#x}");
        }

        assert_eq!(parse_ocsp_status(&der_seq(&[der(0x0a, &[1])])), None);
        assert_eq!(parse_ocsp_status(b"not der"), None);
    }

    #[test]
    fn render_ocsp_status_matches_go_stapled_status_line() {
        let mut out = Printer::new(false);
        render_ocsp_status(&mut out, &test_ocsp_response(0x80));

        assert_eq!(out.into_string().unwrap(), "* OCSP: good (stapled)\n");

        let mut out = Printer::new(false);
        render_ocsp_status(&mut out, b"malformed");
        assert!(out.bytes().is_empty());

        let mut out = Printer::new(true);
        render_ocsp_status(&mut out, &test_ocsp_response(0x80));
        assert!(out.into_string().unwrap().contains("\x1b[32mgood\x1b[0m"));
    }

    #[tokio::test]
    async fn inspect_tcp_supports_ipv6_loopback_literals() {
        let listener = match tokio::net::TcpListener::bind("[::1]:0").await {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::AddrNotAvailable => {
                eprintln!("skipping IPv6 loopback TLS inspection test: {err}");
                return;
            }
            Err(err) => panic!("bind IPv6 TLS server: {err}"),
        };
        let port = listener.local_addr().unwrap().port();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(test_tcp_server_config()));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept IPv6 TLS connection");
            acceptor
                .accept(stream)
                .await
                .expect("accept IPv6 TLS handshake");
        });

        let raw_url = format!("https://[::1]:{port}");
        let cli = Cli::try_parse_from(["fetch", "--inspect-tls", "--insecure", &raw_url]).unwrap();
        let url = tls_url(&raw_url).unwrap();

        let inspection = tokio::time::timeout(
            Duration::from_secs(5),
            inspect_tcp(
                &cli,
                &url,
                Some(HttpVersion::Http2),
                TimeoutBudget::new(None),
            ),
        )
        .await
        .expect("IPv6 TLS inspection timed out")
        .unwrap();

        assert!(inspection.version.is_some());
        assert_eq!(inspection.alpn.as_deref(), Some("h2"));
        assert!(
            inspection
                .chain
                .iter()
                .any(|cert| cert.display_name() == "quic-server")
        );
        assert!(server.await.is_ok());
    }

    #[tokio::test]
    async fn inspect_http3_uses_quic_and_h3_alpn() {
        let server_config = test_quic_server_config();
        let endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse::<SocketAddr>().unwrap())
                .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let incoming = endpoint.accept().await.expect("incoming QUIC connection");
            let connection = incoming.await.expect("accepted QUIC connection");
            connection.closed().await;
            endpoint.close(0_u32.into(), b"");
        });

        let raw_url = format!("https://{addr}");
        let cli = Cli::try_parse_from([
            "fetch",
            "--inspect-tls",
            "--http",
            "3",
            "--insecure",
            &raw_url,
        ])
        .unwrap();
        let url = tls_url(&raw_url).unwrap();

        let inspection = inspect(
            &cli,
            &url,
            Some(HttpVersion::Http3),
            TimeoutBudget::new(None),
        )
        .await
        .unwrap();

        assert_eq!(inspection.alpn.as_deref(), Some("h3"));
        assert_eq!(inspection.version, Some(ProtocolVersion::TLSv1_3));
        assert!(
            inspection
                .chain
                .iter()
                .any(|cert| cert.display_name() == "quic-server")
        );
        assert!(server.await.is_ok());
    }

    fn test_tcp_server_config() -> rustls::ServerConfig {
        crate::tls::install_default_crypto_provider();

        let certs = super::super::pem_certificates(TEST_QUIC_CERT_PEM)
            .unwrap()
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        let key = super::super::first_private_key(TEST_QUIC_KEY_PEM)
            .unwrap()
            .expect("test TLS private key");
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        config
    }

    fn test_quic_server_config() -> quinn::ServerConfig {
        crate::tls::install_default_crypto_provider();

        let certs = super::super::pem_certificates(TEST_QUIC_CERT_PEM)
            .unwrap()
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        let key = super::super::first_private_key(TEST_QUIC_KEY_PEM)
            .unwrap()
            .expect("test QUIC private key");
        let mut crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto).unwrap()))
    }

    fn test_ocsp_response(status_tag: u8) -> Vec<u8> {
        let cert_id = der_seq(&[
            der_seq(&[]),
            der(0x04, &[1]),
            der(0x04, &[2]),
            der(0x02, &[1]),
        ]);
        let single_response =
            der_seq(&[cert_id, der(status_tag, &[]), der(0x18, b"20250101000000Z")]);
        let responses = der_seq(&[single_response]);
        let tbs_response_data =
            der_seq(&[der(0xa1, &[]), der(0x18, b"20250101000000Z"), responses]);
        let basic_response = der_seq(&[tbs_response_data, der_seq(&[]), der(0x03, &[0])]);
        let response_bytes = der_seq(&[
            der(
                0x06,
                &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01],
            ),
            der(0x04, &basic_response),
        ]);
        der_seq(&[der(0x0a, &[0]), der(0xa0, &response_bytes)])
    }

    fn der_seq(parts: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        for part in parts {
            body.extend(part);
        }
        der(0x30, &body)
    }

    fn der(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = value.len();
        if len < 128 {
            out.push(len as u8);
        } else {
            let mut bytes = Vec::new();
            let mut n = len;
            while n > 0 {
                bytes.push((n & 0xff) as u8);
                n >>= 8;
            }
            bytes.reverse();
            out.push(0x80 | bytes.len() as u8);
            out.extend(bytes);
        }
        out.extend(value);
        out
    }

    fn chain_test_cert(
        raw: u8,
        common_name: &str,
        subject_der: &[u8],
        issuer_der: &[u8],
        spki_der: &[u8],
        not_after: time::OffsetDateTime,
    ) -> ParsedCert {
        ParsedCert {
            raw: vec![raw],
            common_name: Some(common_name.to_string()),
            organization: None,
            dns_names: Vec::new(),
            ip_addresses: Vec::new(),
            not_after: Some(not_after),
            issuer_der: issuer_der.to_vec(),
            subject_der: subject_der.to_vec(),
            spki_der: spki_der.to_vec(),
            subject_key_id: None,
            authority_key_id: None,
            subject: format!("CN={common_name}"),
        }
    }
}
