use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::crypto::rustls::{HandshakeData, QuicClientConfig};
use rustls::client::EchMode;
use rustls::client::EchStatus;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, ProtocolVersion, SignatureScheme, SupportedCipherSuite};
use tokio_rustls::TlsConnector;
use url::{Host, Url};

use crate::cli::{Cli, HttpVersion};
use crate::core;
#[cfg(test)]
use crate::core::Printer;
use crate::dns::svcb::HttpsRecordResolver;
use crate::duration::{TimeoutBudget, duration_from_seconds};
use crate::error::{FetchError, write_warning_with_separator_with_color};

mod cert;
mod der;
mod render;

use cert::{OcspCapture, ParsedCert};
use render::render_to;

#[cfg(test)]
use cert::{OcspStatus, parse_ocsp_status};
#[cfg(test)]
use render::{cert_expiry_info, render, render_ocsp_status, render_with_color};

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
        .run(Box::pin(inspect(cli, &url, http_version, connect_timeout)))
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
        .map(|opt| opt.flatten())
}

fn inspection_connect_timeout(
    cli: &Cli,
    request_timeout: Option<Duration>,
    request_start: Instant,
) -> Result<TimeoutBudget, FetchError> {
    let connect_timeout = cli
        .connect_timeout
        .map(|seconds| duration_from_seconds("connect-timeout", seconds))
        .transpose()?
        .flatten();
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

    let url = Url::parse(&format!("https://{raw}"))?;
    let is_loopback = match url.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback() || ip.to_ipv4().is_some_and(|ip| ip.is_loopback()),
        None => false,
    };
    if is_loopback {
        return Err("--inspect-tls requires an HTTPS URL".into());
    }
    Ok(url)
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
    // Resolve ECH configuration from DNS.
    let ech_mode = resolve_inspect_ech_mode(cli, &host, timeout).await?;

    let ocsp_capture = OcspCapture::default();
    let mut config = build_client_config(cli, ocsp_capture.clone(), ech_mode)?;
    config.alpn_protocols = alpn_protocols(http_version)
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();

    let server_name = ServerName::try_from(host.clone())
        .map_err(|_| FetchError::Message(format!("invalid server name '{host}'")))?;
    let stream = crate::net::connect_tcp_with_doh_tls(
        url,
        cli.dns_server.as_deref(),
        crate::http::client::doh_tls_config_for_cli(cli)?,
        timeout,
    )
    .await?;
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
    let ech_status = conn.ech_status();

    // Enforce --ech on: handshake must accept ECH.
    if matches!(cli.ech.as_deref(), Some("on")) && !matches!(ech_status, EchStatus::Accepted) {
        return Err(FetchError::Message(format!(
            "ECH was not accepted by the server (status: {ech_status:?})"
        )));
    }

    let mut peer_chain = Vec::new();
    if let Some(certs) = conn.peer_certificates() {
        peer_chain.extend(
            certs
                .iter()
                .filter_map(|cert| ParsedCert::parse(cert.as_ref())),
        );
    }
    Ok(Inspection {
        version: conn.protocol_version(),
        cipher_suite: conn
            .negotiated_cipher_suite()
            .map(CipherSuiteStatus::Negotiated)
            .unwrap_or(CipherSuiteStatus::Unavailable),
        alpn: conn
            .alpn_protocol()
            .map(|protocol| String::from_utf8_lossy(protocol).into_owned()),
        ech_status,
        chain: peer_chain,
        trust_anchor_details_unavailable: !cli.insecure,
        ocsp_response: ocsp_capture.get(),
    })
}

/// Resolve the ECH mode for inspection by fetching HTTPS/SVCB records from DNS
/// and extracting the `ech` SvcParam.
async fn resolve_inspect_ech_mode(
    cli: &Cli,
    host: &str,
    timeout: TimeoutBudget,
) -> Result<Option<EchMode>, FetchError> {
    if !super::ech::is_ech_active(cli) {
        return Ok(None);
    }

    // Skip DNS lookup for IP literals.
    if host.parse::<std::net::IpAddr>().is_ok() {
        return super::ech::resolve_ech_mode(cli, &[]);
    }

    let candidates = lookup_inspect_ech_candidates(cli, host, timeout).await?;
    let candidate_refs: Vec<&[u8]> = candidates.iter().map(|b| b.as_slice()).collect();
    super::ech::resolve_ech_mode(cli, &candidate_refs)
}

/// Fetch HTTPS/SVCB records for a host and return ECH candidate byte slices
/// from usable records ordered by SvcPriority.
async fn lookup_inspect_ech_candidates(
    cli: &Cli,
    host: &str,
    timeout: TimeoutBudget,
) -> Result<Vec<Vec<u8>>, FetchError> {
    let resolver = cli
        .dns_server
        .as_deref()
        .map(HttpsRecordResolver::Custom)
        .unwrap_or(HttpsRecordResolver::System);

    let ech_timeout = timeout
        .remaining()?
        .unwrap_or(std::time::Duration::from_secs(5));
    let doh_tls_config = crate::http::client::doh_tls_config_for_cli(cli)?;
    let records = match TimeoutBudget::new(Some(ech_timeout))
        .run(crate::dns::svcb::lookup_https_records_with_doh_tls_config(
            resolver,
            host,
            Some(ech_timeout),
            doh_tls_config,
        ))
        .await
    {
        Ok(lookup) => lookup.records,
        Err(err) => {
            let authenticated = cli
                .dns_server
                .as_deref()
                .map(|server| {
                    crate::dns::custom::dns_server_is_authenticated(server, !cli.insecure)
                })
                .transpose()?
                .unwrap_or(false);
            super::ech::handle_ech_discovery_error(cli, err, authenticated)?;
            Vec::new()
        }
    };

    let mut usable: Vec<&crate::dns::svcb::SvcbRecord> = records
        .iter()
        .filter(|r| !r.is_alias_mode() && r.is_usable())
        .collect();
    usable.sort_by_key(|r| r.priority);
    Ok(usable
        .iter()
        .filter_map(|r| r.ech.as_ref().filter(|b| !b.is_empty()).cloned())
        .collect())
}

async fn inspect_quic(
    cli: &Cli,
    url: &Url,
    timeout: TimeoutBudget,
) -> Result<Inspection, FetchError> {
    if super::ech::is_ech_active(cli) {
        return Err("--ech with --http 3 is not yet supported for TLS inspection".into());
    }

    let host = tls_host(url)?;
    ensure_quic_protocol_versions(cli)?;
    let port = url.port_or_known_default().unwrap_or(443);
    let addrs = crate::net::resolve_host_with_doh_tls(
        &host,
        cli.dns_server.as_deref(),
        crate::http::client::doh_tls_config_for_cli(cli)?,
        timeout,
    )
    .await?
    .into_iter()
    .map(|mut addr| {
        addr.set_port(port);
        addr
    })
    .collect();
    let addrs = crate::net::interleave_socket_addrs(addrs)?;

    // Each raced connection needs its own capture: a handshake completing after
    // the winner must not overwrite the winner's stapled OCSP response.
    let connections = addrs
        .into_iter()
        .map(|addr| {
            let ocsp_capture = OcspCapture::default();
            let mut config = build_client_config(cli, ocsp_capture.clone(), None)?;
            config.alpn_protocols = alpn_protocols(Some(HttpVersion::Http3))
                .iter()
                .map(|protocol| protocol.as_bytes().to_vec())
                .collect();
            Ok((addr, quic_client_config(config)?, ocsp_capture))
        })
        .collect::<Result<Vec<_>, FetchError>>()?;

    race_quic_inspections(connections, host, !cli.insecure, timeout).await
}

type QuicInspectionConnection = (SocketAddr, quinn::ClientConfig, OcspCapture);

async fn race_quic_inspections(
    connections: Vec<QuicInspectionConnection>,
    host: String,
    verified: bool,
    timeout: TimeoutBudget,
) -> Result<Inspection, FetchError> {
    crate::net::race_staggered(
        connections,
        crate::net::HAPPY_EYEBALLS_FALLBACK_DELAY,
        "lookup returned no addresses",
        "QUIC inspection connect",
        move |(addr, quic_config, ocsp_capture)| {
            inspect_quic_addr(
                addr,
                host.clone(),
                quic_config,
                verified,
                ocsp_capture,
                timeout,
            )
        },
    )
    .await
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
    host: String,
    quic_config: quinn::ClientConfig,
    verified: bool,
    ocsp_capture: OcspCapture,
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
        .connect(addr, &host)
        .map_err(|err| FetchError::Message(err.to_string()))?;
    let connection = timeout
        .run(async {
            connecting
                .await
                .map_err(|err| FetchError::Message(err.to_string()))
        })
        .await?;
    let alpn = quic_alpn(&connection);
    let chain = quic_peer_certificates(&connection);

    // Do not wait for the peer to acknowledge the close. A diagnostic command
    // must return a successful inspection within its connection timeout.
    connection.close(0_u32.into(), b"");
    endpoint.close(0_u32.into(), b"");

    Ok(Inspection {
        version: Some(ProtocolVersion::TLSv1_3),
        // Quinn 0.11 exposes QUIC handshake ALPN and peer identity, but not
        // the rustls cipher suite selected by the TLS handshake.
        cipher_suite: CipherSuiteStatus::UnavailableForHttp3,
        alpn,
        ech_status: EchStatus::NotOffered,
        chain,
        trust_anchor_details_unavailable: verified,
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
    ocsp_capture: OcspCapture,
    ech_mode: Option<EchMode>,
) -> Result<rustls::ClientConfig, FetchError> {
    super::install_default_crypto_provider();

    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
    let versions_builder = rustls::ClientConfig::builder_with_provider(provider.clone());
    let versions = inspection_protocol_versions(cli)?;
    let builder = if let Some(ech_mode) = ech_mode {
        if !versions
            .iter()
            .any(|v| v.version == rustls::ProtocolVersion::TLSv1_3)
        {
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
            return Err(super::ech_tls_version_error(
                min_tls,
                cli.max_tls.as_deref(),
            ));
        }
        versions_builder
            .with_ech(ech_mode)
            .map_err(|err| FetchError::Message(format!("invalid ECH configuration: {err}")))?
    } else {
        versions_builder
            .with_protocol_versions(&versions)
            .map_err(|_| FetchError::Message("invalid TLS versions".to_string()))?
    };
    let verifier: Arc<dyn ServerCertVerifier> = if cli.insecure {
        Arc::new(super::InsecureServerVerifier::new(
            provider.signature_verification_algorithms,
        ))
    } else {
        Arc::new(super::rustls_platform_verifier(&cli.ca_cert, provider)?)
    };
    let builder = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(CapturingServerVerifier {
            inner: verifier,
            ocsp_capture,
        }));

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

#[derive(Clone, Copy)]
enum CipherSuiteStatus {
    Negotiated(SupportedCipherSuite),
    Unavailable,
    UnavailableForHttp3,
}

#[derive(Clone)]
struct Inspection {
    version: Option<ProtocolVersion>,
    cipher_suite: CipherSuiteStatus,
    alpn: Option<String>,
    ech_status: EchStatus,
    chain: Vec<ParsedCert>,
    trust_anchor_details_unavailable: bool,
    ocsp_response: Vec<u8>,
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

impl fmt::Debug for Inspection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inspection")
            .field("version", &self.version)
            .field("alpn", &self.alpn)
            .field("chain_len", &self.chain.len())
            .field(
                "trust_anchor_details_unavailable",
                &self.trust_anchor_details_unavailable,
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use quinn::crypto::rustls::QuicServerConfig;
    use sha1::{Digest as _, Sha1};
    use std::net::IpAddr;

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
    fn tls_url_rejects_schemeless_loopback_addresses() {
        for raw in ["[::1]", "[::1]:443", "[::ffff:127.0.0.1]"] {
            let err = tls_url(raw).unwrap_err();

            assert_eq!(err.to_string(), "--inspect-tls requires an HTTPS URL");
        }
    }

    #[test]
    fn tls_url_preserves_schemeless_host_port_userinfo_and_ipv6() {
        for (raw, expected) in [
            ("example.com:8443", "https://example.com:8443/"),
            (
                "user:pass@example.com:8443",
                "https://user:pass@example.com:8443/",
            ),
            ("[2001:db8::1]:8443", "https://[2001:db8::1]:8443/"),
        ] {
            assert_eq!(tls_url(raw).unwrap().as_str(), expected);
        }
    }

    #[test]
    fn http_version_flags_are_not_ignored_for_tls_inspection() {
        let cli = Cli::try_parse_from([
            "fetch",
            "--inspect-tls",
            "--http",
            "3",
            "https://example.com",
        ])
        .unwrap();

        assert!(ignored_inspection_flags(&cli).is_empty());
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
                "--data",
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
                "--compress",
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
            subject_name_der: Vec::new(),
            spki_der: Vec::new(),
            subject_public_key: Vec::new(),
            serial_number: Vec::new(),
            subject_key_id: None,
            authority_key_id: None,
            subject: "CN=example.com, O=Example Inc".to_string(),
        };

        assert_eq!(cert.display_name(), "example.com, Example Inc");
    }

    #[test]
    fn verified_display_does_not_infer_a_root_from_colliding_metadata() {
        let not_after = time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(24_000);
        let mut peer = chain_test_cert(
            1,
            "test-server",
            b"leaf-subject",
            b"colliding-root-subject",
            b"leaf-spki",
            not_after,
        );
        peer.authority_key_id = Some(b"colliding-key-id".to_vec());
        let mut first_candidate = chain_test_cert(
            2,
            "First CA",
            b"colliding-root-subject",
            b"colliding-root-subject",
            b"first-root-spki",
            not_after,
        );
        first_candidate.subject_key_id = Some(b"colliding-key-id".to_vec());
        let mut second_candidate = chain_test_cert(
            3,
            "Second CA",
            b"colliding-root-subject",
            b"colliding-root-subject",
            b"second-root-spki",
            not_after,
        );
        second_candidate.subject_key_id = Some(b"colliding-key-id".to_vec());
        assert_eq!(peer.issuer_der, first_candidate.subject_der);
        assert_eq!(peer.issuer_der, second_candidate.subject_der);
        assert_eq!(peer.authority_key_id, first_candidate.subject_key_id);
        assert_eq!(peer.authority_key_id, second_candidate.subject_key_id);

        let inspection = Inspection {
            version: Some(ProtocolVersion::TLSv1_3),
            cipher_suite: CipherSuiteStatus::Unavailable,
            alpn: None,
            ech_status: EchStatus::NotOffered,
            chain: vec![peer],
            trust_anchor_details_unavailable: true,
            ocsp_response: Vec::new(),
        };

        let out = render(&inspection);

        assert!(out.contains("Peer certificate chain"));
        assert_eq!(out.matches("└─").count(), 1);
        assert!(!out.contains("First CA"));
        assert!(!out.contains("Second CA"));
        assert!(out.contains("Trust anchor: platform-selected, details unavailable"));
    }

    #[test]
    fn cert_expiry_info_matches_go_less_than_one_day_case() {
        let not_after = time::OffsetDateTime::now_utc() + time::Duration::hours(1);

        assert_eq!(cert_expiry_info(Some(not_after)), "expires in <1 day");
    }

    #[test]
    fn render_tcp_contains_tls_alpn_chain_sans_and_cipher_suite() {
        let inspection = Inspection {
            version: Some(ProtocolVersion::TLSv1_3),
            cipher_suite: CipherSuiteStatus::Negotiated(
                rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
            ),
            alpn: Some("h2".to_string()),
            ech_status: EchStatus::NotOffered,
            chain: vec![ParsedCert {
                raw: vec![1],
                common_name: Some("example.com".to_string()),
                organization: None,
                dns_names: vec!["example.com".to_string()],
                ip_addresses: vec![IpAddr::from([127, 0, 0, 1])],
                not_after: Some(time::OffsetDateTime::now_utc() + time::Duration::hours(1)),
                issuer_der: Vec::new(),
                subject_der: Vec::new(),
                subject_name_der: Vec::new(),
                spki_der: Vec::new(),
                subject_public_key: Vec::new(),
                serial_number: Vec::new(),
                subject_key_id: None,
                authority_key_id: None,
                subject: "CN=example.com".to_string(),
            }],
            trust_anchor_details_unavailable: false,
            ocsp_response: Vec::new(),
        };

        let out = render(&inspection);

        assert!(out.contains("TLS 1.3: TLS13_AES_256_GCM_SHA384"));
        assert!(out.contains("ALPN: h2"));
        assert!(out.contains("Peer certificate chain"));
        assert!(out.contains("SANs: example.com, 127.0.0.1"));
    }

    #[test]
    fn render_escapes_untrusted_tls_diagnostic_text() {
        let inspection = Inspection {
            version: Some(ProtocolVersion::TLSv1_3),
            cipher_suite: CipherSuiteStatus::Unavailable,
            alpn: Some("h2\x1b]0;owned\x07".to_string()),
            ech_status: EchStatus::NotOffered,
            chain: vec![ParsedCert {
                raw: vec![1],
                common_name: Some("cn\x1b\n\r\x07\u{202e}.example".to_string()),
                organization: None,
                dns_names: vec!["dns\u{85}\u{7f}\u{2066}\\name".to_string()],
                ip_addresses: Vec::new(),
                not_after: None,
                issuer_der: Vec::new(),
                subject_der: Vec::new(),
                subject_name_der: Vec::new(),
                spki_der: Vec::new(),
                subject_public_key: Vec::new(),
                serial_number: Vec::new(),
                subject_key_id: None,
                authority_key_id: None,
                subject: String::new(),
            }],
            trust_anchor_details_unavailable: false,
            ocsp_response: Vec::new(),
        };

        let out = render(&inspection);

        assert!(out.contains("ALPN: h2\\x1b]0;owned\\x07"));
        assert!(out.contains("cn\\x1b\\n\\r\\x07\\u{202e}.example"));
        assert!(out.contains("SANs: dns\\u{85}\\x7f\\u{2066}\\\\name"));
        assert!(!out.contains('\x1b'));
        assert!(!out.contains('\r'));
        assert!(!out.contains('\x07'));
        assert!(!out.contains('\u{202e}'));
    }

    #[test]
    fn render_quic_reports_unavailable_cipher_suite() {
        let inspection = Inspection {
            version: Some(ProtocolVersion::TLSv1_3),
            cipher_suite: CipherSuiteStatus::UnavailableForHttp3,
            alpn: Some("h3".to_string()),
            ech_status: EchStatus::NotOffered,
            chain: Vec::new(),
            trust_anchor_details_unavailable: false,
            ocsp_response: Vec::new(),
        };

        assert_eq!(
            render(&inspection),
            "* TLS 1.3: cipher suite unavailable for HTTP/3\n* ALPN: h3\n"
        );
    }

    #[test]
    fn render_with_color_colors_tls_metadata_like_go() {
        let inspection = Inspection {
            version: Some(ProtocolVersion::TLSv1_3),
            cipher_suite: CipherSuiteStatus::Negotiated(
                rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
            ),
            alpn: Some("h2".to_string()),
            ech_status: EchStatus::NotOffered,
            chain: vec![ParsedCert {
                raw: vec![1],
                common_name: Some("example.com".to_string()),
                organization: None,
                dns_names: vec!["example.com".to_string()],
                ip_addresses: Vec::new(),
                not_after: Some(time::OffsetDateTime::now_utc() + time::Duration::hours(1)),
                issuer_der: Vec::new(),
                subject_der: Vec::new(),
                subject_name_der: Vec::new(),
                spki_der: Vec::new(),
                subject_public_key: Vec::new(),
                serial_number: Vec::new(),
                subject_key_id: None,
                authority_key_id: None,
                subject: "CN=example.com".to_string(),
            }],
            trust_anchor_details_unavailable: false,
            ocsp_response: Vec::new(),
        };

        let out = render_with_color(&inspection, true);

        assert!(out.contains("\x1b[1m\x1b[33mTLS 1.3\x1b[0m"));
        assert!(out.contains("ALPN: \x1b[3mh2\x1b[0m"));
        assert!(out.contains("\x1b[1mPeer certificate chain\x1b[0m"));
        assert!(out.contains("\x1b[2m└─ \x1b[0m"));
        assert!(out.contains("\x1b[1mexample.com\x1b[0m"));
        assert!(out.contains("\x1b[31mexpires in <1 day\x1b[0m"));
        assert!(out.contains("SANs: \x1b[3mexample.com\x1b[0m"));
    }

    #[test]
    fn parse_ocsp_status_reads_matching_basic_response_statuses() {
        let cert = ParsedCert::parse(
            &super::super::pem_certificates(TEST_QUIC_CERT_PEM)
                .unwrap()
                .remove(0),
        )
        .unwrap();
        for (tag, want) in [
            (0x80, OcspStatus::Good),
            (0xa1, OcspStatus::Revoked),
            (0x82, OcspStatus::Unknown),
        ] {
            let cert_id = test_ocsp_cert_id(&cert, &cert);
            let response = test_ocsp_response_entries(vec![(cert_id, tag)]);
            assert_eq!(
                parse_ocsp_status(&response, &cert, &cert),
                Some(want),
                "tag {tag:#x}"
            );
        }

        assert_eq!(
            parse_ocsp_status(&der_seq(&[der(0x0a, &[1])]), &cert, &cert),
            None
        );
        assert_eq!(parse_ocsp_status(b"not der", &cert, &cert), None);
    }

    #[test]
    fn parse_ocsp_status_matches_leaf_cert_id_across_all_entries() {
        let cert = ParsedCert::parse(
            &super::super::pem_certificates(TEST_QUIC_CERT_PEM)
                .unwrap()
                .remove(0),
        )
        .unwrap();
        let matching_cert_id = test_ocsp_cert_id(&cert, &cert);
        let unrelated_cert_id = der_seq(&[
            der_seq(&[der(0x06, &[0x2b, 0x0e, 0x03, 0x02, 0x1a]), der(0x05, &[])]),
            der(0x04, &[9; 20]),
            der(0x04, &[8; 20]),
            der(0x02, &[7]),
        ]);
        let response = test_ocsp_response_entries(vec![
            (unrelated_cert_id.clone(), 0xa1),
            (matching_cert_id, 0x80),
        ]);
        let no_match_response = test_ocsp_response_entries(vec![(unrelated_cert_id, 0x80)]);

        assert_eq!(
            parse_ocsp_status(&response, &cert, &cert),
            Some(OcspStatus::Good)
        );
        assert_eq!(parse_ocsp_status(&no_match_response, &cert, &cert), None);
    }

    #[test]
    fn render_ocsp_status_is_neutral_for_unverified_matching_response() {
        let cert = ParsedCert::parse(
            &super::super::pem_certificates(TEST_QUIC_CERT_PEM)
                .unwrap()
                .remove(0),
        )
        .unwrap();
        let cert_id = test_ocsp_cert_id(&cert, &cert);
        let response = test_ocsp_response_entries(vec![(cert_id, 0x80)]);

        let mut out = Printer::new(false);
        render_ocsp_status(&mut out, &response, Some(&cert), Some(&cert));
        assert_eq!(
            out.into_string().unwrap(),
            "* OCSP: good (stapled, unverified)\n"
        );

        let mut out = Printer::new(true);
        render_ocsp_status(&mut out, &response, Some(&cert), Some(&cert));
        let rendered = out.into_string().unwrap();
        assert!(rendered.contains("OCSP: good (stapled, unverified)"));
        assert!(!rendered.contains("\x1b[32m"));
        assert!(!rendered.contains("\x1b[31m"));
        assert!(!rendered.contains("\x1b[33m"));
    }

    #[test]
    fn render_ocsp_status_hides_status_for_unrelated_response() {
        let cert = ParsedCert::parse(
            &super::super::pem_certificates(TEST_QUIC_CERT_PEM)
                .unwrap()
                .remove(0),
        )
        .unwrap();
        let unrelated_cert_id = der_seq(&[
            der_seq(&[der(0x06, &[0x2b, 0x0e, 0x03, 0x02, 0x1a]), der(0x05, &[])]),
            der(0x04, &[9; 20]),
            der(0x04, &[8; 20]),
            der(0x02, &[7]),
        ]);
        let response = test_ocsp_response_entries(vec![(unrelated_cert_id, 0xa1)]);

        let mut out = Printer::new(true);
        render_ocsp_status(&mut out, &response, Some(&cert), Some(&cert));
        let rendered = out.into_string().unwrap();

        assert!(rendered.contains("OCSP staple present (unverified)"));
        assert!(!rendered.contains("revoked"));
        assert!(!rendered.contains("\x1b[31m"));
    }

    #[test]
    fn render_ocsp_status_hides_status_without_issuer() {
        let mut out = Printer::new(true);
        render_ocsp_status(&mut out, &test_ocsp_response(0x80), None, None);
        let rendered = out.into_string().unwrap();

        assert!(rendered.contains("OCSP staple present (unverified)"));
        assert!(!rendered.contains("good"));
        assert!(!rendered.contains("\x1b[32m"));
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
        assert!(matches!(
            inspection.cipher_suite,
            CipherSuiteStatus::Negotiated(_)
        ));
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
    async fn quic_race_keeps_winning_connection_ocsp_response() {
        let losing_ocsp = test_ocsp_response(0x80);
        let winning_ocsp = test_ocsp_response(0x82);
        let first = match quinn::Endpoint::server(
            test_quic_server_config_with_ocsp(losing_ocsp),
            "[::1]:0".parse::<SocketAddr>().unwrap(),
        ) {
            Ok(endpoint) => endpoint,
            Err(err) if err.kind() == std::io::ErrorKind::AddrNotAvailable => {
                eprintln!("skipping IPv6 QUIC race test: {err}");
                return;
            }
            Err(err) => panic!("bind IPv6 QUIC server: {err}"),
        };
        let first_addr = first.local_addr().unwrap();
        let second = quinn::Endpoint::server(
            test_quic_server_config_with_ocsp(winning_ocsp.clone()),
            SocketAddr::new("127.0.0.1".parse().unwrap(), first_addr.port()),
        )
        .unwrap();
        let second_addr = second.local_addr().unwrap();

        // Keep the preferred address's handshake pending long enough for the
        // staggered fallback to win. Its distinct OCSP response must not leak
        // into the winning inspection.
        let losing_server = tokio::spawn(async move {
            if let Some(incoming) = first.accept().await {
                tokio::time::sleep(Duration::from_millis(600)).await;
                let _ = incoming.await;
            }
        });
        let winning_server = tokio::spawn(async move {
            if let Some(incoming) = second.accept().await {
                let _ = incoming.await;
            }
        });

        let cli = Cli::try_parse_from([
            "fetch",
            "--inspect-tls",
            "--http",
            "3",
            "--insecure",
            "https://localhost",
        ])
        .unwrap();
        let connections = [first_addr, second_addr]
            .into_iter()
            .map(|addr| {
                let capture = OcspCapture::default();
                let mut config = build_client_config(&cli, capture.clone(), None)?;
                config.alpn_protocols = vec![b"h3".to_vec()];
                Ok((addr, quic_client_config(config)?, capture))
            })
            .collect::<Result<Vec<_>, FetchError>>()
            .unwrap();

        let inspection = tokio::time::timeout(
            Duration::from_secs(5),
            race_quic_inspections(
                connections,
                "localhost".to_string(),
                false,
                TimeoutBudget::new(None),
            ),
        )
        .await
        .expect("QUIC inspection race timed out")
        .unwrap();

        assert_eq!(inspection.ocsp_response, winning_ocsp);
        losing_server.abort();
        winning_server.abort();
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
            let _connection = incoming.await.expect("accepted QUIC connection");
            // Keep the peer open and do not acknowledge the client's close.
            // This verifies inspection does not wait for graceful QUIC cleanup.
            std::future::pending::<()>().await;
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
        assert!(ignored_inspection_flags(&cli).is_empty());

        let inspection = tokio::time::timeout(
            Duration::from_secs(1),
            inspect(
                &cli,
                &url,
                Some(HttpVersion::Http3),
                TimeoutBudget::new(None),
            ),
        )
        .await
        .expect("QUIC inspection waited for peer cleanup")
        .unwrap();

        assert_eq!(inspection.alpn.as_deref(), Some("h3"));
        assert_eq!(inspection.version, Some(ProtocolVersion::TLSv1_3));
        assert!(matches!(
            inspection.cipher_suite,
            CipherSuiteStatus::UnavailableForHttp3
        ));
        assert!(
            inspection
                .chain
                .iter()
                .any(|cert| cert.display_name() == "quic-server")
        );
        server.abort();
        assert!(server.await.is_err());
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
        test_quic_server_config_with_ocsp(Vec::new())
    }

    fn test_quic_server_config_with_ocsp(ocsp_response: Vec<u8>) -> quinn::ServerConfig {
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
            .with_single_cert_with_ocsp(certs, key, ocsp_response)
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
        test_ocsp_response_entries(vec![(cert_id, status_tag)])
    }

    fn test_ocsp_response_entries(entries: Vec<(Vec<u8>, u8)>) -> Vec<u8> {
        let singles = entries
            .into_iter()
            .map(|(cert_id, status_tag)| {
                der_seq(&[cert_id, der(status_tag, &[]), der(0x18, b"20250101000000Z")])
            })
            .collect::<Vec<_>>();
        let responses = der_seq(&singles);
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

    fn test_ocsp_cert_id(leaf: &ParsedCert, issuer: &ParsedCert) -> Vec<u8> {
        der_seq(&[
            der_seq(&[der(0x06, &[0x2b, 0x0e, 0x03, 0x02, 0x1a]), der(0x05, &[])]),
            der(0x04, &Sha1::digest(&issuer.subject_name_der)),
            der(0x04, &Sha1::digest(&issuer.subject_public_key)),
            der(0x02, &leaf.serial_number),
        ])
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
            subject_name_der: Vec::new(),
            spki_der: spki_der.to_vec(),
            subject_public_key: Vec::new(),
            serial_number: vec![raw],
            subject_key_id: None,
            authority_key_id: None,
            subject: format!("CN={common_name}"),
        }
    }
}
