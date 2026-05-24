use std::collections::BTreeMap;
use std::env;
use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::io::{IsTerminal, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime};

use base64::Engine;
use bytes::Bytes;
use flate2::read::GzDecoder;
use http_body_util::BodyExt;
use reqwest::header::{
    ACCEPT, ACCEPT_ENCODING, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, RANGE, RETRY_AFTER,
    USER_AGENT, WWW_AUTHENTICATE,
};
use reqwest::redirect;
use reqwest::{Client, Method, RequestBuilder, Response, StatusCode};
use tower::{Layer, Service};
use url::Url;

use crate::auth::aws_sigv4;
use crate::auth::digest;
use crate::cli::{Cli, HttpVersion};
use crate::core;
use crate::error::{FetchError, write_error_with_color, write_warning_with_color};
use crate::format::content_type::{self, ContentType};
use crate::format::css;
use crate::format::csv;
use crate::format::grpc as grpc_format;
use crate::format::html;
use crate::format::json;
use crate::format::markdown;
use crate::format::msgpack;
use crate::format::protobuf;
use crate::format::sse;
use crate::format::xml;
use crate::format::yaml;
use crate::grpc::status as grpc_status;
use crate::output;
use crate::proto;
use crate::timing::{self, AttemptTiming, DnsTiming, ResponseTiming};

mod edit;
pub mod multipart;

pub(crate) type RequestBody = Option<(Vec<u8>, Option<String>)>;

pub async fn execute(cli: &Cli) -> Result<i32, FetchError> {
    let http_version =
        crate::cli::parse_http_version(cli.http.as_deref()).map_err(FetchError::Message)?;
    let http_version = effective_http_version(cli, http_version);
    let mut url = normalize_url(cli.url.as_deref().expect("URL checked by app"))?;
    apply_query(&mut url, &cli.query);
    validate_proxy_for_http_version(cli.proxy.as_deref(), http_version)?;
    validate_http_version_options(http_version, &url, cli.grpc, cli.unix.as_deref())?;
    let grpc_schema = if cli.grpc {
        proto::load_local_schema(cli)?
    } else {
        None
    };
    let mut grpc_method = if let Some(schema) = &grpc_schema {
        Some(proto::method_for_url(schema, &url)?)
    } else {
        None
    };
    let session = load_session(cli)?;

    let dns_resolution = resolve_dns_for_client(cli, &url, http_version).await?;

    crate::tls::install_default_crypto_provider();

    let mut builder = Client::builder().use_rustls_tls().no_gzip().no_zstd();
    let connect_timing = ConnectionTiming::default();
    builder = configure_http_version(builder, http_version);
    builder = configure_unix_socket(builder, cli.unix.as_deref())?;
    builder = configure_http3_local_address(builder, http_version, &url, dns_resolution.as_ref());
    builder = configure_dns_resolution(builder, url.host_str(), dns_resolution.as_ref());
    if cli.timing || (cli.verbose >= 3 && !cli.silent) {
        builder = builder.connector_layer(ConnectionTimingLayer::new(connect_timing.clone()));
    }
    builder = configure_tls(builder, cli)?;
    builder = configure_proxy(builder, cli.proxy.as_deref())?;
    if cli.insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    if let Some(seconds) = cli.timeout {
        builder = builder.timeout(duration_from_seconds("timeout", seconds)?);
    }
    if let Some(seconds) = cli.connect_timeout {
        builder = builder.connect_timeout(duration_from_seconds("connect-timeout", seconds)?);
    }
    if let Some(session) = &session {
        builder = builder.cookie_provider(session.cookie_provider());
    }
    let redirect_history = RedirectHistory::default();
    builder = builder.redirect(redirect_policy_with_history(
        cli.redirects,
        cli.verbose,
        cli.silent,
        redirect_history.clone(),
        cli.color.clone(),
    ));
    let client = builder.build()?;
    if cli.grpc && grpc_method.is_none() && grpc_request_requires_schema(cli) {
        let schema = crate::grpc::reflection::schema_for_call(cli, &url, &client).await?;
        grpc_method = Some(proto::method_for_url(&schema, &url)?);
    }
    let method_name = effective_method(cli);
    let method = Method::from_bytes(method_name.as_bytes())
        .map_err(|err| FetchError::Message(format!("invalid method '{method_name}': {err}")))?;

    let mut headers = HeaderMap::new();
    headers.insert(
        USER_AGENT,
        HeaderValue::from_str(&core::user_agent()).expect("valid user agent"),
    );
    if cli.grpc {
        apply_headers(&mut headers, &cli.headers)?;
        apply_grpc_headers(&mut headers);
    } else {
        headers.insert(
            ACCEPT,
            HeaderValue::from_static(
                "application/json,application/vnd.msgpack,application/xml,image/webp,*/*",
            ),
        );
        apply_headers(&mut headers, &cli.headers)?;
    }
    apply_ranges(&mut headers, &cli.ranges);
    let encoding_requested = apply_accept_encoding(&mut headers, cli, &method);
    let mut body = request_body(cli)?;
    apply_body_content_type(&mut headers, &body);
    if cli.edit {
        body = edit::edit_request_body(&headers, body)?;
    }
    if cli.grpc {
        body = proto::grpc_request_body(body, grpc_method.as_ref())?;
    }
    apply_body_content_type(&mut headers, &body);

    let digest_credentials = digest_credentials(cli.digest.as_deref())?;
    let aws_config = aws_config(cli.aws_sigv4.as_deref())?;

    if cli.dry_run {
        let mut dry_run_headers = headers.clone();
        if let Some(config) = &aws_config {
            aws_sigv4::sign(
                method.as_str(),
                &url,
                &mut dry_run_headers,
                request_body_bytes(&body),
                config,
                time::OffsetDateTime::now_utc(),
                aws_unsigned_payload(cli, config),
            )
            .map_err(|err| FetchError::Message(err.to_string()))?;
        }
        apply_builder_authorization_headers(&mut dry_run_headers, cli, None)?;
        print_request_metadata(cli, &method, &url, &dry_run_headers, &body, http_version);
        print_dry_run_body(cli, &body)?;
        return Ok(0);
    }

    let retry_count = cli.retry();
    let retry_delay = duration_from_seconds("retry-delay", cli.retry_delay())?;
    let total_attempts = retry_count + 1;
    let mut attempt = 0;
    let result = loop {
        let mut attempt_headers = headers.clone();
        if cli.verbose >= 2 && !cli.silent {
            print_request_metadata(cli, &method, &url, &attempt_headers, &body, http_version);
        }
        if cli.verbose >= 3
            && !cli.silent
            && let Some(dns) = dns_resolution
                .as_ref()
                .and_then(|resolution| resolution.timing.as_ref())
        {
            print_dns_debug(cli, dns);
        }
        if let Some(config) = &aws_config {
            aws_sigv4::sign(
                method.as_str(),
                &url,
                &mut attempt_headers,
                request_body_bytes(&body),
                config,
                time::OffsetDateTime::now_utc(),
                aws_unsigned_payload(cli, config),
            )
            .map_err(|err| FetchError::Message(err.to_string()))?;
        }

        redirect_history.clear();
        let req = build_request(
            &client,
            method.clone(),
            url.clone(),
            attempt_headers,
            body.clone(),
            cli,
            None,
        )?;
        let mut timing = AttemptTiming::start();
        timing.set_dns(
            dns_resolution
                .as_ref()
                .and_then(|resolution| resolution.timing.as_ref())
                .map(|dns| dns.duration),
        );
        connect_timing.clear();
        match req.send().await {
            Ok(response) => {
                timing.mark_response_headers();
                timing.set_connect(connect_timing.duration());
                if cli.verbose >= 3 && !cli.silent {
                    let connect_target =
                        connect_debug_target(&response, &url, dns_resolution.as_ref());
                    timing::print_debug_lines(&timing, &connect_target, cli.color.as_deref());
                }
                let response = apply_digest_challenge(
                    response,
                    DigestRetryContext {
                        client: &client,
                        method: method.clone(),
                        headers: headers.clone(),
                        body: body.clone(),
                        cli,
                        redirect_statuses: redirect_history.statuses(),
                    },
                    digest_credentials.as_ref(),
                )
                .await?;
                let status = response.status();
                if attempt < retry_count && should_retry_status(status) {
                    let delay =
                        compute_delay(retry_delay, attempt, parse_retry_after(response.headers()));
                    print_retry(
                        cli,
                        attempt + 2,
                        total_attempts,
                        delay,
                        &retry_reason(status),
                    );
                    let _ = response.bytes().await;
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                    continue;
                }
                break finish_response(
                    cli,
                    response,
                    encoding_requested,
                    Some(timing),
                    grpc_method.as_ref(),
                )
                .await;
            }
            Err(err) => {
                if let Some(message) = redirect_error_message(&err) {
                    break Err(FetchError::Runtime(message));
                }
                if attempt < retry_count && is_retryable_error(&err) {
                    let delay = compute_delay(retry_delay, attempt, Duration::ZERO);
                    print_retry(cli, attempt + 2, total_attempts, delay, &err.to_string());
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                    continue;
                }
                if let Some(message) = timeout_error_message(cli, &err) {
                    break Err(FetchError::Runtime(message));
                }
                let message = reqwest_request_error_message(&err);
                if is_certificate_validation_error(&err) {
                    break Err(FetchError::CertificateValidation(message));
                }
                break Err(FetchError::Runtime(message));
            }
        }
    };
    save_session(cli, session.as_ref());
    result
}

fn load_session(cli: &Cli) -> Result<Option<crate::session::Session>, FetchError> {
    let Some(name) = cli.session.as_deref() else {
        return Ok(None);
    };
    let loaded =
        crate::session::Session::load(name).map_err(|err| FetchError::Message(err.to_string()))?;
    if let Some(warning) = loaded.warning {
        write_warning(
            cli,
            &format!("session '{name}' is corrupted, starting fresh: {warning}"),
        );
    }
    Ok(Some(loaded.session))
}

fn save_session(cli: &Cli, session: Option<&crate::session::Session>) {
    let Some(session) = session else {
        return;
    };
    if let Err(err) = session.save() {
        write_warning(
            cli,
            &format!("unable to save session '{}': {err}", session.name()),
        );
    }
}

fn write_warning(cli: &Cli, message: &str) {
    if !cli.silent {
        write_warning_with_color(message, cli.color.as_deref());
    }
}

fn effective_method(cli: &Cli) -> &str {
    if cli.grpc && cli.method.is_none() {
        "POST"
    } else {
        cli.method()
    }
}

fn effective_http_version(cli: &Cli, version: Option<HttpVersion>) -> Option<HttpVersion> {
    if cli.grpc && version.is_none() {
        Some(HttpVersion::Http2)
    } else {
        version
    }
}

fn configure_unix_socket(
    builder: reqwest::ClientBuilder,
    path: Option<&str>,
) -> Result<reqwest::ClientBuilder, FetchError> {
    let Some(path) = path else {
        return Ok(builder);
    };

    #[cfg(unix)]
    {
        Ok(builder.unix_socket(path))
    }

    #[cfg(not(unix))]
    {
        let _ = path;
        Err("--unix is not supported on this platform".into())
    }
}

#[derive(Clone, Debug)]
struct DnsResolution {
    socket_addrs: Vec<SocketAddr>,
    timing: Option<DnsTiming>,
}

async fn resolve_dns_for_client(
    cli: &Cli,
    url: &Url,
    http_version: Option<HttpVersion>,
) -> Result<Option<DnsResolution>, FetchError> {
    let Some(host) = url.host_str() else {
        return Ok(None);
    };
    if host.parse::<IpAddr>().is_ok() || cli.proxy.is_some() || cli.unix.is_some() {
        return Ok(None);
    }

    let debug_dns = (cli.timing || (cli.verbose >= 3 && !cli.silent))
        && !matches!(http_version, Some(HttpVersion::Http3));

    if let Some(dns_server) = cli.dns_server.as_deref() {
        let start = Instant::now();
        let addrs = if dns_server.starts_with("http://") || dns_server.starts_with("https://") {
            let server_url = Url::parse(dns_server).map_err(|err| {
                FetchError::Message(format!("invalid dns-server '{dns_server}': {err}"))
            })?;
            crate::dns::doh::lookup_doh(&server_url, host)
                .await
                .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))?
        } else {
            let server_addr = crate::dns::resolver::normalize_udp_dns_server(dns_server)
                .map_err(|err| FetchError::Message(err.to_string()))?;
            crate::dns::resolver::lookup_udp(&server_addr, host)
                .await
                .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))?
        };
        let addrs = sorted_unique_ips(addrs);
        return Ok(Some(DnsResolution {
            socket_addrs: crate::dns::doh::socket_addrs_for_override(&addrs),
            timing: debug_dns.then(|| DnsTiming {
                host: host.to_string(),
                addrs,
                duration: start.elapsed(),
            }),
        }));
    }

    if !debug_dns {
        return Ok(None);
    }

    let port = url.port_or_known_default().unwrap_or_else(|| {
        if url.scheme().eq_ignore_ascii_case("https") {
            443
        } else {
            80
        }
    });
    let start = Instant::now();
    let mut socket_addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))?
        .collect::<Vec<_>>();
    sort_socket_addrs(&mut socket_addrs);
    let addrs = sorted_unique_ips(socket_addrs.iter().map(|addr| addr.ip()).collect());
    Ok(Some(DnsResolution {
        socket_addrs,
        timing: Some(DnsTiming {
            host: host.to_string(),
            addrs,
            duration: start.elapsed(),
        }),
    }))
}

fn configure_dns_resolution(
    builder: reqwest::ClientBuilder,
    host: Option<&str>,
    resolution: Option<&DnsResolution>,
) -> reqwest::ClientBuilder {
    match (host, resolution) {
        (Some(host), Some(resolution)) if !resolution.socket_addrs.is_empty() => {
            builder.resolve_to_addrs(host, &resolution.socket_addrs)
        }
        _ => builder,
    }
}

fn configure_http3_local_address(
    builder: reqwest::ClientBuilder,
    version: Option<HttpVersion>,
    url: &Url,
    resolution: Option<&DnsResolution>,
) -> reqwest::ClientBuilder {
    if !matches!(version, Some(HttpVersion::Http3)) {
        return builder;
    }

    match http3_local_address(url, resolution) {
        Some(addr) => builder.local_address(addr),
        None => builder,
    }
}

fn http3_local_address(url: &Url, resolution: Option<&DnsResolution>) -> Option<IpAddr> {
    let destination_ip = url
        .host_str()
        .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
        .and_then(|host| host.parse::<IpAddr>().ok())
        .or_else(|| resolution?.socket_addrs.first().map(SocketAddr::ip));

    match destination_ip {
        Some(IpAddr::V4(_)) => Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        Some(IpAddr::V6(_)) => Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
        None => None,
    }
}

fn sorted_unique_ips(mut addrs: Vec<IpAddr>) -> Vec<IpAddr> {
    addrs.sort_by(compare_ip_addrs);
    addrs.dedup();
    addrs
}

fn sort_socket_addrs(addrs: &mut [SocketAddr]) {
    addrs.sort_by(|left, right| {
        compare_ip_addrs(&left.ip(), &right.ip()).then_with(|| left.port().cmp(&right.port()))
    });
}

fn compare_ip_addrs(left: &IpAddr, right: &IpAddr) -> std::cmp::Ordering {
    match (left, right) {
        (IpAddr::V4(left), IpAddr::V4(right)) => left.octets().cmp(&right.octets()),
        (IpAddr::V6(left), IpAddr::V6(right)) => left.octets().cmp(&right.octets()),
        (IpAddr::V4(_), IpAddr::V6(_)) => std::cmp::Ordering::Less,
        (IpAddr::V6(_), IpAddr::V4(_)) => std::cmp::Ordering::Greater,
    }
}

fn print_dns_debug(cli: &Cli, dns: &DnsTiming) {
    eprint!(
        "{}",
        timing::render_dns_debug(
            dns,
            core::color_enabled(cli.color.as_deref(), std::io::stderr().is_terminal())
        )
    );
}

fn connect_debug_target(
    response: &Response,
    url: &Url,
    dns_resolution: Option<&DnsResolution>,
) -> String {
    if let Some(addr) = response.remote_addr() {
        return addr.to_string();
    }
    if let Some(addr) = dns_resolution.and_then(|resolution| resolution.socket_addrs.first()) {
        return addr.to_string();
    }
    url.host_str()
        .map(|host| {
            if let Some(port) = url.port() {
                format!("{host}:{port}")
            } else {
                host.to_string()
            }
        })
        .unwrap_or_default()
}

fn configure_tls(
    mut builder: reqwest::ClientBuilder,
    cli: &Cli,
) -> Result<reqwest::ClientBuilder, FetchError> {
    let min_tls = cli.min_tls.as_deref().or(cli.tls.as_deref());
    crate::tls::ensure_rustls_supported_range(
        min_tls.map(|value| {
            if cli.min_tls.is_some() {
                ("min-tls", value)
            } else {
                ("tls", value)
            }
        }),
        cli.max_tls.as_deref(),
    )?;
    let min_version = match min_tls {
        Some(value) => crate::tls::reqwest_tls_version(
            if cli.min_tls.is_some() {
                "min-tls"
            } else {
                "tls"
            },
            value,
        )?,
        None => crate::tls::default_min_tls_version(),
    };
    builder = builder.min_tls_version(min_version);
    if let Some(value) = cli.max_tls.as_deref() {
        builder = builder.max_tls_version(crate::tls::reqwest_tls_version("max-tls", value)?);
    }
    for cert in crate::tls::ca_certificates(&cli.ca_cert)? {
        builder = builder.add_root_certificate(cert);
    }
    if let Some(identity) = crate::tls::client_identity(cli.cert.as_deref(), cli.key.as_deref())? {
        builder = builder.identity(identity);
    }
    Ok(builder)
}

fn configure_proxy(
    builder: reqwest::ClientBuilder,
    proxy: Option<&str>,
) -> Result<reqwest::ClientBuilder, FetchError> {
    if let Some(proxy) = proxy {
        let proxy_config = reqwest::Proxy::all(proxy)
            .map_err(|err| FetchError::Message(format!("invalid proxy '{proxy}': {err}")))?;
        return Ok(builder.proxy(proxy_config));
    }

    configure_environment_proxies(builder)
}

fn configure_environment_proxies(
    mut builder: reqwest::ClientBuilder,
) -> Result<reqwest::ClientBuilder, FetchError> {
    let no_proxy = reqwest::NoProxy::from_env();

    if let Some(proxy) = env_proxy_value(&["HTTP_PROXY", "http_proxy"]) {
        let proxy_config = reqwest::Proxy::http(&proxy)
            .map_err(|err| FetchError::Message(format!("invalid proxy '{proxy}': {err}")))?
            .no_proxy(no_proxy.clone());
        builder = builder.proxy(proxy_config);
    }

    if let Some(proxy) = env_proxy_value(&["HTTPS_PROXY", "https_proxy"]) {
        let proxy_config = reqwest::Proxy::https(&proxy)
            .map_err(|err| FetchError::Message(format!("invalid proxy '{proxy}': {err}")))?
            .no_proxy(no_proxy.clone());
        builder = builder.proxy(proxy_config);
    }

    if let Some(proxy) = env_proxy_value(&["ALL_PROXY", "all_proxy"]) {
        let proxy_config = reqwest::Proxy::all(&proxy)
            .map_err(|err| FetchError::Message(format!("invalid proxy '{proxy}': {err}")))?
            .no_proxy(no_proxy);
        builder = builder.proxy(proxy_config);
    }

    Ok(builder)
}

fn env_proxy_value(keys: &[&str]) -> Option<String> {
    for key in keys {
        if *key == "HTTP_PROXY"
            && env::var("REQUEST_METHOD")
                .map(|value| !value.is_empty())
                .unwrap_or(false)
        {
            continue;
        }
        let Ok(value) = env::var(key) else {
            continue;
        };
        if !value.trim().is_empty() {
            return Some(value);
        }
    }
    None
}

fn print_request_metadata(
    cli: &Cli,
    method: &Method,
    url: &Url,
    headers: &HeaderMap,
    body: &RequestBody,
    http_version: Option<HttpVersion>,
) {
    let mut printer = core::Printer::stderr(cli.color.as_deref());
    let debug = cli.verbose >= 2;
    if debug {
        printer.write_request_prefix();
    }
    printer.write_styled(
        method.as_str(),
        &[core::Sequence::Bold, core::Sequence::Yellow],
    );
    printer.push_str(" ");
    write_request_target(&mut printer, url);
    printer.push_str(" ");
    printer.write_styled(request_protocol_label(http_version), &[core::Sequence::Dim]);
    printer.push_str("\n");
    for (name, value) in header_lines(headers) {
        if name.eq_ignore_ascii_case("host") {
            continue;
        }
        if debug {
            printer.write_request_prefix();
        }
        printer.write_styled(&name, &[core::Sequence::Bold, core::Sequence::Blue]);
        printer.push_str(": ");
        printer.push_str(&value);
        printer.push_str("\n");
    }
    if let Some((bytes, _)) = body {
        if debug {
            printer.write_request_prefix();
        }
        printer.write_styled(
            "content-length",
            &[core::Sequence::Bold, core::Sequence::Blue],
        );
        printer.push_str(": ");
        printer.push_str(&bytes.len().to_string());
        printer.push_str("\n");
    }
    let host = headers
        .get(reqwest::header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
        .or_else(|| {
            url.host_str().map(|host| match url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            })
        });
    if let Some(host) = host {
        if debug {
            printer.write_request_prefix();
        }
        printer.write_styled("host", &[core::Sequence::Bold, core::Sequence::Blue]);
        printer.push_str(": ");
        printer.push_str(host.as_str());
        printer.push_str("\n");
    }
    if debug {
        printer.write_request_prefix();
        printer.push_str("\n");
    }
    flush_stderr(printer);
}

fn print_dry_run_body(cli: &Cli, body: &RequestBody) -> Result<(), FetchError> {
    let Some((bytes, _)) = body else {
        return Ok(());
    };
    if cli.verbose < 2 {
        eprintln!();
    }
    if is_printable(bytes) {
        std::io::stderr().write_all(bytes)?;
    } else {
        let mut printer = core::Printer::stderr(cli.color.as_deref());
        core::write_warning_msg_no_flush(&mut printer, "the request body appears to be binary");
        flush_stderr(printer);
    }
    Ok(())
}

fn is_printable(bytes: &[u8]) -> bool {
    let mut preview = bytes;
    if bytes.len() > 1024 {
        preview = &bytes[..1024];
    }
    if preview.contains(&0) {
        return false;
    }

    let mut safe = 0usize;
    let mut total = 0usize;
    let mut remaining = preview;
    while !remaining.is_empty() {
        match std::str::from_utf8(remaining) {
            Ok(valid) => {
                for ch in valid.chars() {
                    total += 1;
                    if ch.is_whitespace() || !ch.is_control() || ch == '\x1b' {
                        safe += 1;
                    }
                }
                break;
            }
            Err(err) => {
                let valid_up_to = err.valid_up_to();
                if valid_up_to > 0 {
                    let valid = std::str::from_utf8(&remaining[..valid_up_to])
                        .expect("valid prefix reported by utf8 error");
                    for ch in valid.chars() {
                        total += 1;
                        if ch.is_whitespace() || !ch.is_control() || ch == '\x1b' {
                            safe += 1;
                        }
                    }
                }
                if err.error_len().is_none() {
                    break;
                }
                total += 1;
                remaining = &remaining[valid_up_to + err.error_len().unwrap()..];
            }
        }
    }

    total == 0 || (safe as f64 / total as f64) >= 0.9
}

fn request_protocol_label(version: Option<HttpVersion>) -> &'static str {
    version.map(HttpVersion::label).unwrap_or("HTTP/1.1")
}

fn write_request_target(printer: &mut core::Printer, url: &Url) {
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    printer.write_styled(path, &[core::Sequence::Bold, core::Sequence::Cyan]);
    if let Some(query) = url.query() {
        printer.write_styled("?", &[core::Sequence::Italic, core::Sequence::Cyan]);
        printer.write_styled(query, &[core::Sequence::Italic, core::Sequence::Cyan]);
    }
}

fn header_lines(headers: &HeaderMap) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (name, value) in headers {
        if let Ok(value) = value.to_str() {
            out.push((name.as_str().to_ascii_lowercase(), value.to_string()));
        }
    }
    out
}

fn configure_http_version(
    builder: reqwest::ClientBuilder,
    version: Option<HttpVersion>,
) -> reqwest::ClientBuilder {
    match version {
        Some(HttpVersion::Http1) => builder.http1_only(),
        Some(HttpVersion::Http2) => builder.http2_prior_knowledge(),
        Some(HttpVersion::Http3) => builder.http3_prior_knowledge(),
        None => builder,
    }
}

fn validate_http_version_options(
    version: Option<HttpVersion>,
    url: &Url,
    allow_h2c: bool,
    unix_socket: Option<&str>,
) -> Result<(), FetchError> {
    match version {
        Some(HttpVersion::Http2) if url.scheme() == "http" && !allow_h2c => {
            Err("http2: unsupported scheme".into())
        }
        Some(HttpVersion::Http3) if unix_socket.is_some() => {
            Err("cannot use a unix socket with HTTP/3.0".into())
        }
        Some(HttpVersion::Http3) if url.scheme() != "https" => {
            Err(format!("http3: unsupported protocol scheme: {}", url.scheme()).into())
        }
        _ => Ok(()),
    }
}

fn validate_proxy_for_http_version(
    proxy: Option<&str>,
    version: Option<HttpVersion>,
) -> Result<(), FetchError> {
    if proxy.is_some() && matches!(version, Some(HttpVersion::Http2 | HttpVersion::Http3)) {
        return Err("a proxy can only be used with HTTP/1.1".into());
    }
    Ok(())
}

async fn finish_response(
    cli: &Cli,
    response: Response,
    encoding_requested: bool,
    timing: Option<AttemptTiming>,
    grpc_method: Option<&prost_reflect::MethodDescriptor>,
) -> Result<i32, FetchError> {
    let status = response.status();
    print_response_metadata(cli, &response);
    let response_headers = response.headers().clone();
    let response_url = response.url().clone();
    let response_content_length = response
        .content_length()
        .and_then(|len| i64::try_from(len).ok());
    let method_is_head = cli.method().eq_ignore_ascii_case("HEAD");
    let response_timing = timing.and_then(AttemptTiming::response_timing);
    if cli.discard {
        let body_start = Instant::now();
        let (bytes, trailers) = read_response_body(response).await?;
        let body_duration = body_duration(method_is_head, bytes.as_ref(), body_start);
        let _ = decode_response_bytes(encoding_requested, &response_headers, bytes.as_ref())?;
        print_timing(cli, response_timing, body_duration);
        let code = exit_code(status.as_u16(), cli.ignore_status);
        return Ok(check_grpc_status(cli, &response_headers, &trailers, code));
    }

    let output_path = output::resolve_output_path(
        cli.output.as_deref(),
        cli.remote_name,
        cli.remote_header_name,
        &response_url,
        &response_headers,
    )
    .map_err(|err| FetchError::Message(err.to_string()))?;
    if let Some(path) = output_path {
        let progress = if cli.silent {
            output::WriteProgress::disabled()
        } else {
            let stderr_is_terminal = std::io::stderr().is_terminal();
            output::WriteProgress::stdio(
                core::color_enabled(cli.color.as_deref(), stderr_is_terminal),
                stderr_is_terminal,
                std::io::stdout().is_terminal(),
                response_content_length,
            )
        };
        let body_start = Instant::now();
        let streamed = stream_response_to_output(
            response,
            response_headers.clone(),
            encoding_requested,
            path,
            cli.clobber,
            progress,
        )
        .await?;
        let body_duration = if method_is_head || streamed.bytes_written == 0 {
            None
        } else {
            Some(body_start.elapsed())
        };
        print_timing(cli, response_timing, body_duration);

        let code = exit_code(status.as_u16(), cli.ignore_status);
        Ok(check_grpc_status(
            cli,
            &response_headers,
            &streamed.trailers,
            code,
        ))
    } else {
        let body_start = Instant::now();
        let (bytes, trailers) = read_response_body(response).await?;
        let body_duration = body_duration(method_is_head, bytes.as_ref(), body_start);
        let bytes = decode_response_bytes(encoding_requested, &response_headers, bytes.as_ref())?;
        let bytes = format_stdout_bytes(
            cli,
            &response_headers,
            &bytes,
            grpc_method.map(|method| method.output()),
        )?;
        std::io::stdout().write_all(&bytes)?;
        print_timing(cli, response_timing, body_duration);

        let code = exit_code(status.as_u16(), cli.ignore_status);
        Ok(check_grpc_status(cli, &response_headers, &trailers, code))
    }
}

async fn read_response_body(response: Response) -> Result<(Vec<u8>, HeaderMap), FetchError> {
    let response: http::Response<reqwest::Body> = response.into();
    let collected = response.into_body().collect().await?;
    let trailers = collected.trailers().cloned().unwrap_or_default();
    Ok((collected.to_bytes().to_vec(), trailers))
}

struct StreamedOutput {
    trailers: HeaderMap,
    bytes_written: i64,
}

async fn stream_response_to_output(
    response: Response,
    response_headers: HeaderMap,
    encoding_requested: bool,
    path: String,
    clobber: bool,
    progress: output::WriteProgress,
) -> Result<StreamedOutput, FetchError> {
    let response: http::Response<reqwest::Body> = response.into();
    let body = response.into_body();
    let trailers = Arc::new(Mutex::new(HeaderMap::new()));
    let reader = BlockingBodyReader {
        body,
        buffer: Bytes::new(),
        trailers: trailers.clone(),
        handle: tokio::runtime::Handle::current(),
        done: false,
    };

    let result = tokio::task::spawn_blocking(move || -> Result<StreamedOutput, FetchError> {
        let mut reader = decoded_response_reader(reader, encoding_requested, &response_headers)?;
        let bytes_written = output::write_output_reader(&path, &mut reader, clobber, progress)
            .map_err(|err| FetchError::Message(err.to_string()))?;
        let trailers = trailers
            .lock()
            .map(|trailers| trailers.clone())
            .unwrap_or_default();
        Ok(StreamedOutput {
            trailers,
            bytes_written,
        })
    })
    .await
    .map_err(|err| FetchError::Message(err.to_string()))??;

    Ok(result)
}

struct BlockingBodyReader {
    body: reqwest::Body,
    buffer: Bytes,
    trailers: Arc<Mutex<HeaderMap>>,
    handle: tokio::runtime::Handle,
    done: bool,
}

impl Read for BlockingBodyReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if !self.buffer.is_empty() {
                let n = out.len().min(self.buffer.len());
                out[..n].copy_from_slice(&self.buffer[..n]);
                let _ = self.buffer.split_to(n);
                return Ok(n);
            }
            if self.done {
                return Ok(0);
            }

            let next = self.handle.block_on(async { self.body.frame().await });
            let Some(frame) = next else {
                self.done = true;
                return Ok(0);
            };
            let frame = frame.map_err(|err| std::io::Error::other(err.to_string()))?;
            match frame.into_data() {
                Ok(data) => {
                    if data.is_empty() {
                        continue;
                    }
                    self.buffer = data;
                }
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers()
                        && let Ok(mut stored) = self.trailers.lock()
                    {
                        *stored = trailers;
                    }
                }
            }
        }
    }
}

fn body_duration(method_is_head: bool, bytes: &[u8], start: Instant) -> Option<Duration> {
    if method_is_head || bytes.is_empty() {
        None
    } else {
        Some(start.elapsed())
    }
}

fn print_timing(cli: &Cli, timing: Option<ResponseTiming>, body: Option<Duration>) {
    if !cli.timing || cli.silent {
        return;
    }
    let Some(mut timing) = timing else {
        return;
    };
    timing.body = body;
    eprint!(
        "{}",
        timing::render_waterfall(
            timing,
            core::color_enabled(cli.color.as_deref(), std::io::stderr().is_terminal())
        )
    );
}

#[derive(Clone, Default)]
struct ConnectionTiming {
    duration: Arc<Mutex<Option<Duration>>>,
}

impl ConnectionTiming {
    fn clear(&self) {
        if let Ok(mut duration) = self.duration.lock() {
            *duration = None;
        }
    }

    fn set(&self, value: Duration) {
        if let Ok(mut duration) = self.duration.lock() {
            *duration = Some(value);
        }
    }

    fn duration(&self) -> Option<Duration> {
        self.duration.lock().ok().and_then(|duration| *duration)
    }
}

#[derive(Clone)]
struct ConnectionTimingLayer {
    timing: ConnectionTiming,
}

impl ConnectionTimingLayer {
    fn new(timing: ConnectionTiming) -> Self {
        Self { timing }
    }
}

impl<S> Layer<S> for ConnectionTimingLayer {
    type Service = ConnectionTimingService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ConnectionTimingService {
            inner,
            timing: self.timing.clone(),
        }
    }
}

#[derive(Clone)]
struct ConnectionTimingService<S> {
    inner: S,
    timing: ConnectionTiming,
}

impl<S, Request> Service<Request> for ConnectionTimingService<S>
where
    S: Service<Request> + Clone + Send + Sync + 'static,
    S::Future: Send + 'static,
    S::Response: Send + 'static,
    S::Error: Send + 'static,
    Request: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let mut inner = self.inner.clone();
        let timing = self.timing.clone();
        Box::pin(async move {
            let start = Instant::now();
            let result = inner.call(request).await;
            if result.is_ok() {
                timing.set(start.elapsed());
            }
            result
        })
    }
}

fn build_request(
    client: &Client,
    method: Method,
    url: Url,
    headers: HeaderMap,
    body: RequestBody,
    cli: &Cli,
    authorization: Option<&str>,
) -> Result<RequestBuilder, FetchError> {
    let mut req = client.request(method, url).headers(headers);
    if let Some(version) = reqwest_request_version_for_cli(cli)? {
        req = req.version(version);
    }

    if let Some((body, _content_type)) = body {
        req = req.body(body);
    }

    let mut authorization_headers = HeaderMap::new();
    apply_builder_authorization_headers(&mut authorization_headers, cli, authorization)?;
    req = req.headers(authorization_headers);

    Ok(req)
}

fn apply_builder_authorization_headers(
    headers: &mut HeaderMap,
    cli: &Cli,
    authorization: Option<&str>,
) -> Result<(), FetchError> {
    if let Some(auth) = authorization {
        let value = HeaderValue::from_str(auth)
            .map_err(|err| FetchError::Message(format!("invalid authorization header: {err}")))?;
        headers.insert(reqwest::header::AUTHORIZATION, value);
    } else if let Some(auth) = basic_header(cli.basic.as_deref())? {
        let value = HeaderValue::from_str(&auth)
            .map_err(|err| FetchError::Message(format!("invalid authorization header: {err}")))?;
        headers.insert(reqwest::header::AUTHORIZATION, value);
    }
    if let Some(token) = cli.bearer.as_deref() {
        let value = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|err| FetchError::Message(format!("invalid bearer token: {err}")))?;
        headers.insert(reqwest::header::AUTHORIZATION, value);
    }
    Ok(())
}

fn reqwest_request_version_for_cli(cli: &Cli) -> Result<Option<reqwest::Version>, FetchError> {
    let version =
        crate::cli::parse_http_version(cli.http.as_deref()).map_err(FetchError::Message)?;
    Ok(match effective_http_version(cli, version) {
        Some(HttpVersion::Http1) => Some(reqwest::Version::HTTP_11),
        Some(HttpVersion::Http2) => Some(reqwest::Version::HTTP_2),
        Some(HttpVersion::Http3) => Some(reqwest::Version::HTTP_3),
        None => None,
    })
}

struct DigestRetryContext<'a> {
    client: &'a Client,
    method: Method,
    headers: HeaderMap,
    body: RequestBody,
    cli: &'a Cli,
    redirect_statuses: Vec<StatusCode>,
}

async fn apply_digest_challenge(
    response: Response,
    context: DigestRetryContext<'_>,
    credentials: Option<&(String, String)>,
) -> Result<Response, FetchError> {
    let Some((username, password)) = credentials else {
        return Ok(response);
    };
    if response.status() != StatusCode::UNAUTHORIZED {
        return Ok(response);
    }

    let challenge = digest::find_digest_challenge(
        response
            .headers()
            .get_all(WWW_AUTHENTICATE)
            .iter()
            .filter_map(|value| value.to_str().ok()),
    );
    let Some(challenge) = challenge else {
        return Ok(response);
    };
    let Ok(challenge) = digest::parse_challenge(&challenge) else {
        return Ok(response);
    };

    let challenged_url = response.url().clone();
    let (challenged_method, challenged_body) =
        digest_challenged_request(context.method, context.body, &context.redirect_statuses);
    let auth = match digest::response(
        challenged_method.as_str(),
        &request_target(&challenged_url),
        &challenge,
        username,
        password,
    ) {
        Ok(auth) => auth,
        Err(_) => return Ok(response),
    };

    let _ = response.bytes().await;
    build_request(
        context.client,
        challenged_method,
        challenged_url,
        context.headers,
        challenged_body,
        context.cli,
        Some(&auth),
    )?
    .send()
    .await
    .map_err(Into::into)
}

fn digest_challenged_request(
    original_method: Method,
    original_body: RequestBody,
    redirect_statuses: &[StatusCode],
) -> (Method, RequestBody) {
    let mut method = original_method;
    let mut body = original_body;

    for status in redirect_statuses {
        match *status {
            StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND | StatusCode::SEE_OTHER => {
                if method != Method::GET && method != Method::HEAD {
                    method = Method::GET;
                }
                body = None;
            }
            StatusCode::TEMPORARY_REDIRECT | StatusCode::PERMANENT_REDIRECT => {}
            _ => {}
        }
    }

    (method, body)
}

fn digest_credentials(value: Option<&str>) -> Result<Option<(String, String)>, FetchError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let Some((username, password)) = value.split_once(':') else {
        return Err("digest format must be <USERNAME:PASSWORD>".into());
    };
    Ok(Some((username.to_string(), password.to_string())))
}

fn aws_config(value: Option<&str>) -> Result<Option<aws_sigv4::Config>, FetchError> {
    value
        .map(aws_sigv4::parse_config)
        .transpose()
        .map_err(|err| FetchError::Message(err.to_string()))
}

fn aws_unsigned_payload(cli: &Cli, config: &aws_sigv4::Config) -> bool {
    config.service == "s3" && cli.data.as_deref() == Some("@-") && !cli.data_is_literal
}

fn request_body_bytes(body: &RequestBody) -> Option<&[u8]> {
    body.as_ref().map(|(bytes, _)| bytes.as_slice())
}

fn apply_body_content_type(headers: &mut HeaderMap, body: &RequestBody) {
    let Some((_bytes, Some(content_type))) = body.as_ref() else {
        return;
    };
    if !headers.contains_key(CONTENT_TYPE)
        && let Ok(value) = HeaderValue::from_str(content_type)
    {
        headers.insert(CONTENT_TYPE, value);
    }
}

fn apply_grpc_headers(headers: &mut HeaderMap) {
    headers.insert(ACCEPT, HeaderValue::from_static("application/grpc+proto"));
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/grpc+proto"),
    );
    headers.insert(
        HeaderName::from_static("te"),
        HeaderValue::from_static("trailers"),
    );
}

fn check_grpc_status(cli: &Cli, headers: &HeaderMap, trailers: &HeaderMap, exit_code: i32) -> i32 {
    if !cli.grpc {
        return exit_code;
    }
    let Some(status) =
        grpc_status_from_headers(trailers).or_else(|| grpc_status_from_headers(headers))
    else {
        return exit_code;
    };
    if status.ok() {
        return exit_code;
    }
    if !cli.silent {
        write_error_with_color(status, cli.color.as_deref());
    }
    if exit_code == 0 { 1 } else { exit_code }
}

fn grpc_status_from_headers(headers: &HeaderMap) -> Option<grpc_status::Status> {
    let status = headers.get("grpc-status")?.to_str().ok()?;
    if status == "0" {
        return None;
    }
    let message = headers
        .get("grpc-message")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    Some(grpc_status::parse_status(status, message))
}

fn print_response_metadata(cli: &Cli, response: &Response) {
    if cli.silent {
        return;
    }

    let status = response.status();
    let mut printer = core::Printer::stderr(cli.color.as_deref());
    if cli.verbose >= 2 {
        printer.write_response_prefix();
    }
    printer.write_styled(version_label(response.version()), &[core::Sequence::Dim]);
    printer.push_str(" ");
    let status_color = color_for_status(status.as_u16());
    printer.write_styled(
        &status.as_u16().to_string(),
        &[status_color, core::Sequence::Bold],
    );
    let reason = status.canonical_reason().unwrap_or("");
    if !reason.is_empty() {
        printer.push_str(" ");
        printer.write_styled(reason, &[status_color]);
    }
    printer.push_str("\n");

    if cli.verbose > 0 {
        for (name, value) in header_lines(response.headers()) {
            if cli.verbose >= 2 {
                printer.write_response_prefix();
            }
            printer.write_styled(&name, &[core::Sequence::Bold, core::Sequence::Cyan]);
            printer.push_str(": ");
            printer.push_str(&value);
            printer.push_str("\n");
        }
    }
    if cli.verbose >= 2 {
        printer.write_response_prefix();
    }
    printer.push_str("\n");
    flush_stderr(printer);
}

fn format_stdout_bytes(
    cli: &Cli,
    headers: &HeaderMap,
    bytes: &[u8],
    grpc_response_desc: Option<prost_reflect::MessageDescriptor>,
) -> Result<Vec<u8>, FetchError> {
    let stdout_is_terminal = std::io::stdout().is_terminal();
    let terminal_cols = if stdout_is_terminal {
        core::terminal_cols()
    } else {
        0
    };
    format_stdout_bytes_with_terminal(
        cli,
        headers,
        bytes,
        grpc_response_desc,
        stdout_is_terminal,
        terminal_cols,
    )
}

fn format_stdout_bytes_with_terminal(
    cli: &Cli,
    headers: &HeaderMap,
    bytes: &[u8],
    grpc_response_desc: Option<prost_reflect::MessageDescriptor>,
    stdout_is_terminal: bool,
    terminal_cols: usize,
) -> Result<Vec<u8>, FetchError> {
    if !format_enabled(cli.format.as_deref(), stdout_is_terminal) {
        return Ok(bytes.to_vec());
    }

    let use_color = core::color_enabled(cli.color.as_deref(), stdout_is_terminal);
    let content_type = headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    let (mut content_type, charset) = content_type::get_content_type(content_type);
    if content_type == ContentType::Unknown {
        content_type = content_type::sniff_content_type(bytes);
    }
    let bytes = transcode_format_bytes(bytes, &charset, content_type);
    match content_type {
        ContentType::Json => {
            Ok(json::format_json(&bytes, use_color).unwrap_or_else(|_| bytes.to_vec()))
        }
        ContentType::Ndjson => {
            Ok(json::format_ndjson(&bytes, use_color).unwrap_or_else(|_| bytes.to_vec()))
        }
        ContentType::Csv => {
            Ok(
                csv::format_csv_with_terminal_cols(&bytes, use_color, terminal_cols)
                    .map(|formatted| formatted.into_bytes())
                    .unwrap_or_else(|_| bytes.to_vec()),
            )
        }
        ContentType::Xml => {
            Ok(xml::format_xml(&bytes, use_color).unwrap_or_else(|_| bytes.to_vec()))
        }
        ContentType::Yaml => {
            Ok(yaml::format_yaml(&bytes, use_color).unwrap_or_else(|_| bytes.to_vec()))
        }
        ContentType::Css => {
            Ok(css::format_css(&bytes, use_color).unwrap_or_else(|_| bytes.to_vec()))
        }
        ContentType::Html => {
            Ok(html::format_html(&bytes, use_color).unwrap_or_else(|_| bytes.to_vec()))
        }
        ContentType::Markdown => {
            Ok(markdown::format_markdown(&bytes, use_color).unwrap_or_else(|_| bytes.to_vec()))
        }
        ContentType::MsgPack => {
            Ok(msgpack::format_msgpack(&bytes, use_color).unwrap_or_else(|_| bytes.to_vec()))
        }
        ContentType::Protobuf => {
            if let Some(desc) = grpc_response_desc {
                if let Ok(json_bytes) = proto::protobuf_to_json(&bytes, &desc) {
                    return Ok(json::format_json(&json_bytes, use_color).unwrap_or(json_bytes));
                }
                return Ok(bytes.to_vec());
            }
            Ok(protobuf::format_protobuf(&bytes)
                .map(|formatted| formatted.into_bytes())
                .unwrap_or_else(|_| bytes.to_vec()))
        }
        ContentType::Image => {
            if cli.image.as_deref() == Some("off") {
                Ok(bytes.to_vec())
            } else {
                crate::image::render(&bytes, cli.image.as_deref() == Some("native"))
                    .map_err(|err| FetchError::Message(err.to_string()))
            }
        }
        ContentType::Grpc => {
            if let Some(desc) = grpc_response_desc {
                proto::format_grpc_stream_with_descriptor(&bytes, &desc)
                    .map(|formatted| formatted.into_bytes())
                    .map_err(|err| FetchError::Message(err.to_string()))
            } else {
                grpc_format::format_grpc_stream(&bytes)
                    .map(|formatted| formatted.into_bytes())
                    .map_err(|err| FetchError::Message(err.to_string()))
            }
        }
        ContentType::Sse => sse::format_event_stream(&bytes)
            .map(|formatted| formatted.into_bytes())
            .map_err(|err| FetchError::Message(err.to_string())),
        _ => Ok(bytes.to_vec()),
    }
}

fn format_enabled(setting: Option<&str>, stdout_is_terminal: bool) -> bool {
    match setting {
        Some("on") => true,
        Some("off") => false,
        Some("auto") | None => stdout_is_terminal,
        Some(_) => false,
    }
}

fn transcode_format_bytes(bytes: &[u8], charset: &str, content_type: ContentType) -> Vec<u8> {
    if matches!(
        content_type,
        ContentType::Image | ContentType::MsgPack | ContentType::Protobuf | ContentType::Grpc
    ) {
        return bytes.to_vec();
    }
    transcode_bytes(bytes, charset)
}

fn charset_decoder(charset: &str) -> Option<&'static encoding_rs::Encoding> {
    let charset = charset.trim();
    if charset.is_empty() {
        return None;
    }
    if matches!(
        charset.to_ascii_lowercase().as_str(),
        "utf-8" | "utf8" | "us-ascii" | "ascii"
    ) {
        return None;
    }
    encoding_rs::Encoding::for_label(charset.as_bytes())
}

fn transcode_bytes(bytes: &[u8], charset: &str) -> Vec<u8> {
    let Some(encoding) = charset_decoder(charset) else {
        return bytes.to_vec();
    };
    let (decoded, _, had_errors) = encoding.decode(bytes);
    if had_errors {
        return bytes.to_vec();
    }
    decoded.into_owned().into_bytes()
}

fn should_retry_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::TOO_MANY_REQUESTS
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

fn parse_retry_after(headers: &HeaderMap) -> Duration {
    let Some(value) = headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
    else {
        return Duration::ZERO;
    };

    if let Ok(seconds) = value.parse::<i64>() {
        if seconds <= 0 {
            return Duration::ZERO;
        }
        return Duration::from_secs(seconds as u64);
    }

    let Ok(time) = httpdate::parse_http_date(value) else {
        return Duration::ZERO;
    };
    time.duration_since(SystemTime::now())
        .unwrap_or(Duration::ZERO)
}

fn is_retryable_error(err: &reqwest::Error) -> bool {
    if is_certificate_validation_error(err) {
        return false;
    }
    err.is_timeout() || err.is_connect()
}

#[derive(Debug)]
struct RedirectLimitError {
    max: usize,
}

impl fmt::Display for RedirectLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "exceeded maximum number of redirects: {}", self.max)
    }
}

impl StdError for RedirectLimitError {}

fn redirect_policy_with_history(
    redirect_limit: Option<usize>,
    verbose: u8,
    silent: bool,
    history: RedirectHistory,
    color: Option<String>,
) -> redirect::Policy {
    let max = redirect_limit.unwrap_or(10);
    if redirect_limit == Some(0) {
        return redirect::Policy::none();
    }

    redirect::Policy::custom(move |attempt| {
        history.record(attempt.status());
        if verbose >= 2 && !silent {
            let status = attempt.status();
            let mut printer = core::Printer::stderr(color.as_deref());
            printer.write_response_prefix();
            printer.write_styled("HTTP/1.1", &[core::Sequence::Dim]);
            printer.push_str(" ");
            let status_color = color_for_status(status.as_u16());
            printer.write_styled(
                &status.as_u16().to_string(),
                &[status_color, core::Sequence::Bold],
            );
            let reason = status.canonical_reason().unwrap_or("");
            if !reason.is_empty() {
                printer.push_str(" ");
                printer.write_styled(reason, &[status_color]);
            }
            printer.push_str("\n");
            flush_stderr(printer);
        }
        if attempt.previous().len() > max {
            attempt.error(RedirectLimitError { max })
        } else {
            attempt.follow()
        }
    })
}

fn flush_stderr(mut printer: core::Printer) {
    let mut stderr = std::io::stderr();
    let _ = printer.flush_to(&mut stderr);
}

fn color_for_status(code: u16) -> core::Sequence {
    match code {
        200..=299 => core::Sequence::Green,
        300..=399 => core::Sequence::Yellow,
        _ => core::Sequence::Red,
    }
}

#[derive(Clone, Default)]
struct RedirectHistory {
    statuses: Arc<Mutex<Vec<StatusCode>>>,
}

impl RedirectHistory {
    fn record(&self, status: StatusCode) {
        if let Ok(mut statuses) = self.statuses.lock() {
            statuses.push(status);
        }
    }

    fn clear(&self) {
        if let Ok(mut statuses) = self.statuses.lock() {
            statuses.clear();
        }
    }

    fn statuses(&self) -> Vec<StatusCode> {
        self.statuses
            .lock()
            .map(|statuses| statuses.clone())
            .unwrap_or_default()
    }
}

fn redirect_error_message(err: &reqwest::Error) -> Option<String> {
    if !err.is_redirect() {
        return None;
    }

    let mut source = err.source();
    while let Some(err) = source {
        let message = err.to_string();
        if message.contains("exceeded maximum number of redirects") {
            return Some(message);
        }
        source = err.source();
    }
    None
}

fn timeout_error_message(cli: &Cli, err: &reqwest::Error) -> Option<String> {
    if !err.is_timeout() {
        return None;
    }
    let seconds = cli.timeout?;
    let duration = duration_from_seconds("timeout", seconds).ok()?;
    Some(format!(
        "request timed out after {}",
        format_go_duration(duration)
    ))
}

fn reqwest_request_error_message(err: &reqwest::Error) -> String {
    let mut message = err.to_string();
    let mut source = err.source();
    while let Some(err) = source {
        let source_message = go_style_reqwest_source_message(&err.to_string());
        if !source_message.is_empty() && !message.contains(&source_message) {
            message.push_str(": ");
            message.push_str(&source_message);
        }
        source = err.source();
    }
    message
}

fn go_style_reqwest_source_message(message: &str) -> String {
    let lower = message.to_ascii_lowercase();
    if !lower.contains("tls")
        && (lower.contains("protocolversion")
            || lower.contains("certificate")
            || lower.contains("rustls"))
    {
        format!("tls: {message}")
    } else {
        message.to_string()
    }
}

fn is_certificate_validation_error(err: &reqwest::Error) -> bool {
    if is_certificate_validation_message(&err.to_string()) {
        return true;
    }

    let mut source = err.source();
    while let Some(err) = source {
        if is_certificate_validation_message(&err.to_string()) {
            return true;
        }
        source = err.source();
    }

    false
}

fn is_certificate_validation_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("hostnameerror")
        || (lower.contains("certificate")
            && (lower.contains("unknownissuer")
                || lower.contains("unknown issuer")
                || lower.contains("unknown authority")
                || lower.contains("invalid peer certificate")
                || lower.contains("certificateverifyfailed")
                || lower.contains("certificate verify failed")
                || lower.contains("not valid")
                || lower.contains("notvalid")
                || lower.contains("expired")
                || lower.contains("hostname")))
}

fn format_go_duration(duration: Duration) -> String {
    let nanos = duration.as_nanos();
    if nanos < 1_000 {
        return format!("{nanos}ns");
    }
    if nanos < 1_000_000 {
        return format_duration_unit(nanos, 1_000, "us");
    }
    if nanos < 1_000_000_000 {
        return format_duration_unit(nanos, 1_000_000, "ms");
    }
    format_duration_unit(nanos, 1_000_000_000, "s")
}

fn format_duration_unit(nanos: u128, unit_nanos: u128, suffix: &str) -> String {
    let whole = nanos / unit_nanos;
    let remainder = nanos % unit_nanos;
    if remainder == 0 {
        return format!("{whole}{suffix}");
    }

    let digits = match suffix {
        "us" => 3_u32,
        "ms" => 6_u32,
        _ => 9_u32,
    };
    let scale = 10_u128.pow(digits);
    let fraction_value = remainder * scale / unit_nanos;
    let fraction = format!(
        "{fraction_value:0width$}",
        width = usize::try_from(digits).expect("small duration precision")
    );
    let fraction = fraction.trim_end_matches('0');
    format!("{whole}.{fraction}{suffix}")
}

fn retry_reason(status: StatusCode) -> String {
    format!(
        "{} {}",
        status.as_u16(),
        status.canonical_reason().unwrap_or("")
    )
}

fn compute_delay(initial_delay: Duration, attempt: usize, retry_after: Duration) -> Duration {
    let mut delay = if initial_delay.is_zero() {
        Duration::from_secs(1)
    } else {
        initial_delay
    };

    for _ in 0..attempt {
        delay = delay.saturating_mul(2);
        if delay > Duration::from_secs(30) {
            delay = Duration::from_secs(30);
            break;
        }
    }

    let jitter = delay.as_secs_f64() * 0.25;
    let jittered = delay.as_secs_f64() + rand::random_range(-jitter..=jitter);
    let delay = Duration::from_secs_f64(jittered.max(0.0));

    delay.max(retry_after)
}

fn print_retry(
    cli: &Cli,
    next_attempt: usize,
    total_attempts: usize,
    delay: Duration,
    reason: &str,
) {
    if cli.silent {
        return;
    }

    let prefix = if cli.verbose >= 2 { "* " } else { "" };
    eprintln!(
        "{prefix}retry: attempt {next_attempt}/{total_attempts} in {} ({reason})",
        format_delay(delay)
    );
}

fn format_delay(delay: Duration) -> String {
    if delay < Duration::from_millis(1) {
        return "0s".to_string();
    }
    if delay < Duration::from_secs(1) {
        return format!("{:.0}ms", delay.as_secs_f64() * 1000.0);
    }
    format!("{:.1}s", delay.as_secs_f64())
}

pub(crate) fn request_target(url: &Url) -> String {
    let mut target = if url.path().is_empty() {
        "/".to_string()
    } else {
        url.path().to_string()
    };
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }
    target
}

pub(crate) fn duration_from_seconds(flag: &str, seconds: f64) -> Result<Duration, FetchError> {
    if !seconds.is_finite() || seconds < 0.0 {
        return Err(format!("{flag} must be a non-negative number").into());
    }
    Ok(Duration::from_secs_f64(seconds))
}

pub(crate) fn normalize_url(raw: &str) -> Result<Url, FetchError> {
    if raw.is_empty() {
        return Err("empty URL provided".into());
    }

    if raw.contains("://") {
        let url = Url::parse(raw)?;
        match url.scheme() {
            "http" | "https" => Ok(url),
            "ws" => rewrite_url_scheme(url, "http"),
            "wss" => rewrite_url_scheme(url, "https"),
            scheme => Err(format!("unsupported url scheme: {scheme}").into()),
        }
    } else {
        let probe = Url::parse(&format!("http://{raw}"))?;
        let scheme = if probe.host_str().is_some_and(is_loopback) {
            "http"
        } else {
            "https"
        };
        Url::parse(&format!("{scheme}://{raw}")).map_err(Into::into)
    }
}

fn rewrite_url_scheme(mut url: Url, scheme: &str) -> Result<Url, FetchError> {
    let original = url.scheme().to_string();
    url.set_scheme(scheme)
        .map_err(|_| FetchError::Message(format!("unsupported url scheme: {original}")))?;
    Ok(url)
}

fn grpc_request_requires_schema(cli: &Cli) -> bool {
    cli.json.is_some()
}

fn is_loopback(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

pub(crate) fn apply_query(url: &mut Url, query: &[String]) {
    if query.is_empty() {
        return;
    }

    let mut values = BTreeMap::<String, Vec<String>>::new();
    for (key, val) in url.query_pairs() {
        values
            .entry(key.into_owned())
            .or_default()
            .push(val.into_owned());
    }
    for raw in query {
        let (key, val) = raw.split_once('=').unwrap_or((raw, ""));
        values
            .entry(key.trim().to_string())
            .or_default()
            .push(val.trim().to_string());
    }

    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, vals) in values {
        for val in vals {
            serializer.append_pair(&key, &val);
        }
    }
    url.set_query(Some(&serializer.finish()));
}

pub(crate) fn apply_headers(headers: &mut HeaderMap, values: &[String]) -> Result<(), FetchError> {
    for raw in values {
        let Some((key, val)) = raw.split_once(':') else {
            return Err(FetchError::Message(format!(
                "invalid value '{raw}' for option '--header': must be in the format NAME:VALUE with a valid non-empty header name"
            )));
        };
        let key = key.trim();
        if key.is_empty() {
            return Err(FetchError::Message(format!(
                "invalid value '{raw}' for option '--header': must be in the format NAME:VALUE with a valid non-empty header name"
            )));
        }
        let name = HeaderName::from_bytes(key.as_bytes()).map_err(|_| {
            FetchError::Message(format!(
                "invalid value '{raw}' for option '--header': must be in the format NAME:VALUE with a valid non-empty header name"
            ))
        })?;
        let value = HeaderValue::from_str(val.trim()).map_err(|err| {
            FetchError::Message(format!("invalid header value for '{key}': {err}"))
        })?;
        headers.insert(name, value);
    }
    Ok(())
}

fn apply_ranges(headers: &mut HeaderMap, ranges: &[String]) {
    if ranges.is_empty() {
        return;
    }
    headers.insert(
        RANGE,
        HeaderValue::from_str(&format!("bytes={}", ranges.join(", ")))
            .expect("range is a valid header value"),
    );
}

fn apply_accept_encoding(headers: &mut HeaderMap, cli: &Cli, method: &Method) -> bool {
    if cli.no_encode || method == Method::HEAD || headers.contains_key(ACCEPT_ENCODING) {
        return false;
    }
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip, zstd"));
    true
}

fn decode_response_bytes(
    encoding_requested: bool,
    headers: &HeaderMap,
    bytes: &[u8],
) -> Result<Vec<u8>, FetchError> {
    if !encoding_requested {
        return Ok(bytes.to_vec());
    }

    let Some(encodings) = content_encoding_decoders(headers) else {
        return Ok(bytes.to_vec());
    };

    let mut decoded = bytes.to_vec();
    for encoding in encodings {
        decoded = match encoding.as_str() {
            "gzip" => decode_gzip(&decoded)?,
            "zstd" => decode_zstd(&decoded)?,
            "aws-chunked" => decoded,
            _ => unreachable!("unsupported encodings are filtered"),
        };
    }
    Ok(decoded)
}

fn decoded_response_reader<R>(
    reader: R,
    encoding_requested: bool,
    headers: &HeaderMap,
) -> Result<Box<dyn Read + Send>, FetchError>
where
    R: Read + Send + 'static,
{
    let mut reader: Box<dyn Read + Send> = Box::new(reader);
    if !encoding_requested {
        return Ok(reader);
    }

    let Some(encodings) = content_encoding_decoders(headers) else {
        return Ok(reader);
    };

    for encoding in encodings {
        reader = match encoding.as_str() {
            "gzip" => Box::new(PrefixedReadError {
                prefix: "gzip",
                inner: GzDecoder::new(reader),
            }),
            "zstd" => {
                let decoder = zstd::stream::read::Decoder::new(reader)
                    .map_err(|err| FetchError::Message(format!("zstd: {err}")))?;
                Box::new(PrefixedReadError {
                    prefix: "zstd",
                    inner: decoder,
                })
            }
            "aws-chunked" => reader,
            _ => unreachable!("unsupported encodings are filtered"),
        };
    }
    Ok(reader)
}

struct PrefixedReadError<R> {
    prefix: &'static str,
    inner: R,
}

impl<R: Read> Read for PrefixedReadError<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner
            .read(buf)
            .map_err(|err| std::io::Error::new(err.kind(), format!("{}: {err}", self.prefix)))
    }
}

fn content_encoding_decoders(headers: &HeaderMap) -> Option<Vec<String>> {
    let encodings = content_encodings(headers);
    let mut decoders = Vec::with_capacity(encodings.len());
    for encoding in encodings.into_iter().rev() {
        match encoding.as_str() {
            "gzip" | "zstd" | "aws-chunked" => decoders.push(encoding),
            _ => return None,
        }
    }
    Some(decoders)
}

fn content_encodings(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(reqwest::header::CONTENT_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn decode_gzip(bytes: &[u8]) -> Result<Vec<u8>, FetchError> {
    let mut decoder = GzDecoder::new(bytes);
    let mut decoded = Vec::new();
    decoder
        .read_to_end(&mut decoded)
        .map_err(|err| FetchError::Message(format!("gzip: {err}")))?;
    Ok(decoded)
}

fn decode_zstd(bytes: &[u8]) -> Result<Vec<u8>, FetchError> {
    zstd::stream::decode_all(bytes).map_err(|err| FetchError::Message(format!("zstd: {err}")))
}

pub(crate) fn request_body(cli: &Cli) -> Result<RequestBody, FetchError> {
    if !cli.multipart.is_empty() {
        let multipart = multipart::Multipart::from_cli_fields(&cli.multipart)
            .map_err(|err| FetchError::Message(err.to_string()))?
            .expect("non-empty multipart input creates multipart body");
        let body = multipart
            .open()
            .map_err(|err| FetchError::Message(err.to_string()))?;
        return Ok(Some((body, Some(multipart.content_type()))));
    }
    if let Some(value) = cli.data.as_deref() {
        if let Some(bytes) = &cli.data_literal_bytes {
            return Ok(Some((bytes.clone(), None)));
        }
        if cli.data_is_literal {
            return Ok(Some((value.as_bytes().to_vec(), None)));
        }
        let (body, path) = read_body_value(value)?;
        let content_type = detect_body_content_type(&body, path.as_deref());
        return Ok(Some((body, Some(content_type))));
    }
    if let Some(value) = cli.json.as_deref() {
        return Ok(Some((
            read_body_value(value)?.0,
            Some("application/json".to_string()),
        )));
    }
    if let Some(value) = cli.xml.as_deref() {
        return Ok(Some((
            read_body_value(value)?.0,
            Some("application/xml".to_string()),
        )));
    }
    if !cli.form.is_empty() {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for raw in &cli.form {
            let (key, val) = raw.split_once('=').unwrap_or((raw, ""));
            serializer.append_pair(key.trim(), val.trim());
        }
        return Ok(Some((
            serializer.finish().into_bytes(),
            Some("application/x-www-form-urlencoded".to_string()),
        )));
    }
    Ok(None)
}

fn read_body_value(value: &str) -> Result<(Vec<u8>, Option<String>), FetchError> {
    if value == "@-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        return Ok((buf, None));
    }
    if let Some(path) = value.strip_prefix('@') {
        let expanded = expand_home(path);
        let metadata = std::fs::metadata(&expanded).map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                FetchError::Message(format!("file '{path}' does not exist"))
            } else {
                err.into()
            }
        })?;
        if metadata.is_dir() {
            return Err(format!("file '{path}' is a directory").into());
        }
        return Ok((std::fs::read(&expanded)?, Some(expanded)));
    }
    Ok((value.as_bytes().to_vec(), None))
}

fn expand_home(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return format!("{}/{}", home.to_string_lossy(), rest);
    }
    path.to_string()
}

fn detect_body_content_type(body: &[u8], path: Option<&str>) -> String {
    if let Some(path) = path
        && let Some(content_type) = detect_type_by_extension(path)
    {
        return content_type.to_string();
    }
    sniff_content_type_like_go(body)
}

fn detect_type_by_extension(path: &str) -> Option<&'static str> {
    let ext = Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(str::to_ascii_lowercase)?;
    match ext.as_str() {
        "jpg" | "jpeg" => Some("image/jpeg"),
        "png" => Some("image/png"),
        "gif" => Some("image/gif"),
        "webp" => Some("image/webp"),
        "avif" => Some("image/avif"),
        "heic" | "heif" => Some("image/heif"),
        "jxl" => Some("image/jxl"),
        "tif" | "tiff" => Some("image/tiff"),
        "bmp" => Some("image/bmp"),
        "ico" => Some("image/x-icon"),
        "svg" => Some("image/svg+xml"),
        "psd" => Some("image/vnd.adobe.photoshop"),
        "raw" | "dng" | "nef" | "cr2" | "arw" => Some("image/x-raw"),
        "mp4" => Some("video/mp4"),
        "m4v" => Some("video/x-m4v"),
        "webm" => Some("video/webm"),
        "mov" => Some("video/quicktime"),
        "mkv" => Some("video/x-matroska"),
        "avi" => Some("video/x-msvideo"),
        "wmv" => Some("video/x-ms-wmv"),
        "flv" => Some("video/x-flv"),
        "mpeg" | "mpg" => Some("video/mpeg"),
        "ogv" => Some("video/ogg"),
        "mp3" => Some("audio/mpeg"),
        "m4a" => Some("audio/mp4"),
        "aac" => Some("audio/aac"),
        "wav" => Some("audio/wav"),
        "flac" => Some("audio/flac"),
        "ogg" => Some("audio/ogg"),
        "opus" => Some("audio/opus"),
        "aiff" | "aif" => Some("audio/aiff"),
        "mid" | "midi" => Some("audio/midi"),
        "pdf" => Some("application/pdf"),
        "txt" => Some("text/plain; charset=utf-8"),
        "html" | "htm" => Some("text/html; charset=utf-8"),
        "css" => Some("text/css; charset=utf-8"),
        "csv" => Some("text/csv; charset=utf-8"),
        "json" => Some("application/json"),
        "xml" => Some("application/xml"),
        "yaml" | "yml" => Some("application/yaml"),
        "md" => Some("text/markdown; charset=utf-8"),
        "rtf" => Some("application/rtf"),
        "doc" => Some("application/msword"),
        "docx" => Some("application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        "xls" => Some("application/vnd.ms-excel"),
        "xlsx" => Some("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        "ppt" => Some("application/vnd.ms-powerpoint"),
        "pptx" => Some("application/vnd.openxmlformats-officedocument.presentationml.presentation"),
        "woff" => Some("font/woff"),
        "woff2" => Some("font/woff2"),
        "ttf" => Some("font/ttf"),
        "otf" => Some("font/otf"),
        "eot" => Some("application/vnd.ms-fontobject"),
        "zip" => Some("application/zip"),
        "tar" => Some("application/x-tar"),
        "gz" | "tgz" => Some("application/gzip"),
        "bz2" => Some("application/x-bzip2"),
        "xz" => Some("application/x-xz"),
        "7z" => Some("application/x-7z-compressed"),
        "rar" => Some("application/vnd.rar"),
        "exe" => Some("application/vnd.microsoft.portable-executable"),
        "msi" => Some("application/x-msi"),
        "deb" => Some("application/vnd.debian.binary-package"),
        "rpm" => Some("application/x-rpm"),
        "js" | "mjs" => Some("application/javascript"),
        "ts" => Some("application/typescript"),
        "go" => Some("text/x-go; charset=utf-8"),
        "rs" => Some("text/x-rust; charset=utf-8"),
        "py" => Some("text/x-python; charset=utf-8"),
        "sh" => Some("application/x-sh"),
        _ => None,
    }
}

fn sniff_content_type_like_go(body: &[u8]) -> String {
    let sniff = &body[..body.len().min(512)];
    if sniff.starts_with(b"\xFF\xD8\xFF") {
        return "image/jpeg".to_string();
    }
    if sniff.starts_with(b"\x89PNG\r\n\x1A\n") {
        return "image/png".to_string();
    }
    if sniff.starts_with(b"GIF87a") || sniff.starts_with(b"GIF89a") {
        return "image/gif".to_string();
    }
    if sniff.len() >= 12 && &sniff[..4] == b"RIFF" && &sniff[8..12] == b"WEBP" {
        return "image/webp".to_string();
    }
    if sniff.starts_with(b"%PDF-") {
        return "application/pdf".to_string();
    }
    if sniff.starts_with(b"PK\x03\x04")
        || sniff.starts_with(b"PK\x05\x06")
        || sniff.starts_with(b"PK\x07\x08")
    {
        return "application/zip".to_string();
    }
    if looks_like_html(sniff) {
        return "text/html; charset=utf-8".to_string();
    }
    if is_text_like_go(sniff) {
        "text/plain; charset=utf-8".to_string()
    } else {
        "application/octet-stream".to_string()
    }
}

fn looks_like_html(bytes: &[u8]) -> bool {
    let trimmed = trim_ascii_whitespace(bytes);
    let lower = String::from_utf8_lossy(trimmed).to_ascii_lowercase();
    [
        "<!doctype html",
        "<html",
        "<head",
        "<script",
        "<iframe",
        "<h1",
        "<div",
        "<font",
        "<table",
        "<a",
        "<style",
        "<title",
        "<body",
        "<br",
        "<p",
    ]
    .iter()
    .any(|tag| lower.starts_with(tag))
}

fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map(|idx| idx + 1)
        .unwrap_or(start);
    &bytes[start..end]
}

fn is_text_like_go(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| {
        matches!(*byte, b'\t' | b'\n' | b'\x0c' | b'\r') || (*byte >= 0x20 && *byte != 0x7f)
    })
}

pub(crate) fn basic_header(value: Option<&str>) -> Result<Option<String>, FetchError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let Some((username, password)) = value.split_once(':') else {
        return Err("basic format must be <USERNAME:PASSWORD>".into());
    };
    let normalized = format!("{}:{}", username.trim(), password.trim());
    let encoded = base64::engine::general_purpose::STANDARD.encode(normalized.as_bytes());
    Ok(Some(format!("Basic {encoded}")))
}

fn version_label(version: reqwest::Version) -> &'static str {
    match version {
        reqwest::Version::HTTP_09 => "HTTP/0.9",
        reqwest::Version::HTTP_10 => "HTTP/1.0",
        reqwest::Version::HTTP_11 => "HTTP/1.1",
        reqwest::Version::HTTP_2 => "HTTP/2.0",
        reqwest::Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/?",
    }
}

fn exit_code(status: u16, ignore_status: bool) -> i32 {
    if ignore_status || (200..400).contains(&status) {
        0
    } else if (400..500).contains(&status) {
        4
    } else if (500..600).contains(&status) {
        5
    } else {
        6
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use prost::Message;
    use prost_reflect::{DynamicMessage, Value as ReflectValue};
    use prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        MethodDescriptorProto, ServiceDescriptorProto,
        field_descriptor_proto::{Label, Type},
    };
    use std::io::Write;

    #[test]
    fn default_scheme_loopback_is_http() {
        let url = normalize_url("localhost:3000/path").unwrap();
        assert_eq!(url.as_str(), "http://localhost:3000/path");
    }

    #[test]
    fn default_scheme_ipv6_loopback_is_http_like_go_hostname() {
        let url = normalize_url("[::1]:3000/path").unwrap();
        assert_eq!(url.as_str(), "http://[::1]:3000/path");
    }

    #[test]
    fn default_scheme_loopback_with_query_is_http_like_go_hostname() {
        let url = normalize_url("LOCALHOST?debug=true").unwrap();
        assert_eq!(url.as_str(), "http://localhost/?debug=true");
    }

    #[test]
    fn default_scheme_non_loopback_is_https() {
        let url = normalize_url("example.com/path").unwrap();
        assert_eq!(url.as_str(), "https://example.com/path");
    }

    #[test]
    fn test_is_loopback() {
        let cases = [
            ("localhost", true),
            ("LOCALHOST", true),
            ("Localhost", true),
            ("127.0.0.1", true),
            ("127.255.255.255", true),
            ("127.0.0.100", true),
            ("::1", true),
            ("[::1]", true),
            ("myserver", false),
            ("192.168.1.1", false),
            ("10.0.0.1", false),
            ("example.com", false),
            ("0.0.0.0", false),
            ("172.16.0.1", false),
            ("::2", false),
            ("2001:db8::1", false),
            ("", false),
        ];

        for (host, want) in cases {
            assert_eq!(is_loopback(host), want, "host {host}");
        }
    }

    #[test]
    fn websocket_schemes_are_rewritten_like_go_parse_url() {
        let ws = normalize_url("WS://example.com/socket").unwrap();
        let wss = normalize_url("wss://example.com/socket").unwrap();
        assert_eq!(ws.as_str(), "http://example.com/socket");
        assert_eq!(wss.as_str(), "https://example.com/socket");
    }

    #[test]
    fn method_defaults_and_custom_method_parse_like_go() {
        let cli = Cli::try_parse_from(["fetch", "https://example.com"]).unwrap();
        assert_eq!(cli.method(), "GET");
        assert_eq!(effective_method(&cli), "GET");

        let cli = Cli::try_parse_from(["fetch", "--method", "PUT", "https://example.com"]).unwrap();
        assert_eq!(cli.method(), "PUT");
        assert_eq!(effective_method(&cli), "PUT");
    }

    #[test]
    fn apply_query_sorts_and_encodes_like_go_url_values() {
        let mut url = Url::parse("https://example.com/path?z=old&space=hello+world").unwrap();
        apply_query(
            &mut url,
            &[
                "a=one".to_string(),
                "z=two".to_string(),
                "blank".to_string(),
                "space=second value".to_string(),
            ],
        );

        assert_eq!(
            url.as_str(),
            "https://example.com/path?a=one&blank=&space=hello+world&space=second+value&z=old&z=two"
        );
    }

    #[test]
    fn apply_headers_matches_go_header_flag_validation() {
        let mut headers = HeaderMap::new();
        apply_headers(
            &mut headers,
            &["X-Test: value".to_string(), "X-Empty:".to_string()],
        )
        .unwrap();
        assert_eq!(headers.get("x-test").unwrap(), "value");
        assert_eq!(headers.get("x-empty").unwrap(), "");

        let err = apply_headers(&mut HeaderMap::new(), &[": value".to_string()])
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "invalid value ': value' for option '--header': must be in the format NAME:VALUE with a valid non-empty header name"
        );

        let err = apply_headers(&mut HeaderMap::new(), &["Bad Header: value".to_string()])
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "invalid value 'Bad Header: value' for option '--header': must be in the format NAME:VALUE with a valid non-empty header name"
        );
    }

    #[test]
    fn header_lines_preserves_header_map_order_without_grouping() {
        let mut headers = HeaderMap::new();
        headers.insert("x-zeta", HeaderValue::from_static("first"));
        headers.insert("accept", HeaderValue::from_static("second"));
        headers.append("x-zeta", HeaderValue::from_static("third"));

        assert_eq!(
            header_lines(&headers),
            [
                ("x-zeta".to_string(), "first".to_string()),
                ("x-zeta".to_string(), "third".to_string()),
                ("accept".to_string(), "second".to_string()),
            ]
        );
    }

    #[test]
    fn request_body_printability_matches_go_heuristic() {
        assert!(is_printable(br#"{"key":"value"}"#));
        assert!(is_printable("snowman: \u{2603}\n".as_bytes()));
        assert!(!is_printable(b"abc\0def"));
        assert!(!is_printable(&[0xff, 0xfe, 0xfd, b'a']));
    }

    #[test]
    fn request_body_data_detects_go_style_content_type() {
        let cli = Cli::try_parse_from(["fetch", "--data", "hello", "https://example.com"]).unwrap();
        let body = request_body(&cli).unwrap().unwrap();
        assert_eq!(body.0, b"hello");
        assert_eq!(body.1.as_deref(), Some("text/plain; charset=utf-8"));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.json");
        std::fs::write(&path, br#"{"ok":true}"#).unwrap();
        let cli = Cli::try_parse_from([
            "fetch",
            "--data",
            &format!("@{}", path.display()),
            "https://example.com",
        ])
        .unwrap();
        let body = request_body(&cli).unwrap().unwrap();
        assert_eq!(body.0, br#"{"ok":true}"#);
        assert_eq!(body.1.as_deref(), Some("application/json"));
    }

    #[test]
    fn request_body_file_errors_match_go_cli_surface() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.txt");
        let cli = Cli::try_parse_from([
            "fetch",
            "--data",
            &format!("@{}", missing.display()),
            "https://example.com",
        ])
        .unwrap();
        let err = request_body(&cli).unwrap_err().to_string();
        assert_eq!(err, format!("file '{}' does not exist", missing.display()));

        let cli = Cli::try_parse_from([
            "fetch",
            "--data",
            &format!("@{}", dir.path().display()),
            "https://example.com",
        ])
        .unwrap();
        let err = request_body(&cli).unwrap_err().to_string();
        assert_eq!(
            err,
            format!("file '{}' is a directory", dir.path().display())
        );
    }

    #[test]
    fn image_off_returns_raw_image_bytes() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("image/png"));
        let cli = Cli::try_parse_from([
            "fetch",
            "--format",
            "on",
            "--image",
            "off",
            "https://example.com",
        ])
        .unwrap();

        let out = format_stdout_bytes(&cli, &headers, b"not decoded", None).unwrap();
        assert_eq!(out, b"not decoded");
    }

    #[test]
    fn charset_decoder_matches_go_noop_and_known_charset_policy() {
        for charset in [
            "", "utf-8", "UTF-8", "utf8", "us-ascii", "ascii", "US-ASCII",
        ] {
            assert!(
                charset_decoder(charset).is_none(),
                "{charset} should not need transcoding"
            );
        }
        for charset in [
            "iso-8859-1",
            "ISO-8859-1",
            "windows-1252",
            "shift_jis",
            "euc-kr",
        ] {
            assert!(
                charset_decoder(charset).is_some(),
                "{charset} should have a decoder"
            );
        }
        assert!(charset_decoder("not-a-real-charset").is_none());
    }

    #[test]
    fn transcode_bytes_matches_go_charset_cases() {
        let cases = [
            (
                "latin1 cafe",
                &[0x63, 0x61, 0x66, 0xe9][..],
                "iso-8859-1",
                "café",
            ),
            (
                "windows-1252 curly quotes",
                &[0x93, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x94][..],
                "windows-1252",
                "“hello”",
            ),
            ("empty charset returns unchanged", b"hello", "", "hello"),
            (
                "utf-8 charset returns unchanged",
                b"hello",
                "utf-8",
                "hello",
            ),
            (
                "unknown charset returns unchanged",
                b"hello",
                "not-a-real-charset",
                "hello",
            ),
        ];

        for (name, input, charset, want) in cases {
            let got = transcode_bytes(input, charset);
            assert_eq!(String::from_utf8(got).unwrap(), want, "{name}");
        }
    }

    #[test]
    fn formatted_stdout_transcodes_charset_before_formatting_like_go() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=iso-8859-1"),
        );
        let cli = Cli::try_parse_from([
            "fetch",
            "--format",
            "on",
            "--color",
            "off",
            "https://example.com",
        ])
        .unwrap();

        let out = format_stdout_bytes_with_terminal(
            &cli,
            &headers,
            b"{\"word\":\"caf\xe9\"}",
            None,
            false,
            0,
        )
        .unwrap();

        assert_eq!(
            String::from_utf8(out).unwrap(),
            "{\n  \"word\": \"café\"\n}\n"
        );
    }

    #[test]
    fn formatted_stdout_does_not_transcode_binary_formats_like_go() {
        let raw = [0x0a, 0x01, 0xe9];
        for content_type in [
            ContentType::Image,
            ContentType::MsgPack,
            ContentType::Protobuf,
            ContentType::Grpc,
        ] {
            assert_eq!(
                transcode_format_bytes(&raw, "windows-1252", content_type),
                raw
            );
        }
    }

    #[test]
    fn formatted_stdout_uses_go_color_auto_target_policy() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let cli = Cli::try_parse_from(["fetch", "--format", "on", "https://example.com"]).unwrap();

        let out =
            format_stdout_bytes_with_terminal(&cli, &headers, br#"{"ok":"yes"}"#, None, false, 0)
                .unwrap();
        assert!(!String::from_utf8(out).unwrap().contains("\x1b["));

        let out =
            format_stdout_bytes_with_terminal(&cli, &headers, br#"{"ok":"yes"}"#, None, true, 80)
                .unwrap();
        assert!(String::from_utf8(out).unwrap().contains("\x1b["));

        let cli = Cli::try_parse_from([
            "fetch",
            "--format",
            "on",
            "--color",
            "off",
            "https://example.com",
        ])
        .unwrap();
        let out =
            format_stdout_bytes_with_terminal(&cli, &headers, br#"{"ok":"yes"}"#, None, true, 80)
                .unwrap();
        assert!(!String::from_utf8(out).unwrap().contains("\x1b["));

        let cli = Cli::try_parse_from([
            "fetch",
            "--format",
            "on",
            "--color",
            "on",
            "https://example.com",
        ])
        .unwrap();
        let out =
            format_stdout_bytes_with_terminal(&cli, &headers, br#"{"ok":"yes"}"#, None, false, 0)
                .unwrap();
        assert!(String::from_utf8(out).unwrap().contains("\x1b["));
    }

    #[test]
    fn formatted_stdout_auto_follows_stdout_terminal_like_go() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        for args in [
            ["fetch", "https://example.com"].as_slice(),
            ["fetch", "--format", "auto", "https://example.com"].as_slice(),
        ] {
            let cli = Cli::try_parse_from(args).unwrap();
            let out = format_stdout_bytes_with_terminal(
                &cli,
                &headers,
                br#"{"ok":"yes"}"#,
                None,
                false,
                0,
            )
            .unwrap();
            assert_eq!(String::from_utf8(out).unwrap(), r#"{"ok":"yes"}"#);

            let out = format_stdout_bytes_with_terminal(
                &cli,
                &headers,
                br#"{"ok":"yes"}"#,
                None,
                true,
                80,
            )
            .unwrap();
            let out = String::from_utf8(out).unwrap();
            assert!(out.starts_with("{\n  \""));
            assert!(out.contains("\x1b[34m\x1b[1mok\x1b[0m"));
            assert!(out.contains("\x1b[32myes\x1b[0m"));
        }

        let cli = Cli::try_parse_from(["fetch", "--format", "off", "https://example.com"]).unwrap();
        let out =
            format_stdout_bytes_with_terminal(&cli, &headers, br#"{"ok":"yes"}"#, None, true, 80)
                .unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), r#"{"ok":"yes"}"#);
    }

    #[test]
    fn formatted_stdout_passes_terminal_width_to_csv_like_go() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/csv"));
        let cli = Cli::try_parse_from([
            "fetch",
            "--format",
            "on",
            "--color",
            "off",
            "https://example.com",
        ])
        .unwrap();

        let out = format_stdout_bytes_with_terminal(
            &cli,
            &headers,
            b"name,age,city\nAlice,30,NYC\nBob,25,LA",
            None,
            true,
            5,
        )
        .unwrap();
        let out = String::from_utf8(out).unwrap();

        assert!(out.contains("--- Row 1 ---"));
        assert!(out.contains("name: Alice"));
    }

    #[test]
    fn protobuf_response_uses_grpc_descriptor_for_unframed_body_like_go() {
        let desc = test_response_descriptor();
        let mut msg = DynamicMessage::new(desc.clone());
        msg.set_field(
            &desc.get_field_by_name("response_text").unwrap(),
            ReflectValue::String("hello".to_string()),
        );
        msg.set_field(
            &desc.get_field_by_name("count").unwrap(),
            ReflectValue::I64(7),
        );
        let body = msg.encode_to_vec();

        let json_bytes = proto::protobuf_to_json(&body, &desc).unwrap();
        let out = json::format_json(&json_bytes, false).unwrap();
        let text = String::from_utf8(out).unwrap();
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();

        assert_eq!(json["response_text"], "hello");
        assert_eq!(json["count"], "7");
        assert!(!text.contains("1:"));
    }

    #[test]
    fn protobuf_descriptor_decode_failure_falls_back_to_raw_bytes_like_go() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/protobuf"),
        );
        let cli = Cli::try_parse_from([
            "fetch",
            "--grpc",
            "--format",
            "on",
            "https://example.com/testpkg.TestService/Get",
        ])
        .unwrap();

        let raw = b"\x0a\xff";
        let out =
            format_stdout_bytes(&cli, &headers, raw, Some(test_response_descriptor())).unwrap();

        assert_eq!(out, raw);
    }

    fn test_response_descriptor() -> prost_reflect::MessageDescriptor {
        let fds = FileDescriptorSet {
            file: vec![FileDescriptorProto {
                name: Some("response.proto".to_string()),
                package: Some("testpkg".to_string()),
                syntax: Some("proto3".to_string()),
                message_type: vec![
                    DescriptorProto {
                        name: Some("TestRequest".to_string()),
                        ..Default::default()
                    },
                    DescriptorProto {
                        name: Some("TestResponse".to_string()),
                        field: vec![
                            FieldDescriptorProto {
                                name: Some("response_text".to_string()),
                                json_name: Some("responseText".to_string()),
                                number: Some(1),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::String as i32),
                                ..Default::default()
                            },
                            FieldDescriptorProto {
                                name: Some("count".to_string()),
                                json_name: Some("count".to_string()),
                                number: Some(2),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::Int64 as i32),
                                ..Default::default()
                            },
                        ],
                        ..Default::default()
                    },
                ],
                service: vec![ServiceDescriptorProto {
                    name: Some("TestService".to_string()),
                    method: vec![MethodDescriptorProto {
                        name: Some("Get".to_string()),
                        input_type: Some(".testpkg.TestRequest".to_string()),
                        output_type: Some(".testpkg.TestResponse".to_string()),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        let schema = proto::Schema::from_descriptor_set(&fds.encode_to_vec()).unwrap();
        schema
            .find_method("testpkg.TestService/Get")
            .unwrap()
            .output()
    }

    #[test]
    fn exit_code_maps_status_classes() {
        assert_eq!(exit_code(200, false), 0);
        assert_eq!(exit_code(302, false), 0);
        assert_eq!(exit_code(404, false), 4);
        assert_eq!(exit_code(503, false), 5);
        assert_eq!(exit_code(999, false), 6);
        assert_eq!(exit_code(404, true), 0);
    }

    #[test]
    fn digest_credentials_require_username_password() {
        assert_eq!(
            digest_credentials(Some("user:pass")).unwrap(),
            Some(("user".to_string(), "pass".to_string()))
        );
        assert!(digest_credentials(Some("nocolon")).is_err());
        assert_eq!(digest_credentials(None).unwrap(), None);
    }

    #[test]
    fn digest_challenge_after_redirect_uses_go_redirect_method_and_body() {
        let original_body = Some((b"payload".to_vec(), Some("text/plain".to_string())));

        let (method, body) = digest_challenged_request(
            Method::POST,
            original_body.clone(),
            &[StatusCode::SEE_OTHER],
        );
        assert_eq!(method, Method::GET);
        assert!(body.is_none());

        let (method, body) = digest_challenged_request(
            Method::POST,
            original_body.clone(),
            &[StatusCode::TEMPORARY_REDIRECT],
        );
        assert_eq!(method, Method::POST);
        assert_eq!(request_body_bytes(&body), Some(b"payload".as_slice()));

        let (method, body) = digest_challenged_request(
            Method::HEAD,
            original_body,
            &[StatusCode::MOVED_PERMANENTLY],
        );
        assert_eq!(method, Method::HEAD);
        assert!(body.is_none());
    }

    #[test]
    fn basic_header_encodes_credentials_like_go() {
        assert_eq!(
            basic_header(Some(" user : pass ")).unwrap(),
            Some("Basic dXNlcjpwYXNz".to_string())
        );
        assert!(basic_header(Some("nocolon")).is_err());
        assert_eq!(basic_header(None).unwrap(), None);
    }

    #[test]
    fn redirect_limit_error_matches_go_message() {
        assert_eq!(
            RedirectLimitError { max: 10 }.to_string(),
            "exceeded maximum number of redirects: 10"
        );
    }

    #[test]
    fn compute_delay_matches_go_backoff_bounds() {
        for attempt in 0..5 {
            let delay = compute_delay(Duration::from_secs(1), attempt, Duration::ZERO);
            let base = Duration::from_secs(1_u64 << attempt).min(Duration::from_secs(30));
            let min = base.mul_f64(0.75);
            let max = base.mul_f64(1.25);
            assert!(
                delay >= min && delay <= max,
                "attempt {attempt}: delay {delay:?} outside {min:?}..={max:?}"
            );
        }

        let delay = compute_delay(Duration::from_secs(1), 10, Duration::ZERO);
        assert!(delay <= Duration::from_secs(30).mul_f64(1.25));

        let retry_after = Duration::from_secs(60);
        let delay = compute_delay(Duration::from_secs(1), 0, retry_after);
        assert!(delay >= retry_after);

        let delay = compute_delay(Duration::ZERO, 0, Duration::ZERO);
        assert!(delay >= Duration::from_millis(750));
        assert!(delay <= Duration::from_millis(1250));
    }

    #[test]
    fn format_delay_matches_go_retry_output() {
        assert_eq!(format_delay(Duration::from_micros(500)), "0s");
        assert_eq!(format_delay(Duration::from_millis(250)), "250ms");
        assert_eq!(format_delay(Duration::from_millis(2500)), "2.5s");
        assert_eq!(format_delay(Duration::from_secs(1)), "1.0s");
    }

    #[test]
    fn parse_retry_after_matches_go_integer_and_date_cases() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("5"));
        assert_eq!(parse_retry_after(&headers), Duration::from_secs(5));

        headers.insert(RETRY_AFTER, HeaderValue::from_static("0"));
        assert_eq!(parse_retry_after(&headers), Duration::ZERO);

        headers.insert(RETRY_AFTER, HeaderValue::from_static("-5"));
        assert_eq!(parse_retry_after(&headers), Duration::ZERO);

        headers.insert(RETRY_AFTER, HeaderValue::from_static("not-a-number"));
        assert_eq!(parse_retry_after(&headers), Duration::ZERO);

        let future = SystemTime::now() + Duration::from_secs(10);
        let future = httpdate::fmt_http_date(future);
        headers.insert(RETRY_AFTER, HeaderValue::from_str(&future).unwrap());
        let parsed = parse_retry_after(&headers);
        assert!(parsed >= Duration::from_secs(8), "parsed {parsed:?}");
        assert!(parsed <= Duration::from_secs(12), "parsed {parsed:?}");

        assert_eq!(parse_retry_after(&HeaderMap::new()), Duration::ZERO);
    }

    #[test]
    fn should_retry_status_matches_go_status_table() {
        for status in [
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            assert!(should_retry_status(status), "{status} should be retryable");
        }

        for status in [
            StatusCode::OK,
            StatusCode::BAD_REQUEST,
            StatusCode::NOT_FOUND,
        ] {
            assert!(
                !should_retry_status(status),
                "{status} should not be retryable"
            );
        }
    }

    #[test]
    fn owned_request_body_clone_replays_without_go_temp_spool() {
        let body = Some((b"hello".to_vec(), Some("text/plain".to_string())));
        let first = request_body_bytes(&body).unwrap().to_vec();
        let replay = body.clone();

        assert_eq!(first, b"hello");
        assert_eq!(request_body_bytes(&replay).unwrap(), b"hello");
    }

    #[test]
    fn reqwest_tls_source_messages_keep_go_style_tls_hint() {
        assert_eq!(
            go_style_reqwest_source_message("received fatal alert: ProtocolVersion"),
            "tls: received fatal alert: ProtocolVersion"
        );
        assert_eq!(
            go_style_reqwest_source_message("invalid peer certificate: UnknownIssuer"),
            "tls: invalid peer certificate: UnknownIssuer"
        );
        assert_eq!(
            go_style_reqwest_source_message("tls: handshake failure"),
            "tls: handshake failure"
        );
    }

    #[test]
    fn certificate_validation_messages_match_go_error_classes() {
        for message in [
            "invalid peer certificate: UnknownIssuer",
            "invalid peer certificate: NotValidForName",
            "x509: certificate signed by unknown authority",
            "certificate verify failed",
            "certificate has expired",
            "x509: certificate is not valid for any names",
            "x509: HostnameError",
        ] {
            assert!(
                is_certificate_validation_message(message),
                "{message} should be treated as certificate validation"
            );
        }

        for message in [
            "received fatal alert: ProtocolVersion",
            "tls: handshake failure",
            "connection refused",
        ] {
            assert!(
                !is_certificate_validation_message(message),
                "{message} should not be treated as certificate validation"
            );
        }
    }

    #[test]
    fn format_go_duration_matches_common_go_units() {
        assert_eq!(format_go_duration(Duration::from_nanos(100)), "100ns");
        assert_eq!(format_go_duration(Duration::from_nanos(1_500)), "1.5us");
        assert_eq!(format_go_duration(Duration::from_nanos(1_500_000)), "1.5ms");
        assert_eq!(
            format_go_duration(Duration::from_nanos(1_500_000_000)),
            "1.5s"
        );
    }

    #[test]
    fn http2_plain_http_rejects_like_go_transport() {
        let url = Url::parse("http://127.0.0.1:3000/").unwrap();
        let err =
            validate_http_version_options(Some(HttpVersion::Http2), &url, false, None).unwrap_err();

        assert_eq!(err.to_string(), "http2: unsupported scheme");
    }

    #[test]
    fn grpc_h2c_plain_http_is_allowed_like_go() {
        let url = Url::parse("http://127.0.0.1:3000/").unwrap();

        validate_http_version_options(Some(HttpVersion::Http2), &url, true, None).unwrap();
    }

    #[test]
    fn http3_https_is_allowed_and_plain_http_rejects_like_go_transport() {
        let url = Url::parse("https://example.com/").unwrap();
        validate_http_version_options(Some(HttpVersion::Http3), &url, false, None).unwrap();

        let url = Url::parse("http://example.com/").unwrap();
        let err =
            validate_http_version_options(Some(HttpVersion::Http3), &url, false, None).unwrap_err();
        assert_eq!(err.to_string(), "http3: unsupported protocol scheme: http");
    }

    #[test]
    fn http3_rejects_unix_socket_like_go_app() {
        let url = Url::parse("https://example.com/").unwrap();
        let err = validate_http_version_options(
            Some(HttpVersion::Http3),
            &url,
            false,
            Some("/tmp/fetch.sock"),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "cannot use a unix socket with HTTP/3.0");
    }

    #[test]
    fn http3_local_address_matches_ip_literal_family() {
        let ipv4_url = Url::parse("https://127.0.0.1:3000/").unwrap();
        assert_eq!(
            http3_local_address(&ipv4_url, None),
            Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        );

        let ipv6_url = Url::parse("https://[::1]:3000/").unwrap();
        assert_eq!(
            http3_local_address(&ipv6_url, None),
            Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
        );
    }

    #[test]
    fn proxy_rejects_http2_and_http3_like_go_app() {
        let err = validate_proxy_for_http_version(
            Some("http://proxy.example:8080"),
            Some(HttpVersion::Http2),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "a proxy can only be used with HTTP/1.1");

        let err = validate_proxy_for_http_version(
            Some("http://proxy.example:8080"),
            Some(HttpVersion::Http3),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "a proxy can only be used with HTTP/1.1");
    }

    #[test]
    fn proxy_allows_default_and_http1_like_go_app() {
        validate_proxy_for_http_version(Some("http://proxy.example:8080"), None).unwrap();
        validate_proxy_for_http_version(
            Some("http://proxy.example:8080"),
            Some(HttpVersion::Http1),
        )
        .unwrap();
    }

    #[test]
    fn socks_proxy_urls_are_accepted_by_reqwest_feature() {
        reqwest::Proxy::all("socks5://127.0.0.1:1080").unwrap();
        reqwest::Proxy::http("socks5://127.0.0.1:1080").unwrap();
        reqwest::Proxy::all("socks5h://localhost:1080").unwrap();
    }

    #[test]
    fn grpc_defaults_to_post_and_http2_like_go() {
        let cli =
            Cli::try_parse_from(["fetch", "--grpc", "https://example.com/pkg.Svc/Method"]).unwrap();

        assert_eq!(effective_method(&cli), "POST");
        assert_eq!(effective_http_version(&cli, None), Some(HttpVersion::Http2));
        assert_eq!(
            effective_http_version(&cli, Some(HttpVersion::Http1)),
            Some(HttpVersion::Http1)
        );
    }

    #[test]
    fn grpc_request_body_frames_empty_and_raw_bodies() {
        let empty = proto::grpc_request_body(None, None).unwrap().unwrap();
        assert_eq!(empty.0, crate::grpc::framing::frame(&[], false));
        assert_eq!(empty.1.as_deref(), Some("application/grpc+proto"));

        let framed = proto::grpc_request_body(Some((b"hello".to_vec(), None)), None)
            .unwrap()
            .unwrap();
        assert_eq!(framed.0, crate::grpc::framing::frame(b"hello", false));
    }

    #[test]
    fn grpc_status_from_headers_parses_non_ok_status() {
        let mut headers = HeaderMap::new();
        headers.insert("grpc-status", HeaderValue::from_static("13"));
        headers.insert("grpc-message", HeaderValue::from_static("oh%20no%21"));

        let status = grpc_status_from_headers(&headers).unwrap();

        assert_eq!(status.code, grpc_status::Code::INTERNAL);
        assert_eq!(status.message, "oh no!");
        assert_eq!(status.to_string(), "grpc error: INTERNAL: oh no!");
    }

    #[test]
    fn grpc_status_from_headers_ignores_ok_or_missing_status() {
        assert!(grpc_status_from_headers(&HeaderMap::new()).is_none());

        let mut headers = HeaderMap::new();
        headers.insert("grpc-status", HeaderValue::from_static("0"));
        assert!(grpc_status_from_headers(&headers).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn unix_socket_configures_reqwest_builder_on_unix() {
        assert!(configure_unix_socket(Client::builder(), Some("/tmp/fetch.sock")).is_ok());
    }

    #[test]
    fn regular_http_rejects_legacy_tls_only_range_on_rustls_path() {
        let cli = Cli::try_parse_from([
            "fetch",
            "--min-tls",
            "1.0",
            "--max-tls",
            "1.1",
            "https://example.com",
        ])
        .unwrap();

        let err = configure_tls(Client::builder().use_rustls_tls(), &cli).unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS versions 1.0 and 1.1 are not supported"
        );
    }

    #[test]
    fn content_encodings_splits_multiple_header_values() {
        let mut headers = HeaderMap::new();
        headers.append(
            reqwest::header::CONTENT_ENCODING,
            HeaderValue::from_static("gzip"),
        );
        headers.append(
            reqwest::header::CONTENT_ENCODING,
            HeaderValue::from_static("zstd, aws-chunked"),
        );

        assert_eq!(content_encodings(&headers), ["gzip", "zstd", "aws-chunked"]);
    }

    #[test]
    fn decodes_stacked_content_encoding_in_reverse_order() {
        let data = b"this is stacked encoded data";
        let body = zstd_encode(&gzip_encode(data));
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_ENCODING,
            HeaderValue::from_static("gzip, zstd"),
        );

        let decoded = decode_response_bytes(true, &headers, &body).unwrap();

        assert_eq!(decoded, data);
    }

    #[test]
    fn decodes_aws_chunked_plus_gzip() {
        let data = b"this is gzip encoded data";
        let body = gzip_encode(data);
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_ENCODING,
            HeaderValue::from_static("aws-chunked, gzip"),
        );

        let decoded = decode_response_bytes(true, &headers, &body).unwrap();

        assert_eq!(decoded, data);
    }

    #[test]
    fn leaves_unsupported_stacked_content_encoding_untouched() {
        let body = b"not decoded";
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_ENCODING,
            HeaderValue::from_static("br, gzip"),
        );

        let decoded = decode_response_bytes(true, &headers, body).unwrap();

        assert_eq!(decoded, body);
    }

    #[test]
    fn skips_decoding_when_encoding_was_not_requested_by_fetch() {
        let data = b"this stays gzip encoded";
        let body = gzip_encode(data);
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_ENCODING,
            HeaderValue::from_static("gzip"),
        );

        let decoded = decode_response_bytes(false, &headers, &body).unwrap();

        assert_eq!(decoded, body);
    }

    #[test]
    fn gzip_decoder_errors_are_prefixed() {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_ENCODING,
            HeaderValue::from_static("gzip"),
        );

        let err = decode_response_bytes(true, &headers, b"not gzip").unwrap_err();

        assert!(err.to_string().contains("gzip:"));
    }

    fn gzip_encode(data: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn zstd_encode(data: &[u8]) -> Vec<u8> {
        zstd::stream::encode_all(data, 0).unwrap()
    }
}
