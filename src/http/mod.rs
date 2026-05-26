use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::fmt;
use std::io::{ErrorKind, IsTerminal, Read, Write};
use std::path::Path;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime};

use async_compression::tokio::bufread::{
    BrotliDecoder as AsyncBrotliDecoder, GzipDecoder as AsyncGzipDecoder,
    ZstdDecoder as AsyncZstdDecoder,
};
use base64::Engine;
use bytes::Bytes;
#[cfg(test)]
use flate2::read::GzDecoder;
use futures_util::stream;
use http_body_util::BodyExt;
use reqwest::header::{
    ACCEPT, ACCEPT_ENCODING, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HeaderMap,
    HeaderName, HeaderValue, LOCATION, PROXY_AUTHORIZATION, RANGE, RETRY_AFTER, TRANSFER_ENCODING,
    USER_AGENT, WWW_AUTHENTICATE,
};
use reqwest::{Body, Client, Method, RequestBuilder, Response, StatusCode};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_util::io::{ReaderStream, StreamReader};
use url::Url;

use crate::auth::aws_sigv4;
use crate::auth::digest;
use crate::cli::{Cli, CompressionMode, HttpVersion};
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
use crate::http::client::DnsResolution;
use crate::output;
use crate::output::clipboard;
use crate::proto;
use crate::timing::{self, AttemptTiming, DnsTiming, ResponseTiming};

pub(crate) mod client;
mod edit;
pub mod multipart;

pub(crate) type RequestBody = Option<RequestBodyPayload>;
pub(crate) type MaterializedRequestBody = Option<(Vec<u8>, Option<String>)>;
type AsyncReadBox = Pin<Box<dyn AsyncRead + Send>>;

#[derive(Debug, Clone)]
pub(crate) struct RequestBodyPayload {
    source: RequestBodySource,
    content_type: Option<String>,
}

#[derive(Debug, Clone)]
enum RequestBodySource {
    Bytes(Bytes),
    File { path: String, len: u64 },
    Stdin,
    Multipart(multipart::Multipart),
}

impl RequestBodyPayload {
    pub(crate) fn from_bytes(bytes: Vec<u8>, content_type: Option<String>) -> Self {
        Self {
            source: RequestBodySource::Bytes(Bytes::from(bytes)),
            content_type,
        }
    }
}

const MAX_BUFFERED_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_DISCARDED_RESPONSE_BYTES: usize = 1024 * 1024;
const BINARY_RESPONSE_WARNING: &str =
    "the response body appears to be binary\n\nTo output to the terminal anyway, use '--output -'";
pub(crate) const MAX_DURATION_SECONDS: f64 = i64::MAX as f64 / 1_000_000_000_f64;

pub async fn execute(cli: &Cli) -> Result<i32, FetchError> {
    let http_version =
        crate::cli::parse_http_version(cli.http.as_deref()).map_err(FetchError::Message)?;
    let http_version = effective_http_version(cli, http_version);
    let mut url = normalize_url(cli.url.as_deref().expect("URL checked by app"))?;
    apply_query(&mut url, &cli.query);
    client::validate_proxy_for_http_version(cli.proxy.as_deref(), http_version)?;
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

    let request_start = Instant::now();
    let request_timeout = cli
        .timeout
        .map(|seconds| duration_from_seconds("timeout", seconds))
        .transpose()?;
    let connect_timeout = cli
        .connect_timeout
        .map(|seconds| duration_from_seconds("connect-timeout", seconds))
        .transpose()?;
    crate::tls::install_default_crypto_provider();

    let connect_timing = client::ConnectionTiming::default();
    let client_build = client::ClientBuildContext {
        mode: client::ClientMode::Request(http_version),
        request_timeout,
        connect_timeout,
        request_start,
        session: session.as_ref(),
        connect_timing: Some(&connect_timing),
    };
    let mut initial_client = client::build_client_for_url(cli, &url, &client_build).await?;
    if cli.grpc && grpc_method.is_none() {
        let request_requires_schema = grpc_request_requires_schema(cli);
        match crate::grpc::reflection::schema_for_call(cli, &url, &initial_client.client).await {
            Ok(schema) => match proto::method_for_url(&schema, &url) {
                Ok(method) => grpc_method = Some(method),
                Err(err) if request_requires_schema => return Err(err),
                Err(_) => {}
            },
            Err(err) if request_requires_schema => return Err(err),
            Err(_) => {}
        }
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
            HeaderValue::from_static(core::DEFAULT_ACCEPT_HEADER),
        );
        apply_headers(&mut headers, &cli.headers)?;
    }
    apply_ranges(&mut headers, &cli.ranges);
    let mut compression = apply_accept_encoding(&mut headers, cli, &method);
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
            apply_aws_sigv4(
                cli,
                method.as_str(),
                &url,
                &mut dry_run_headers,
                &body,
                config,
            )?;
        }
        apply_builder_authorization_headers(&mut dry_run_headers, cli, None)?;
        print_request_metadata(cli, &method, &url, &dry_run_headers, &body, http_version);
        print_dry_run_body(cli, &body)?;
        return Ok(0);
    }

    let retry_count = cli.retry();
    let retry_delay = duration_from_seconds("retry-delay", cli.retry_delay())?;
    let total_attempts = total_attempts_for_retry(retry_count)?;
    let mut attempt = 0;
    let result = loop {
        let mut request_method = method.clone();
        let mut request_url = url.clone();
        let mut request_body = body.clone();
        let mut request_client = initial_client.clone();
        let mut redirect_statuses = Vec::new();
        let mut redirect_count = 0_usize;
        let mut strip_entity_headers = false;
        let mut timing = AttemptTiming::start();
        let attempt_result = loop {
            let mut attempt_headers = headers.clone();
            let auth_allowed = same_origin(&url, &request_url);
            if !auth_allowed {
                strip_cross_origin_sensitive_headers(&mut attempt_headers);
            }
            if strip_entity_headers {
                strip_entity_headers_for_bodyless_redirect(&mut attempt_headers);
            }
            if auth_allowed && let Some(config) = &aws_config {
                apply_aws_sigv4(
                    cli,
                    request_method.as_str(),
                    &request_url,
                    &mut attempt_headers,
                    &request_body,
                    config,
                )?;
            }
            if cli.verbose >= 2 && !cli.silent {
                print_request_metadata(
                    cli,
                    &request_method,
                    &request_url,
                    &attempt_headers,
                    &request_body,
                    http_version,
                );
            }
            if cli.verbose >= 3
                && !cli.silent
                && let Some(dns) = request_client
                    .dns_resolution
                    .as_ref()
                    .and_then(|resolution| resolution.timing.as_ref())
            {
                print_dns_debug(cli, dns);
            }

            let req = build_request(
                &request_client.client,
                request_method.clone(),
                request_url.clone(),
                attempt_headers,
                request_body.clone(),
                cli,
                if auth_allowed {
                    RequestAuthorization::Cli
                } else {
                    RequestAuthorization::None
                },
            )?;
            timing.set_dns(
                request_client
                    .dns_resolution
                    .as_ref()
                    .and_then(|resolution| resolution.timing.as_ref())
                    .map(|dns| dns.duration),
            );
            connect_timing.clear();
            match req.send().await {
                Ok(response) => {
                    if let Some(redirect) = redirect_target(cli, &response, redirect_count)? {
                        timing.mark_response_headers();
                        timing.set_connect(connect_timing.duration());
                        print_redirect_status(cli, response.status());
                        redirect_statuses.push(response.status());
                        let redirected =
                            redirected_request(request_method, request_body, response.status())?;
                        let refresh_client = redirect_requires_client_refresh(
                            cli,
                            http_version,
                            &request_url,
                            &redirect,
                        );
                        drain_response_body_bounded(response).await;
                        request_method = redirected.method;
                        request_url = redirect;
                        request_body = redirected.body;
                        strip_entity_headers |= redirected.strip_entity_headers;
                        if refresh_client {
                            request_client =
                                client::build_client_for_url(cli, &request_url, &client_build)
                                    .await?;
                        }
                        redirect_count += 1;
                        continue;
                    }
                    break Ok(response);
                }
                Err(err) => break Err(err),
            }
        };
        match attempt_result {
            Ok(response) => {
                timing.mark_response_headers();
                timing.set_connect(connect_timing.duration());
                if cli.verbose >= 3 && !cli.silent {
                    let connect_target = connect_debug_target(
                        &response,
                        &request_url,
                        request_client.dns_resolution.as_ref(),
                    );
                    timing::print_debug_lines(&timing, &connect_target, cli.color.as_deref());
                }
                let response = apply_digest_challenge(
                    response,
                    DigestRetryContext {
                        client: &request_client.client,
                        method: request_method,
                        headers: headers.clone(),
                        body: request_body.clone(),
                        cli,
                        redirect_statuses,
                        strip_entity_headers,
                        auth_allowed: same_origin(&url, &request_url),
                    },
                    digest_credentials.as_ref(),
                )
                .await?;
                let status = response.status();
                let retry_sse_uncompressed =
                    should_retry_sse_without_compression(&response, compression);
                if retry_sse_uncompressed {
                    ensure_request_body_replayable(&request_body, "retry SSE without compression")?;
                    headers.remove(ACCEPT_ENCODING);
                    compression = CompressionMode::Off;
                    continue;
                }
                if attempt < retry_count && should_retry_status(status) {
                    ensure_request_body_replayable(&request_body, "retry")?;
                    let delay =
                        compute_delay(retry_delay, attempt, parse_retry_after(response.headers()));
                    print_retry(
                        cli,
                        attempt + 2,
                        total_attempts,
                        delay,
                        &retry_reason(status),
                    );
                    drain_response_body_bounded(response).await;
                    tokio::time::sleep(delay).await;
                    let retry_client_build = client::ClientBuildContext {
                        mode: client_build.mode,
                        request_timeout,
                        connect_timeout,
                        request_start: Instant::now(),
                        session: session.as_ref(),
                        connect_timing: Some(&connect_timing),
                    };
                    initial_client =
                        client::build_client_for_url(cli, &url, &retry_client_build).await?;
                    attempt += 1;
                    continue;
                }
                break finish_response(
                    cli,
                    response,
                    compression,
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
                    ensure_request_body_replayable(&request_body, "retry")?;
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

pub(crate) fn load_session(cli: &Cli) -> Result<Option<crate::session::Session>, FetchError> {
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

fn redirect_requires_client_refresh(
    cli: &Cli,
    http_version: Option<HttpVersion>,
    current: &Url,
    next: &Url,
) -> bool {
    if url_client_endpoint(current) == url_client_endpoint(next) {
        return false;
    }
    if cli.proxy.is_some() || cli.unix.is_some() {
        return false;
    }
    cli.dns_server.is_some()
        || matches!(http_version, Some(HttpVersion::Http3))
        || cli.timing
        || (cli.verbose >= 3 && !cli.silent)
}

fn url_client_endpoint(url: &Url) -> Option<(&str, &str, Option<u16>)> {
    Some((url.scheme(), url.host_str()?, url.port_or_known_default()))
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
    let mut lines = header_lines(headers);
    lines.retain(|(name, _)| !name.eq_ignore_ascii_case("host"));
    if let Some(len) = request_body_content_len(body) {
        lines.push(("content-length".to_string(), len.to_string()));
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
        lines.push(("host".to_string(), host));
    }
    if cli.sort_headers {
        sort_header_lines(&mut lines);
    }

    for (name, value) in lines {
        if debug {
            printer.write_request_prefix();
        }
        printer.write_styled(&name, &[core::Sequence::Bold, core::Sequence::Blue]);
        printer.push_str(": ");
        printer.push_str(&value);
        printer.push_str("\n");
    }
    if debug {
        printer.write_request_prefix();
        printer.push_str("\n");
    }
    flush_stderr(printer);
}

fn print_dry_run_body(cli: &Cli, body: &RequestBody) -> Result<(), FetchError> {
    let Some(body) = body else {
        return Ok(());
    };
    if cli.verbose < 2 {
        eprintln!();
    }
    if matches!(body.source, RequestBodySource::Stdin) {
        let mut bytes = Vec::new();
        std::io::stdin().read_to_end(&mut bytes)?;
        return print_dry_run_bytes(cli, &bytes);
    }
    let preview = request_body_preview(body)?;
    if is_printable(&preview) {
        write_request_body_to_stderr(body)?;
    } else {
        let mut printer = core::Printer::stderr(cli.color.as_deref());
        core::write_warning_msg_no_flush(&mut printer, "the request body appears to be binary");
        flush_stderr(printer);
    }
    Ok(())
}

fn print_dry_run_bytes(cli: &Cli, bytes: &[u8]) -> Result<(), FetchError> {
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

fn sort_header_lines(lines: &mut [(String, String)]) {
    lines.sort_by(
        |(left, _), (right, _)| match (left.starts_with(':'), right.starts_with(':')) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => left.cmp(right),
        },
    );
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

async fn finish_response(
    cli: &Cli,
    response: Response,
    compression: CompressionMode,
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
    let output_progress_total =
        output_progress_total_bytes(compression, &response_headers, response_content_length);
    let method_is_head = cli.method().eq_ignore_ascii_case("HEAD");
    let response_timing = timing.and_then(AttemptTiming::response_timing);
    if cli.discard {
        let body_start = Instant::now();
        let streamed =
            stream_response_to_discard(response, response_headers.clone(), compression).await?;
        let body_duration =
            body_duration_from_len(method_is_head, streamed.bytes_written, body_start);
        print_timing(cli, response_timing, body_duration);
        let code = exit_code(status.as_u16(), cli.ignore_status);
        return Ok(check_grpc_status(
            cli,
            &response_headers,
            &streamed.trailers,
            code,
        ));
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
                output_progress_total,
            )
        };
        let body_start = Instant::now();
        let streamed = stream_response_to_output(
            response,
            response_headers.clone(),
            compression,
            path,
            cli.clobber,
            progress,
            cli.copy,
        )
        .await?;
        handle_optional_clipboard_outcome(cli, streamed.clipboard);
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
        let stdout_is_terminal = std::io::stdout().is_terminal();
        if should_stream_formatted_sse_stdout(cli, &response_headers, stdout_is_terminal) {
            let use_color = core::color_enabled(cli.color.as_deref(), stdout_is_terminal);
            let streamed = stream_response_to_formatted_sse_stdout(
                response,
                response_headers.clone(),
                compression,
                cli.copy,
                use_color,
            )
            .await?;
            handle_optional_clipboard_outcome(cli, streamed.clipboard);
            let body_duration =
                body_duration_from_len(method_is_head, streamed.bytes_written, body_start);
            print_timing(cli, response_timing, body_duration);

            let code = exit_code(status.as_u16(), cli.ignore_status);
            return Ok(check_grpc_status(
                cli,
                &response_headers,
                &streamed.trailers,
                code,
            ));
        }
        if let Some(target) = stdout_stream_target(cli, &response_headers, stdout_is_terminal) {
            let streamed = stream_response_to_stdout(
                cli,
                response,
                response_headers.clone(),
                compression,
                cli.copy,
                target,
                stdout_is_terminal,
            )
            .await?;
            handle_optional_clipboard_outcome(cli, streamed.clipboard);
            let body_duration =
                body_duration_from_len(method_is_head, streamed.bytes_written, body_start);
            print_timing(cli, response_timing, body_duration);

            let code = exit_code(status.as_u16(), cli.ignore_status);
            return Ok(check_grpc_status(
                cli,
                &response_headers,
                &streamed.trailers,
                code,
            ));
        }

        let (bytes, trailers) =
            read_decoded_response_body_limited(response, response_headers.clone(), compression)
                .await?;
        let body_duration = body_duration(method_is_head, bytes.as_ref(), body_start);
        if cli.copy {
            handle_clipboard_outcome(cli, clipboard::copy_bytes(&bytes));
        }
        let stdout_body = format_stdout_bytes(
            cli,
            &response_headers,
            &bytes,
            grpc_method.map(|method| method.output()),
        )?;
        write_stdout_bytes(cli, &stdout_body)?;
        print_timing(cli, response_timing, body_duration);

        let code = exit_code(status.as_u16(), cli.ignore_status);
        Ok(check_grpc_status(cli, &response_headers, &trailers, code))
    }
}

struct StdoutBody {
    bytes: Vec<u8>,
    content_type: ContentType,
}

fn write_stdout_bytes(cli: &Cli, body: &StdoutBody) -> Result<(), FetchError> {
    let stdout_is_terminal = std::io::stdout().is_terminal();
    if should_warn_for_terminal_binary_stdout(cli, &body.bytes, stdout_is_terminal) {
        write_warning(cli, BINARY_RESPONSE_WARNING);
        return Ok(());
    }

    if should_page_stdout(cli, &body.bytes, body.content_type, stdout_is_terminal) {
        return write_stdout_bytes_with_pager(&body.bytes);
    }

    std::io::stdout().write_all(&body.bytes)?;
    Ok(())
}

fn should_page_stdout(
    cli: &Cli,
    bytes: &[u8],
    content_type: ContentType,
    stdout_is_terminal: bool,
) -> bool {
    let pager_allowed = !bytes.is_empty() && content_type != ContentType::Image;
    pager_allowed
        && match crate::cli::PagerMode::from_cli(cli) {
            crate::cli::PagerMode::Auto => stdout_is_terminal,
            crate::cli::PagerMode::On => true,
            crate::cli::PagerMode::Off => false,
        }
}

fn write_stdout_bytes_with_pager(bytes: &[u8]) -> Result<(), FetchError> {
    let mut child = match std::process::Command::new("less")
        .arg("-FIRX")
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(child) => child,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            std::io::stdout().write_all(bytes)?;
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };

    if let Some(mut stdin) = child.stdin.take() {
        match stdin.write_all(bytes) {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::BrokenPipe => {}
            Err(err) => return Err(err.into()),
        }
    }

    let status = child.wait()?;
    if !status.success() {
        return Err(FetchError::Runtime(format!("pager exited with {status}")));
    }

    Ok(())
}

#[derive(Clone, Copy)]
enum StdoutStreamTarget {
    Direct,
    Pager,
}

fn stdout_stream_target(
    cli: &Cli,
    headers: &HeaderMap,
    stdout_is_terminal: bool,
) -> Option<StdoutStreamTarget> {
    if format_enabled(cli.format.as_deref(), stdout_is_terminal) {
        return None;
    }

    let is_image = response_header_content_type(headers) == ContentType::Image;
    match crate::cli::PagerMode::from_cli(cli) {
        crate::cli::PagerMode::Auto if stdout_is_terminal && !is_image => {
            Some(StdoutStreamTarget::Pager)
        }
        crate::cli::PagerMode::On if !is_image => Some(StdoutStreamTarget::Pager),
        crate::cli::PagerMode::Auto | crate::cli::PagerMode::Off | crate::cli::PagerMode::On => {
            Some(StdoutStreamTarget::Direct)
        }
    }
}

fn response_header_content_type(headers: &HeaderMap) -> ContentType {
    let content_type = headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    content_type::get_content_type(content_type).0
}

fn terminal_binary_stdout_guard_enabled(cli: &Cli, stdout_is_terminal: bool) -> bool {
    stdout_is_terminal && cli.output.as_deref() != Some("-")
}

fn should_warn_for_terminal_binary_stdout(
    cli: &Cli,
    bytes: &[u8],
    stdout_is_terminal: bool,
) -> bool {
    terminal_binary_stdout_guard_enabled(cli, stdout_is_terminal) && !is_printable(bytes)
}

fn should_stream_formatted_sse_stdout(
    cli: &Cli,
    headers: &HeaderMap,
    stdout_is_terminal: bool,
) -> bool {
    response_header_content_type(headers) == ContentType::Sse
        && format_enabled(cli.format.as_deref(), stdout_is_terminal)
}

fn should_retry_sse_without_compression(response: &Response, compression: CompressionMode) -> bool {
    compression == CompressionMode::Auto
        && response_header_content_type(response.headers()) == ContentType::Sse
        && content_encoding_decoders(response.headers(), compression).is_some_and(|decoders| {
            decoders
                .iter()
                .any(|encoding| encoding.as_str() != "aws-chunked")
        })
}

async fn read_decoded_response_body_limited(
    response: Response,
    response_headers: HeaderMap,
    compression: CompressionMode,
) -> Result<(Vec<u8>, HeaderMap), FetchError> {
    let (reader, trailers) = async_response_reader(response);
    let mut reader = decoded_async_response_reader(reader, compression, &response_headers)?;
    let mut bytes = Vec::new();
    let mut buf = vec![0; 16 * 1024];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            let trailers = trailers
                .lock()
                .map(|trailers| trailers.clone())
                .unwrap_or_default();
            return Ok((bytes, trailers));
        }
        if bytes.len().saturating_add(n) > MAX_BUFFERED_RESPONSE_BYTES {
            return Err(FetchError::Message(format!(
                "response body exceeds {} bytes and cannot be buffered; use '--format off' or write to a file to stream it",
                MAX_BUFFERED_RESPONSE_BYTES
            )));
        }
        bytes.extend_from_slice(&buf[..n]);
    }
}

async fn drain_response_body_bounded(mut response: Response) {
    drain_response_body_bounded_mut(&mut response).await;
}

async fn drain_response_body_bounded_mut(response: &mut Response) {
    let mut discarded = 0usize;
    while discarded < MAX_DISCARDED_RESPONSE_BYTES {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                discarded = discarded.saturating_add(chunk.len());
            }
            Ok(None) | Err(_) => break,
        }
    }
}

struct StreamedOutput {
    trailers: HeaderMap,
    bytes_written: i64,
    clipboard: Option<clipboard::CopyOutcome>,
}

async fn stream_response_to_discard(
    response: Response,
    response_headers: HeaderMap,
    compression: CompressionMode,
) -> Result<StreamedOutput, FetchError> {
    let (reader, trailers) = async_response_reader(response);
    let mut reader = decoded_async_response_reader(reader, compression, &response_headers)?;
    let mut sink = tokio::io::sink();
    let bytes_written = copy_async_reader_to_writer(&mut reader, &mut sink, None).await?;
    let trailers = trailers
        .lock()
        .map(|trailers| trailers.clone())
        .unwrap_or_default();
    Ok(StreamedOutput {
        trailers,
        bytes_written,
        clipboard: None,
    })
}

async fn stream_response_to_stdout(
    cli: &Cli,
    response: Response,
    response_headers: HeaderMap,
    compression: CompressionMode,
    copy: bool,
    target: StdoutStreamTarget,
    stdout_is_terminal: bool,
) -> Result<StreamedOutput, FetchError> {
    let (reader, trailers) = async_response_reader(response);
    let mut reader = decoded_async_response_reader(reader, compression, &response_headers)?;
    let mut capture = copy.then(clipboard::Capture::default);
    let bytes_written = if terminal_binary_stdout_guard_enabled(cli, stdout_is_terminal) {
        stream_response_to_stdout_with_binary_check(cli, &mut reader, target, capture.as_mut())
            .await?
    } else {
        copy_async_reader_to_stdout_target(&mut reader, target, &[], capture.as_mut()).await?
    };
    let clipboard = capture.map(clipboard::Capture::copy);
    let trailers = trailers
        .lock()
        .map(|trailers| trailers.clone())
        .unwrap_or_default();
    Ok(StreamedOutput {
        trailers,
        bytes_written,
        clipboard,
    })
}

async fn stream_response_to_formatted_sse_stdout(
    response: Response,
    response_headers: HeaderMap,
    compression: CompressionMode,
    copy: bool,
    use_color: bool,
) -> Result<StreamedOutput, FetchError> {
    let (reader, trailers) = async_response_reader(response);
    let mut reader = decoded_async_response_reader(reader, compression, &response_headers)?;
    let mut stdout = tokio::io::stdout();
    let mut capture = copy.then(clipboard::Capture::default);
    let mut formatter = sse::EventStreamFormatter::new(use_color);
    let mut pending = Vec::new();
    let mut buf = vec![0; 16 * 1024];
    let mut bytes_read = 0i64;

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            let formatted =
                finish_sse_stream_formatter(&mut pending, &mut formatter).map_err(|err| {
                    FetchError::Message(format!("invalid UTF-8 in event stream: {err}"))
                })?;
            if !formatted.is_empty() {
                stdout.write_all(formatted.as_bytes()).await?;
            }
            stdout.flush().await?;
            let clipboard = capture.map(clipboard::Capture::copy);
            let trailers = trailers
                .lock()
                .map(|trailers| trailers.clone())
                .unwrap_or_default();
            return Ok(StreamedOutput {
                trailers,
                bytes_written: bytes_read,
                clipboard,
            });
        }

        if let Some(capture) = capture.as_mut() {
            capture.push(&buf[..n]);
        }
        bytes_read = bytes_read.saturating_add(i64::try_from(n).unwrap_or(i64::MAX));
        pending.extend_from_slice(&buf[..n]);
        let formatted = push_sse_stream_bytes(&mut pending, &mut formatter)
            .map_err(|err| FetchError::Message(format!("invalid UTF-8 in event stream: {err}")))?;
        if !formatted.is_empty() {
            stdout.write_all(formatted.as_bytes()).await?;
            stdout.flush().await?;
        }
    }
}

fn push_sse_stream_bytes(
    pending: &mut Vec<u8>,
    formatter: &mut sse::EventStreamFormatter,
) -> Result<String, std::str::Utf8Error> {
    let mut out = String::new();
    loop {
        match std::str::from_utf8(pending) {
            Ok(input) => {
                formatter.push_str(input, &mut out);
                pending.clear();
                return Ok(out);
            }
            Err(err) if err.error_len().is_none() => {
                let valid_up_to = err.valid_up_to();
                if valid_up_to == 0 {
                    return Ok(out);
                }
                let input = std::str::from_utf8(&pending[..valid_up_to])?.to_string();
                formatter.push_str(&input, &mut out);
                pending.drain(..valid_up_to);
            }
            Err(err) => return Err(err),
        }
    }
}

fn finish_sse_stream_formatter(
    pending: &mut Vec<u8>,
    formatter: &mut sse::EventStreamFormatter,
) -> Result<String, std::str::Utf8Error> {
    let mut out = push_sse_stream_bytes(pending, formatter)?;
    formatter.finish(&mut out);
    Ok(out)
}

async fn stream_response_to_output(
    response: Response,
    response_headers: HeaderMap,
    compression: CompressionMode,
    path: String,
    clobber: bool,
    progress: output::WriteProgress,
    copy: bool,
) -> Result<StreamedOutput, FetchError> {
    let (reader, trailers) = async_response_reader(response);
    let mut reader = decoded_async_response_reader(reader, compression, &response_headers)?;
    let mut capture = copy.then(clipboard::Capture::default);
    let bytes_written = if let Some(capture) = capture.as_mut() {
        let mut reader = AsyncClipboardTeeReader { reader, capture };
        output::write_output_async_reader(&path, &mut reader, clobber, progress)
            .await
            .map_err(|err| FetchError::Message(err.to_string()))?
    } else {
        output::write_output_async_reader(&path, &mut reader, clobber, progress)
            .await
            .map_err(|err| FetchError::Message(err.to_string()))?
    };
    let clipboard = capture.map(clipboard::Capture::copy);
    let trailers = trailers
        .lock()
        .map(|trailers| trailers.clone())
        .unwrap_or_default();
    Ok(StreamedOutput {
        trailers,
        bytes_written,
        clipboard,
    })
}

struct AsyncClipboardTeeReader<'a> {
    reader: AsyncReadBox,
    capture: &'a mut clipboard::Capture,
}

impl AsyncRead for AsyncClipboardTeeReader<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let filled_before = buf.filled().len();
        match self.reader.as_mut().poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let filled = buf.filled();
                self.capture.push(&filled[filled_before..]);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

fn async_response_reader(response: Response) -> (AsyncReadBox, Arc<Mutex<HeaderMap>>) {
    let response: http::Response<reqwest::Body> = response.into();
    let body = response.into_body();
    let trailers = Arc::new(Mutex::new(HeaderMap::new()));
    let stream_trailers = trailers.clone();
    let stream = stream::try_unfold(body, move |mut body| {
        let stream_trailers = stream_trailers.clone();
        async move {
            loop {
                let Some(frame) = body.frame().await else {
                    return Ok::<Option<(Bytes, reqwest::Body)>, std::io::Error>(None);
                };
                let frame = frame.map_err(|err| {
                    std::io::Error::other(reqwest_response_body_error_message(&err))
                })?;
                match frame.into_data() {
                    Ok(data) => {
                        if data.is_empty() {
                            continue;
                        }
                        return Ok(Some((data, body)));
                    }
                    Err(frame) => {
                        if let Ok(trailers) = frame.into_trailers()
                            && let Ok(mut stored) = stream_trailers.lock()
                        {
                            *stored = trailers;
                        }
                    }
                }
            }
        }
    });
    (Box::pin(StreamReader::new(stream)), trailers)
}

async fn stream_response_to_stdout_with_binary_check(
    cli: &Cli,
    reader: &mut AsyncReadBox,
    target: StdoutStreamTarget,
    mut capture: Option<&mut clipboard::Capture>,
) -> Result<i64, FetchError> {
    let mut first_chunk = vec![0; 16 * 1024];
    let n = reader.read(&mut first_chunk).await?;
    if n == 0 {
        return Ok(0);
    }

    let first_chunk = &first_chunk[..n];
    if !is_printable(first_chunk) {
        write_warning(cli, BINARY_RESPONSE_WARNING);
        if let Some(capture) = capture.as_mut() {
            capture.push(first_chunk);
        }
        let mut sink = tokio::io::sink();
        let drained = copy_async_reader_to_writer(reader, &mut sink, capture).await?;
        return Ok(i64::try_from(n).unwrap_or(i64::MAX).saturating_add(drained));
    }

    copy_async_reader_to_stdout_target(reader, target, first_chunk, capture).await
}

async fn copy_async_reader_to_stdout_target(
    reader: &mut AsyncReadBox,
    target: StdoutStreamTarget,
    prefix: &[u8],
    capture: Option<&mut clipboard::Capture>,
) -> Result<i64, FetchError> {
    match target {
        StdoutStreamTarget::Direct => {
            let mut stdout = tokio::io::stdout();
            Ok(
                copy_async_reader_to_writer_with_prefix(reader, &mut stdout, prefix, capture)
                    .await?,
            )
        }
        StdoutStreamTarget::Pager => stream_async_reader_to_pager(reader, prefix, capture).await,
    }
}

async fn copy_async_reader_to_writer<W>(
    reader: &mut AsyncReadBox,
    writer: &mut W,
    mut capture: Option<&mut clipboard::Capture>,
) -> std::io::Result<i64>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0; 64 * 1024];
    let mut written = 0i64;
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            writer.flush().await?;
            return Ok(written);
        }
        if let Some(capture) = capture.as_mut() {
            capture.push(&buf[..n]);
        }
        writer.write_all(&buf[..n]).await?;
        written = written.saturating_add(i64::try_from(n).unwrap_or(i64::MAX));
    }
}

async fn copy_async_reader_to_writer_with_prefix<W>(
    reader: &mut AsyncReadBox,
    writer: &mut W,
    prefix: &[u8],
    mut capture: Option<&mut clipboard::Capture>,
) -> std::io::Result<i64>
where
    W: AsyncWrite + Unpin,
{
    let mut written = 0i64;
    if !prefix.is_empty() {
        if let Some(capture) = capture.as_mut() {
            capture.push(prefix);
        }
        writer.write_all(prefix).await?;
        written = i64::try_from(prefix.len()).unwrap_or(i64::MAX);
    }
    Ok(written.saturating_add(copy_async_reader_to_writer(reader, writer, capture).await?))
}

async fn stream_async_reader_to_pager(
    reader: &mut AsyncReadBox,
    prefix: &[u8],
    capture: Option<&mut clipboard::Capture>,
) -> Result<i64, FetchError> {
    let mut child = match tokio::process::Command::new("less")
        .arg("-FIRX")
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(child) => child,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            let mut stdout = tokio::io::stdout();
            return Ok(copy_async_reader_to_writer_with_prefix(
                reader,
                &mut stdout,
                prefix,
                capture,
            )
            .await?);
        }
        Err(err) => return Err(err.into()),
    };

    let mut bytes_written = 0;
    if let Some(mut stdin) = child.stdin.take() {
        match copy_async_reader_to_writer_with_prefix(reader, &mut stdin, prefix, capture).await {
            Ok(n) => bytes_written = n,
            Err(err) if err.kind() == ErrorKind::BrokenPipe => {}
            Err(err) => return Err(err.into()),
        }
    }

    let status = child.wait().await?;
    if !status.success() {
        return Err(FetchError::Runtime(format!("pager exited with {status}")));
    }

    Ok(bytes_written)
}

fn handle_optional_clipboard_outcome(cli: &Cli, outcome: Option<clipboard::CopyOutcome>) {
    if let Some(outcome) = outcome {
        handle_clipboard_outcome(cli, outcome);
    }
}

fn handle_clipboard_outcome(cli: &Cli, outcome: clipboard::CopyOutcome) {
    match outcome {
        clipboard::CopyOutcome::Copied { .. } => {}
        other => write_warning(cli, &other.to_string()),
    }
}

fn body_duration(method_is_head: bool, bytes: &[u8], start: Instant) -> Option<Duration> {
    body_duration_from_len(
        method_is_head,
        i64::try_from(bytes.len()).unwrap_or(i64::MAX),
        start,
    )
}

fn body_duration_from_len(method_is_head: bool, len: i64, start: Instant) -> Option<Duration> {
    if method_is_head || len == 0 {
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

fn build_request(
    client: &Client,
    method: Method,
    url: Url,
    mut headers: HeaderMap,
    body: RequestBody,
    cli: &Cli,
    authorization: RequestAuthorization<'_>,
) -> Result<RequestBuilder, FetchError> {
    if let Some(len) = request_body_content_len(&body)
        && !headers.contains_key(CONTENT_LENGTH)
    {
        headers.insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&len.to_string())
                .expect("content length is a valid header value"),
        );
    }
    let mut req = client.request(method, url).headers(headers);
    if let Some(version) = reqwest_request_version_for_cli(cli)? {
        req = req.version(version);
    }

    if let Some(body) = body {
        req = req.body(request_body_to_reqwest_body(body)?);
    }

    match authorization {
        RequestAuthorization::Cli => {
            let mut authorization_headers = HeaderMap::new();
            apply_builder_authorization_headers(&mut authorization_headers, cli, None)?;
            req = req.headers(authorization_headers);
        }
        RequestAuthorization::Digest(auth) => {
            let mut authorization_headers = HeaderMap::new();
            apply_builder_authorization_headers(&mut authorization_headers, cli, Some(auth))?;
            req = req.headers(authorization_headers);
        }
        RequestAuthorization::None => {}
    }

    Ok(req)
}

enum RequestAuthorization<'a> {
    Cli,
    Digest(&'a str),
    None,
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
    strip_entity_headers: bool,
    auth_allowed: bool,
}

async fn apply_digest_challenge(
    mut response: Response,
    context: DigestRetryContext<'_>,
    credentials: Option<&(String, String)>,
) -> Result<Response, FetchError> {
    let Some((username, password)) = credentials else {
        return Ok(response);
    };
    if response.status() != StatusCode::UNAUTHORIZED {
        return Ok(response);
    }
    if !context.auth_allowed {
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
    ensure_request_body_replayable(&challenged_body, "digest authentication")?;
    let mut challenged_headers = context.headers;
    if context.strip_entity_headers {
        strip_entity_headers_for_bodyless_redirect(&mut challenged_headers);
    }
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

    let retry_request = build_request(
        context.client,
        challenged_method,
        challenged_url,
        challenged_headers,
        challenged_body,
        context.cli,
        RequestAuthorization::Digest(&auth),
    )?;

    if response_body_exceeds_discard_bound(&response) {
        drain_response_body_bounded_mut(&mut response).await;
        let retry_response: Result<Response, FetchError> =
            retry_request.send().await.map_err(Into::into);
        drop(response);
        retry_response
    } else if digest_retry_before_drain(&response) {
        let retry_response: Result<Response, FetchError> =
            retry_request.send().await.map_err(Into::into);
        drop(response);
        retry_response
    } else {
        drain_response_body_bounded(response).await;
        retry_request.send().await.map_err(Into::into)
    }
}

fn digest_retry_before_drain(response: &Response) -> bool {
    if response_body_exceeds_discard_bound(response) {
        return true;
    }

    #[cfg(windows)]
    {
        !response_connection_close(response)
    }

    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(windows)]
fn response_connection_close(response: &Response) -> bool {
    response
        .headers()
        .get_all(reqwest::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("close"))
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

fn response_body_exceeds_discard_bound(response: &Response) -> bool {
    response
        .content_length()
        .is_some_and(|len| len > MAX_DISCARDED_RESPONSE_BYTES as u64)
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

fn apply_aws_sigv4(
    cli: &Cli,
    method: &str,
    url: &Url,
    headers: &mut HeaderMap,
    body: &RequestBody,
    config: &aws_sigv4::Config,
) -> Result<(), FetchError> {
    let unsigned_payload = aws_unsigned_payload(cli, config);
    let body_bytes = request_body_bytes(body);
    let content_sha256 = HeaderName::from_static("x-amz-content-sha256");
    if body_bytes.is_none() && !unsigned_payload && !headers.contains_key(&content_sha256) {
        let hash = request_body_sha256_hex(body)?;
        headers.insert(
            content_sha256,
            HeaderValue::from_str(&hash)
                .map_err(|err| FetchError::Message(format!("invalid AWS payload hash: {err}")))?,
        );
    }
    aws_sigv4::sign(
        method,
        url,
        headers,
        body_bytes,
        config,
        time::OffsetDateTime::now_utc(),
        unsigned_payload,
    )
    .map_err(|err| FetchError::Message(err.to_string()))
}

fn request_body_sha256_hex(body: &RequestBody) -> Result<String, FetchError> {
    let Some(body) = body else {
        return hex_sha256_stream(std::io::empty());
    };
    let mut hasher = Sha256::new();
    match &body.source {
        RequestBodySource::Bytes(bytes) => hasher.update(bytes),
        RequestBodySource::File { path, .. } => {
            hash_reader(&mut hasher, std::fs::File::open(path)?)?;
        }
        RequestBodySource::Multipart(multipart) => {
            let mut writer = Sha256Writer(&mut hasher);
            multipart
                .write_to(&mut writer)
                .map_err(|err| FetchError::Message(err.to_string()))?;
        }
        RequestBodySource::Stdin => {
            return Err(FetchError::Message(
                "AWS SigV4 cannot sign a streaming stdin request body unless x-amz-content-sha256 is set or S3 unsigned payload is used".to_string(),
            ));
        }
    }
    Ok(hex_encode(hasher.finalize().as_slice()))
}

fn hash_reader(hasher: &mut Sha256, mut reader: impl Read) -> Result<(), FetchError> {
    let mut buf = [0_u8; 8192];
    loop {
        let len = reader.read(&mut buf)?;
        if len == 0 {
            return Ok(());
        }
        hasher.update(&buf[..len]);
    }
}

fn hex_sha256_stream(reader: impl Read) -> Result<String, FetchError> {
    let mut hasher = Sha256::new();
    hash_reader(&mut hasher, reader)?;
    Ok(hex_encode(hasher.finalize().as_slice()))
}

struct Sha256Writer<'a>(&'a mut Sha256);

impl Write for Sha256Writer<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn request_body_bytes(body: &RequestBody) -> Option<&[u8]> {
    match body.as_ref().map(|body| &body.source) {
        Some(RequestBodySource::Bytes(bytes)) => Some(bytes.as_ref()),
        _ => None,
    }
}

fn request_body_content_len(body: &RequestBody) -> Option<u64> {
    match body.as_ref()? {
        RequestBodyPayload {
            source: RequestBodySource::Bytes(bytes),
            ..
        } => Some(bytes.len() as u64),
        RequestBodyPayload {
            source: RequestBodySource::File { len, .. },
            ..
        } => Some(*len),
        RequestBodyPayload {
            source: RequestBodySource::Multipart(multipart),
            ..
        } => multipart.content_len().ok(),
        RequestBodyPayload {
            source: RequestBodySource::Stdin,
            ..
        } => None,
    }
}

fn request_body_to_reqwest_body(body: RequestBodyPayload) -> Result<Body, FetchError> {
    match body.source {
        RequestBodySource::Bytes(bytes) => Ok(Body::from(bytes)),
        RequestBodySource::File { path, .. } => {
            let file = std::fs::File::open(&path)?;
            Ok(Body::from(tokio::fs::File::from_std(file)))
        }
        RequestBodySource::Stdin => Ok(Body::wrap_stream(ReaderStream::new(tokio::io::stdin()))),
        RequestBodySource::Multipart(multipart) => Ok(Body::wrap_stream(multipart.stream())),
    }
}

pub(crate) fn request_body_into_bytes(
    body: RequestBody,
) -> Result<MaterializedRequestBody, FetchError> {
    let Some(body) = body else {
        return Ok(None);
    };
    let content_type = body.content_type.clone();
    let bytes = match body.source {
        RequestBodySource::Bytes(bytes) => bytes.to_vec(),
        RequestBodySource::File { path, .. } => std::fs::read(path)?,
        RequestBodySource::Stdin => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            buf
        }
        RequestBodySource::Multipart(multipart) => multipart
            .open()
            .map_err(|err| FetchError::Message(err.to_string()))?,
    };
    Ok(Some((bytes, content_type)))
}

fn request_body_preview(body: &RequestBodyPayload) -> Result<Vec<u8>, FetchError> {
    match &body.source {
        RequestBodySource::Bytes(bytes) => Ok(bytes.slice(..bytes.len().min(1024)).to_vec()),
        RequestBodySource::File { path, .. } => read_file_prefix(path, 1024),
        RequestBodySource::Stdin => Ok(Vec::new()),
        RequestBodySource::Multipart(multipart) => {
            let mut out = Vec::new();
            let mut writer = PrefixWriter {
                out: &mut out,
                limit: 1024,
            };
            multipart
                .write_to(&mut writer)
                .map_err(|err| FetchError::Message(err.to_string()))?;
            Ok(out)
        }
    }
}

fn write_request_body_to_stderr(body: &RequestBodyPayload) -> Result<(), FetchError> {
    let mut stderr = std::io::stderr();
    match &body.source {
        RequestBodySource::Bytes(bytes) => stderr.write_all(bytes)?,
        RequestBodySource::File { path, .. } => {
            let mut file = std::fs::File::open(path)?;
            std::io::copy(&mut file, &mut stderr)?;
        }
        RequestBodySource::Stdin => {}
        RequestBodySource::Multipart(multipart) => multipart
            .write_to(&mut stderr)
            .map_err(|err| FetchError::Message(err.to_string()))?,
    }
    Ok(())
}

struct PrefixWriter<'a> {
    out: &'a mut Vec<u8>,
    limit: usize,
}

impl Write for PrefixWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let remaining = self.limit.saturating_sub(self.out.len());
        self.out.extend_from_slice(&buf[..buf.len().min(remaining)]);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn apply_body_content_type(headers: &mut HeaderMap, body: &RequestBody) {
    let Some(RequestBodyPayload {
        content_type: Some(content_type),
        ..
    }) = body.as_ref()
    else {
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
        let mut lines = header_lines(response.headers());
        if cli.sort_headers {
            sort_header_lines(&mut lines);
        }
        for (name, value) in lines {
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
) -> Result<StdoutBody, FetchError> {
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
) -> Result<StdoutBody, FetchError> {
    let content_type = headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    let (mut content_type, charset) = content_type::get_content_type(content_type);
    if content_type == ContentType::Unknown {
        content_type = content_type::sniff_content_type(bytes);
    }
    if !format_enabled(cli.format.as_deref(), stdout_is_terminal) {
        return Ok(StdoutBody {
            bytes: bytes.to_vec(),
            content_type,
        });
    }

    let use_color = core::color_enabled(cli.color.as_deref(), stdout_is_terminal);
    let bytes = transcode_format_bytes(bytes, &charset, content_type);
    let bytes = match content_type {
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
                    Ok(json::format_json(&json_bytes, use_color).unwrap_or(json_bytes))
                } else {
                    Ok(bytes.to_vec())
                }
            } else {
                Ok(protobuf::format_protobuf(&bytes)
                    .map(|formatted| formatted.into_bytes())
                    .unwrap_or_else(|_| bytes.to_vec()))
            }
        }
        ContentType::Image => {
            if cli.image.as_deref() == Some("off") {
                Ok(bytes.to_vec())
            } else {
                let decode_mode = if cli.image.as_deref() == Some("external") {
                    crate::image::DecodeMode::External
                } else {
                    crate::image::DecodeMode::BuiltIn
                };
                crate::image::render(&bytes, decode_mode)
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
        ContentType::Sse => sse::format_event_stream(&bytes, use_color)
            .map(|formatted| formatted.into_bytes())
            .map_err(|err| FetchError::Message(err.to_string())),
        _ => Ok(bytes.to_vec()),
    }?;
    Ok(StdoutBody {
        bytes,
        content_type,
    })
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

fn redirect_target(
    cli: &Cli,
    response: &Response,
    redirect_count: usize,
) -> Result<Option<Url>, FetchError> {
    if cli.redirects == Some(0) || !is_redirect_status(response.status()) {
        return Ok(None);
    }
    let Some(location) = response.headers().get(LOCATION) else {
        return Ok(None);
    };
    let location = location
        .to_str()
        .map_err(|err| FetchError::Runtime(format!("invalid redirect location: {err}")))?;
    let max = cli.redirects.unwrap_or(10);
    if redirect_count >= max {
        return Err(FetchError::Runtime(RedirectLimitError { max }.to_string()));
    }
    let url = response
        .url()
        .join(location)
        .map_err(|err| FetchError::Runtime(format!("invalid redirect location: {err}")))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(FetchError::Runtime(format!(
            "unsupported redirect scheme '{}'",
            url.scheme()
        )));
    }
    Ok(Some(url))
}

fn is_redirect_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str()
            .zip(b.host_str())
            .is_some_and(|(a_host, b_host)| a_host.eq_ignore_ascii_case(b_host))
        && a.port_or_known_default() == b.port_or_known_default()
}

fn strip_cross_origin_sensitive_headers(headers: &mut HeaderMap) {
    headers.remove(AUTHORIZATION);
    headers.remove(COOKIE);
    headers.remove(PROXY_AUTHORIZATION);
}

fn strip_entity_headers_for_bodyless_redirect(headers: &mut HeaderMap) {
    headers.remove(CONTENT_TYPE);
    headers.remove(CONTENT_LENGTH);
    headers.remove(TRANSFER_ENCODING);
}

struct RedirectedRequest {
    method: Method,
    body: RequestBody,
    strip_entity_headers: bool,
}

fn redirected_request(
    mut method: Method,
    mut body: RequestBody,
    status: StatusCode,
) -> Result<RedirectedRequest, FetchError> {
    let mut strip_entity_headers = false;
    match status {
        StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND | StatusCode::SEE_OTHER => {
            if method != Method::GET && method != Method::HEAD {
                method = Method::GET;
            }
            body = None;
            strip_entity_headers = true;
        }
        StatusCode::TEMPORARY_REDIRECT | StatusCode::PERMANENT_REDIRECT
            if !request_body_replayable(&body) =>
        {
            return Err(FetchError::Runtime(
                "request body from stdin cannot be replayed for redirect".to_string(),
            ));
        }
        _ => {}
    }
    Ok(RedirectedRequest {
        method,
        body,
        strip_entity_headers,
    })
}

fn request_body_replayable(body: &RequestBody) -> bool {
    !matches!(
        body.as_ref().map(|body| &body.source),
        Some(RequestBodySource::Stdin)
    )
}

fn ensure_request_body_replayable(body: &RequestBody, action: &str) -> Result<(), FetchError> {
    if request_body_replayable(body) {
        return Ok(());
    }
    Err(FetchError::Runtime(format!(
        "request body from stdin cannot be replayed for {action}"
    )))
}

fn print_redirect_status(cli: &Cli, status: StatusCode) {
    if cli.verbose < 2 || cli.silent {
        return;
    }
    let mut printer = core::Printer::stderr(cli.color.as_deref());
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

fn reqwest_response_body_error_message(err: &reqwest::Error) -> String {
    let mut details = Vec::new();
    let mut source = err.source();
    while let Some(err) = source {
        let source_message = go_style_reqwest_source_message(&err.to_string());
        if !source_message.is_empty()
            && source_message != "request or response body error"
            && !details.contains(&source_message)
        {
            details.push(source_message);
        }
        source = err.source();
    }

    let reqwest_message = err.to_string();
    if details.is_empty() && reqwest_message != "request or response body error" {
        details.push(reqwest_message);
    }

    if details.is_empty() {
        "response body error".to_string()
    } else {
        format!("response body error: {}", details.join(": "))
    }
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

pub(crate) fn format_go_duration(duration: Duration) -> String {
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
    if !seconds.is_finite() || !(0.0..=MAX_DURATION_SECONDS).contains(&seconds) {
        return Err(format!("{flag} must be a non-negative number").into());
    }
    Ok(Duration::from_secs_f64(seconds))
}

pub(crate) fn total_attempts_for_retry(retry_count: usize) -> Result<usize, FetchError> {
    retry_count.checked_add(1).ok_or_else(|| {
        FetchError::invalid_value(
            "--retry",
            retry_count.to_string(),
            "must be less than the maximum usize value",
        )
    })
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

fn apply_accept_encoding(headers: &mut HeaderMap, cli: &Cli, method: &Method) -> CompressionMode {
    let compression = CompressionMode::from_cli(cli);
    let Some(accept_encoding) = compression.accept_encoding() else {
        return CompressionMode::Off;
    };
    if method == Method::HEAD || headers.contains_key(ACCEPT_ENCODING) {
        return CompressionMode::Off;
    }
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static(accept_encoding));
    compression
}

#[cfg(test)]
fn decode_response_bytes(
    compression: CompressionMode,
    headers: &HeaderMap,
    bytes: &[u8],
) -> Result<Vec<u8>, FetchError> {
    if compression == CompressionMode::Off {
        return Ok(bytes.to_vec());
    }

    let Some(encodings) = content_encoding_decoders(headers, compression) else {
        return Ok(bytes.to_vec());
    };

    let mut decoded = bytes.to_vec();
    for encoding in encodings {
        decoded = match encoding.as_str() {
            "br" => decode_brotli(&decoded)?,
            "gzip" => decode_gzip(&decoded)?,
            "zstd" => decode_zstd(&decoded)?,
            "aws-chunked" => decoded,
            _ => unreachable!("unsupported encodings are filtered"),
        };
    }
    Ok(decoded)
}

fn decoded_async_response_reader(
    mut reader: AsyncReadBox,
    compression: CompressionMode,
    headers: &HeaderMap,
) -> Result<AsyncReadBox, FetchError> {
    if compression == CompressionMode::Off {
        return Ok(reader);
    }

    let Some(encodings) = content_encoding_decoders(headers, compression) else {
        return Ok(reader);
    };

    for encoding in encodings {
        reader = match encoding.as_str() {
            "br" => Box::pin(AsyncPrefixedReadError {
                prefix: "br",
                inner: AsyncBrotliDecoder::new(tokio::io::BufReader::new(reader)),
            }),
            "gzip" => Box::pin(AsyncPrefixedReadError {
                prefix: "gzip",
                inner: AsyncGzipDecoder::new(tokio::io::BufReader::new(reader)),
            }),
            "zstd" => Box::pin(AsyncPrefixedReadError {
                prefix: "zstd",
                inner: AsyncZstdDecoder::new(tokio::io::BufReader::new(reader)),
            }),
            "aws-chunked" => reader,
            _ => unreachable!("unsupported encodings are filtered"),
        };
    }
    Ok(reader)
}

fn output_progress_total_bytes(
    compression: CompressionMode,
    headers: &HeaderMap,
    content_length: Option<i64>,
) -> Option<i64> {
    if compression != CompressionMode::Off
        && content_encoding_decoders(headers, compression)
            .is_some_and(|decoders| !decoders.is_empty())
    {
        None
    } else {
        content_length
    }
}

struct AsyncPrefixedReadError<R> {
    prefix: &'static str,
    inner: R,
}

impl<R: AsyncRead + Unpin> AsyncRead for AsyncPrefixedReadError<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let prefix = self.prefix;
        Pin::new(&mut self.inner)
            .poll_read(cx, buf)
            .map_err(|err| std::io::Error::new(err.kind(), format!("{prefix}: {err}")))
    }
}

fn content_encoding_decoders(
    headers: &HeaderMap,
    compression: CompressionMode,
) -> Option<Vec<String>> {
    let encodings = content_encodings(headers);
    let mut decoders = Vec::with_capacity(encodings.len());
    for encoding in encodings.into_iter().rev() {
        if compression.decodes(&encoding) {
            decoders.push(encoding);
        } else {
            return None;
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

#[cfg(test)]
fn decode_gzip(bytes: &[u8]) -> Result<Vec<u8>, FetchError> {
    let mut decoder = GzDecoder::new(bytes);
    let mut decoded = Vec::new();
    decoder
        .read_to_end(&mut decoded)
        .map_err(|err| FetchError::Message(format!("gzip: {err}")))?;
    Ok(decoded)
}

#[cfg(test)]
fn decode_brotli(bytes: &[u8]) -> Result<Vec<u8>, FetchError> {
    let mut decoder = brotli::Decompressor::new(bytes, 4096);
    let mut decoded = Vec::new();
    decoder
        .read_to_end(&mut decoded)
        .map_err(|err| FetchError::Message(format!("br: {err}")))?;
    Ok(decoded)
}

#[cfg(test)]
fn decode_zstd(bytes: &[u8]) -> Result<Vec<u8>, FetchError> {
    zstd::stream::decode_all(bytes).map_err(|err| FetchError::Message(format!("zstd: {err}")))
}

pub(crate) fn request_body(cli: &Cli) -> Result<RequestBody, FetchError> {
    if !cli.multipart.is_empty() {
        let multipart = multipart::Multipart::from_cli_fields(&cli.multipart)
            .map_err(|err| FetchError::Message(err.to_string()))?
            .expect("non-empty multipart input creates multipart body");
        multipart
            .content_len()
            .map_err(|err| FetchError::Message(err.to_string()))?;
        let content_type = multipart.content_type();
        return Ok(Some(RequestBodyPayload {
            source: RequestBodySource::Multipart(multipart),
            content_type: Some(content_type),
        }));
    }
    if let Some(value) = cli.data.as_deref() {
        if let Some(bytes) = &cli.data_literal_bytes {
            return Ok(Some(RequestBodyPayload {
                source: RequestBodySource::Bytes(Bytes::copy_from_slice(bytes)),
                content_type: None,
            }));
        }
        if cli.data_is_literal {
            return Ok(Some(RequestBodyPayload {
                source: RequestBodySource::Bytes(Bytes::copy_from_slice(value.as_bytes())),
                content_type: None,
            }));
        }
        let (source, content_type) = body_value_source(value, true)?;
        return Ok(Some(RequestBodyPayload {
            source,
            content_type,
        }));
    }
    if let Some(value) = cli.json.as_deref() {
        let (source, _) = body_value_source(value, false)?;
        return Ok(Some(RequestBodyPayload {
            source,
            content_type: Some("application/json".to_string()),
        }));
    }
    if let Some(value) = cli.xml.as_deref() {
        let (source, _) = body_value_source(value, false)?;
        return Ok(Some(RequestBodyPayload {
            source,
            content_type: Some("application/xml".to_string()),
        }));
    }
    if !cli.form.is_empty() {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for raw in &cli.form {
            let (key, val) = raw.split_once('=').unwrap_or((raw, ""));
            serializer.append_pair(key.trim(), val.trim());
        }
        return Ok(Some(RequestBodyPayload {
            source: RequestBodySource::Bytes(Bytes::from(serializer.finish().into_bytes())),
            content_type: Some("application/x-www-form-urlencoded".to_string()),
        }));
    }
    Ok(None)
}

fn body_value_source(
    value: &str,
    detect_content_type: bool,
) -> Result<(RequestBodySource, Option<String>), FetchError> {
    if value == "@-" {
        return Ok((
            RequestBodySource::Stdin,
            detect_content_type.then(|| "application/octet-stream".to_string()),
        ));
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
        let content_type = if detect_content_type {
            Some(detect_body_file_content_type(&expanded)?)
        } else {
            None
        };
        return Ok((
            RequestBodySource::File {
                path: expanded,
                len: metadata.len(),
            },
            content_type,
        ));
    }
    Ok((
        RequestBodySource::Bytes(Bytes::copy_from_slice(value.as_bytes())),
        detect_content_type.then(|| sniff_content_type_like_go(value.as_bytes())),
    ))
}

fn expand_home(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return format!("{}/{}", home.to_string_lossy(), rest);
    }
    path.to_string()
}

fn detect_body_file_content_type(path: &str) -> Result<String, FetchError> {
    if let Some(content_type) = detect_type_by_extension(path) {
        return Ok(content_type.to_string());
    }
    Ok(sniff_content_type_like_go(&read_file_prefix(path, 512)?))
}

fn read_file_prefix(path: &str, limit: usize) -> Result<Vec<u8>, FetchError> {
    let mut file = std::fs::File::open(path)?;
    let mut out = vec![0_u8; limit];
    let len = file.read(&mut out)?;
    out.truncate(len);
    Ok(out)
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
    if !value.contains(':') {
        return Err("basic format must be <USERNAME:PASSWORD>".into());
    }
    let encoded = base64::engine::general_purpose::STANDARD.encode(value.as_bytes());
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
    use crate::http::client::{
        configure_tls, configure_unix_socket, http3_local_address, no_proxy_matches_url,
        validate_proxy_for_http_version,
    };
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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    #[derive(Default)]
    struct RecordingAsyncWriter {
        bytes: Vec<u8>,
        flushes: usize,
    }

    impl AsyncWrite for RecordingAsyncWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.bytes.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

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
    fn sort_header_lines_orders_by_name_and_preserves_duplicates() {
        let mut lines = vec![
            ("x-zeta".to_string(), "first".to_string()),
            ("accept".to_string(), "second".to_string()),
            ("x-zeta".to_string(), "third".to_string()),
            ("content-type".to_string(), "fourth".to_string()),
        ];

        sort_header_lines(&mut lines);

        assert_eq!(
            lines,
            [
                ("accept".to_string(), "second".to_string()),
                ("content-type".to_string(), "fourth".to_string()),
                ("x-zeta".to_string(), "first".to_string()),
                ("x-zeta".to_string(), "third".to_string()),
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
    fn terminal_binary_stdout_guard_requires_terminal_and_allows_forced_stdout() {
        let cli = Cli::try_parse_from(["fetch", "https://example.com"]).unwrap();
        assert!(should_warn_for_terminal_binary_stdout(
            &cli,
            b"abc\0def",
            true
        ));
        assert!(!should_warn_for_terminal_binary_stdout(
            &cli,
            b"abc\0def",
            false
        ));
        assert!(!should_warn_for_terminal_binary_stdout(
            &cli,
            b"plain text",
            true
        ));

        let forced = Cli::try_parse_from(["fetch", "-o", "-", "https://example.com"]).unwrap();
        assert!(!should_warn_for_terminal_binary_stdout(
            &forced,
            b"abc\0def",
            true
        ));
    }

    #[test]
    fn request_body_data_detects_go_style_content_type() {
        let cli = Cli::try_parse_from(["fetch", "--data", "hello", "https://example.com"]).unwrap();
        let body = request_body_into_bytes(request_body(&cli).unwrap())
            .unwrap()
            .unwrap();
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
        let body = request_body_into_bytes(request_body(&cli).unwrap())
            .unwrap()
            .unwrap();
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
        assert_eq!(out.bytes, b"not decoded");
        assert_eq!(out.content_type, ContentType::Image);
    }

    #[test]
    fn pager_auto_uses_stdout_terminal_and_skips_images() {
        let cli = Cli::try_parse_from(["fetch", "https://example.com"]).unwrap();
        assert!(!should_page_stdout(
            &cli,
            b"\x1b_Gq=2,f=100,a=T,t=d,s=1,v=1,m=0;AAAA\x1b\\\n",
            ContentType::Image,
            true,
        ));
        assert!(should_page_stdout(
            &cli,
            b"{\"ok\":true}\n",
            ContentType::Json,
            true,
        ));
        assert!(!should_page_stdout(
            &cli,
            b"{\"ok\":true}\n",
            ContentType::Json,
            false,
        ));
    }

    #[test]
    fn pager_on_forces_pager_for_non_terminal_stdout() {
        let cli = Cli::try_parse_from(["fetch", "--pager", "on", "https://example.com"]).unwrap();
        assert!(should_page_stdout(
            &cli,
            b"{\"ok\":true}\n",
            ContentType::Json,
            false,
        ));
    }

    #[test]
    fn pager_off_disables_pager_for_terminal_stdout() {
        let cli = Cli::try_parse_from(["fetch", "--pager", "off", "https://example.com"]).unwrap();
        assert!(!should_page_stdout(
            &cli,
            b"{\"ok\":true}\n",
            ContentType::Json,
            true,
        ));
    }

    #[test]
    fn stdout_streaming_follows_format_and_pager_modes() {
        let headers = HeaderMap::new();
        let cli = Cli::try_parse_from(["fetch", "https://example.com"]).unwrap();
        assert!(matches!(
            stdout_stream_target(&cli, &headers, false),
            Some(StdoutStreamTarget::Direct)
        ));
        assert!(stdout_stream_target(&cli, &headers, true).is_none());

        let cli = Cli::try_parse_from(["fetch", "--format", "off", "https://example.com"]).unwrap();
        assert!(matches!(
            stdout_stream_target(&cli, &headers, false),
            Some(StdoutStreamTarget::Direct)
        ));
        assert!(matches!(
            stdout_stream_target(&cli, &headers, true),
            Some(StdoutStreamTarget::Pager)
        ));

        let cli = Cli::try_parse_from([
            "fetch",
            "--format",
            "off",
            "--pager",
            "off",
            "https://example.com",
        ])
        .unwrap();
        assert!(matches!(
            stdout_stream_target(&cli, &headers, true),
            Some(StdoutStreamTarget::Direct)
        ));

        let cli = Cli::try_parse_from([
            "fetch",
            "--format",
            "off",
            "--pager",
            "on",
            "https://example.com",
        ])
        .unwrap();
        assert!(matches!(
            stdout_stream_target(&cli, &headers, false),
            Some(StdoutStreamTarget::Pager)
        ));

        let cli = Cli::try_parse_from(["fetch", "--format", "on", "https://example.com"]).unwrap();
        assert!(stdout_stream_target(&cli, &headers, false).is_none());

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("image/png"));
        let cli = Cli::try_parse_from(["fetch", "--format", "off", "https://example.com"]).unwrap();
        assert!(matches!(
            stdout_stream_target(&cli, &headers, true),
            Some(StdoutStreamTarget::Direct)
        ));
    }

    #[tokio::test]
    async fn async_copy_flushes_once_after_streaming_body() {
        let input = vec![b'a'; (64 * 1024) + 17];
        let mut reader: AsyncReadBox = Box::pin(std::io::Cursor::new(input.clone()));
        let mut writer = RecordingAsyncWriter::default();

        let written = copy_async_reader_to_writer(&mut reader, &mut writer, None)
            .await
            .unwrap();

        assert_eq!(written, i64::try_from(input.len()).unwrap());
        assert_eq!(writer.bytes, input);
        assert_eq!(writer.flushes, 1);
    }

    #[tokio::test]
    async fn async_copy_with_prefix_flushes_once_after_streaming_body() {
        let prefix = b"first chunk";
        let body = vec![b'b'; (64 * 1024) + 17];
        let mut reader: AsyncReadBox = Box::pin(std::io::Cursor::new(body.clone()));
        let mut writer = RecordingAsyncWriter::default();

        let written =
            copy_async_reader_to_writer_with_prefix(&mut reader, &mut writer, prefix, None)
                .await
                .unwrap();

        let mut expected = prefix.to_vec();
        expected.extend_from_slice(&body);
        assert_eq!(written, i64::try_from(expected.len()).unwrap());
        assert_eq!(writer.bytes, expected);
        assert_eq!(writer.flushes, 1);
    }

    #[test]
    fn formatted_sse_uses_dedicated_streaming_path() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));

        let cli = Cli::try_parse_from(["fetch", "https://example.com"]).unwrap();
        assert!(!should_stream_formatted_sse_stdout(&cli, &headers, false));
        assert!(should_stream_formatted_sse_stdout(&cli, &headers, true));

        let cli = Cli::try_parse_from(["fetch", "--format", "on", "https://example.com"]).unwrap();
        assert!(should_stream_formatted_sse_stdout(&cli, &headers, false));

        let cli = Cli::try_parse_from(["fetch", "--format", "off", "https://example.com"]).unwrap();
        assert!(!should_stream_formatted_sse_stdout(&cli, &headers, true));
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
            String::from_utf8(out.bytes).unwrap(),
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
        assert!(!String::from_utf8(out.bytes).unwrap().contains("\x1b["));

        let out =
            format_stdout_bytes_with_terminal(&cli, &headers, br#"{"ok":"yes"}"#, None, true, 80)
                .unwrap();
        assert!(String::from_utf8(out.bytes).unwrap().contains("\x1b["));

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
        assert!(!String::from_utf8(out.bytes).unwrap().contains("\x1b["));

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
        assert!(String::from_utf8(out.bytes).unwrap().contains("\x1b["));
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
            assert_eq!(String::from_utf8(out.bytes).unwrap(), r#"{"ok":"yes"}"#);

            let out = format_stdout_bytes_with_terminal(
                &cli,
                &headers,
                br#"{"ok":"yes"}"#,
                None,
                true,
                80,
            )
            .unwrap();
            let out = String::from_utf8(out.bytes).unwrap();
            assert!(out.starts_with("{\n  \""));
            assert!(out.contains("\x1b[34m\x1b[1mok\x1b[0m"));
            assert!(out.contains("\x1b[32myes\x1b[0m"));
        }

        let cli = Cli::try_parse_from(["fetch", "--format", "off", "https://example.com"]).unwrap();
        let out =
            format_stdout_bytes_with_terminal(&cli, &headers, br#"{"ok":"yes"}"#, None, true, 80)
                .unwrap();
        assert_eq!(String::from_utf8(out.bytes).unwrap(), r#"{"ok":"yes"}"#);
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
        let out = String::from_utf8(out.bytes).unwrap();

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

        assert_eq!(out.bytes, raw);
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
        assert_eq!(
            digest_credentials(Some(" user : pass ")).unwrap(),
            Some((" user ".to_string(), " pass ".to_string()))
        );
        assert!(digest_credentials(Some("nocolon")).is_err());
        assert_eq!(digest_credentials(None).unwrap(), None);
    }

    #[test]
    fn digest_challenge_after_redirect_uses_go_redirect_method_and_body() {
        let original_body = Some(RequestBodyPayload::from_bytes(
            b"payload".to_vec(),
            Some("text/plain".to_string()),
        ));

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
    fn redirected_post_to_get_marks_entity_headers_for_stripping() {
        let original_body = Some(RequestBodyPayload::from_bytes(
            b"payload".to_vec(),
            Some("text/plain".to_string()),
        ));

        let redirected =
            redirected_request(Method::POST, original_body, StatusCode::FOUND).unwrap();
        assert_eq!(redirected.method, Method::GET);
        assert!(redirected.body.is_none());
        assert!(redirected.strip_entity_headers);

        let preserved =
            redirected_request(Method::POST, None, StatusCode::TEMPORARY_REDIRECT).unwrap();
        assert_eq!(preserved.method, Method::POST);
        assert!(!preserved.strip_entity_headers);
    }

    #[test]
    fn basic_header_preserves_credential_spaces() {
        assert_eq!(
            basic_header(Some(" user : pass ")).unwrap(),
            Some("Basic IHVzZXIgOiBwYXNzIA==".to_string())
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
    fn duration_from_seconds_rejects_values_outside_supported_range() {
        assert_eq!(
            duration_from_seconds("timeout", 1.5).unwrap(),
            Duration::from_millis(1500)
        );

        for seconds in [-1.0, f64::NAN, f64::INFINITY, 1e100] {
            let err = duration_from_seconds("timeout", seconds).unwrap_err();
            assert_eq!(err.to_string(), "timeout must be a non-negative number");
        }
    }

    #[test]
    fn total_attempts_for_retry_rejects_overflow() {
        assert_eq!(total_attempts_for_retry(0).unwrap(), 1);
        assert_eq!(total_attempts_for_retry(3).unwrap(), 4);

        let err = total_attempts_for_retry(usize::MAX).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "invalid value '{}' for option '--retry': must be less than the maximum usize value",
                usize::MAX
            )
        );
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
        let body = Some(RequestBodyPayload::from_bytes(
            b"hello".to_vec(),
            Some("text/plain".to_string()),
        ));
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
    fn no_proxy_matching_for_env_proxy_guard() {
        let url = Url::parse("https://api.example.com:443/path").unwrap();

        assert!(no_proxy_matches_url(&url, Some("*")));
        assert!(no_proxy_matches_url(&url, Some("example.com")));
        assert!(no_proxy_matches_url(&url, Some(".example.com")));
        assert!(no_proxy_matches_url(&url, Some("EXAMPLE.COM")));
        assert!(no_proxy_matches_url(
            &url,
            Some("localhost, api.example.com")
        ));
        assert!(!no_proxy_matches_url(&url, Some("notexample.com")));
        assert!(!no_proxy_matches_url(&url, Some("")));
        assert!(!no_proxy_matches_url(&url, None));
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
        let empty = proto::grpc_request_body(None, None).unwrap();
        let empty = request_body_into_bytes(empty).unwrap().unwrap();
        assert_eq!(empty.0, crate::grpc::framing::frame(&[], false).unwrap());
        assert_eq!(empty.1.as_deref(), Some("application/grpc+proto"));

        let framed = proto::grpc_request_body(
            Some(RequestBodyPayload::from_bytes(b"hello".to_vec(), None)),
            None,
        )
        .unwrap();
        let framed = request_body_into_bytes(framed).unwrap().unwrap();
        assert_eq!(
            framed.0,
            crate::grpc::framing::frame(b"hello", false).unwrap()
        );
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
    fn regular_http_rejects_legacy_tls_versions_on_rustls_path() {
        let cli =
            Cli::try_parse_from(["fetch", "--min-tls", "1.0", "https://example.com"]).unwrap();

        let err = configure_tls(Client::builder().use_rustls_tls(), &cli).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid value '1.0' for option '--min-tls': must be one of [1.2, 1.3]"
        );

        let cli =
            Cli::try_parse_from(["fetch", "--max-tls", "1.1", "https://example.com"]).unwrap();

        let err = configure_tls(Client::builder().use_rustls_tls(), &cli).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid value '1.1' for option '--max-tls': must be one of [1.2, 1.3]"
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
    fn apply_accept_encoding_uses_requested_compression_mode() {
        for (args, expected_mode, expected_header) in [
            (
                vec!["fetch", "https://example.com"],
                CompressionMode::Auto,
                Some("gzip, br, zstd"),
            ),
            (
                vec!["fetch", "--compress", "br", "https://example.com"],
                CompressionMode::Brotli,
                Some("br"),
            ),
            (
                vec!["fetch", "--compress", "brotli", "https://example.com"],
                CompressionMode::Brotli,
                Some("br"),
            ),
            (
                vec!["fetch", "--compress", "gzip", "https://example.com"],
                CompressionMode::Gzip,
                Some("gzip"),
            ),
            (
                vec!["fetch", "--compress", "zstd", "https://example.com"],
                CompressionMode::Zstd,
                Some("zstd"),
            ),
            (
                vec!["fetch", "--compress", "off", "https://example.com"],
                CompressionMode::Off,
                None,
            ),
        ] {
            let cli = Cli::try_parse_from(args).unwrap();
            let mut headers = HeaderMap::new();

            let mode = apply_accept_encoding(&mut headers, &cli, &Method::GET);

            assert_eq!(mode, expected_mode);
            assert_eq!(
                headers
                    .get(ACCEPT_ENCODING)
                    .and_then(|value| value.to_str().ok()),
                expected_header
            );
        }
    }

    #[test]
    fn apply_accept_encoding_skips_head_and_custom_header() {
        let cli = Cli::try_parse_from(["fetch", "https://example.com"]).unwrap();
        let mut headers = HeaderMap::new();
        assert_eq!(
            apply_accept_encoding(&mut headers, &cli, &Method::HEAD),
            CompressionMode::Off
        );
        assert!(!headers.contains_key(ACCEPT_ENCODING));

        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("br"));
        assert_eq!(
            apply_accept_encoding(&mut headers, &cli, &Method::GET),
            CompressionMode::Off
        );
        assert_eq!(headers.get(ACCEPT_ENCODING).unwrap(), "br");
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

        let decoded = decode_response_bytes(CompressionMode::Auto, &headers, &body).unwrap();

        assert_eq!(decoded, data);
    }

    #[test]
    fn decodes_brotli_content_encoding() {
        let data = b"this is brotli encoded data";
        let body = brotli_encode(data);
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_ENCODING,
            HeaderValue::from_static("br"),
        );

        let decoded = decode_response_bytes(CompressionMode::Brotli, &headers, &body).unwrap();

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

        let decoded = decode_response_bytes(CompressionMode::Auto, &headers, &body).unwrap();

        assert_eq!(decoded, data);
    }

    #[test]
    fn compression_mode_only_decodes_requested_algorithm() {
        let data = b"this is gzip encoded data";
        let body = gzip_encode(data);
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_ENCODING,
            HeaderValue::from_static("gzip"),
        );

        let decoded = decode_response_bytes(CompressionMode::Gzip, &headers, &body).unwrap();
        assert_eq!(decoded, data);

        let decoded = decode_response_bytes(CompressionMode::Brotli, &headers, &body).unwrap();
        assert_eq!(decoded, body);

        let decoded = decode_response_bytes(CompressionMode::Zstd, &headers, &body).unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn leaves_unsupported_stacked_content_encoding_untouched() {
        let body = b"not decoded";
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_ENCODING,
            HeaderValue::from_static("deflate, gzip"),
        );

        let decoded = decode_response_bytes(CompressionMode::Auto, &headers, body).unwrap();

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

        let decoded = decode_response_bytes(CompressionMode::Off, &headers, &body).unwrap();

        assert_eq!(decoded, body);
    }

    #[test]
    fn output_progress_omits_total_for_decoded_content_encoding() {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_ENCODING,
            HeaderValue::from_static("gzip"),
        );

        assert_eq!(
            output_progress_total_bytes(CompressionMode::Auto, &headers, Some(10)),
            None
        );
    }

    #[test]
    fn output_progress_keeps_total_when_written_length_matches_wire_length() {
        let content_length = Some(10);
        assert_eq!(
            output_progress_total_bytes(CompressionMode::Auto, &HeaderMap::new(), content_length),
            content_length
        );

        let mut compressed_headers = HeaderMap::new();
        compressed_headers.insert(
            reqwest::header::CONTENT_ENCODING,
            HeaderValue::from_static("gzip"),
        );
        assert_eq!(
            output_progress_total_bytes(CompressionMode::Off, &compressed_headers, content_length),
            content_length
        );

        let mut unsupported_headers = HeaderMap::new();
        unsupported_headers.insert(
            reqwest::header::CONTENT_ENCODING,
            HeaderValue::from_static("deflate"),
        );
        assert_eq!(
            output_progress_total_bytes(
                CompressionMode::Auto,
                &unsupported_headers,
                content_length
            ),
            content_length
        );
    }

    #[test]
    fn gzip_decoder_errors_are_prefixed() {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_ENCODING,
            HeaderValue::from_static("gzip"),
        );

        let err = decode_response_bytes(CompressionMode::Auto, &headers, b"not gzip").unwrap_err();

        assert!(err.to_string().contains("gzip:"));
    }

    #[test]
    fn brotli_decoder_errors_are_prefixed() {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_ENCODING,
            HeaderValue::from_static("br"),
        );

        let err =
            decode_response_bytes(CompressionMode::Auto, &headers, b"not brotli").unwrap_err();

        assert!(err.to_string().contains("br:"));
    }

    fn gzip_encode(data: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn brotli_encode(data: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::new();
        {
            let mut encoder = brotli::CompressorWriter::new(&mut encoded, 4096, 5, 22);
            encoder.write_all(data).unwrap();
        }
        encoded
    }

    fn zstd_encode(data: &[u8]) -> Vec<u8> {
        zstd::stream::encode_all(data, 0).unwrap()
    }
}
