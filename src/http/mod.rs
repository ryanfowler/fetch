use std::error::Error as StdError;
use std::fmt;
use std::io::{ErrorKind, Read, Write};
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
use http::header::{
    ACCEPT, ACCEPT_ENCODING, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HeaderMap,
    HeaderName, HeaderValue, LOCATION, PROXY_AUTHORIZATION, RANGE, RETRY_AFTER, TRANSFER_ENCODING,
    USER_AGENT, WWW_AUTHENTICATE,
};
use http::{Method, StatusCode};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_util::io::{ReaderStream, StreamReader};
use url::Url;

use crate::auth::aws_sigv4;
use crate::auth::digest;
use crate::cli::{Cli, CompressionMode, HttpVersion};
use crate::core;
use crate::duration::{TimeoutBudget, duration_from_seconds, request_timeout_message};
use crate::error::{
    FetchError, write_error_with_color, write_warning_with_color,
    write_warning_with_separator_with_color,
};
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
use crate::grpc::encoding as grpc_encoding;
use crate::grpc::headers as grpc_headers;
use crate::grpc::status as grpc_status;
use crate::http::client::DnsResolution;
use crate::output;
use crate::output::clipboard;
use crate::proto;
use crate::timing::{self, AttemptTiming, DnsTiming, ResponseTiming};

pub(crate) mod client;
mod edit;
mod encoding;
mod http3_cache;
mod metadata;
pub mod multipart;
mod request;
mod response;
mod retry;
pub(crate) mod transport;

pub(crate) use core::color_for_status;
pub(crate) use metadata::{
    apply_headers, apply_query, has_authority_scheme, load_session, normalize_url, request_target,
    save_session, validate_ech_for_url,
};
pub(crate) use request::{
    RequestBody, RequestBodyPayload, apply_aws_sigv4, apply_builder_authorization_headers,
    aws_config, basic_header, request_body, request_body_into_bytes,
    request_body_into_bytes_limited,
};
#[cfg(test)]
pub(crate) use request::{request_body_bytes, request_body_content_len, request_body_preview};
pub(crate) use retry::{is_certificate_validation_message, total_attempts_for_retry};
pub(crate) use transport::{basic_auth_header_value, extract_url_basic_auth};

use encoding::*;
use metadata::*;
use request::*;
use response::*;
use retry::*;
use transport::{Body, Client, RequestBuilder, Response};

type AsyncReadBox = Pin<Box<dyn AsyncRead + Send>>;

pub async fn execute(cli: &Cli) -> Result<i32, FetchError> {
    let http_version = crate::cli::selected_http_version(cli).map_err(FetchError::Message)?;
    let http_version = effective_http_version(cli, http_version);
    let mut url = normalize_url(cli.url.as_deref().expect("URL checked by app"))?;
    apply_query(&mut url, &cli.query);
    client::validate_proxy_for_http_version(cli.proxy.as_deref(), http_version)?;
    validate_http_version_options(http_version, &url, cli.grpc, cli.unix.as_deref())?;
    validate_ech_for_url(cli, &url)?;
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
        .transpose()?
        .flatten();
    let connect_timeout = cli
        .connect_timeout
        .map(|seconds| duration_from_seconds("connect-timeout", seconds))
        .transpose()?
        .flatten();
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
    let mut initial_client = None;
    if cli.grpc && grpc_method.is_none() {
        let reflection_client = client::build_client_for_url(cli, &url, &client_build).await?;
        let request_requires_schema = grpc_request_requires_schema(cli);
        match Box::pin(crate::grpc::reflection::schema_for_call(
            cli,
            &url,
            &reflection_client.client,
        ))
        .await
        {
            Ok(schema) => match proto::method_for_url(&schema, &url) {
                Ok(method) => grpc_method = Some(method),
                Err(err) if request_requires_schema => return Err(err),
                Err(_) => {}
            },
            Err(err) if request_requires_schema => return Err(err),
            Err(_) => {}
        }
        initial_client = Some(reflection_client);
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
        grpc_headers::apply_standard_headers(&mut headers);
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
        print_request_metadata(cli, &method, &url, &dry_run_headers, &body, http_version)?;
        print_dry_run_body(cli, &body)?;
        return Ok(0);
    }

    let initial_client = match initial_client {
        Some(client) => client,
        None => client::build_client_for_url(cli, &url, &client_build).await?,
    };

    let retry_count = cli.retry();
    let retry_delay =
        duration_from_seconds("retry-delay", cli.retry_delay())?.unwrap_or(Duration::ZERO);
    let total_attempts = total_attempts_for_retry(retry_count)?;
    let original_body_replayable = request_body_replayable(&body);
    let mut attempt = 0;
    let result = loop {
        let mut request_method = method.clone();
        let mut request_url = url.clone();
        let mut request_body = body.clone();
        let mut request_client = initial_client.clone();
        let mut redirect_statuses = Vec::new();
        let mut redirect_count = 0_usize;
        let mut protocol_nack_retries = 0_usize;
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
                )?;
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
            let req = apply_request_timeout(req, request_timeout, request_start)?;
            request_client.clear_runtime_dns_resolution();
            connect_timing.clear();
            match req.send().await {
                Ok(response) => {
                    record_request_dns_timing(cli, &request_client, &mut timing);
                    if let Some(redirect) = redirect_target(cli, &response, redirect_count)? {
                        timing.mark_response_headers();
                        timing.set_transport(connect_timing.timing());
                        print_redirect_status(cli, &response);
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
                Err(err) => {
                    if protocol_nack_retries < MAX_PROTOCOL_NACK_RETRIES
                        && is_protocol_nack_error(&err)
                    {
                        ensure_request_body_replayable(&request_body, "protocol retry")?;
                        protocol_nack_retries += 1;
                        continue;
                    }
                    record_request_dns_timing(cli, &request_client, &mut timing);
                    break Err(err);
                }
            }
        };
        match attempt_result {
            Ok(response) => {
                timing.mark_response_headers();
                timing.set_transport(connect_timing.timing());
                if cli.verbose >= 3 && !cli.silent {
                    let dns_resolution = request_client.current_dns_resolution();
                    let connect_target =
                        connect_debug_target(&response, &request_url, dns_resolution.as_ref());
                    timing::print_debug_lines(&timing, &connect_target, cli.color.as_deref());
                }
                let response = apply_digest_challenge(
                    response,
                    DigestRetryContext {
                        client: &request_client.client,
                        client_build: &client_build,
                        method: request_method.clone(),
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
                    if should_retry_sse_without_compression_for_method(&request_method) {
                        ensure_body_replayable(
                            original_body_replayable,
                            "retry SSE without compression",
                        )?;
                        headers.remove(ACCEPT_ENCODING);
                        compression = CompressionMode::Off;
                        drain_response_body_bounded(response).await;
                        continue;
                    }
                    write_warning_before_output(
                        cli,
                        &format!(
                            "not retrying compressed SSE response without compression for {} because the method is not safe; use --compress off to avoid compression on the first request",
                            request_method
                        ),
                    );
                }
                if attempt < retry_count && should_retry_status(status) {
                    ensure_body_replayable(original_body_replayable, "retry")?;
                    let requested_delay =
                        compute_delay(retry_delay, attempt, parse_retry_after(response.headers()));
                    drain_response_body_bounded(response).await;
                    let delay = retry_delay_within_timeout(
                        requested_delay,
                        request_timeout,
                        request_start,
                    )?;
                    print_retry(
                        cli,
                        attempt + 2,
                        total_attempts,
                        delay,
                        &retry_reason(status),
                    );
                    tokio::time::sleep(delay).await;
                    ensure_retry_delay_completed(
                        requested_delay,
                        delay,
                        request_timeout,
                        request_start,
                    )?;
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
                if attempt < retry_count && is_retryable_error(&err) {
                    ensure_body_replayable(original_body_replayable, "retry")?;
                    let requested_delay = compute_delay(retry_delay, attempt, Duration::ZERO);
                    let delay = retry_delay_within_timeout(
                        requested_delay,
                        request_timeout,
                        request_start,
                    )?;
                    print_retry(cli, attempt + 2, total_attempts, delay, &err.to_string());
                    tokio::time::sleep(delay).await;
                    ensure_retry_delay_completed(
                        requested_delay,
                        delay,
                        request_timeout,
                        request_start,
                    )?;
                    attempt += 1;
                    continue;
                }
                if let Some(message) = timeout_error_message(cli, &err) {
                    break Err(FetchError::Runtime(message));
                }
                let mut message = transport_request_error_message(&err);
                append_schemeless_plaintext_hint(&mut message, cli, &url, &request_url, &err);
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

fn record_request_dns_timing(
    cli: &Cli,
    request_client: &client::UrlClient,
    timing: &mut AttemptTiming,
) {
    let dns_resolution = request_client.current_dns_resolution();
    if cli.verbose >= 3
        && !cli.silent
        && let Some(dns) = dns_resolution
            .as_ref()
            .and_then(|resolution| resolution.timing.as_ref())
    {
        print_dns_debug(cli, dns);
    }
    timing.set_dns(
        dns_resolution
            .as_ref()
            .and_then(|resolution| resolution.timing.as_ref())
            .map(|dns| dns.duration),
    );
}
