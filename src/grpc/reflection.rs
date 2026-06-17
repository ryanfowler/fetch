use std::time::Instant;

use http::StatusCode;
use http::header::{HeaderMap, HeaderValue, USER_AGENT};
use url::Url;

use crate::cli::Cli;
use crate::core;
use crate::duration::duration_from_seconds;
use crate::error::FetchError;
use crate::grpc::body;
use crate::grpc::encoding::MessageEncoding;
use crate::grpc::framing;
use crate::grpc::headers as grpc_headers;
use crate::grpc::status;
use crate::http::transport::Client;
use crate::http::{RequestBodyPayload, apply_aws_sigv4, aws_config};
use crate::proto::Schema;

const REFLECTION_V1_PATH: &str = "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo";
const REFLECTION_V1ALPHA_PATH: &str =
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo";
const REFLECTION_PROTOCOLS: [&str; 2] = [REFLECTION_V1_PATH, REFLECTION_V1ALPHA_PATH];
const MAX_REFLECTION_RESPONSE_MESSAGES: usize = 128;
const MAX_REFLECTION_RESPONSE_BYTES: usize = framing::MAX_MESSAGE_SIZE;
const REFLECTION_RESPONSE_LIMITS: body::FramedBodyLimits = body::FramedBodyLimits::new(
    "gRPC reflection response",
    MAX_REFLECTION_RESPONSE_MESSAGES,
    MAX_REFLECTION_RESPONSE_BYTES,
);

pub async fn execute_discovery(cli: &Cli) -> Result<i32, FetchError> {
    if cli.has_proto_schema() {
        return crate::proto::execute_local_discovery(cli);
    }

    let raw_url = cli.url.as_deref().ok_or_else(|| {
        FetchError::Message(
            "gRPC reflection is unavailable; provide --proto-file or --proto-desc".to_string(),
        )
    })?;
    let url = crate::http::normalize_url(raw_url)?;
    let session = crate::http::load_session(cli)?;
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
    let connect_timing = crate::http::client::ConnectionTiming::default();
    let client_build = crate::http::client::ClientBuildContext {
        mode: crate::http::client::ClientMode::GrpcReflection,
        request_timeout,
        connect_timeout,
        request_start,
        session: session.as_ref(),
        connect_timing: Some(&connect_timing),
    };
    let client = crate::http::client::build_client_for_url(cli, &url, &client_build)
        .await?
        .client;

    if cli.grpc_list {
        core::write_stdout(service_list_output(
            Box::pin(list_services(cli, &url, &client)).await?,
        ))?;
        return Ok(0);
    }

    let Some(symbol) = cli.grpc_describe.as_deref() else {
        return Err("gRPC discovery requires --grpc-list or --grpc-describe".into());
    };
    let symbol = normalize_reflection_symbol(symbol);
    let schema = Box::pin(schema_for_symbol(cli, &url, &client, &symbol)).await?;
    core::write_stdout(crate::proto::describe_symbol(&schema, &symbol)?)?;
    Ok(0)
}

fn service_list_output(services: Vec<String>) -> String {
    let mut output = String::new();
    for service in services {
        output.push_str(&service);
        output.push('\n');
    }
    output
}

pub async fn schema_for_call(cli: &Cli, url: &Url, client: &Client) -> Result<Schema, FetchError> {
    let service = service_from_path(url.path())?;
    Box::pin(schema_for_symbol(cli, url, client, service)).await
}

async fn list_services(cli: &Cli, url: &Url, client: &Client) -> Result<Vec<String>, FetchError> {
    let mut last_unimplemented = None;
    for (index, path) in REFLECTION_PROTOCOLS.iter().enumerate() {
        match Box::pin(invoke(
            cli,
            url,
            client,
            path,
            build_reflection_list_request(),
        ))
        .await
        {
            Ok(frames) => {
                let Some(first) = frames.first() else {
                    return Err(reflection_unavailable("empty reflection response"));
                };
                let mut names = match parse_reflection_list_response(first) {
                    Ok(names) => names,
                    Err(err) if index == 0 && err.is_unimplemented_reflection_error() => {
                        last_unimplemented = Some(err.to_string());
                        continue;
                    }
                    Err(err) => return Err(reflection_unavailable(&err.to_string())),
                };
                names.sort();
                return Ok(names);
            }
            Err(err) if index == 0 && is_unimplemented_error(&err) => {
                last_unimplemented = Some(err.to_string());
            }
            Err(err) => return Err(reflection_unavailable(&err.to_string())),
        }
    }
    Err(reflection_unavailable(
        last_unimplemented
            .as_deref()
            .unwrap_or("reflection request failed"),
    ))
}

async fn schema_for_symbol(
    cli: &Cli,
    url: &Url,
    client: &Client,
    symbol: &str,
) -> Result<Schema, FetchError> {
    let mut last_unimplemented = None;
    'protocols: for (index, path) in REFLECTION_PROTOCOLS.iter().enumerate() {
        match Box::pin(invoke(
            cli,
            url,
            client,
            path,
            build_reflection_symbol_request(symbol),
        ))
        .await
        {
            Ok(frames) => {
                let mut files = Vec::new();
                for frame in frames {
                    let mut descriptors = match parse_reflection_file_descriptor_response(&frame) {
                        Ok(descriptors) => descriptors,
                        Err(err) if index == 0 && err.is_unimplemented_reflection_error() => {
                            last_unimplemented = Some(err.to_string());
                            continue 'protocols;
                        }
                        Err(err) => return Err(reflection_unavailable(&err.to_string())),
                    };
                    files.append(&mut descriptors);
                }
                return Schema::from_file_descriptor_protos(&files)
                    .map_err(|err| reflection_unavailable(&err.to_string()));
            }
            Err(err) if index == 0 && is_unimplemented_error(&err) => {
                last_unimplemented = Some(err.to_string());
            }
            Err(err) => return Err(reflection_unavailable(&err.to_string())),
        }
    }
    Err(reflection_unavailable(
        last_unimplemented
            .as_deref()
            .unwrap_or("reflection request failed"),
    ))
}

async fn invoke(
    cli: &Cli,
    base_url: &Url,
    client: &Client,
    path: &str,
    payload: Vec<u8>,
) -> Result<Vec<Vec<u8>>, FetchError> {
    let mut url = base_url.clone();
    url.set_path(path);
    url.set_query(None);
    url.set_fragment(None);
    let request_body =
        framing::frame(&payload, false).map_err(|err| FetchError::Message(err.to_string()))?;

    let headers = reflection_headers(cli, &url, &request_body)?;
    let response = Box::pin(client.post(url).headers(headers).body(request_body).send()).await?;
    let status_code = response.status();
    if status_code != StatusCode::OK {
        return Err(format!(
            "unexpected HTTP status: {} {}",
            status_code.as_u16(),
            status_code.canonical_reason().unwrap_or("")
        )
        .into());
    }

    let headers = response.headers().clone();
    let message_encoding = MessageEncoding::from_headers(&headers);
    let (response_body, body_deadline) = response.into_body_with_deadline();
    let body = body::read_framed_body_with_deadline_and_limits(
        response_body,
        &message_encoding,
        body_deadline,
        Some(REFLECTION_RESPONSE_LIMITS),
    )
    .await?;
    if let Some(grpc_status) = status::from_headers_or_trailers(&headers, &body.trailers)
        && !grpc_status.ok()
    {
        return Err(grpc_status.to_string().into());
    }

    Ok(body.messages)
}

fn reflection_headers(cli: &Cli, url: &Url, request_body: &[u8]) -> Result<HeaderMap, FetchError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        USER_AGENT,
        HeaderValue::from_str(&core::user_agent()).expect("valid user agent"),
    );
    crate::http::apply_headers(&mut headers, &cli.headers)?;
    grpc_headers::apply_standard_headers(&mut headers);
    if let Some(config) = aws_config(cli.aws_sigv4.as_deref())? {
        let signed_body = Some(RequestBodyPayload::from_bytes(request_body.to_vec(), None));
        apply_aws_sigv4(cli, "POST", url, &mut headers, &signed_body, &config)?;
    }
    crate::http::apply_builder_authorization_headers(&mut headers, cli, None)?;
    Ok(headers)
}

fn build_reflection_list_request() -> Vec<u8> {
    let mut data = Vec::new();
    append_string(&mut data, 7, "*");
    data
}

fn build_reflection_symbol_request(symbol: &str) -> Vec<u8> {
    let mut data = Vec::new();
    append_string(&mut data, 4, symbol);
    data
}

fn parse_reflection_list_response(raw: &[u8]) -> Result<Vec<String>, WireError> {
    let mut raw = raw;
    let mut names = None;
    while !raw.is_empty() {
        let (field, wire) = read_key(&mut raw)?;
        match (field, wire) {
            (6, WIRE_BYTES) => names = Some(parse_reflection_service_list(&read_bytes(&mut raw)?)?),
            (7, WIRE_BYTES) => {
                return Err(WireError::reflection(parse_reflection_error(&read_bytes(
                    &mut raw,
                )?)));
            }
            _ => skip_value(wire, &mut raw)?,
        }
    }
    names.ok_or_else(|| WireError::message("missing list services response".to_string()))
}

fn parse_reflection_service_list(raw: &[u8]) -> Result<Vec<String>, WireError> {
    let mut raw = raw;
    let mut names = Vec::new();
    while !raw.is_empty() {
        let (field, wire) = read_key(&mut raw)?;
        if field == 1 && wire == WIRE_BYTES {
            names.push(parse_reflection_service_name(&read_bytes(&mut raw)?)?);
        } else {
            skip_value(wire, &mut raw)?;
        }
    }
    Ok(names)
}

fn parse_reflection_service_name(raw: &[u8]) -> Result<String, WireError> {
    let mut raw = raw;
    while !raw.is_empty() {
        let (field, wire) = read_key(&mut raw)?;
        if field == 1 && wire == WIRE_BYTES {
            return read_string(&mut raw);
        }
        skip_value(wire, &mut raw)?;
    }
    Err(WireError::message(
        "reflection service response missing service name".to_string(),
    ))
}

fn parse_reflection_file_descriptor_response(raw: &[u8]) -> Result<Vec<Vec<u8>>, WireError> {
    let mut raw = raw;
    let mut files = None;
    while !raw.is_empty() {
        let (field, wire) = read_key(&mut raw)?;
        match (field, wire) {
            (4, WIRE_BYTES) => {
                files = Some(parse_reflection_descriptor_list(&read_bytes(&mut raw)?)?)
            }
            (7, WIRE_BYTES) => {
                return Err(WireError::reflection(parse_reflection_error(&read_bytes(
                    &mut raw,
                )?)));
            }
            _ => skip_value(wire, &mut raw)?,
        }
    }
    files.ok_or_else(|| WireError::message("missing file descriptor response".to_string()))
}

fn parse_reflection_descriptor_list(raw: &[u8]) -> Result<Vec<Vec<u8>>, WireError> {
    let mut raw = raw;
    let mut files = Vec::new();
    while !raw.is_empty() {
        let (field, wire) = read_key(&mut raw)?;
        if field == 1 && wire == WIRE_BYTES {
            files.push(read_bytes(&mut raw)?);
        } else {
            skip_value(wire, &mut raw)?;
        }
    }
    Ok(files)
}

fn parse_reflection_error(raw: &[u8]) -> ReflectionErrorResponse {
    let mut raw = raw;
    let mut code = None;
    let mut message = None;
    while !raw.is_empty() {
        let Ok((field, wire)) = read_key(&mut raw) else {
            break;
        };
        match (field, wire) {
            (1, WIRE_VARINT) => {
                let Ok(raw_code) = read_varint(&mut raw) else {
                    break;
                };
                if raw_code <= i32::MAX as u64 {
                    code = Some(status::Code(raw_code as i32));
                }
            }
            (2, WIRE_BYTES) => message = read_string(&mut raw).ok(),
            _ => {
                if skip_value(wire, &mut raw).is_err() {
                    break;
                }
            }
        }
    }
    ReflectionErrorResponse {
        code,
        message: message.unwrap_or_default(),
    }
}

fn service_from_path(path: &str) -> Result<&str, FetchError> {
    let path = path.trim_start_matches('/');
    let Some((service, method)) = path.rsplit_once('/') else {
        return Err("invalid gRPC path: expected '/Service/Method' format".into());
    };
    if service.is_empty() || method.is_empty() {
        return Err("invalid gRPC path: service and method cannot be empty".into());
    }
    Ok(service)
}

fn normalize_reflection_symbol(symbol: &str) -> String {
    let symbol = crate::proto::normalize_symbol_name(symbol);
    if let Some((service, method)) = symbol.rsplit_once('/') {
        format!("{service}.{method}")
    } else {
        symbol.to_string()
    }
}

fn reflection_unavailable(reason: &str) -> FetchError {
    FetchError::Message(format!(
        "gRPC reflection is unavailable: {reason}. Provide --proto-file or --proto-desc"
    ))
}

fn is_unimplemented_error(err: &FetchError) -> bool {
    contains_unimplemented(&err.to_string())
}

fn contains_unimplemented(message: &str) -> bool {
    message.to_ascii_lowercase().contains("unimplemented")
}

const WIRE_VARINT: u8 = 0;
const WIRE_64BIT: u8 = 1;
const WIRE_BYTES: u8 = 2;
const WIRE_32BIT: u8 = 5;

fn append_string(out: &mut Vec<u8>, field: u64, value: &str) {
    append_bytes(out, field, value.as_bytes());
}

fn append_bytes(out: &mut Vec<u8>, field: u64, value: &[u8]) {
    append_key(out, field, WIRE_BYTES);
    append_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

fn append_key(out: &mut Vec<u8>, field: u64, wire: u8) {
    append_varint(out, (field << 3) | u64::from(wire));
}

fn append_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn read_key(raw: &mut &[u8]) -> Result<(u64, u8), WireError> {
    let key = read_varint(raw)?;
    Ok((key >> 3, (key & 0x07) as u8))
}

fn read_varint(raw: &mut &[u8]) -> Result<u64, WireError> {
    let mut value = 0_u64;
    for shift in (0..64).step_by(7) {
        let Some((&byte, rest)) = raw.split_first() else {
            return Err(WireError::message(
                "unexpected EOF while reading varint".to_string(),
            ));
        };
        *raw = rest;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(WireError::message("varint overflows uint64".to_string()))
}

fn read_bytes(raw: &mut &[u8]) -> Result<Vec<u8>, WireError> {
    let len = read_len(raw, "unexpected EOF while reading bytes")?;
    let out = raw[..len].to_vec();
    *raw = &raw[len..];
    Ok(out)
}

fn read_len(raw: &mut &[u8], eof_message: &'static str) -> Result<usize, WireError> {
    let len = read_varint(raw)?;
    if len > raw.len() as u64 {
        return Err(WireError::message(eof_message.to_string()));
    }
    Ok(len as usize)
}

fn read_string(raw: &mut &[u8]) -> Result<String, WireError> {
    String::from_utf8(read_bytes(raw)?)
        .map_err(|err| WireError::message(format!("invalid UTF-8: {err}")))
}

fn skip_value(wire: u8, raw: &mut &[u8]) -> Result<(), WireError> {
    match wire {
        WIRE_VARINT => {
            read_varint(raw)?;
        }
        WIRE_64BIT => skip(raw, 8)?,
        WIRE_BYTES => {
            let len = read_len(raw, "unexpected EOF while skipping field")?;
            skip(raw, len)?;
        }
        WIRE_32BIT => skip(raw, 4)?,
        _ => return Err(WireError::message(format!("unsupported wire type {wire}"))),
    }
    Ok(())
}

fn skip(raw: &mut &[u8], len: usize) -> Result<(), WireError> {
    if raw.len() < len {
        return Err(WireError::message(
            "unexpected EOF while skipping field".to_string(),
        ));
    }
    *raw = &raw[len..];
    Ok(())
}

#[derive(Debug, Clone)]
struct ReflectionErrorResponse {
    code: Option<status::Code>,
    message: String,
}

impl ReflectionErrorResponse {
    fn is_unimplemented(&self) -> bool {
        self.code == Some(status::Code::UNIMPLEMENTED) || contains_unimplemented(&self.message)
    }

    fn display_message(&self) -> String {
        if !self.message.is_empty() {
            self.message.clone()
        } else if let Some(code) = self.code {
            format!("reflection request failed: {code}")
        } else {
            "reflection request failed".to_string()
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
struct WireError {
    message: String,
    reflection_error: Option<ReflectionErrorResponse>,
}

impl WireError {
    fn message(message: String) -> Self {
        Self {
            message,
            reflection_error: None,
        }
    }

    fn reflection(error: ReflectionErrorResponse) -> Self {
        Self {
            message: error.display_message(),
            reflection_error: Some(error),
        }
    }

    fn is_unimplemented_reflection_error(&self) -> bool {
        self.reflection_error
            .as_ref()
            .is_some_and(ReflectionErrorResponse::is_unimplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reflection_list_request_matches_go_shape() {
        assert_eq!(build_reflection_list_request(), b"\x3a\x01*");
    }

    #[test]
    fn reflection_symbol_request_matches_go_shape() {
        assert_eq!(
            build_reflection_symbol_request("pkg.Service"),
            b"\x22\x0bpkg.Service"
        );
    }

    #[test]
    fn parses_reflection_list_response() {
        let mut service = Vec::new();
        append_string(&mut service, 1, "grpc.health.v1.Health");
        let mut list = Vec::new();
        append_bytes(&mut list, 1, &service);
        let mut response = Vec::new();
        append_bytes(&mut response, 6, &list);

        let services = parse_reflection_list_response(&response).unwrap();

        assert_eq!(services, ["grpc.health.v1.Health"]);
    }

    #[test]
    fn parses_reflection_error_responses() {
        let mut error = Vec::new();
        append_string(&mut error, 2, "symbol missing");
        let mut response = Vec::new();
        append_bytes(&mut response, 7, &error);

        let list_err = parse_reflection_list_response(&response).unwrap_err();
        assert_eq!(list_err.to_string(), "symbol missing");

        let file_err = parse_reflection_file_descriptor_response(&response).unwrap_err();
        assert_eq!(file_err.to_string(), "symbol missing");
    }

    #[test]
    fn recognizes_unimplemented_reflection_error_responses() {
        let mut error = Vec::new();
        append_key(&mut error, 1, WIRE_VARINT);
        append_varint(&mut error, status::Code::UNIMPLEMENTED.0 as u64);
        append_string(&mut error, 2, "reflection v1 disabled");
        let mut response = Vec::new();
        append_bytes(&mut response, 7, &error);

        let err = parse_reflection_list_response(&response).unwrap_err();
        assert!(err.is_unimplemented_reflection_error());
        assert_eq!(err.to_string(), "reflection v1 disabled");

        let mut error = Vec::new();
        append_string(&mut error, 2, "server reflection API is unimplemented");
        let mut response = Vec::new();
        append_bytes(&mut response, 7, &error);

        let err = parse_reflection_file_descriptor_response(&response).unwrap_err();
        assert!(err.is_unimplemented_reflection_error());
    }

    #[test]
    fn parses_reflection_descriptor_lists_and_missing_fields() {
        let mut descriptors = Vec::new();
        append_bytes(&mut descriptors, 1, b"first descriptor");
        append_bytes(&mut descriptors, 1, b"second descriptor");
        let mut response = Vec::new();
        append_bytes(&mut response, 4, &descriptors);

        let files = parse_reflection_file_descriptor_response(&response).unwrap();
        assert_eq!(
            files,
            [b"first descriptor".to_vec(), b"second descriptor".to_vec()]
        );

        assert!(parse_reflection_list_response(&[]).is_err());
        assert!(parse_reflection_file_descriptor_response(&[]).is_err());
    }

    #[test]
    fn rejects_oversized_reflection_wire_lengths_before_casting() {
        let oversized = u64::from(u32::MAX) + 1;

        let mut bytes_field = Vec::new();
        append_varint(&mut bytes_field, oversized);
        let mut raw = bytes_field.as_slice();
        let err = read_bytes(&mut raw).unwrap_err();
        assert_eq!(err.to_string(), "unexpected EOF while reading bytes");

        let mut skipped_field = Vec::new();
        append_varint(&mut skipped_field, oversized);
        let mut raw = skipped_field.as_slice();
        let err = skip_value(WIRE_BYTES, &mut raw).unwrap_err();
        assert_eq!(err.to_string(), "unexpected EOF while skipping field");
    }

    #[test]
    fn normalize_reflection_symbol_replaces_method_slash() {
        assert_eq!(
            normalize_reflection_symbol("grpc.health.v1.Health/Check"),
            "grpc.health.v1.Health.Check"
        );
    }

    #[test]
    fn normalize_reflection_symbol_trims_leading_dot() {
        assert_eq!(normalize_reflection_symbol(".pkg.Service"), "pkg.Service");
        assert_eq!(
            normalize_reflection_symbol(".pkg.Service.Method"),
            "pkg.Service.Method"
        );
        assert_eq!(
            normalize_reflection_symbol(".pkg.Service/Method"),
            "pkg.Service.Method"
        );
    }
}
