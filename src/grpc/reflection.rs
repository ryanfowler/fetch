use std::time::Instant;

use http_body_util::BodyExt;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, USER_AGENT};
use reqwest::{Client, StatusCode};
use url::Url;

use crate::cli::Cli;
use crate::core;
use crate::error::FetchError;
use crate::grpc::framing;
use crate::grpc::status;
use crate::proto::Schema;

const REFLECTION_V1_PATH: &str = "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo";
const REFLECTION_V1ALPHA_PATH: &str =
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo";
const REFLECTION_PROTOCOLS: [&str; 2] = [REFLECTION_V1_PATH, REFLECTION_V1ALPHA_PATH];

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
        .map(|seconds| crate::http::duration_from_seconds("timeout", seconds))
        .transpose()?;
    let connect_timeout = cli
        .connect_timeout
        .map(|seconds| crate::http::duration_from_seconds("connect-timeout", seconds))
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
        for service in list_services(cli, &url, &client).await? {
            println!("{service}");
        }
        return Ok(0);
    }

    let Some(symbol) = cli.grpc_describe.as_deref() else {
        return Err("gRPC discovery requires --grpc-list or --grpc-describe".into());
    };
    let schema =
        schema_for_symbol(cli, &url, &client, &normalize_reflection_symbol(symbol)).await?;
    print!("{}", crate::proto::describe_symbol(&schema, symbol)?);
    Ok(0)
}

pub async fn schema_for_call(cli: &Cli, url: &Url, client: &Client) -> Result<Schema, FetchError> {
    let service = service_from_path(url.path())?;
    schema_for_symbol(cli, url, client, service).await
}

async fn list_services(cli: &Cli, url: &Url, client: &Client) -> Result<Vec<String>, FetchError> {
    let mut last_unimplemented = None;
    for (index, path) in REFLECTION_PROTOCOLS.iter().enumerate() {
        match invoke(cli, url, client, path, build_reflection_list_request()).await {
            Ok(frames) => {
                let Some(first) = frames.first() else {
                    return Err(reflection_unavailable("empty reflection response"));
                };
                let mut names = parse_reflection_list_response(first)
                    .map_err(|err| reflection_unavailable(&err.to_string()))?;
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
    for (index, path) in REFLECTION_PROTOCOLS.iter().enumerate() {
        match invoke(
            cli,
            url,
            client,
            path,
            build_reflection_symbol_request(symbol),
        )
        .await
        {
            Ok(frames) => {
                let mut files = Vec::new();
                for frame in frames {
                    let mut descriptors = parse_reflection_file_descriptor_response(&frame)
                        .map_err(|err| reflection_unavailable(&err.to_string()))?;
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

    let response = client
        .post(url)
        .headers(reflection_headers(cli)?)
        .body(request_body)
        .send()
        .await?;
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
    let response: http::Response<reqwest::Body> = response.into();
    let (out, trailers) = read_reflection_frames(response.into_body()).await?;
    if let Some(grpc_status) =
        grpc_status_from_headers(&trailers).or_else(|| grpc_status_from_headers(&headers))
    {
        return Err(grpc_status.to_string().into());
    }

    Ok(out)
}

async fn read_reflection_frames(
    mut body: reqwest::Body,
) -> Result<(Vec<Vec<u8>>, HeaderMap), FetchError> {
    let mut decoder = framing::FrameDecoder::new();
    let mut out = Vec::new();
    let mut trailers = HeaderMap::new();

    while let Some(frame) = body.frame().await {
        let frame = frame?;
        match frame.into_data() {
            Ok(data) => {
                for frame in decoder
                    .push(&data)
                    .map_err(|err| FetchError::Message(err.to_string()))?
                {
                    if frame.compressed {
                        return Err("compressed gRPC messages are not supported".into());
                    }
                    out.push(frame.data);
                }
            }
            Err(frame) => {
                if let Ok(frame_trailers) = frame.into_trailers() {
                    trailers = frame_trailers;
                }
            }
        }
    }

    decoder
        .finish()
        .map_err(|err| FetchError::Message(err.to_string()))?;
    Ok((out, trailers))
}

fn reflection_headers(cli: &Cli) -> Result<HeaderMap, FetchError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        USER_AGENT,
        HeaderValue::from_str(&core::user_agent()).expect("valid user agent"),
    );
    headers.insert(ACCEPT, HeaderValue::from_static("application/grpc+proto"));
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/grpc+proto"),
    );
    headers.insert(
        HeaderName::from_static("te"),
        HeaderValue::from_static("trailers"),
    );
    for raw in &cli.headers {
        let Some((name, value)) = raw.split_once(':') else {
            return Err(format!("invalid header {raw:?}: expected name:value").into());
        };
        let name = HeaderName::from_bytes(name.trim().as_bytes())
            .map_err(|err| FetchError::Message(format!("invalid header name {name:?}: {err}")))?;
        let value = HeaderValue::from_str(value.trim()).map_err(|err| {
            FetchError::Message(format!("invalid header value for {}: {err}", name.as_str()))
        })?;
        headers.append(name, value);
    }
    if let Some(auth) = crate::http::basic_header(cli.basic.as_deref())? {
        headers.insert(
            reqwest::header::AUTHORIZATION,
            HeaderValue::from_str(&auth)
                .map_err(|err| FetchError::Message(format!("invalid auth header: {err}")))?,
        );
    }
    if let Some(token) = cli.bearer.as_deref() {
        headers.insert(
            reqwest::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|err| FetchError::Message(format!("invalid bearer token: {err}")))?,
        );
    }
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
                return Err(WireError(parse_reflection_error(&read_bytes(&mut raw)?)));
            }
            _ => skip_value(wire, &mut raw)?,
        }
    }
    names.ok_or_else(|| WireError("missing list services response".to_string()))
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
    Err(WireError(
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
                return Err(WireError(parse_reflection_error(&read_bytes(&mut raw)?)));
            }
            _ => skip_value(wire, &mut raw)?,
        }
    }
    files.ok_or_else(|| WireError("missing file descriptor response".to_string()))
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

fn parse_reflection_error(raw: &[u8]) -> String {
    let mut raw = raw;
    let mut message = None;
    while !raw.is_empty() {
        let Ok((field, wire)) = read_key(&mut raw) else {
            break;
        };
        if field == 2 && wire == WIRE_BYTES {
            message = read_string(&mut raw).ok();
        } else if skip_value(wire, &mut raw).is_err() {
            break;
        }
    }
    message.unwrap_or_else(|| "reflection request failed".to_string())
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
    let symbol = symbol.trim_start_matches('/');
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
    err.to_string().contains("UNIMPLEMENTED")
}

fn grpc_status_from_headers(headers: &HeaderMap) -> Option<status::Status> {
    let grpc_status = headers.get("grpc-status")?.to_str().ok()?;
    if grpc_status == "0" {
        return None;
    }
    let message = headers
        .get("grpc-message")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    Some(status::parse_status(grpc_status, message))
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
            return Err(WireError("unexpected EOF while reading varint".to_string()));
        };
        *raw = rest;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(WireError("varint overflows uint64".to_string()))
}

fn read_bytes(raw: &mut &[u8]) -> Result<Vec<u8>, WireError> {
    let len = read_varint(raw)? as usize;
    if raw.len() < len {
        return Err(WireError("unexpected EOF while reading bytes".to_string()));
    }
    let out = raw[..len].to_vec();
    *raw = &raw[len..];
    Ok(out)
}

fn read_string(raw: &mut &[u8]) -> Result<String, WireError> {
    String::from_utf8(read_bytes(raw)?).map_err(|err| WireError(format!("invalid UTF-8: {err}")))
}

fn skip_value(wire: u8, raw: &mut &[u8]) -> Result<(), WireError> {
    match wire {
        WIRE_VARINT => {
            read_varint(raw)?;
        }
        WIRE_64BIT => skip(raw, 8)?,
        WIRE_BYTES => {
            let len = read_varint(raw)? as usize;
            skip(raw, len)?;
        }
        WIRE_32BIT => skip(raw, 4)?,
        _ => return Err(WireError(format!("unsupported wire type {wire}"))),
    }
    Ok(())
}

fn skip(raw: &mut &[u8], len: usize) -> Result<(), WireError> {
    if raw.len() < len {
        return Err(WireError("unexpected EOF while skipping field".to_string()));
    }
    *raw = &raw[len..];
    Ok(())
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
struct WireError(String);

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
    fn normalize_reflection_symbol_replaces_method_slash() {
        assert_eq!(
            normalize_reflection_symbol("grpc.health.v1.Health/Check"),
            "grpc.health.v1.Health.Check"
        );
    }

    #[tokio::test]
    async fn reflection_reader_rejects_oversized_message_from_header() {
        let body =
            reqwest::Body::wrap_stream(futures_util::stream::iter([Ok::<_, std::io::Error>(
                bytes::Bytes::from_static(&[0x00, 0x04, 0x00, 0x00, 0x01]),
            )]));

        let err = read_reflection_frames(body).await.unwrap_err();

        assert!(err.to_string().contains("gRPC message too large"));
    }
}
