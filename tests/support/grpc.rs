use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use flate2::Compression;
use flate2::write::GzEncoder;
use prost::Message;
use prost_types::{
    DescriptorProto, EnumDescriptorProto, EnumValueDescriptorProto, FieldDescriptorProto,
    FileDescriptorProto, FileDescriptorSet, MethodDescriptorProto, ServiceDescriptorProto,
    field_descriptor_proto,
};
use tempfile::TempDir;

use super::http::TestRequest;

pub(crate) struct ReflectionGrpcServer {
    pub(crate) url: String,
    pub(crate) ca_cert_path: Option<PathBuf>,
    pub(crate) requests: Arc<Mutex<Vec<TestRequest>>>,
}

impl ReflectionGrpcServer {
    pub(crate) fn requests(&self) -> Vec<TestRequest> {
        self.requests.lock().unwrap().clone()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReflectionBehavior {
    Enabled,
    Disabled,
    ManySmallFrames,
    V1ErrorResponseUnimplemented,
}

pub(crate) fn start_reflection_grpc_h2c_server(enable_reflection: bool) -> ReflectionGrpcServer {
    start_reflection_grpc_h2c_server_with_behavior(if enable_reflection {
        ReflectionBehavior::Enabled
    } else {
        ReflectionBehavior::Disabled
    })
}

pub(crate) fn start_reflection_grpc_h2c_v1_error_response_server() -> ReflectionGrpcServer {
    start_reflection_grpc_h2c_server_with_behavior(ReflectionBehavior::V1ErrorResponseUnimplemented)
}

pub(crate) fn start_reflection_grpc_h2c_many_small_frames_server() -> ReflectionGrpcServer {
    start_reflection_grpc_h2c_server_with_behavior(ReflectionBehavior::ManySmallFrames)
}

pub(crate) fn start_reflection_grpc_h2c_server_with_behavior(
    behavior: ReflectionBehavior,
) -> ReflectionGrpcServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind h2c grpc server");
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let descriptor = reflection_health_descriptor();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured_requests = Arc::clone(&requests);
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let descriptor = descriptor.clone();
                let requests = Arc::clone(&captured_requests);
                tokio::spawn(async move {
                    serve_reflection_h2_connection(stream, descriptor, behavior, requests).await;
                });
            }
        });
    });
    ReflectionGrpcServer {
        url,
        ca_cert_path: None,
        requests,
    }
}

pub(crate) fn start_reflection_grpc_tls_server(enable_reflection: bool) -> ReflectionGrpcServer {
    start_reflection_grpc_tls_server_with_versions(
        enable_reflection,
        &[&rustls::version::TLS13, &rustls::version::TLS12],
    )
}

pub(crate) fn start_reflection_grpc_tls_server_with_versions(
    enable_reflection: bool,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> ReflectionGrpcServer {
    let behavior = if enable_reflection {
        ReflectionBehavior::Enabled
    } else {
        ReflectionBehavior::Disabled
    };
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let certified =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string(), "localhost".to_string()])
            .unwrap();
    let dir = TempDir::new().unwrap().keep();
    let ca_cert_path = dir.join("ca.pem");
    fs::write(&ca_cert_path, certified.cert.pem()).unwrap();
    let cert_der = certified.cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()),
    );
    let mut config = rustls::ServerConfig::builder_with_protocol_versions(versions)
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tls grpc server");
    listener.set_nonblocking(true).unwrap();
    let url = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let descriptor = reflection_health_descriptor();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured_requests = Arc::clone(&requests);
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let descriptor = descriptor.clone();
                let requests = Arc::clone(&captured_requests);
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    serve_reflection_h2_connection(tls, descriptor, behavior, requests).await;
                });
            }
        });
    });
    ReflectionGrpcServer {
        url,
        ca_cert_path: Some(ca_cert_path),
        requests,
    }
}

pub(crate) fn reflection_health_descriptor() -> Vec<u8> {
    let path = write_health_descriptor_set(TempDir::new().unwrap().keep().as_path());
    let fds = fs::read(path).unwrap();
    let set = FileDescriptorSet::decode(fds.as_slice()).unwrap();
    set.file[0].encode_to_vec()
}

async fn serve_reflection_h2_connection<T>(
    stream: T,
    descriptor: Vec<u8>,
    behavior: ReflectionBehavior,
    requests: Arc<Mutex<Vec<TestRequest>>>,
) where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Ok(mut connection) = h2::server::handshake(stream).await else {
        return;
    };
    while let Some(result) = connection.accept().await {
        let Ok((request, respond)) = result else {
            break;
        };
        let descriptor = descriptor.clone();
        let requests = Arc::clone(&requests);
        tokio::spawn(async move {
            handle_reflection_h2_request(request, respond, descriptor, behavior, requests).await;
        });
    }
}

pub(crate) fn start_status_grpc_h2c_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind status grpc server");
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    serve_status_grpc_h2_connection(stream).await;
                });
            }
        });
    });
    url
}

#[cfg(unix)]
pub(crate) fn start_delayed_response_grpc_h2c_server(close_rx: mpsc::Receiver<()>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind delayed grpc server");
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            serve_delayed_response_grpc_h2_connection(stream, close_rx).await;
        });
    });
    url
}

pub(crate) fn start_delayed_bidi_grpc_h2c_server(finish_rx: mpsc::Receiver<()>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind delayed bidi grpc server");
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            serve_delayed_bidi_grpc_h2_connection(stream, finish_rx).await;
        });
    });
    url
}

async fn serve_status_grpc_h2_connection<T>(stream: T)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Ok(mut connection) = h2::server::handshake(stream).await else {
        return;
    };
    while let Some(result) = connection.accept().await {
        let Ok((request, respond)) = result else {
            break;
        };
        tokio::spawn(async move {
            handle_status_grpc_h2_request(request, respond).await;
        });
    }
}

#[cfg(unix)]
async fn serve_delayed_response_grpc_h2_connection<T>(stream: T, close_rx: mpsc::Receiver<()>)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Ok(mut connection) = h2::server::handshake(stream).await else {
        return;
    };
    if let Some(Ok((request, respond))) = connection.accept().await {
        tokio::spawn(async move {
            handle_delayed_response_grpc_h2_request(request, respond, close_rx).await;
        });
    }
    while let Some(result) = connection.accept().await {
        if result.is_err() {
            break;
        }
    }
}

async fn serve_delayed_bidi_grpc_h2_connection<T>(stream: T, finish_rx: mpsc::Receiver<()>)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Ok(mut connection) = h2::server::handshake(stream).await else {
        return;
    };
    if let Some(Ok((request, respond))) = connection.accept().await {
        tokio::spawn(async move {
            handle_delayed_bidi_grpc_h2_request(request, respond, finish_rx).await;
        });
    }
    while let Some(result) = connection.accept().await {
        if result.is_err() {
            break;
        }
    }
}

async fn handle_status_grpc_h2_request(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
) {
    let path = request.uri().path().to_string();
    let mut body = request.into_body();
    while let Some(chunk) = body.data().await {
        if chunk.is_err() {
            return;
        }
    }

    let (payload, status, message) = match path.as_str() {
        "/test.Stream/Events" => {
            let mut frames = grpc_frame(&proto_field_string(1, "first"));
            frames.extend(grpc_frame(&proto_field_string(1, "second")));
            (frames, "0", "")
        }
        "/test.Status/Denied" => (Vec::new(), "7", "permission%20denied"),
        _ => (Vec::new(), "12", "unimplemented"),
    };

    let Ok(response) = http::Response::builder()
        .status(200)
        .header("content-type", "application/grpc+proto")
        .body(())
    else {
        return;
    };
    let Ok(mut send) = respond.send_response(response, false) else {
        return;
    };
    if !payload.is_empty() && send.send_data(bytes::Bytes::from(payload), false).is_err() {
        return;
    }
    let mut trailers = http::HeaderMap::new();
    trailers.insert("grpc-status", http::HeaderValue::from_static(status));
    if !message.is_empty() {
        trailers.insert("grpc-message", http::HeaderValue::from_static(message));
    }
    let _ = send.send_trailers(trailers);
}

#[cfg(unix)]
async fn handle_delayed_response_grpc_h2_request(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    close_rx: mpsc::Receiver<()>,
) {
    let mut body = request.into_body();
    while let Some(chunk) = body.data().await {
        if chunk.is_err() {
            return;
        }
    }

    let Ok(response) = http::Response::builder()
        .status(200)
        .header("content-type", "application/grpc+proto")
        .body(())
    else {
        return;
    };
    let Ok(mut send) = respond.send_response(response, false) else {
        return;
    };
    if send
        .send_data(
            bytes::Bytes::from(grpc_frame(&proto_field_varint(1, 1))),
            false,
        )
        .is_err()
    {
        return;
    }
    wait_for_test_signal(close_rx, Duration::from_secs(5)).await;
    if send
        .send_data(
            bytes::Bytes::from(grpc_frame(&proto_field_varint(1, 2))),
            false,
        )
        .is_err()
    {
        return;
    }
    send_ok_grpc_trailers(send);
}

async fn handle_delayed_bidi_grpc_h2_request(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    finish_rx: mpsc::Receiver<()>,
) {
    let mut body = request.into_body();
    let mut pending = Vec::new();
    while !has_complete_grpc_frame(&pending) {
        match body.data().await {
            Some(Ok(chunk)) => pending.extend_from_slice(&chunk),
            Some(Err(_)) | None => return,
        }
    }

    let Ok(response) = http::Response::builder()
        .status(200)
        .header("content-type", "application/grpc+proto")
        .body(())
    else {
        return;
    };
    let Ok(mut send) = respond.send_response(response, false) else {
        return;
    };
    if send
        .send_data(
            bytes::Bytes::from(grpc_frame(&proto_field_varint(1, 1))),
            false,
        )
        .is_err()
    {
        return;
    }
    wait_for_test_signal(finish_rx, Duration::from_secs(5)).await;
    while let Some(chunk) = body.data().await {
        if chunk.is_err() {
            return;
        }
    }
    send_ok_grpc_trailers(send);
}

pub(crate) fn has_complete_grpc_frame(bytes: &[u8]) -> bool {
    if bytes.len() < 5 {
        return false;
    }
    let len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
    bytes.len() >= 5 + len
}

pub(crate) fn send_ok_grpc_trailers(mut send: h2::SendStream<bytes::Bytes>) {
    let mut trailers = http::HeaderMap::new();
    trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
    let _ = send.send_trailers(trailers);
}

async fn wait_for_test_signal(rx: mpsc::Receiver<()>, timeout: Duration) {
    let _ = tokio::task::spawn_blocking(move || rx.recv_timeout(timeout)).await;
}

async fn handle_reflection_h2_request(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    descriptor: Vec<u8>,
    behavior: ReflectionBehavior,
    requests: Arc<Mutex<Vec<TestRequest>>>,
) {
    let (parts, mut body) = request.into_parts();
    let path = parts.uri.path().to_string();
    let request_path = parts
        .uri
        .path_and_query()
        .map(|path| path.as_str())
        .unwrap_or("/")
        .to_string();
    let mut headers = HashMap::new();
    let mut header_lines = Vec::new();
    let mut current_name = None;
    for (name, value) in parts.headers {
        if let Some(name) = name {
            current_name = Some(name.as_str().to_ascii_lowercase());
        }
        if let Some(name) = &current_name
            && let Ok(value) = value.to_str()
        {
            let value = value.to_string();
            header_lines.push((name.clone(), value.clone()));
            headers.insert(name.clone(), value);
        }
    }
    let mut raw = Vec::new();
    while let Some(chunk) = body.data().await {
        let Ok(chunk) = chunk else {
            return;
        };
        raw.extend_from_slice(&chunk);
    }
    requests.lock().unwrap().push(TestRequest {
        method: parts.method.to_string(),
        path: request_path,
        headers,
        header_lines,
        body: raw.clone(),
    });
    let (headers, payload) = match path.as_str() {
        "/grpc.health.v1.Health/Check" => (
            vec![("content-type", "application/grpc+proto")],
            Some(grpc_frame(&proto_field_varint(1, 1))),
        ),
        "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"
        | "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo" => {
            if behavior == ReflectionBehavior::Disabled {
                (
                    vec![
                        ("content-type", "application/grpc+proto"),
                        ("grpc-status", "12"),
                        ("grpc-message", "reflection disabled"),
                    ],
                    None,
                )
            } else if behavior == ReflectionBehavior::V1ErrorResponseUnimplemented
                && path == "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"
            {
                (
                    vec![("content-type", "application/grpc+proto")],
                    Some(grpc_frame(&reflection_error_response(
                        12,
                        "reflection v1 unavailable",
                    ))),
                )
            } else if behavior == ReflectionBehavior::ManySmallFrames {
                match reflection_response_for_request(&raw, &descriptor) {
                    Ok(payload) => {
                        let mut frames = Vec::new();
                        for _ in 0..129 {
                            frames.extend(grpc_frame(&payload));
                        }
                        (
                            vec![("content-type", "application/grpc+proto")],
                            Some(frames),
                        )
                    }
                    Err(_) => (
                        vec![
                            ("content-type", "application/grpc+proto"),
                            ("grpc-status", "5"),
                            ("grpc-message", "symbol not found"),
                        ],
                        None,
                    ),
                }
            } else {
                match reflection_response_for_request(&raw, &descriptor) {
                    Ok(payload) => (
                        vec![("content-type", "application/grpc+proto")],
                        Some(grpc_frame(&payload)),
                    ),
                    Err(_) => (
                        vec![
                            ("content-type", "application/grpc+proto"),
                            ("grpc-status", "5"),
                            ("grpc-message", "symbol not found"),
                        ],
                        None,
                    ),
                }
            }
        }
        _ => (
            vec![
                ("content-type", "application/grpc+proto"),
                ("grpc-status", "12"),
                ("grpc-message", "unimplemented"),
            ],
            None,
        ),
    };
    let mut builder = http::Response::builder().status(200);
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    let Ok(response) = builder.body(()) else {
        return;
    };
    let Ok(mut send) = respond.send_response(response, payload.is_none()) else {
        return;
    };
    if let Some(payload) = payload {
        let _ = send.send_data(bytes::Bytes::from(payload), true);
    }
}

pub(crate) fn reflection_response_for_request(
    raw_frame: &[u8],
    descriptor: &[u8],
) -> Result<Vec<u8>, String> {
    if raw_frame.len() < 5 {
        return Err("invalid reflection request".to_string());
    }
    let len = u32::from_be_bytes([raw_frame[1], raw_frame[2], raw_frame[3], raw_frame[4]]) as usize;
    if raw_frame.len() < 5 + len {
        return Err("invalid reflection request".to_string());
    }
    let raw = &raw_frame[5..5 + len];
    if raw.windows(3).any(|w| w == b"\x3a\x01*") {
        let service = proto_field_string(1, "grpc.health.v1.Health");
        let list = proto_field_bytes(1, &service);
        return Ok(proto_field_bytes(6, &list));
    }
    for symbol in [
        "grpc.health.v1.Health",
        "grpc.health.v1.Health.Check",
        "grpc.health.v1.HealthCheckRequest",
        "grpc.health.v1.HealthCheckResponse",
    ] {
        let needle = proto_field_string(4, symbol);
        if raw.windows(needle.len()).any(|w| w == needle.as_slice()) {
            let fd_resp = proto_field_bytes(1, descriptor);
            return Ok(proto_field_bytes(4, &fd_resp));
        }
    }
    Err("symbol not found".to_string())
}

pub(crate) fn reflection_error_response(code: u64, message: &str) -> Vec<u8> {
    let mut error = proto_field_varint(1, code);
    error.extend(proto_field_string(2, message));
    proto_field_bytes(7, &error)
}

pub(crate) fn grpc_frame(payload: &[u8]) -> Vec<u8> {
    grpc_frame_with_flag(payload, false)
}

pub(crate) fn grpc_frame_with_flag(payload: &[u8], compressed: bool) -> Vec<u8> {
    let mut out = vec![u8::from(compressed); 5 + payload.len()];
    out[1..5].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    out[5..].copy_from_slice(payload);
    out
}

pub(crate) fn gzip_bytes(payload: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(payload).unwrap();
    encoder.finish().unwrap()
}

pub(crate) fn proto_field_string(field: u64, value: &str) -> Vec<u8> {
    proto_field_bytes(field, value.as_bytes())
}

pub(crate) fn proto_field_bytes(field: u64, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(proto_varint((field << 3) | 2));
    out.extend(proto_varint(value.len() as u64));
    out.extend_from_slice(value);
    out
}

pub(crate) fn proto_field_varint(field: u64, value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(proto_varint(field << 3));
    out.extend(proto_varint(value));
    out
}

pub(crate) fn proto_varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

pub(crate) fn write_health_descriptor_set(dir: &Path) -> PathBuf {
    let str_type = field_descriptor_proto::Type::String as i32;
    let enum_type = field_descriptor_proto::Type::Enum as i32;
    let fds = FileDescriptorSet {
        file: vec![FileDescriptorProto {
            name: Some("grpc/health/v1/health.proto".to_string()),
            package: Some("grpc.health.v1".to_string()),
            syntax: Some("proto3".to_string()),
            message_type: vec![
                DescriptorProto {
                    name: Some("HealthCheckRequest".to_string()),
                    field: vec![FieldDescriptorProto {
                        name: Some("service".to_string()),
                        number: Some(1),
                        r#type: Some(str_type),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                DescriptorProto {
                    name: Some("HealthCheckResponse".to_string()),
                    field: vec![FieldDescriptorProto {
                        name: Some("status".to_string()),
                        number: Some(1),
                        r#type: Some(enum_type),
                        type_name: Some(
                            ".grpc.health.v1.HealthCheckResponse.ServingStatus".to_string(),
                        ),
                        ..Default::default()
                    }],
                    enum_type: vec![EnumDescriptorProto {
                        name: Some("ServingStatus".to_string()),
                        value: vec![
                            EnumValueDescriptorProto {
                                name: Some("UNKNOWN".to_string()),
                                number: Some(0),
                                ..Default::default()
                            },
                            EnumValueDescriptorProto {
                                name: Some("SERVING".to_string()),
                                number: Some(1),
                                ..Default::default()
                            },
                        ],
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ],
            service: vec![ServiceDescriptorProto {
                name: Some("Health".to_string()),
                method: vec![MethodDescriptorProto {
                    name: Some("Check".to_string()),
                    input_type: Some(".grpc.health.v1.HealthCheckRequest".to_string()),
                    output_type: Some(".grpc.health.v1.HealthCheckResponse".to_string()),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    let path = dir.join("grpc-health.pb");
    fs::write(&path, fds.encode_to_vec()).unwrap();
    path
}

pub(crate) fn write_stream_descriptor_set(dir: &Path) -> PathBuf {
    let str_type = field_descriptor_proto::Type::String as i32;
    let int64_type = field_descriptor_proto::Type::Int64 as i32;
    let fds = FileDescriptorSet {
        file: vec![FileDescriptorProto {
            name: Some("stream.proto".to_string()),
            package: Some("streampkg".to_string()),
            syntax: Some("proto3".to_string()),
            message_type: vec![
                DescriptorProto {
                    name: Some("StreamRequest".to_string()),
                    field: vec![FieldDescriptorProto {
                        name: Some("value".to_string()),
                        number: Some(1),
                        r#type: Some(str_type),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                DescriptorProto {
                    name: Some("StreamResponse".to_string()),
                    field: vec![FieldDescriptorProto {
                        name: Some("count".to_string()),
                        number: Some(1),
                        r#type: Some(int64_type),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ],
            service: vec![ServiceDescriptorProto {
                name: Some("StreamService".to_string()),
                method: vec![
                    MethodDescriptorProto {
                        name: Some("ClientStream".to_string()),
                        input_type: Some(".streampkg.StreamRequest".to_string()),
                        output_type: Some(".streampkg.StreamResponse".to_string()),
                        client_streaming: Some(true),
                        ..Default::default()
                    },
                    MethodDescriptorProto {
                        name: Some("ServerStream".to_string()),
                        input_type: Some(".streampkg.StreamRequest".to_string()),
                        output_type: Some(".streampkg.StreamResponse".to_string()),
                        server_streaming: Some(true),
                        ..Default::default()
                    },
                    MethodDescriptorProto {
                        name: Some("Bidi".to_string()),
                        input_type: Some(".streampkg.StreamRequest".to_string()),
                        output_type: Some(".streampkg.StreamResponse".to_string()),
                        client_streaming: Some(true),
                        server_streaming: Some(true),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    let path = dir.join("stream.pb");
    fs::write(&path, fds.encode_to_vec()).unwrap();
    path
}
