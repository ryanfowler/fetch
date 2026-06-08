use std::collections::HashMap;
use std::fs;
use std::io::BufReader;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use tempfile::TempDir;

use super::http::{TestRequest, TestResponse, read_request, write_response};

pub(crate) struct TlsTestServer {
    pub(crate) url: String,
    pub(crate) ca_cert_path: PathBuf,
    pub(crate) shutdown: Option<mpsc::Sender<()>>,
    pub(crate) join: Option<thread::JoinHandle<()>>,
}

pub(crate) struct MtlsTestServer {
    pub(crate) url: String,
    pub(crate) ca_cert_path: PathBuf,
    pub(crate) client_cert_path: PathBuf,
    pub(crate) client_key_path: PathBuf,
    pub(crate) client_combined_path: PathBuf,
    pub(crate) shutdown: Option<mpsc::Sender<()>>,
    pub(crate) join: Option<thread::JoinHandle<()>>,
}

impl Drop for TlsTestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for MtlsTestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

pub(crate) fn start_tls_server(
    handler: impl Fn(TestRequest) -> TestResponse + Send + Sync + 'static,
) -> TlsTestServer {
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
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tls server");
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("https://localhost:{port}");
    let handler = Arc::new(handler);
    let (tx, rx) = mpsc::channel();
    let join = thread::spawn(move || {
        loop {
            if rx.try_recv().is_ok() {
                break;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let config = Arc::clone(&config);
                    let handler = Arc::clone(&handler);
                    thread::spawn(move || {
                        let Ok(conn) = rustls::ServerConnection::new(config) else {
                            return;
                        };
                        let mut tls = rustls::StreamOwned::new(conn, stream);
                        let mut reader = BufReader::new(&mut tls);
                        let Some(req) = read_request(&mut reader) else {
                            return;
                        };
                        let resp = handler(req);
                        let tls = reader.into_inner();
                        write_response(tls, resp);
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    TlsTestServer {
        url,
        ca_cert_path,
        shutdown: Some(tx),
        join: Some(join),
    }
}

pub(crate) fn start_h2_tls_server(
    handler: impl Fn(TestRequest) -> TestResponse + Send + Sync + 'static,
) -> TlsTestServer {
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
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind h2 tls server");
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("https://localhost:{port}");
    let handler: Arc<dyn Fn(TestRequest) -> TestResponse + Send + Sync> = Arc::new(handler);
    let (tx, rx) = mpsc::channel();
    let join = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        loop {
            if rx.try_recv().is_ok() {
                break;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(true);
                    let acceptor = acceptor.clone();
                    let handler = Arc::clone(&handler);
                    runtime.block_on(async move {
                        let Ok(stream) = tokio::net::TcpStream::from_std(stream) else {
                            return;
                        };
                        let Ok(tls) = acceptor.accept(stream).await else {
                            return;
                        };
                        serve_test_h2_connection(tls, handler).await;
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    TlsTestServer {
        url,
        ca_cert_path,
        shutdown: Some(tx),
        join: Some(join),
    }
}

async fn serve_test_h2_connection<T>(
    stream: T,
    handler: Arc<dyn Fn(TestRequest) -> TestResponse + Send + Sync>,
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
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            handle_test_h2_request(request, respond, handler).await;
        });
    }
}

async fn handle_test_h2_request(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    handler: Arc<dyn Fn(TestRequest) -> TestResponse + Send + Sync>,
) {
    let (parts, mut body) = request.into_parts();
    let mut body_bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let Ok(chunk) = chunk else {
            return;
        };
        body_bytes.extend_from_slice(&chunk);
    }
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
    let resp = handler(TestRequest {
        method: parts.method.to_string(),
        path: parts
            .uri
            .path_and_query()
            .map(|path| path.as_str())
            .unwrap_or("/")
            .to_string(),
        headers,
        header_lines,
        body: body_bytes,
    });
    if let Some(reason) = resp.h2_reset {
        respond.send_reset(reason);
        return;
    }
    let mut response_headers = resp.headers;
    if !response_headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-length"))
    {
        response_headers.push(("content-length".to_string(), resp.body.len().to_string()));
    }
    let mut builder = http::Response::builder().status(resp.status);
    for (name, value) in response_headers {
        if name.eq_ignore_ascii_case("connection") || name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        builder = builder.header(name, value);
    }
    let Ok(response) = builder.body(()) else {
        return;
    };
    let body_is_empty = resp.body.is_empty();
    let Ok(mut send) = respond.send_response(response, body_is_empty) else {
        return;
    };
    if !body_is_empty {
        let _ = send.send_data(bytes::Bytes::from(resp.body), true);
    }
}

pub(crate) fn start_mtls_server() -> MtlsTestServer {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let dir = TempDir::new().unwrap().keep();

    let ca_key =
        rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
            .unwrap();
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Test CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);

    let server_key =
        rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
            .unwrap();
    let mut server_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    server_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "server");
    server_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_params.signed_by(&server_key, &ca_issuer).unwrap();

    let client_key =
        rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
            .unwrap();
    let mut client_params = rcgen::CertificateParams::new(vec!["client".to_string()]).unwrap();
    client_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "client");
    client_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = client_params.signed_by(&client_key, &ca_issuer).unwrap();

    let ca_cert_path = dir.join("ca.crt");
    let client_cert_path = dir.join("client.crt");
    let client_key_path = dir.join("client.key");
    let client_combined_path = dir.join("client-combined.pem");
    fs::write(&ca_cert_path, ca_cert.pem()).unwrap();
    fs::write(&client_cert_path, client_cert.pem()).unwrap();
    fs::write(&client_key_path, client_key.serialize_pem()).unwrap();
    fs::write(
        &client_combined_path,
        format!("{}{}", client_cert.pem(), client_key.serialize_pem()),
    )
    .unwrap();

    let mut client_roots = rustls::RootCertStore::empty();
    client_roots.add(ca_cert.der().clone()).unwrap();
    let client_verifier = rustls::server::WebPkiClientVerifier::builder(client_roots.into())
        .build()
        .unwrap();
    let server_key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()),
    );
    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(vec![server_cert.der().clone()], server_key_der)
        .unwrap();
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mtls server");
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("https://localhost:{port}");
    let (tx, rx) = mpsc::channel();
    let join = thread::spawn(move || {
        loop {
            if rx.try_recv().is_ok() {
                break;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let config = Arc::clone(&config);
                    thread::spawn(move || {
                        let Ok(conn) = rustls::ServerConnection::new(config) else {
                            return;
                        };
                        let mut tls = rustls::StreamOwned::new(conn, stream);
                        let mut reader = BufReader::new(&mut tls);
                        let Some(req) = read_request(&mut reader) else {
                            return;
                        };
                        let resp = if req.path == "/" {
                            TestResponse::ok("mtls-success")
                        } else {
                            TestResponse::status(404, "Not Found", "")
                        };
                        let tls = reader.into_inner();
                        write_response(tls, resp);
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    MtlsTestServer {
        url,
        ca_cert_path,
        client_cert_path,
        client_key_path,
        client_combined_path,
        shutdown: Some(tx),
        join: Some(join),
    }
}
