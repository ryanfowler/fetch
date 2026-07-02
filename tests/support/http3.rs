use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use bytes::Buf;
use tempfile::TempDir;

impl H3Request {
    pub(crate) fn header(&self, name: &str) -> String {
        self.headers
            .get(&name.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn body_string(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

impl H3Response {
    pub(crate) fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            body: body.into(),
            body_delay: None,
            trailers: Vec::new(),
        }
    }

    pub(crate) fn status(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.into(),
            body_delay: None,
            trailers: Vec::new(),
        }
    }

    pub(crate) fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub(crate) fn delay_body(mut self, delay: Duration) -> Self {
        self.body_delay = Some(delay);
        self
    }

    pub(crate) fn trailer(mut self, name: &str, value: &str) -> Self {
        self.trailers.push((name.to_string(), value.to_string()));
        self
    }
}

impl H3TestServer {
    pub(crate) fn requests(&self) -> Vec<H3Request> {
        self.requests.lock().unwrap().clone()
    }

    pub(crate) fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct H3Request {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) query: String,
    pub(crate) headers: HashMap<String, String>,
    pub(crate) body: Vec<u8>,
}

pub(crate) struct H3Response {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
    pub(crate) body_delay: Option<Duration>,
    pub(crate) trailers: Vec<(String, String)>,
}

pub(crate) struct H3TestServer {
    pub(crate) url: String,
    pub(crate) ca_cert_path: PathBuf,
    pub(crate) requests: Arc<Mutex<Vec<H3Request>>>,
    request_notify: mpsc::Receiver<()>,
    pub(crate) connections: Arc<AtomicUsize>,
}

pub(crate) fn wait_for_h3_requests(server: &H3TestServer, count: usize) -> Vec<H3Request> {
    let start = Instant::now();
    while server.requests().len() < count {
        let remaining = Duration::from_secs(3).saturating_sub(start.elapsed());
        if remaining.is_zero() {
            let requests = server.requests();
            panic!(
                "timed out waiting for {count} HTTP/3 requests; got {}",
                requests.len()
            );
        }
        let _ = server.request_notify.recv_timeout(remaining);
    }
    server.requests()
}

pub(crate) fn start_http3_server(
    handler: impl Fn(H3Request) -> H3Response + Send + Sync + 'static,
) -> H3TestServer {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let certified =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string(), "localhost".to_string()])
            .unwrap();
    let dir = TempDir::new().unwrap().keep();
    let ca_cert_path = dir.join("h3-ca.pem");
    fs::write(&ca_cert_path, certified.cert.pem()).unwrap();

    let cert_der = certified.cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()),
    );
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto).unwrap(),
    ));
    let handler = Arc::new(handler);
    let requests = Arc::new(Mutex::new(Vec::new()));
    let connections = Arc::new(AtomicUsize::new(0));
    let requests_for_thread = Arc::clone(&requests);
    let connections_for_thread = Arc::clone(&connections);
    let (addr_tx, addr_rx) = mpsc::channel();
    let (notify_tx, notify_rx) = mpsc::channel();
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let endpoint = quinn::Endpoint::server(
                server_config,
                "127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap(),
            )
            .unwrap();
            let _ = addr_tx.send(endpoint.local_addr().unwrap());
            while let Some(incoming) = endpoint.accept().await {
                let handler = Arc::clone(&handler);
                let requests = Arc::clone(&requests_for_thread);
                let connections = Arc::clone(&connections_for_thread);
                let notify = notify_tx.clone();
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    connections.fetch_add(1, Ordering::SeqCst);
                    let conn = h3_quinn::Connection::new(connection);
                    let Ok(mut h3_conn) = h3::server::builder().build(conn).await else {
                        return;
                    };
                    loop {
                        let resolver = match h3_conn.accept().await {
                            Ok(Some(resolver)) => resolver,
                            Ok(None) | Err(_) => break,
                        };
                        let handler = Arc::clone(&handler);
                        let requests = Arc::clone(&requests);
                        let notify = notify.clone();
                        tokio::spawn(async move {
                            let Ok((req, mut stream)) = resolver.resolve_request().await else {
                                return;
                            };
                            let mut body = Vec::new();
                            loop {
                                match stream.recv_data().await {
                                    Ok(Some(mut chunk)) => {
                                        while chunk.has_remaining() {
                                            let bytes = chunk.copy_to_bytes(chunk.remaining());
                                            body.extend_from_slice(&bytes);
                                        }
                                    }
                                    Ok(None) => break,
                                    Err(_) => return,
                                }
                            }
                            let path = req.uri().path().to_string();
                            let query = req.uri().query().unwrap_or_default().to_string();
                            let headers = req
                                .headers()
                                .iter()
                                .map(|(name, value)| {
                                    (
                                        name.as_str().to_ascii_lowercase(),
                                        value.to_str().unwrap_or_default().to_string(),
                                    )
                                })
                                .collect::<HashMap<_, _>>();
                            let h3_req = H3Request {
                                method: req.method().as_str().to_string(),
                                path,
                                query,
                                headers,
                                body,
                            };
                            requests.lock().unwrap().push(h3_req.clone());
                            let _ = notify.send(());
                            let response = handler(h3_req);
                            let mut builder = http::Response::builder().status(response.status);
                            for (name, value) in response.headers {
                                builder = builder.header(name, value);
                            }
                            let Ok(resp) = builder.body(()) else {
                                return;
                            };
                            if stream.send_response(resp).await.is_err() {
                                return;
                            }
                            if let Some(delay) = response.body_delay {
                                tokio::time::sleep(delay).await;
                            }
                            if !response.body.is_empty()
                                && stream
                                    .send_data(bytes::Bytes::from(response.body))
                                    .await
                                    .is_err()
                            {
                                return;
                            }
                            if !response.trailers.is_empty() {
                                let mut trailers = http::HeaderMap::new();
                                for (name, value) in response.trailers {
                                    let Ok(name) = http::HeaderName::from_bytes(name.as_bytes())
                                    else {
                                        return;
                                    };
                                    let Ok(value) = http::HeaderValue::from_str(&value) else {
                                        return;
                                    };
                                    trailers.insert(name, value);
                                }
                                if stream.send_trailers(trailers).await.is_err() {
                                    return;
                                }
                            }
                            let _ = stream.finish().await;
                        });
                    }
                });
            }
        });
    });
    let addr = addr_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let url = format!("https://127.0.0.1:{}", addr.port());

    H3TestServer {
        url,
        ca_cert_path,
        requests,
        request_notify: notify_rx,
        connections,
    }
}
