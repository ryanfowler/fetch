use std::fs;
use std::io::{BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use tempfile::TempDir;

use super::http::{TestRequest, TestResponse, read_request, write_response};

pub(crate) struct HttpsProxyTestServer {
    pub(crate) url: String,
    pub(crate) ca_cert_path: PathBuf,
    pub(crate) client_cert_path: PathBuf,
    pub(crate) client_key_path: PathBuf,
    pub(crate) requests: Arc<Mutex<Vec<TestRequest>>>,
    pub(crate) shutdown: Option<mpsc::Sender<()>>,
    pub(crate) join: Option<thread::JoinHandle<()>>,
}

impl HttpsProxyTestServer {
    pub(crate) fn requests(&self) -> Vec<TestRequest> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for HttpsProxyTestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

pub(crate) fn start_socks5_proxy(target_addr: String) -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind socks proxy");
    let proxy_url = format!("socks5://{}", listener.local_addr().unwrap());
    let (seen_tx, seen_rx) = mpsc::channel();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(conn) = conn else {
                break;
            };
            let target_addr = target_addr.clone();
            let seen_tx = seen_tx.clone();
            thread::spawn(move || handle_socks5_conn(conn, &target_addr, seen_tx));
        }
    });
    (proxy_url, seen_rx)
}

pub(crate) fn handle_socks5_conn(
    mut conn: TcpStream,
    target_addr: &str,
    seen: mpsc::Sender<String>,
) {
    let mut header = [0_u8; 2];
    if conn.read_exact(&mut header).is_err() || header[0] != 0x05 {
        return;
    }
    let mut methods = vec![0; header[1] as usize];
    if conn.read_exact(&mut methods).is_err() || conn.write_all(&[0x05, 0x00]).is_err() {
        return;
    }
    let mut req = [0_u8; 4];
    if conn.read_exact(&mut req).is_err() || req[0] != 0x05 || req[1] != 0x01 {
        let _ = conn.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        return;
    }
    let host = match req[3] {
        0x01 => {
            let mut raw = [0_u8; 4];
            if conn.read_exact(&mut raw).is_err() {
                return;
            }
            Ipv4Addr::from(raw).to_string()
        }
        0x03 => {
            let mut len = [0_u8; 1];
            if conn.read_exact(&mut len).is_err() {
                return;
            }
            let mut raw = vec![0; len[0] as usize];
            if conn.read_exact(&mut raw).is_err() {
                return;
            }
            String::from_utf8_lossy(&raw).into_owned()
        }
        _ => return,
    };
    let mut port = [0_u8; 2];
    if conn.read_exact(&mut port).is_err() {
        return;
    }
    let connect_target = format!("{host}:{}", u16::from_be_bytes(port));
    let _ = seen.send(connect_target);
    let Ok(mut target) = TcpStream::connect(target_addr) else {
        let _ = conn.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        return;
    };
    if conn
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .is_err()
    {
        return;
    }
    let mut conn_to_target = conn.try_clone().ok();
    let mut target_to_conn = target.try_clone().ok();
    if let (Some(mut c), Some(mut t)) = (conn_to_target.take(), target_to_conn.take()) {
        thread::spawn(move || {
            let _ = std::io::copy(&mut c, &mut t);
        });
    }
    let _ = std::io::copy(&mut target, &mut conn);
}

pub(crate) fn start_http_connect_proxy(target_addr: String) -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind HTTP CONNECT proxy");
    let proxy_url = format!("http://{}", listener.local_addr().unwrap());
    let (seen_tx, seen_rx) = mpsc::channel();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(conn) = conn else {
                break;
            };
            let target_addr = target_addr.clone();
            let seen_tx = seen_tx.clone();
            thread::spawn(move || handle_http_connect_proxy_conn(conn, &target_addr, seen_tx));
        }
    });
    (proxy_url, seen_rx)
}

pub(crate) fn start_https_proxy(require_client_auth: bool) -> HttpsProxyTestServer {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let dir = TempDir::new().unwrap().keep();

    let ca_key =
        rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
            .unwrap();
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Proxy Test CA");
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
        .push(rcgen::DnType::CommonName, "proxy");
    server_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_params.signed_by(&server_key, &ca_issuer).unwrap();

    let client_key =
        rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
            .unwrap();
    let mut client_params =
        rcgen::CertificateParams::new(vec!["proxy-client".to_string()]).unwrap();
    client_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "proxy-client");
    client_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = client_params.signed_by(&client_key, &ca_issuer).unwrap();

    let ca_cert_path = dir.join("proxy-ca.crt");
    let client_cert_path = dir.join("proxy-client.crt");
    let client_key_path = dir.join("proxy-client.key");
    fs::write(&ca_cert_path, ca_cert.pem()).unwrap();
    fs::write(&client_cert_path, client_cert.pem()).unwrap();
    fs::write(&client_key_path, client_key.serialize_pem()).unwrap();

    let server_key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()),
    );
    let builder = rustls::ServerConfig::builder();
    let builder = if require_client_auth {
        let mut client_roots = rustls::RootCertStore::empty();
        client_roots.add(ca_cert.der().clone()).unwrap();
        let client_verifier = rustls::server::WebPkiClientVerifier::builder(client_roots.into())
            .build()
            .unwrap();
        builder.with_client_cert_verifier(client_verifier)
    } else {
        builder.with_no_client_auth()
    };
    let mut config = builder
        .with_single_cert(vec![server_cert.der().clone()], server_key_der)
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let config = Arc::new(config);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind HTTPS proxy");
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("https://localhost:{port}");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = Arc::clone(&requests);
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
                    let requests = Arc::clone(&requests_for_thread);
                    thread::spawn(move || {
                        let Ok(conn) = rustls::ServerConnection::new(config) else {
                            return;
                        };
                        let mut tls = rustls::StreamOwned::new(conn, stream);
                        let mut reader = BufReader::new(&mut tls);
                        let Some(req) = read_request(&mut reader) else {
                            return;
                        };
                        requests.lock().unwrap().push(req);
                        let tls = reader.into_inner();
                        write_response(tls, TestResponse::ok("proxied"));
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    HttpsProxyTestServer {
        url,
        ca_cert_path,
        client_cert_path,
        client_key_path,
        requests,
        shutdown: Some(tx),
        join: Some(join),
    }
}

pub(crate) fn start_stalling_proxy(scheme: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stalling proxy");
    let proxy_url = format!("{scheme}://{}", listener.local_addr().unwrap());
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else {
                break;
            };
            thread::spawn(move || {
                let _ = conn.set_read_timeout(Some(Duration::from_millis(200)));
                let mut buf = [0_u8; 1024];
                let _ = conn.read(&mut buf);
                thread::sleep(Duration::from_secs(3));
            });
        }
    });
    proxy_url
}

pub(crate) fn handle_http_connect_proxy_conn(
    mut conn: TcpStream,
    target_addr: &str,
    seen: mpsc::Sender<String>,
) {
    let mut reader = BufReader::new(conn.try_clone().expect("clone proxy stream"));
    let Some(req) = read_request(&mut reader) else {
        return;
    };
    if req.method != "CONNECT" {
        write_response(
            &mut conn,
            TestResponse::status(405, "Method Not Allowed", ""),
        );
        return;
    }
    let _ = seen.send(req.path);
    let Ok(mut target) = TcpStream::connect(target_addr) else {
        write_response(&mut conn, TestResponse::status(502, "Bad Gateway", ""));
        return;
    };
    if conn
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
        return;
    }
    let mut conn_to_target = conn.try_clone().ok();
    let mut target_to_conn = target.try_clone().ok();
    if let (Some(mut c), Some(mut t)) = (conn_to_target.take(), target_to_conn.take()) {
        thread::spawn(move || {
            let _ = std::io::copy(&mut c, &mut t);
        });
    }
    let _ = std::io::copy(&mut target, &mut conn);
}

pub(crate) fn assert_socks_seen(seen: &mpsc::Receiver<String>, want: &str) {
    let got = seen
        .recv_timeout(Duration::from_secs(2))
        .expect("SOCKS proxy was not used");
    assert_eq!(got, want);
}

pub(crate) fn assert_proxy_seen(seen: &mpsc::Receiver<String>, want: &str) {
    let got = seen
        .recv_timeout(Duration::from_secs(2))
        .expect("proxy was not used");
    assert_eq!(got, want);
}
