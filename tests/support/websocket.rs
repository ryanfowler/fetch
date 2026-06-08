use std::fs;
use std::io::{BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use base64::Engine;
use sha1::{Digest as Sha1Digest, Sha1};
use tempfile::TempDir;

use super::http::{TestRequest, TestResponse, read_request, write_response};
use super::tls::TlsTestServer;

pub(crate) fn start_ws_echo_server(
    validate: impl Fn(&TestRequest) -> Result<(), String> + Send + Sync + 'static,
) -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind websocket server");
    listener.set_nonblocking(true).unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let validate = Arc::new(validate);
    let (seen_tx, seen_rx) = mpsc::channel();
    thread::spawn(move || {
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let validate = Arc::clone(&validate);
                    let seen_tx = seen_tx.clone();
                    thread::spawn(move || {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut reader = BufReader::new(stream.try_clone().unwrap());
                        let Some(req) = read_request(&mut reader) else {
                            return;
                        };
                        if let Err(err) = validate(&req) {
                            write_response(
                                &mut stream,
                                TestResponse::status(400, "Bad Request", err),
                            );
                            return;
                        }
                        let key = req.header("sec-websocket-key");
                        let mut sha = Sha1::new();
                        sha.update(key.as_bytes());
                        sha.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
                        let accept =
                            base64::engine::general_purpose::STANDARD.encode(sha.finalize());
                        let response = format!(
                            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
                        );
                        if stream.write_all(response.as_bytes()).is_err() {
                            return;
                        }
                        let msg = read_ws_text(&mut stream);
                        let _ = seen_tx.send(msg.clone());
                        let reply = if msg.trim().starts_with('{') {
                            msg
                        } else {
                            format!("echo: {msg}")
                        };
                        let _ = stream.write_all(&ws_text_frame(reply.as_bytes()));
                        write_ws_close_and_drain(&mut stream, b"done");
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    (url, seen_rx)
}

pub(crate) fn start_wss_echo_server(
    validate: impl Fn(&TestRequest) -> Result<(), String> + Send + Sync + 'static,
) -> (TlsTestServer, mpsc::Receiver<String>) {
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
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind wss websocket server");
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("wss://localhost:{port}");
    let validate = Arc::new(validate);
    let (seen_tx, seen_rx) = mpsc::channel();
    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    let join = thread::spawn(move || {
        loop {
            if shutdown_rx.try_recv().is_ok() {
                break;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let config = Arc::clone(&config);
                    let validate = Arc::clone(&validate);
                    let seen_tx = seen_tx.clone();
                    thread::spawn(move || {
                        let Ok(conn) = rustls::ServerConnection::new(config) else {
                            return;
                        };
                        let mut tls = rustls::StreamOwned::new(conn, stream);
                        let _ = tls.sock.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut reader = BufReader::new(&mut tls);
                        let Some(req) = read_request(&mut reader) else {
                            return;
                        };
                        if let Err(err) = validate(&req) {
                            write_response(
                                reader.into_inner(),
                                TestResponse::status(400, "Bad Request", err),
                            );
                            return;
                        }
                        let key = req.header("sec-websocket-key");
                        let mut sha = Sha1::new();
                        sha.update(key.as_bytes());
                        sha.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
                        let accept =
                            base64::engine::general_purpose::STANDARD.encode(sha.finalize());
                        let response = format!(
                            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
                        );
                        let tls = reader.into_inner();
                        if tls.write_all(response.as_bytes()).is_err() {
                            return;
                        }
                        let msg = read_ws_text(tls);
                        let _ = seen_tx.send(msg.clone());
                        let reply = if msg.trim().starts_with('{') {
                            msg
                        } else {
                            format!("echo: {msg}")
                        };
                        let _ = tls.write_all(&ws_text_frame(reply.as_bytes()));
                        write_ws_close_and_drain(tls, b"done");
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    (
        TlsTestServer {
            url,
            ca_cert_path,
            shutdown: Some(shutdown_tx),
            join: Some(join),
        },
        seen_rx,
    )
}

pub(crate) fn start_ws_multi_echo_server(messages: usize) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind websocket server");
    listener.set_nonblocking(true).unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    thread::spawn(move || {
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    thread::spawn(move || {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut reader = BufReader::new(stream.try_clone().unwrap());
                        let Some(req) = read_request(&mut reader) else {
                            return;
                        };
                        let key = req.header("sec-websocket-key");
                        let mut sha = Sha1::new();
                        sha.update(key.as_bytes());
                        sha.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
                        let accept =
                            base64::engine::general_purpose::STANDARD.encode(sha.finalize());
                        let response = format!(
                            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
                        );
                        if stream.write_all(response.as_bytes()).is_err() {
                            return;
                        }
                        for _ in 0..messages {
                            let Some(msg) = read_ws_text_frame(&mut stream) else {
                                return;
                            };
                            let _ = stream.write_all(&ws_text_frame(msg.as_bytes()));
                        }
                        write_ws_close_and_drain(&mut stream, b"done");
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    url
}

pub(crate) fn start_ws_push_server(
    validate: impl Fn(&TestRequest) -> Result<(), String> + Send + Sync + 'static,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind websocket push server");
    listener.set_nonblocking(true).unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let validate = Arc::new(validate);
    thread::spawn(move || {
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let validate = Arc::clone(&validate);
                    thread::spawn(move || {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut reader = BufReader::new(stream.try_clone().unwrap());
                        let Some(req) = read_request(&mut reader) else {
                            return;
                        };
                        if let Err(err) = validate(&req) {
                            write_response(
                                &mut stream,
                                TestResponse::status(400, "Bad Request", err),
                            );
                            return;
                        }
                        let key = req.header("sec-websocket-key");
                        let mut sha = Sha1::new();
                        sha.update(key.as_bytes());
                        sha.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
                        let accept =
                            base64::engine::general_purpose::STANDARD.encode(sha.finalize());
                        let response = format!(
                            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
                        );
                        if stream.write_all(response.as_bytes()).is_err() {
                            return;
                        }
                        let _ = stream.write_all(&ws_text_frame(br#"{"hello":"websocket"}"#));
                        let _ = stream.write_all(&ws_binary_frame(b"\x00\x01\x02\x03"));
                        let _ = stream.write_all(&ws_text_frame(b"plain text"));
                        write_ws_close_and_drain(&mut stream, b"done");
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    url
}

pub(crate) fn start_ws_hold_open_push_server(
    message: impl Into<Vec<u8>>,
) -> (String, mpsc::Sender<()>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind websocket hold-open server");
    listener.set_nonblocking(true).unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let message = message.into();
    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    let join = thread::spawn(move || {
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return,
            }
        };
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let Some(req) = read_request(&mut reader) else {
            return;
        };
        let key = req.header("sec-websocket-key");
        let mut sha = Sha1::new();
        sha.update(key.as_bytes());
        sha.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        let accept = base64::engine::general_purpose::STANDARD.encode(sha.finalize());
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        if stream.write_all(response.as_bytes()).is_err() {
            return;
        }
        if stream
            .write_all(&ws_text_frame(&message))
            .and_then(|()| stream.flush())
            .is_err()
        {
            return;
        }
        loop {
            match shutdown_rx.try_recv() {
                Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
                Err(mpsc::TryRecvError::Empty) => thread::sleep(Duration::from_millis(10)),
            }
        }
        let _ = stream.write_all(&ws_close_frame(b"done"));
    });
    (url, shutdown_tx, join)
}

pub(crate) fn read_ws_text(reader: &mut impl Read) -> String {
    read_ws_text_frame(reader).unwrap_or_default()
}

pub(crate) fn read_ws_text_frame(reader: &mut impl Read) -> Option<String> {
    let (_opcode, payload) = read_ws_frame(reader)?;
    Some(String::from_utf8_lossy(&payload).into_owned())
}

pub(crate) fn read_ws_frame(reader: &mut impl Read) -> Option<(u8, Vec<u8>)> {
    let mut header = [0_u8; 2];
    if reader.read_exact(&mut header).is_err() {
        return None;
    }
    let opcode = header[0] & 0x0f;
    let masked = header[1] & 0x80 != 0;
    let mut len = (header[1] & 0x7f) as usize;
    if len == 126 {
        let mut raw = [0_u8; 2];
        if reader.read_exact(&mut raw).is_err() {
            return None;
        }
        len = u16::from_be_bytes(raw) as usize;
    } else if len == 127 {
        let mut raw = [0_u8; 8];
        if reader.read_exact(&mut raw).is_err() {
            return None;
        }
        len = usize::try_from(u64::from_be_bytes(raw)).ok()?;
    }
    let mut mask = [0_u8; 4];
    if masked && reader.read_exact(&mut mask).is_err() {
        return None;
    }
    let mut payload = vec![0; len];
    if reader.read_exact(&mut payload).is_err() {
        return None;
    }
    if masked {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[i % 4];
        }
    }
    if opcode == 0x8 {
        return None;
    }
    Some((opcode, payload))
}

pub(crate) fn write_ws_close_and_drain<T: Read + Write>(stream: &mut T, reason: &[u8]) {
    let _ = stream.write_all(&ws_close_frame(reason));
    let _ = read_ws_text_frame(stream);
}

pub(crate) fn ws_text_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 10);
    out.push(0x81);
    if payload.len() < 126 {
        out.push(payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        out.push(126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        out.push(127);
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    out.extend_from_slice(payload);
    out
}

pub(crate) fn ws_binary_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 10);
    out.push(0x82);
    if payload.len() < 126 {
        out.push(payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        out.push(126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        out.push(127);
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    out.extend_from_slice(payload);
    out
}

pub(crate) fn ws_close_frame(reason: &[u8]) -> Vec<u8> {
    let mut payload = 1000_u16.to_be_bytes().to_vec();
    payload.extend_from_slice(reason);
    let mut out = vec![0x88, payload.len() as u8];
    out.extend(payload);
    out
}
