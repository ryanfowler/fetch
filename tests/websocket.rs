mod support;

use base64::Engine;
use sha1::{Digest as Sha1Digest, Sha1};
use std::fs;
use std::io::{BufReader, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use support::common::{
    FetchOpts, FetchOutput, assert_exit, fetch_bin, run_fetch, run_fetch_once, run_fetch_opts,
    start_read_capture, url_host_port, wait_child,
};
use support::dns::{start_udp_dns_server, start_unresponsive_udp_dns_server};
use support::http::{TestResponse, TestServer, read_request, write_response};
use support::proxy::{
    assert_proxy_seen, assert_socks_seen, start_http_connect_proxy, start_socks5_proxy,
    start_stalling_proxy,
};
#[cfg(unix)]
use support::pty::{configure_pty_child, open_pty, start_pty_capture};
use support::websocket::{
    read_ws_frame, read_ws_text, start_ws_echo_server, start_ws_hold_open_push_server,
    start_ws_multi_echo_server, start_ws_push_server, start_wss_echo_server,
    write_ws_close_and_drain, ws_binary_frame, ws_text_frame,
};
use tempfile::TempDir;
use url::Url;

const WEBSOCKET_RECEIVE_LIMIT_BYTES: usize = 16 * 1024 * 1024;

fn start_ws_frame_server(reply: Vec<u8>) -> (String, mpsc::Receiver<(u8, Vec<u8>)>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind websocket frame server");
    listener.set_nonblocking(true).unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let (seen_tx, seen_rx) = mpsc::channel();
    thread::spawn(move || {
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let reply = reply.clone();
                    let seen_tx = seen_tx.clone();
                    thread::spawn(move || {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut reader = BufReader::new(&mut stream);
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
                        if reader
                            .get_mut()
                            .write_all(response.as_bytes())
                            .and_then(|()| reader.get_mut().flush())
                            .is_err()
                        {
                            return;
                        }
                        if let Some(frame) = read_ws_frame(&mut reader) {
                            let _ = seen_tx.send(frame);
                        }
                        let stream = reader.into_inner();
                        let _ = stream.write_all(&ws_binary_frame(&reply));
                        write_ws_close_and_drain(stream, b"done");
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

fn start_ws_text_push_server(payload: Vec<u8>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind websocket text push server");
    let url = format!("ws://{}", listener.local_addr().unwrap());
    thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
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
        let _ = stream.write_all(&ws_text_frame(&payload));
        write_ws_close_and_drain(&mut stream, b"done");
    });
    url
}

fn start_ws_session_server() -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind websocket session server");
    listener.set_nonblocking(true).unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let (seen_tx, seen_rx) = mpsc::channel();
    thread::spawn(move || {
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let seen_tx = seen_tx.clone();
                    thread::spawn(move || {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut reader = BufReader::new(stream.try_clone().unwrap());
                        let Some(req) = read_request(&mut reader) else {
                            return;
                        };
                        if !req.header("cookie").contains("sid=abc") {
                            write_response(
                                &mut stream,
                                TestResponse::status(401, "Unauthorized", "missing session"),
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
                            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSet-Cookie: wsid=upgraded; Path=/\r\n\r\n"
                        );
                        if stream.write_all(response.as_bytes()).is_err() {
                            return;
                        }
                        let msg = read_ws_text(&mut stream);
                        let _ = seen_tx.send(msg.clone());
                        let _ = stream.write_all(&ws_text_frame(msg.as_bytes()));
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

#[test]
fn websocket_receive_limit_allows_message_just_below_cap() {
    let payload = vec![b'a'; WEBSOCKET_RECEIVE_LIMIT_BYTES - 1];
    let ws_url = start_ws_text_push_server(payload);
    let dir = TempDir::new().unwrap();
    let stdout_path = dir.path().join("websocket-large-message.txt");
    let stdout_file = fs::File::create(&stdout_path).unwrap();
    let mut cmd = Command::new(fetch_bin());
    cmd.args([&ws_url, "--format", "off", "--ws-interactive", "off"]);
    cmd.stdout(Stdio::from(stdout_file)).stderr(Stdio::piped());
    cmd.env("NO_COLOR", "");
    cmd.env("HTTP_PROXY", "");
    cmd.env("HTTPS_PROXY", "");
    cmd.env("ALL_PROXY", "");
    cmd.env("NO_PROXY", "*");

    let output = cmd.output().expect("run websocket receive limit fetch");
    assert!(
        output.status.success(),
        "fetch exited with {}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = fs::read(&stdout_path).unwrap();
    assert_eq!(stdout.len(), WEBSOCKET_RECEIVE_LIMIT_BYTES);
    assert_eq!(stdout.first(), Some(&b'a'));
    assert!(stdout.ends_with(b"a\n"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("exceeds maximum"));
}

#[test]
fn websocket_receive_limit_rejects_message_above_cap() {
    let payload = vec![b'a'; WEBSOCKET_RECEIVE_LIMIT_BYTES + 1];
    let ws_url = start_ws_text_push_server(payload);
    let res = run_fetch(&[&ws_url, "--format", "off", "--ws-interactive", "off"]);

    assert_exit(&res, 1);
    assert!(res.stdout.is_empty(), "stdout len: {}", res.stdout.len());
    assert!(
        res.stderr
            .contains("WebSocket message exceeds maximum of 16777216 bytes"),
        "stderr:\n{}",
        res.stderr
    );
}

#[test]
fn websocket_noninteractive_go_cases() {
    let (ws_url, seen) = start_ws_echo_server(|_| Ok(()));
    let res = run_fetch(&[
        &ws_url,
        "-d",
        "hello websocket",
        "--format",
        "off",
        "--ws-interactive",
        "off",
    ]);
    assert_exit(&res, 0);
    assert_eq!(
        seen.recv_timeout(Duration::from_secs(2)).unwrap(),
        "hello websocket"
    );
    assert!(res.stdout.contains("echo: hello websocket"));

    let res = run_fetch(&[
        &ws_url,
        "-d",
        r#"{"ok":true}"#,
        "--format",
        "on",
        "--ws-interactive",
        "off",
    ]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("\"ok\": true") || res.stdout.contains("{ \"ok\": true }"));

    let stdin_url = start_ws_multi_echo_server(2);
    let res = run_fetch_opts(
        FetchOpts {
            stdin: Some("line1\nline2\n".to_string()),
            ..Default::default()
        },
        &[&stdin_url, "--format", "off", "--ws-interactive", "off"],
    );
    assert_exit(&res, 0);
    assert!(res.stdout.contains("line1"));
    assert!(res.stdout.contains("line2"));

    let empty_line_url = start_ws_multi_echo_server(3);
    let res = run_fetch_opts(
        FetchOpts {
            stdin: Some("line1\n\nline3\n".to_string()),
            ..Default::default()
        },
        &[
            &empty_line_url,
            "--format",
            "off",
            "--ws-interactive",
            "off",
        ],
    );
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "line1\n\nline3\n");

    let (auth_url, auth_seen) = start_ws_echo_server(|req| {
        if req.header("authorization") == "Bearer token" {
            Ok(())
        } else {
            Err("missing auth".to_string())
        }
    });
    let res = run_fetch(&[
        &auth_url,
        "-d",
        "auth",
        "--bearer",
        "token",
        "--format",
        "off",
        "--ws-interactive",
        "off",
    ]);
    assert_exit(&res, 0);
    assert_eq!(
        auth_seen.recv_timeout(Duration::from_secs(2)).unwrap(),
        "auth"
    );

    let res = run_fetch(&[&ws_url, "--grpc"]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("websocket") || res.stderr.contains("grpc"));

    let res = run_fetch(&["--http", "3", "ws://127.0.0.1:1"]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("WebSocket requires HTTP/1.1"));
    assert!(res.stderr.contains("HTTP/3.0 is not supported"));

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind unused websocket port");
    let addr = listener
        .local_addr()
        .expect("unused websocket port local addr");
    drop(listener);
    let refused_url = format!("ws://{addr}");
    let res = run_fetch_once(
        FetchOpts::default(),
        &[&refused_url, "--ws-interactive", "off"],
    );
    assert_exit(&res, 1);
    assert!(
        res.stderr.to_ascii_lowercase().contains("refused"),
        "stderr:\n{}",
        res.stderr
    );
    assert!(!res.stderr.contains("--help"), "stderr:\n{}", res.stderr);

    let res = run_fetch(&[&ws_url, "--method", "POST", "--timing", "--dry-run"]);
    assert_exit(&res, 0);
    assert!(res.stderr.contains("GET / HTTP/1.1"));
    assert!(
        res.stderr.contains(
            "warning: WebSocket requires GET; ignoring method POST\nwarning: --timing is not supported for WebSocket connections\n\n> GET / HTTP/1.1"
        ),
        "{:?}",
        res.stderr
    );

    let res = run_fetch(&[
        &ws_url,
        "--method",
        "POST",
        "-d",
        "warn",
        "--format",
        "off",
        "--ws-interactive",
        "off",
    ]);
    assert_exit(&res, 0);
    assert!(res.stderr.contains("GET") || res.stderr.contains("method"));
}

#[test]
fn websocket_auto_sends_invalid_utf8_body_as_binary_and_writes_binary_stdout() {
    let reply = vec![0, 1, 2, 3];
    let (ws_url, seen) = start_ws_frame_server(reply.clone());
    let dir = TempDir::new().unwrap();
    let body_path = dir.path().join("ws-body.bin");
    let body = vec![0xff, 0, 0xfe];
    fs::write(&body_path, &body).unwrap();
    let body_arg = format!("@{}", body_path.display());

    let mut cmd = Command::new(fetch_bin());
    cmd.args([
        &ws_url,
        "-d",
        &body_arg,
        "--format",
        "off",
        "--ws-interactive",
        "off",
    ]);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.env("NO_COLOR", "");
    cmd.env("HTTP_PROXY", "");
    cmd.env("HTTPS_PROXY", "");
    cmd.env("ALL_PROXY", "");
    cmd.env("NO_PROXY", "*");

    let output = cmd.output().expect("run websocket binary body fetch");
    assert!(
        output.status.success(),
        "fetch exited with {}; stdout: {:?}; stderr: {}",
        output.status,
        output.stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        seen.recv_timeout(Duration::from_secs(2)).unwrap(),
        (0x2, body)
    );
    assert_eq!(output.stdout, reply);
    assert!(!String::from_utf8_lossy(&output.stderr).contains("[binary"));
}

#[test]
fn websocket_binary_message_mode_streams_stdin_as_raw_bytes() {
    let (ws_url, seen) = start_ws_frame_server(Vec::new());
    let mut cmd = Command::new(fetch_bin());
    cmd.args([
        &ws_url,
        "--format",
        "off",
        "--ws-interactive",
        "off",
        "--ws-message-mode",
        "binary",
    ]);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.env("NO_COLOR", "");
    cmd.env("HTTP_PROXY", "");
    cmd.env("HTTPS_PROXY", "");
    cmd.env("ALL_PROXY", "");
    cmd.env("NO_PROXY", "*");

    let mut child = cmd.spawn().expect("spawn websocket binary stdin fetch");
    let mut stdin = child.stdin.take().expect("child stdin");
    stdin.write_all(b"a\nb\0").unwrap();
    drop(stdin);
    let output = child
        .wait_with_output()
        .expect("wait websocket binary stdin fetch");
    assert!(
        output.status.success(),
        "fetch exited with {}; stdout: {:?}; stderr: {}",
        output.status,
        output.stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        seen.recv_timeout(Duration::from_secs(2)).unwrap(),
        (0x2, b"a\nb\0".to_vec())
    );
}

#[test]
fn websocket_verbose_prints_response_metadata() {
    let (ws_url, seen) = start_ws_echo_server(|_| Ok(()));

    let res = run_fetch(&[
        &ws_url,
        "-d",
        "verbose websocket",
        "--format",
        "off",
        "--ws-interactive",
        "off",
        "-v",
    ]);
    assert_exit(&res, 0);
    assert_eq!(
        seen.recv_timeout(Duration::from_secs(2)).unwrap(),
        "verbose websocket"
    );
    assert!(res.stderr.contains("HTTP/1.1 101 Switching Protocols"));
    assert!(res.stderr.contains("upgrade: websocket"));
    assert!(res.stderr.contains("connection: Upgrade"));
    assert!(res.stderr.contains("sec-websocket-accept:"));
    assert!(!res.stderr.contains("> GET"));
    assert!(!res.stderr.contains("< HTTP/1.1"));

    let res = run_fetch(&[
        &ws_url,
        "-d",
        "prefixed websocket",
        "--format",
        "off",
        "--ws-interactive",
        "off",
        "-vv",
    ]);
    assert_exit(&res, 0);
    assert_eq!(
        seen.recv_timeout(Duration::from_secs(2)).unwrap(),
        "prefixed websocket"
    );
    assert!(res.stderr.contains("> GET / HTTP/1.1"));
    assert!(res.stderr.contains("< HTTP/1.1 101 Switching Protocols"));
    assert!(res.stderr.contains("< upgrade: websocket"));

    let res = run_fetch(&[
        &ws_url,
        "-d",
        "sorted websocket",
        "--format",
        "off",
        "--ws-interactive",
        "off",
        "-v",
        "--sort-headers",
    ]);
    assert_exit(&res, 0);
    assert_eq!(
        seen.recv_timeout(Duration::from_secs(2)).unwrap(),
        "sorted websocket"
    );
    let connection = res.stderr.find("connection: Upgrade").unwrap();
    let accept = res.stderr.find("sec-websocket-accept:").unwrap();
    let upgrade = res.stderr.find("upgrade: websocket").unwrap();
    assert!(connection < accept);
    assert!(accept < upgrade);
}

#[test]
fn websocket_streams_stdin_before_eof() {
    let ws_url = start_ws_multi_echo_server(1);
    let mut cmd = Command::new(fetch_bin());
    cmd.args([&ws_url, "--format", "off", "--ws-interactive", "off"]);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.env("NO_COLOR", "");
    cmd.env("HTTP_PROXY", "");
    cmd.env("HTTPS_PROXY", "");
    cmd.env("ALL_PROXY", "");
    cmd.env("NO_PROXY", "*");

    let mut child = cmd.spawn().expect("spawn websocket stdin fetch");
    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = start_read_capture(child.stdout.take().expect("child stdout"));
    let stderr = start_read_capture(child.stderr.take().expect("child stderr"));

    stdin.write_all(b"line before eof\n").unwrap();
    stdin.flush().unwrap();
    let status = wait_child(&mut child, Duration::from_secs(5))
        .unwrap_or_else(|| {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "fetch did not complete while stdin remained open; stdout:\n{}\nstderr:\n{}",
                stdout.output(),
                stderr.output()
            )
        })
        .expect("wait websocket stdin fetch");
    assert!(
        status.success(),
        "fetch exited with {status}; stdout:\n{}\nstderr:\n{}",
        stdout.output(),
        stderr.output()
    );
    assert!(stdout.output().contains("line before eof"));
    drop(stdin);
    stdout.close();
    stderr.close();
}

#[test]
fn websocket_flushes_noninteractive_stdout_while_socket_stays_open() {
    let (ws_url, shutdown, server) = start_ws_hold_open_push_server(b"message before close");
    let mut cmd = Command::new(fetch_bin());
    cmd.args([&ws_url, "--format", "off", "--ws-interactive", "off"]);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.env("NO_COLOR", "");
    cmd.env("HTTP_PROXY", "");
    cmd.env("HTTPS_PROXY", "");
    cmd.env("ALL_PROXY", "");
    cmd.env("NO_PROXY", "*");

    let mut child = cmd.spawn().expect("spawn hold-open websocket fetch");
    let _stdin = child.stdin.take().expect("child stdin");
    let stdout = start_read_capture(child.stdout.take().expect("child stdout"));
    let stderr = start_read_capture(child.stderr.take().expect("child stderr"));

    stdout.wait_for("message before close\n", Duration::from_secs(2));
    assert!(
        child
            .try_wait()
            .expect("poll hold-open websocket")
            .is_none(),
        "fetch exited before the WebSocket closed; stdout:\n{}\nstderr:\n{}",
        stdout.output(),
        stderr.output()
    );

    let _ = shutdown.send(());
    let status = wait_child(&mut child, Duration::from_secs(5))
        .unwrap_or_else(|| {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "fetch did not exit after WebSocket close; stdout:\n{}\nstderr:\n{}",
                stdout.output(),
                stderr.output()
            )
        })
        .expect("wait hold-open websocket fetch");
    assert!(
        status.success(),
        "fetch exited with {status}; stdout:\n{}\nstderr:\n{}",
        stdout.output(),
        stderr.output()
    );
    stdout.close();
    stderr.close();
    server.join().expect("join hold-open websocket server");
}

#[test]
fn websocket_receives_json_text_binary_and_query_handshake() {
    let ws_url = start_ws_push_server(|req| {
        if req.path != "/stream?topic=builds" {
            return Err(format!("unexpected path: {}", req.path));
        }
        if req.header("x-test") != "yes" {
            return Err("missing test header".to_string());
        }
        Ok(())
    });
    let res = run_fetch(&[
        &format!("{ws_url}/stream"),
        "-q",
        "topic=builds",
        "-H",
        "X-Test: yes",
        "--format",
        "on",
        "--ws-interactive",
        "off",
    ]);

    assert_exit(&res, 0);
    assert!(res.stdout.contains("\"hello\": \"websocket\""));
    assert!(
        res.stdout
            .as_bytes()
            .windows(4)
            .any(|window| window == b"\0\x01\x02\x03")
    );
    assert!(res.stdout.contains("plain text"));
    assert!(!res.stderr.contains("[binary"));
}

#[test]
fn websocket_wss_trusts_custom_ca_go_case() {
    let (wss, seen) = start_wss_echo_server(|req| {
        if req.header("host").starts_with("localhost:") {
            Ok(())
        } else {
            Err("missing host".to_string())
        }
    });
    let res = run_fetch(&[
        &wss.url,
        "--ca-cert",
        wss.ca_cert_path.to_str().unwrap(),
        "-d",
        "secure websocket",
        "--format",
        "off",
        "--ws-interactive",
        "off",
    ]);
    assert_exit(&res, 0);
    assert_eq!(
        seen.recv_timeout(Duration::from_secs(2)).unwrap(),
        "secure websocket"
    );
    assert!(res.stdout.contains("echo: secure websocket"));
}

#[test]
fn websocket_wss_bad_certificate_suggests_insecure_go_case() {
    let (wss, _seen) = start_wss_echo_server(|_| Ok(()));
    let res = run_fetch(&[
        &wss.url,
        "-d",
        "secure websocket",
        "--format",
        "off",
        "--ws-interactive",
        "off",
    ]);

    assert_exit(&res, 1);
    assert!(
        res.stderr.to_ascii_lowercase().contains("certificate"),
        "stderr:\n{}",
        res.stderr
    );
    assert!(res.stderr.contains("--insecure"), "stderr:\n{}", res.stderr);
    assert!(!res.stderr.contains("--help"), "stderr:\n{}", res.stderr);
}

#[test]
fn websocket_custom_dns_and_proxy_cases() {
    let (dns_url, dns_seen) = start_ws_echo_server(|req| {
        if req.header("host").starts_with("ws-dns.test:") {
            Ok(())
        } else {
            Err(format!("unexpected host: {}", req.header("host")))
        }
    });
    let dns_port = Url::parse(&dns_url).unwrap().port().unwrap();
    let dns_addr = start_udp_dns_server("ws-dns.test.", Ipv4Addr::new(127, 0, 0, 1));
    let res = run_fetch(&[
        "--dns-server",
        &dns_addr,
        &format!("ws://ws-dns.test:{dns_port}"),
        "-d",
        "custom dns websocket",
        "--format",
        "off",
        "--ws-interactive",
        "off",
    ]);
    assert_exit(&res, 0);
    assert_eq!(
        dns_seen.recv_timeout(Duration::from_secs(2)).unwrap(),
        "custom dns websocket"
    );
    assert!(res.stdout.contains("echo: custom dns websocket"));

    let (proxy_target_url, proxy_seen_ws) = start_ws_echo_server(|_| Ok(()));
    let proxy_target_addr = url_host_port(&proxy_target_url);
    let (proxy_url, proxy_seen) = start_http_connect_proxy(proxy_target_addr.clone());
    let res = run_fetch(&[
        "--proxy",
        &proxy_url,
        &proxy_target_url,
        "-d",
        "proxied websocket",
        "--format",
        "off",
        "--ws-interactive",
        "off",
    ]);
    assert_exit(&res, 0);
    assert_proxy_seen(&proxy_seen, &proxy_target_addr);
    assert_eq!(
        proxy_seen_ws.recv_timeout(Duration::from_secs(2)).unwrap(),
        "proxied websocket"
    );
    assert!(res.stdout.contains("echo: proxied websocket"));

    let (socks_target_url, socks_seen_ws) = start_ws_echo_server(|_| Ok(()));
    let socks_target_addr = url_host_port(&socks_target_url);
    let (socks_url, socks_seen) = start_socks5_proxy(socks_target_addr.clone());
    let res = run_fetch(&[
        "--proxy",
        &socks_url,
        &socks_target_url,
        "-d",
        "socks websocket",
        "--format",
        "off",
        "--ws-interactive",
        "off",
    ]);
    assert_exit(&res, 0);
    assert_socks_seen(&socks_seen, &socks_target_addr);
    assert_eq!(
        socks_seen_ws.recv_timeout(Duration::from_secs(2)).unwrap(),
        "socks websocket"
    );
    assert!(res.stdout.contains("echo: socks websocket"));

    let (socks_dns_target_url, socks_dns_seen_ws) = start_ws_echo_server(|req| {
        if req.header("host").starts_with("ws-socks-dns.test:") {
            Ok(())
        } else {
            Err(format!("unexpected host: {}", req.header("host")))
        }
    });
    let socks_dns_port = Url::parse(&socks_dns_target_url).unwrap().port().unwrap();
    let socks_dns_target_addr = url_host_port(&socks_dns_target_url);
    let (socks_dns_proxy_url, socks_dns_seen) = start_socks5_proxy(socks_dns_target_addr.clone());
    let socks_dns_addr = start_udp_dns_server("ws-socks-dns.test.", Ipv4Addr::new(127, 0, 0, 1));
    let res = run_fetch(&[
        "--dns-server",
        &socks_dns_addr,
        "--proxy",
        &socks_dns_proxy_url,
        &format!("ws://ws-socks-dns.test:{socks_dns_port}"),
        "-d",
        "socks dns websocket",
        "--format",
        "off",
        "--ws-interactive",
        "off",
    ]);
    assert_exit(&res, 0);
    assert_socks_seen(&socks_dns_seen, &socks_dns_target_addr);
    assert_eq!(
        socks_dns_seen_ws
            .recv_timeout(Duration::from_secs(2))
            .unwrap(),
        "socks dns websocket"
    );
    assert!(res.stdout.contains("echo: socks dns websocket"));

    let socks_dns_proxy_url = socks_dns_proxy_url.replacen("socks5://", "socks5h://", 1);
    let res = run_fetch(&[
        "--dns-server",
        &socks_dns_addr,
        "--proxy",
        &socks_dns_proxy_url,
        &format!("ws://ws-socks-dns.test:{socks_dns_port}"),
        "-d",
        "socks remote dns websocket",
        "--format",
        "off",
        "--ws-interactive",
        "off",
    ]);
    assert_exit(&res, 0);
    assert_socks_seen(
        &socks_dns_seen,
        &format!("ws-socks-dns.test:{socks_dns_port}"),
    );
    assert_eq!(
        socks_dns_seen_ws
            .recv_timeout(Duration::from_secs(2))
            .unwrap(),
        "socks remote dns websocket"
    );
    assert!(res.stdout.contains("echo: socks remote dns websocket"));
}

#[test]
fn websocket_connect_timeout_covers_dns_and_proxy_handshakes() {
    let unresponsive_dns_addr = start_unresponsive_udp_dns_server();
    let res = run_fetch(&[
        "--dns-server",
        &unresponsive_dns_addr,
        "--connect-timeout",
        "0.05",
        "--timeout",
        "1",
        "ws://ws-dns-timeout.test:80",
        "--ws-interactive",
        "off",
    ]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("request timed out after 50ms"));

    let http_proxy = start_stalling_proxy("http");
    let res = run_fetch(&[
        "--proxy",
        &http_proxy,
        "--connect-timeout",
        "0.05",
        "--timeout",
        "1",
        "ws://example.com/socket",
        "--ws-interactive",
        "off",
    ]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("request timed out after 50ms"));

    let socks_proxy = start_stalling_proxy("socks5");
    let res = run_fetch(&[
        "--proxy",
        &socks_proxy,
        "--connect-timeout",
        "0.05",
        "--timeout",
        "1",
        "ws://example.com/socket",
        "--ws-interactive",
        "off",
    ]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("request timed out after 50ms"));
}

#[test]
fn websocket_sessions_send_and_persist_handshake_cookies() {
    let dir = TempDir::new().unwrap();
    let sessions_dir = dir.path().join("sessions");
    let env = vec![(
        "FETCH_INTERNAL_SESSIONS_DIR".to_string(),
        sessions_dir.display().to_string(),
    )];
    let http_server = TestServer::start(|req| {
        if req.path == "/login" {
            return TestResponse::ok("logged in").header("Set-Cookie", "sid=abc; Path=/");
        }
        if req.path == "/check" && req.header("cookie").contains("wsid=upgraded") {
            return TestResponse::ok("persisted");
        }
        TestResponse::status(401, "Unauthorized", "missing cookie")
    });

    let res = run_fetch_opts(
        FetchOpts {
            env: env.clone(),
            ..Default::default()
        },
        &[
            &format!("{}/login", http_server.url),
            "--session",
            "ws-integ",
        ],
    );
    assert_exit(&res, 0);

    let (ws_url, seen) = start_ws_session_server();
    let res = run_fetch_opts(
        FetchOpts {
            env: env.clone(),
            ..Default::default()
        },
        &[
            &ws_url,
            "--session",
            "ws-integ",
            "-d",
            "upgrade",
            "--format",
            "off",
            "--ws-interactive",
            "off",
        ],
    );
    assert_exit(&res, 0);
    assert_eq!(
        seen.recv_timeout(Duration::from_secs(2)).unwrap(),
        "upgrade"
    );
    assert_eq!(res.stdout, "upgrade\n");

    let res = run_fetch_opts(
        FetchOpts {
            env,
            ..Default::default()
        },
        &[
            &format!("{}/check", http_server.url),
            "--session",
            "ws-integ",
        ],
    );
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "persisted");
}

#[test]
fn websocket_dry_run_prints_effective_handshake_headers() {
    let res = run_fetch(&[
        "ws://example.com/socket",
        "--dry-run",
        "-H",
        "X-Test: yes",
        "--bearer",
        "token",
    ]);

    assert_exit(&res, 0);
    assert!(res.stdout.is_empty());
    assert!(res.stderr.contains("> GET /socket HTTP/1.1"));
    assert!(res.stderr.contains("> x-test: yes"));
    assert!(res.stderr.contains("> authorization: Bearer token"));
    assert!(res.stderr.contains("> accept: application/json, */*;q=0.5"));
    assert!(res.stderr.contains("> user-agent: fetch/"));
}

#[test]
fn websocket_dry_run_does_not_read_stdin_body() {
    let mut cmd = Command::new(fetch_bin());
    cmd.args(["ws://example.com/socket", "--dry-run", "-d", "@-"]);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.env("NO_COLOR", "");
    cmd.env("HTTP_PROXY", "");
    cmd.env("HTTPS_PROXY", "");
    cmd.env("ALL_PROXY", "");
    cmd.env("NO_PROXY", "*");

    let mut child = cmd.spawn().expect("spawn websocket dry-run fetch");
    let stdin = child.stdin.take().expect("child stdin");
    let start = Instant::now();
    loop {
        if child
            .try_wait()
            .expect("poll websocket dry-run fetch")
            .is_some()
        {
            break;
        }
        if start.elapsed() > Duration::from_secs(2) {
            let _ = child.kill();
            let out = child.wait_with_output().expect("wait killed fetch");
            panic!(
                "websocket dry-run waited for stdin\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }

    let out = child
        .wait_with_output()
        .expect("wait websocket dry-run fetch");
    drop(stdin);
    let res = FetchOutput {
        status: out.status,
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    };
    assert_exit(&res, 0);
    assert!(res.stdout.is_empty());
    assert!(res.stderr.contains("> GET /socket HTTP/1.1"));
}

#[cfg(unix)]
#[test]
fn websocket_interactive_pty_go_case() {
    let (ws_url, seen) = start_ws_echo_server(|_| Ok(()));
    let pty = open_pty(24, 80, 800, 480);
    let mut cmd = Command::new(fetch_bin());
    cmd.args([
        ws_url.as_str(),
        "--ws-interactive",
        "on",
        "--format",
        "off",
        "--pager",
        "off",
    ]);
    cmd.env("TERM", "xterm-256color");
    cmd.env("HTTP_PROXY", "");
    cmd.env("HTTPS_PROXY", "");
    cmd.env("ALL_PROXY", "");
    cmd.env("NO_PROXY", "*");
    configure_pty_child(&mut cmd, &pty.slave);
    let mut child = cmd.spawn().expect("spawn interactive websocket under PTY");
    drop(pty.slave);
    let mut master = pty.master;
    let capture = start_pty_capture(&master);
    capture.wait_for("connected", Duration::from_secs(5));
    master.write_all(b"hello pty\r").unwrap();
    assert_eq!(
        seen.recv_timeout(Duration::from_secs(5)).unwrap(),
        "hello pty"
    );
    capture.wait_for("echo: hello pty", Duration::from_secs(5));
    let status = wait_child(&mut child, Duration::from_secs(5))
        .unwrap_or_else(|| {
            let _ = child.kill();
            panic!(
                "fetch did not exit after WebSocket close; PTY output:\n{}",
                capture.output()
            )
        })
        .expect("wait interactive websocket");
    assert!(
        status.success(),
        "fetch exited with {status}; PTY output:\n{}",
        capture.output()
    );
    drop(master);
    capture.close();
}
