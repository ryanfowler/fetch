mod support;

use support::*;

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
    assert!(res.stdout.contains("plain text"));
    assert!(res.stderr.contains("[binary 4 bytes]"));
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
