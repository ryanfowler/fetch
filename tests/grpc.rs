mod support;

use sha2::{Digest as Sha2Digest, Sha256};
use support::*;

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest.iter().copied() {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[test]
fn grpc_schema_descriptor_and_client_streaming_cases() {
    let dir = TempDir::new().unwrap();
    let health_desc = write_health_descriptor_set(dir.path());
    let stream_desc = write_stream_descriptor_set(dir.path());

    let res = run_fetch(&["--grpc-list", "--proto-desc", health_desc.to_str().unwrap()]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("grpc.health.v1.Health"));

    let res = run_fetch(&[
        "--grpc-describe",
        "grpc.health.v1.Health",
        "--proto-desc",
        health_desc.to_str().unwrap(),
        "http://127.0.0.1:1",
    ]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("service grpc.health.v1.Health"));

    let health_resp = proto_field_varint(1, 1);
    let health_server = TestServer::start(move |req| {
        if req.path == "/grpc.health.v1.Health/Check" {
            let _ = req.body;
            TestResponse::ok(health_resp.clone()).header("Content-Type", "application/protobuf")
        } else {
            TestResponse::status(404, "Not Found", "")
        }
    });
    let res = run_fetch(&[
        &format!("{}/grpc.health.v1.Health/Check", health_server.url),
        "--grpc",
        "--proto-desc",
        health_desc.to_str().unwrap(),
        "--http",
        "1",
        "--format",
        "on",
    ]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("SERVING"));

    let stream_server = TestServer::start(|req| {
        if req.path == "/streampkg.StreamService/ServerStream" {
            let mut body = grpc_frame(&proto_field_varint(1, 1));
            body.extend(grpc_frame(&proto_field_varint(1, 2)));
            return TestResponse::ok(body).header("Content-Type", "application/grpc+proto");
        }
        let mut body = &req.body[..];
        let mut count = 0_u64;
        while body.len() >= 5 {
            let len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
            if body.len() < 5 + len {
                break;
            }
            count += 1;
            body = &body[5 + len..];
        }
        TestResponse::ok(grpc_frame(&proto_field_varint(1, count)))
            .header("Content-Type", "application/grpc+proto")
    });
    let res = run_fetch(&[
        &format!("{}/streampkg.StreamService/ClientStream", stream_server.url),
        "--grpc",
        "--proto-desc",
        stream_desc.to_str().unwrap(),
        "-d",
        r#"{"value":"one"}{"value":"two"}{"value":"three"}"#,
        "--http",
        "1",
        "--format",
        "on",
    ]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("3"));

    let res = run_fetch(&[
        &format!("{}/streampkg.StreamService/ClientStream", stream_server.url),
        "--grpc",
        "--proto-desc",
        stream_desc.to_str().unwrap(),
        "-d",
        r#"{"value":"only"}"#,
        "--http",
        "1",
        "--format",
        "on",
    ]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("1"));

    let res = run_fetch(&[
        &format!("{}/streampkg.StreamService/ServerStream", stream_server.url),
        "--grpc",
        "--proto-desc",
        stream_desc.to_str().unwrap(),
        "-d",
        r#"{"value":"seed"}"#,
        "--http",
        "1",
        "--format",
        "on",
    ]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("\"count\": \"1\""));
    assert!(res.stdout.contains("\"count\": \"2\""));

    let res = run_fetch(&[
        &format!("{}/streampkg.StreamService/ClientStream", stream_server.url),
        "--grpc",
        "--proto-desc",
        stream_desc.to_str().unwrap(),
        "--http",
        "1",
        "--format",
        "on",
    ]);
    assert_exit(&res, 0);

    let res = run_fetch(&[
        &format!("{}/streampkg.StreamService/ClientStream", stream_server.url),
        "--grpc",
        "--proto-desc",
        stream_desc.to_str().unwrap(),
        "-d",
        r#"{"value":"one"}{"value":"#,
        "--http",
        "1",
    ]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("failed to decode JSON message"));

    if Command::new("protoc").arg("--version").output().is_ok() {
        let proto_file = temp_file(
            dir.path(),
            "stream.proto",
            r#"
syntax = "proto3";
package streampkg;

message StreamRequest {
  string value = 1;
}

message StreamResponse {
  int64 count = 1;
}

service StreamService {
  rpc ClientStream(stream StreamRequest) returns (StreamResponse);
}
"#,
        );

        let res = run_fetch(&["--grpc-list", "--proto-file", proto_file.to_str().unwrap()]);
        assert_exit(&res, 0);
        assert!(res.stdout.contains("streampkg.StreamService"));

        let res = run_fetch(&[
            &format!("{}/streampkg.StreamService/ClientStream", stream_server.url),
            "--grpc",
            "--proto-file",
            proto_file.to_str().unwrap(),
            "-d",
            r#"{"value":"one"}{"value":"two"}"#,
            "--http",
            "1",
            "--format",
            "on",
        ]);
        assert_exit(&res, 0);
        assert!(res.stdout.contains("2"));
    }

    let header_server = TestServer::start(|_| {
        TestResponse::ok(proto_field_varint(1, 1)).header("Content-Type", "application/protobuf")
    });
    let res = run_fetch(&[
        &format!("{}/grpc.health.v1.Health/Check", header_server.url),
        "--grpc",
        "--proto-desc",
        health_desc.to_str().unwrap(),
        "-j",
        r#"{"service":"svc"}"#,
        "--http",
        "1",
        "--basic",
        "user:pass",
        "-H",
        "X-Test: yes",
        "--format",
        "on",
    ]);
    assert_exit(&res, 0);
    let requests = header_server.requests.lock().unwrap();
    let request = requests.last().expect("gRPC request captured");
    assert_eq!(request.method, "POST");
    assert_eq!(request.header("content-type"), "application/grpc+proto");
    assert_eq!(request.header("te"), "trailers");
    assert_eq!(request.header("grpc-accept-encoding"), "gzip");
    assert_eq!(request.header("x-test"), "yes");
    assert!(request.header("authorization").starts_with("Basic "));
    assert_eq!(request.body, grpc_frame(&proto_field_string(1, "svc")));
    drop(requests);

    let res = run_fetch(&[
        &format!("{}/grpc.health.v1.Health/Missing", header_server.url),
        "--grpc",
        "--proto-desc",
        health_desc.to_str().unwrap(),
        "--http",
        "1",
    ]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("method Missing not found"));

    let header_status_server = TestServer::start(|_| {
        TestResponse::ok("")
            .header("Content-Type", "application/grpc+proto")
            .header("grpc-status", "16")
            .header("grpc-message", "bad%20token")
    });
    let res = run_fetch(&[
        &format!("{}/test.Auth/Check", header_status_server.url),
        "--grpc",
        "--http",
        "1",
        "--format",
        "off",
    ]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("UNAUTHENTICATED"));
    assert!(res.stderr.contains("bad token"));

    let res = run_fetch(&[
        "http://example.com/svc/Method",
        "--grpc",
        "--proto-file",
        health_desc.to_str().unwrap(),
        "--proto-desc",
        stream_desc.to_str().unwrap(),
    ]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("cannot be used together"));

    let res = run_fetch(&[
        "http://example.com/svc/Method",
        "--grpc",
        "--proto-desc",
        "/nonexistent/file.pb",
    ]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("does not exist"));

    let res = run_fetch(&[
        "http://example.com/svc/Method",
        "--grpc",
        "--proto-file",
        "/nonexistent/file.proto",
    ]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("protoc") || res.stderr.contains("exist"));
}

#[test]
fn grpc_dry_run_materializes_streaming_stdin_body_once() {
    let dir = TempDir::new().unwrap();
    let stream_desc = write_stream_descriptor_set(dir.path());

    let res = run_fetch_opts(
        FetchOpts {
            stdin: Some(r#"{"value":"one"}{"value":"two"}"#.to_string()),
            ..Default::default()
        },
        &[
            "http://127.0.0.1:1/streampkg.StreamService/ClientStream",
            "--grpc",
            "--proto-desc",
            stream_desc.to_str().unwrap(),
            "-d",
            "@-",
            "--dry-run",
        ],
    );

    assert_exit(&res, 0);
    assert!(res.stdout.is_empty());
    assert!(
        res.stderr
            .contains("POST /streampkg.StreamService/ClientStream ")
    );
    assert!(res.stderr.contains("content-type: application/grpc+proto"));
    assert!(res.stderr.contains("the request body appears to be binary"));
}

#[test]
fn grpc_h2c_stream_frames_and_status_trailers_are_handled() {
    let server_url = start_status_grpc_h2c_server();
    let res = run_fetch(&[
        &format!("{server_url}/test.Stream/Events"),
        "--grpc",
        "--format",
        "on",
    ]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("first"), "stdout:\n{}", res.stdout);
    assert!(res.stdout.contains("second"), "stdout:\n{}", res.stdout);

    let res = run_fetch(&[
        &format!("{server_url}/test.Status/Denied"),
        "--grpc",
        "--format",
        "off",
    ]);
    assert_exit(&res, 1);
    assert!(res.stdout.is_empty(), "stdout:\n{}", res.stdout);
    assert!(res.stderr.contains("PERMISSION_DENIED"), "{}", res.stderr);
    assert!(res.stderr.contains("permission denied"), "{}", res.stderr);
}

#[cfg(unix)]
#[test]
fn formatted_grpc_outputs_frames_before_stream_ends() {
    let dir = TempDir::new().unwrap();
    let stream_desc = write_stream_descriptor_set(dir.path());
    let (close_tx, close_rx) = mpsc::channel();
    let server_url = start_delayed_response_grpc_h2c_server(close_rx);
    let url = format!("{server_url}/streampkg.StreamService/ServerStream");

    let pty = open_pty(24, 80, 800, 480);
    let mut cmd = Command::new(fetch_bin());
    cmd.args([
        url.as_str(),
        "--grpc",
        "--proto-desc",
        stream_desc.to_str().unwrap(),
        "-d",
        r#"{"value":"seed"}"#,
        "--format",
        "on",
        "--pager",
        "off",
    ]);
    cmd.env("TERM", "xterm-256color");
    cmd.env("HTTP_PROXY", "");
    cmd.env("HTTPS_PROXY", "");
    cmd.env("ALL_PROXY", "");
    cmd.env("NO_PROXY", "*");
    configure_pty_child(&mut cmd, &pty.slave);
    let mut child = cmd.spawn().expect("spawn delayed grpc fetch under PTY");
    drop(pty.slave);
    let capture = start_pty_capture(&pty.master);

    capture.wait_for(r#""count": "1""#, Duration::from_secs(5));
    assert!(
        wait_child(&mut child, Duration::from_millis(100)).is_none(),
        "fetch exited before the gRPC stream closed; PTY output:\n{}",
        capture.output()
    );
    close_tx.send(()).unwrap();

    let status = wait_child(&mut child, Duration::from_secs(5))
        .unwrap_or_else(|| {
            let _ = child.kill();
            panic!(
                "fetch did not exit after gRPC stream closed; PTY output:\n{}",
                capture.output()
            )
        })
        .expect("wait delayed grpc fetch");
    assert!(
        status.success(),
        "fetch exited with {status}; PTY output:\n{}",
        capture.output()
    );
    assert!(capture.output().contains(r#""count": "2""#));
    drop(pty.master);
    capture.close();
}

#[test]
fn bidi_grpc_streams_request_and_response_before_stdin_eof() {
    let dir = TempDir::new().unwrap();
    let stream_desc = write_stream_descriptor_set(dir.path());
    let (finish_tx, finish_rx) = mpsc::channel();
    let server_url = start_delayed_bidi_grpc_h2c_server(finish_rx);

    let mut cmd = Command::new(fetch_bin());
    cmd.args([
        &format!("{server_url}/streampkg.StreamService/Bidi"),
        "--grpc",
        "--proto-desc",
        stream_desc.to_str().unwrap(),
        "-d",
        "@-",
        "--format",
        "on",
        "--pager",
        "off",
    ]);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.env("NO_COLOR", "");
    cmd.env("HTTP_PROXY", "");
    cmd.env("HTTPS_PROXY", "");
    cmd.env("ALL_PROXY", "");
    cmd.env("NO_PROXY", "*");

    let mut child = cmd.spawn().expect("spawn delayed bidi grpc fetch");
    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = start_read_capture(child.stdout.take().expect("child stdout"));
    let stderr = start_read_capture(child.stderr.take().expect("child stderr"));

    // Keep stdin open, but delimit the first streaming JSON value with
    // whitespace so platform stdio layers do not need EOF to expose it.
    stdin.write_all(b"{\"value\":\"one\"}\n").unwrap();
    stdin.flush().unwrap();
    stdout.wait_for(r#""count": "1""#, Duration::from_secs(15));
    assert!(
        wait_child(&mut child, Duration::from_millis(100)).is_none(),
        "fetch exited before stdin EOF; stdout:\n{}\nstderr:\n{}",
        stdout.output(),
        stderr.output()
    );

    drop(stdin);
    finish_tx.send(()).unwrap();
    let status = wait_child(&mut child, Duration::from_secs(5))
        .unwrap_or_else(|| {
            let _ = child.kill();
            panic!(
                "fetch did not exit after stdin closed; stdout:\n{}\nstderr:\n{}",
                stdout.output(),
                stderr.output()
            )
        })
        .expect("wait delayed bidi grpc fetch");
    assert!(
        status.success(),
        "fetch exited with {status}; stdout:\n{}\nstderr:\n{}",
        stdout.output(),
        stderr.output()
    );
    stdout.close();
    stderr.close();
}

#[test]
fn grpc_reflection_h2c_go_cases() {
    let server = start_reflection_grpc_h2c_server(true);
    let res = run_fetch(&["--grpc-list", &server.url]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("grpc.health.v1.Health"));

    let fallback = start_reflection_grpc_h2c_v1_error_response_server();
    let res = run_fetch(&["--grpc-list", &fallback.url]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("grpc.health.v1.Health"));

    let res = run_fetch(&[
        "--grpc-describe",
        "grpc.health.v1.Health/Check",
        &fallback.url,
    ]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("method grpc.health.v1.Health/Check"));

    let res = run_fetch(&[
        "--grpc-describe",
        "grpc.health.v1.Health/Check",
        &server.url,
    ]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("method grpc.health.v1.Health/Check"));
    assert!(res.stdout.contains("rpc: unary"));
    assert!(
        res.stdout
            .contains("request: grpc.health.v1.HealthCheckRequest")
    );

    let res = run_fetch(&[
        &format!("{}/grpc.health.v1.Health/Check", server.url),
        "--grpc",
        "-j",
        r#"{"service":""}"#,
        "--format",
        "on",
    ]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("\"status\": \"SERVING\""));

    let res = run_fetch(&[
        &format!("{}/grpc.health.v1.Health/Check", server.url),
        "--grpc",
        "--format",
        "on",
    ]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("\"status\": \"SERVING\""));

    let tls = start_reflection_grpc_tls_server(true);
    let ca_cert = tls.ca_cert_path.as_ref().unwrap().to_str().unwrap();
    let res = run_fetch(&["--grpc-list", "--ca-cert", ca_cert, &tls.url]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("grpc.health.v1.Health"));

    let res = run_fetch(&[
        "--grpc-describe",
        "grpc.health.v1.Health/Check",
        "--ca-cert",
        ca_cert,
        &tls.url,
    ]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("method grpc.health.v1.Health/Check"));
    assert!(
        res.stdout
            .contains("request: grpc.health.v1.HealthCheckRequest")
    );

    let res = run_fetch(&[
        &format!("{}/grpc.health.v1.Health/Check", tls.url),
        "--grpc",
        "--ca-cert",
        ca_cert,
        "-j",
        r#"{"service":""}"#,
        "--format",
        "on",
    ]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("\"status\": \"SERVING\""));

    let tls13 = start_reflection_grpc_tls_server_with_versions(true, &[&rustls::version::TLS13]);
    let tls13_ca_cert = tls13.ca_cert_path.as_ref().unwrap().to_str().unwrap();
    let res = run_fetch(&[
        "--grpc-list",
        "--ca-cert",
        tls13_ca_cert,
        "--min-tls",
        "1.3",
        "--max-tls",
        "1.3",
        &tls13.url,
    ]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("grpc.health.v1.Health"));

    let res = run_fetch(&[
        "--grpc-list",
        "--ca-cert",
        tls13_ca_cert,
        "--max-tls",
        "1.2",
        &tls13.url,
    ]);
    assert_exit(&res, 1);
    assert!(!res.stderr.is_empty());

    let res = run_fetch(&[
        "--grpc-list",
        "--proxy",
        "http://proxy.example:8080",
        &server.url,
    ]);
    assert_exit(&res, 1);
    assert!(
        res.stderr
            .contains("a proxy can only be used with HTTP/1.1")
    );

    let res = run_fetch_opts(
        FetchOpts {
            env: vec![
                (
                    "HTTP_PROXY".to_string(),
                    "http://proxy.example:8080".to_string(),
                ),
                ("NO_PROXY".to_string(), "127.0.0.0/8".to_string()),
            ],
            ..Default::default()
        },
        &["--grpc-list", &server.url],
    );
    assert_exit(&res, 0);
    assert!(res.stdout.contains("grpc.health.v1.Health"));

    let port = server.url.rsplit_once(':').unwrap().1;
    let dns_url = format!("http://fetch-grpc-dns.test:{port}");
    let dns_addr = start_udp_dns_server("fetch-grpc-dns.test.", Ipv4Addr::new(127, 0, 0, 1));
    let res = run_fetch(&["--grpc-list", "--dns-server", &dns_addr, &dns_url]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("grpc.health.v1.Health"));

    let unavailable = start_reflection_grpc_h2c_server(false);
    let res = run_fetch(&["--grpc-list", &unavailable.url]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("gRPC reflection is unavailable"));
    assert!(res.stderr.contains("--proto-file"));

    let res = run_fetch(&[
        &format!("{}/grpc.health.v1.Health/Check", unavailable.url),
        "--grpc",
        "-j",
        r#"{"service":""}"#,
    ]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("gRPC reflection is unavailable"));
    assert!(res.stderr.contains("--proto-desc"));

    let res = run_fetch(&[
        &format!("{}/grpc.health.v1.Health/Check", unavailable.url),
        "--grpc",
        "--format",
        "on",
    ]);
    assert_exit(&res, 0);
    assert!(!res.stdout.is_empty());
}

#[test]
fn grpc_reflection_requests_include_aws_sigv4_headers() {
    let server = start_reflection_grpc_h2c_server(true);
    let res = run_fetch_opts(
        FetchOpts {
            env: vec![
                ("AWS_ACCESS_KEY_ID".to_string(), "1234".to_string()),
                ("AWS_SECRET_ACCESS_KEY".to_string(), "5678".to_string()),
                ("AWS_SESSION_TOKEN".to_string(), "session-token".to_string()),
            ],
            ..Default::default()
        },
        &[
            "--grpc-list",
            "--aws-sigv4",
            "us-east-1/execute-api",
            &server.url,
        ],
    );
    assert_exit(&res, 0);

    let requests = server.requests();
    let reflection = requests
        .iter()
        .find(|req| req.path == "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo")
        .expect("captured reflection request");
    let auth = reflection.header("authorization");
    assert_eq!(reflection.method, "POST");
    assert!(auth.starts_with("AWS4-HMAC-SHA256 "));
    assert!(auth.contains("Credential=1234/"));
    assert!(auth.contains("/us-east-1/execute-api/aws4_request"));
    assert!(auth.contains("x-amz-content-sha256"));
    assert!(auth.contains("x-amz-date"));
    assert!(auth.contains("x-amz-security-token"));
    assert!(!reflection.header("x-amz-date").is_empty());
    assert_eq!(reflection.header("x-amz-security-token"), "session-token");
    assert_eq!(
        reflection.header("x-amz-content-sha256"),
        sha256_hex(&reflection.body)
    );
}
