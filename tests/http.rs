mod support;

use base64::Engine;
use flate2::Compression;
use flate2::write::GzEncoder;
use std::fs;
use std::io::{BufReader, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use support::auth::{md5_hex, parse_digest_auth_params};
#[cfg(unix)]
use support::common::fetch_bin;
use support::common::{
    FAST_RETRY_DELAY, FetchOpts, accept_tcp_connection, assert_exit, fake_editor, host_port,
    run_fetch, run_fetch_once, run_fetch_opts, temp_file,
};
use support::dns::start_udp_dns_server;
use support::http::{
    PartialBodyReplayServer, TestResponse, TestServer, read_request, wait_for_requests,
    write_response,
};
use tempfile::TempDir;

#[test]
fn request_construction_and_data_sources() {
    let server = TestServer::start(|_| TestResponse::ok(""));

    let res = run_fetch(&[&server.url, "--data", "hello"]);
    assert_exit(&res, 0);
    let req = wait_for_requests(&server, 1).remove(0);
    assert_eq!(req.method, "POST");
    assert_eq!(req.body_string(), "hello");
    assert_eq!(req.header("content-type"), "text/plain; charset=utf-8");

    let res = run_fetch(&[&server.url, "--json", r#"{"key":"val"}"#]);
    assert_exit(&res, 0);
    let req = wait_for_requests(&server, 2).remove(1);
    assert_eq!(req.method, "POST");
    assert_eq!(req.body_string(), r#"{"key":"val"}"#);
    assert_eq!(req.header("content-type"), "application/json");

    let res = run_fetch(&[&server.url, "--xml", "<Tag></Tag>"]);
    assert_exit(&res, 0);
    let req = wait_for_requests(&server, 3).remove(2);
    assert_eq!(req.method, "POST");
    assert_eq!(req.body_string(), "<Tag></Tag>");
    assert_eq!(req.header("content-type"), "application/xml");

    let dir = TempDir::new().unwrap();
    let file = temp_file(dir.path(), "body.txt", "temp file data");
    let res = run_fetch(&[&server.url, "--data", &format!("@{}", file.display())]);
    assert_exit(&res, 0);
    let req = wait_for_requests(&server, 4).remove(3);
    assert_eq!(req.method, "POST");
    assert_eq!(req.body_string(), "temp file data");
    assert_eq!(req.header("content-length"), "14");

    let res = run_fetch(&[&server.url, "--data", "hello", "-H", "Content-Length: 5"]);
    assert_exit(&res, 0);
    let req = wait_for_requests(&server, 5).remove(4);
    assert_eq!(req.method, "POST");
    assert_eq!(req.body_string(), "hello");
    assert_eq!(req.header("content-length"), "5");

    let res = run_fetch(&[
        &server.url,
        "--data",
        "chunked body",
        "-H",
        "Transfer-Encoding: chunked",
    ]);
    assert_exit(&res, 0);
    let req = wait_for_requests(&server, 6).remove(5);
    assert_eq!(req.method, "POST");
    assert_eq!(req.body_string(), "chunked body");
    assert_eq!(req.header("transfer-encoding"), "chunked");
    assert!(req.header("content-length").is_empty());

    let res = run_fetch(&[&server.url, "--method", "GET", "--json", r#"{"key":"val"}"#]);
    assert_exit(&res, 0);
    let req = wait_for_requests(&server, 7).remove(6);
    assert_eq!(req.method, "GET");
    assert_eq!(req.body_string(), r#"{"key":"val"}"#);
}

#[test]
fn schemeless_https_connect_error_suggests_plaintext_url() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind plaintext listener");
    listener
        .set_nonblocking(true)
        .expect("set plaintext listener nonblocking");
    let port = listener.local_addr().expect("local addr").port();
    let join = thread::spawn(move || {
        for _ in 0..2 {
            let Ok(mut stream) =
                accept_tcp_connection(&listener, Duration::from_secs(5), "plaintext TLS hint")
            else {
                return;
            };
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok");
            let _ = stream.flush();
            let _ = stream.shutdown(Shutdown::Both);
        }
    });

    let dns_addr = start_udp_dns_server("fetch-plaintext-hint.test.", Ipv4Addr::new(127, 0, 0, 1));
    let raw_url = format!("fetch-plaintext-hint.test:{port}/status");
    let res = run_fetch_once(FetchOpts::default(), &["--dns-server", &dns_addr, &raw_url]);
    assert_exit(&res, 1);
    assert!(
        res.stderr.contains(&format!(
            "If this is a plaintext service, use http://fetch-plaintext-hint.test:{port}/status."
        )),
        "missing plaintext hint\nstderr:\n{}",
        res.stderr
    );

    let explicit_url = format!("https://fetch-plaintext-hint.test:{port}/status");
    let res = run_fetch_once(
        FetchOpts::default(),
        &["--dns-server", &dns_addr, &explicit_url],
    );
    assert_exit(&res, 1);
    assert!(
        !res.stderr.contains("plaintext service"),
        "explicit HTTPS should not get schemeless hint\nstderr:\n{}",
        res.stderr
    );

    join.join().expect("plaintext listener thread");
}

#[cfg(unix)]
#[test]
fn http_stdout_broken_pipe_exits_cleanly() {
    let body = vec![b'a'; 2 * 1024 * 1024];
    let server = TestServer::start(move |_| {
        TestResponse::ok(body.clone()).header("Content-Type", "text/plain")
    });

    let mut fetch = Command::new(fetch_bin());
    fetch.arg(server.url.as_str());
    fetch.stdout(Stdio::piped()).stderr(Stdio::piped());
    fetch.env("NO_COLOR", "");
    fetch.env("HTTP_PROXY", "");
    fetch.env("HTTPS_PROXY", "");
    fetch.env("ALL_PROXY", "");
    fetch.env("NO_PROXY", "*");

    let mut fetch_child = fetch.spawn().expect("spawn fetch");
    let fetch_stdout = fetch_child.stdout.take().expect("fetch stdout");
    let head_output = Command::new("head")
        .args(["-c", "1"])
        .stdin(Stdio::from(fetch_stdout))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run head");
    let fetch_output = fetch_child.wait_with_output().expect("wait fetch");

    assert!(
        head_output.status.success(),
        "head stderr: {:?}",
        head_output.stderr
    );
    assert_eq!(head_output.stdout, b"a");
    assert_eq!(
        fetch_output.status.code(),
        Some(0),
        "fetch stderr:\n{}",
        String::from_utf8_lossy(&fetch_output.stderr)
    );
    let fetch_stderr = String::from_utf8_lossy(&fetch_output.stderr);
    assert!(
        !fetch_stderr.contains("error") && !fetch_stderr.contains("Broken pipe"),
        "fetch stderr:\n{fetch_stderr}"
    );
}

#[test]
fn duplicate_cli_headers_are_sent_as_separate_wire_lines() {
    let server = TestServer::start(|_| TestResponse::ok("ok"));

    let res = run_fetch(&[
        &server.url,
        "--header",
        "X-Test: one",
        "--header",
        "X-Test: two",
    ]);
    assert_exit(&res, 0);

    let req = wait_for_requests(&server, 1).remove(0);
    assert_eq!(req.header_values("x-test"), ["one", "two"]);
}

#[test]
fn config_merges_global_host_and_cli_options() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_for_handler = Arc::clone(&attempts);
    let server = TestServer::start(move |req| {
        if !req.path.contains("global=1")
            || !req.path.contains("host=1")
            || !req.path.contains("cli=1")
            || req.header("x-global") != "yes"
            || req.header("x-host") != "yes"
            || req.header("x-cli") != "yes"
        {
            return TestResponse::status(400, "Bad Request", "missing config values");
        }
        if attempts_for_handler.fetch_add(1, Ordering::SeqCst) == 0 {
            return TestResponse::status(503, "Service Unavailable", "retry me")
                .header("Connection", "keep-alive");
        }
        TestResponse::ok("ok").header("Connection", "keep-alive")
    });

    let host = server
        .url
        .trim_start_matches("http://")
        .split(':')
        .next()
        .unwrap();
    let dir = TempDir::new().unwrap();
    let config = dir.path().join("config");
    fs::write(
        &config,
        format!(
            "format = off\nretry = 1\nretry-delay = {FAST_RETRY_DELAY}\nheader = X-Global: yes\nquery = global=1\n\n[{host}]\nheader = X-Host: yes\nquery = host=1\n"
        ),
    )
    .unwrap();

    let res = run_fetch(&[
        "--config",
        config.to_str().unwrap(),
        "-H",
        "X-Cli: yes",
        "-q",
        "cli=1",
        &server.url,
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "ok");
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
}

#[test]
fn config_duplicate_host_section_is_rejected() {
    let dir = TempDir::new().unwrap();
    let config = dir.path().join("config");
    fs::write(
        &config,
        "format = off\n\n[example.com]\nheader = X-Old: yes\nquery = old=1\n\n[example.com]\nheader = X-New: yes\nquery = new=1\n",
    )
    .unwrap();
    let res = run_fetch(&["--config", config.to_str().unwrap(), "http://example.com"]);
    assert_exit(&res, 1);
    assert!(res.stdout.is_empty(), "stdout: {}", res.stdout);
    assert!(res.stderr.contains("config file"), "{}", res.stderr);
    assert!(res.stderr.contains("line 7"), "{}", res.stderr);
    assert!(
        res.stderr
            .contains("duplicate host section '[example.com]'"),
        "{}",
        res.stderr
    );
    assert!(
        res.stderr.contains("first defined on line 3"),
        "{}",
        res.stderr
    );
}

#[test]
fn default_config_search_uses_xdg_config_home() {
    let server = TestServer::start(|req| {
        if req.path.contains("default=1") && req.header("x-default") == "yes" {
            TestResponse::ok("default")
        } else {
            TestResponse::status(400, "Bad Request", "default config was not applied")
        }
    });
    let dir = TempDir::new().unwrap();
    let xdg_home = dir.path().join("xdg");
    let config_dir = xdg_home.join("fetch");
    fs::create_dir_all(&config_dir).unwrap();
    fs::write(
        config_dir.join("config"),
        "format = off\nheader = X-Default: yes\nquery = default=1\n",
    )
    .unwrap();

    let res = run_fetch_opts(
        FetchOpts {
            env: vec![
                (
                    "XDG_CONFIG_HOME".to_string(),
                    xdg_home.display().to_string(),
                ),
                (
                    "HOME".to_string(),
                    dir.path().join("home").display().to_string(),
                ),
            ],
            ..Default::default()
        },
        &[&server.url],
    );
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "default");
}

#[test]
fn basic_bearer_and_aws_auth_headers() {
    let server = TestServer::start(|req| {
        if req.path == "/basic" {
            let auth = req.header("authorization");
            let raw = auth.strip_prefix("Basic ").unwrap_or_default();
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(raw)
                .unwrap_or_default();
            assert_eq!(String::from_utf8_lossy(&decoded), "user:pass");
            return TestResponse::ok("");
        }
        if req.path == "/basic-spaces" {
            let auth = req.header("authorization");
            let raw = auth.strip_prefix("Basic ").unwrap_or_default();
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(raw)
                .unwrap_or_default();
            assert_eq!(String::from_utf8_lossy(&decoded), " user : pass ");
            return TestResponse::ok("");
        }
        if req.path == "/url-basic" {
            let auth = req.header("authorization");
            let raw = auth.strip_prefix("Basic ").unwrap_or_default();
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(raw)
                .unwrap_or_default();
            assert_eq!(String::from_utf8_lossy(&decoded), "url user:open sesame");
            return TestResponse::ok("");
        }
        if req.path == "/bearer" {
            assert_eq!(req.header("authorization"), "Bearer token");
            return TestResponse::ok("");
        }
        if req.path == "/aws" {
            if !req.header("authorization").starts_with("AWS4-HMAC-SHA256 ")
                || req.header("x-amz-date").is_empty()
                || req.header("x-amz-security-token") != "session-token"
                || !req.header("authorization").contains("x-amz-security-token")
            {
                return TestResponse::status(400, "Bad Request", "bad aws auth");
            }
            return TestResponse::ok(req.header("x-amz-content-sha256"));
        }
        TestResponse::status(404, "Not Found", "")
    });

    let res = run_fetch(&[&format!("{}/basic", server.url), "--basic", "user:pass"]);
    assert_exit(&res, 0);

    let res = run_fetch(&[
        &format!("{}/basic-spaces", server.url),
        "--basic",
        " user : pass ",
    ]);
    assert_exit(&res, 0);

    let url_with_auth = format!(
        "http://url%20user:open%20sesame@{}/url-basic",
        server.url.trim_start_matches("http://")
    );
    let res = run_fetch(&[&url_with_auth]);
    assert_exit(&res, 0);

    let res = run_fetch(&[&format!("{}/bearer", server.url), "--bearer", "token"]);
    assert_exit(&res, 0);

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
            &format!("{}/aws", server.url),
            "--aws-sigv4",
            "us-east-1/s3",
            "-vv",
        ],
    );
    assert_exit(&res, 0);
    assert_eq!(
        res.stdout,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert!(res.stderr.contains("> authorization: AWS4-HMAC-SHA256 "));
    assert!(res.stderr.contains("> x-amz-date: "));
    assert!(res.stderr.contains("> x-amz-security-token: session-token"));
    assert!(res.stderr.contains(
        "> x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ));
}

#[test]
fn digest_auth_replays_after_challenge() {
    let challenged = Arc::new(AtomicUsize::new(0));
    let challenged_for_handler = Arc::clone(&challenged);
    let server = TestServer::start(move |req| {
        let auth = req.header("authorization");
        if auth.is_empty() {
            challenged_for_handler.fetch_add(1, Ordering::SeqCst);
            return TestResponse::status(401, "Unauthorized", "").header(
                "WWW-Authenticate",
                r#"Digest realm="test", nonce="abc123", qop="auth", algorithm="MD5""#,
            );
        }
        assert!(auth.starts_with("Digest "));
        let params = parse_digest_auth_params(auth.trim_start_matches("Digest "));
        assert_eq!(params.get("username").map(String::as_str), Some("user"));
        assert_eq!(params.get("realm").map(String::as_str), Some("test"));
        let ha1 = md5_hex("user:test:pass");
        let ha2 = md5_hex(&format!("{}:{}", req.method, params["uri"]));
        let expected = md5_hex(&format!(
            "{ha1}:abc123:{}:{}:auth:{ha2}",
            params["nc"], params["cnonce"]
        ));
        assert_eq!(
            params.get("response").map(String::as_str),
            Some(expected.as_str())
        );
        TestResponse::ok(req.body)
    });

    let res = run_fetch(&[
        &server.url,
        "--digest",
        "user:pass",
        "--data",
        "hello=world",
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "hello=world");
    assert_eq!(challenged.load(Ordering::SeqCst), 1);
}

#[test]
fn digest_auth_reports_unsupported_qop_challenge() {
    let challenged = Arc::new(AtomicUsize::new(0));
    let challenged_for_handler = Arc::clone(&challenged);
    let server = TestServer::start(move |req| {
        assert!(req.header("authorization").is_empty());
        challenged_for_handler.fetch_add(1, Ordering::SeqCst);
        TestResponse::status(401, "Unauthorized", "").header(
            "WWW-Authenticate",
            r#"Digest realm="test", nonce="abc123", qop="auth-int", algorithm="MD5""#,
        )
    });

    let res = run_fetch(&[&server.url, "--digest", "user:pass"]);
    assert_exit(&res, 1);
    assert!(
        res.stderr.contains(
            "unsupported digest authentication challenge: unsupported digest qop: auth-int"
        ),
        "stderr:\n{}",
        res.stderr
    );
    assert_eq!(challenged.load(Ordering::SeqCst), 1);
}

#[test]
fn digest_auth_reports_unsupported_algorithm_challenge() {
    let challenged = Arc::new(AtomicUsize::new(0));
    let challenged_for_handler = Arc::clone(&challenged);
    let server = TestServer::start(move |req| {
        assert!(req.header("authorization").is_empty());
        challenged_for_handler.fetch_add(1, Ordering::SeqCst);
        TestResponse::status(401, "Unauthorized", "").header(
            "WWW-Authenticate",
            r#"Digest realm="test", nonce="abc123", qop="auth", algorithm="SHA-512""#,
        )
    });

    let res = run_fetch(&[&server.url, "--digest", "user:pass"]);
    assert_exit(&res, 1);
    assert!(
        res.stderr.contains(
            "unsupported digest authentication challenge: unsupported digest algorithm: sha-512"
        ),
        "stderr:\n{}",
        res.stderr
    );
    assert_eq!(challenged.load(Ordering::SeqCst), 1);
}

#[test]
fn digest_auth_rejects_stdin_body_replay_after_challenge() {
    let server = TestServer::start(|req| {
        assert!(req.header("authorization").is_empty());
        TestResponse::status(401, "Unauthorized", "").header(
            "WWW-Authenticate",
            r#"Digest realm="test", nonce="abc123", qop="auth", algorithm="MD5""#,
        )
    });

    let res = run_fetch_opts(
        FetchOpts {
            stdin: Some("hello=world".to_string()),
            ..Default::default()
        },
        &[&server.url, "--digest", "user:pass", "--data", "@-"],
    );
    assert_exit(&res, 1);
    assert!(
        res.stderr
            .contains("request body from stdin cannot be replayed for digest authentication"),
        "stderr:\n{}",
        res.stderr
    );
}

#[cfg(not(windows))]
#[test]
fn digest_auth_drain_is_bounded_for_large_challenge_body() {
    let server = PartialBodyReplayServer::start(
        401,
        "Unauthorized",
        vec![(
            "WWW-Authenticate",
            r#"Digest realm="test", nonce="abc123", qop="auth", algorithm="MD5""#,
        )],
        "authenticated",
    );

    let res = run_fetch(&[
        &server.url,
        "--digest",
        "user:pass",
        "--data",
        "hello=world",
        "--timeout",
        "3",
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "authenticated");

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].header("authorization").is_empty());
    assert!(requests[1].header("authorization").starts_with("Digest "));
    assert_eq!(requests[1].body_string(), "hello=world");
}

#[test]
fn cross_origin_redirect_strips_explicit_sensitive_headers() {
    let target = TestServer::start(|req| {
        if !req.header("authorization").is_empty()
            || !req.header("cookie").is_empty()
            || !req.header("proxy-authorization").is_empty()
        {
            return TestResponse::status(400, "Bad Request", "sensitive header leaked");
        }
        TestResponse::ok("safe")
    });
    let location = target.url.clone();
    let origin = TestServer::start(move |_| {
        TestResponse::status(302, "Found", "").header("Location", &location)
    });

    let res = run_fetch(&[
        &origin.url,
        "--header",
        "Authorization: explicit",
        "--header",
        "Cookie: sid=secret",
        "--header",
        "Proxy-Authorization: proxy-secret",
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "safe");

    let requests = target.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].header("authorization").is_empty());
    assert!(requests[0].header("cookie").is_empty());
    assert!(requests[0].header("proxy-authorization").is_empty());
}

#[test]
fn cross_origin_redirect_does_not_reapply_cli_auth() {
    for args in [vec!["--basic", "user:pass"], vec!["--bearer", "token"]] {
        let target = TestServer::start(|req| {
            if !req.header("authorization").is_empty() {
                return TestResponse::status(400, "Bad Request", "authorization leaked");
            }
            TestResponse::ok("safe")
        });
        let location = target.url.clone();
        let origin = TestServer::start(move |_| {
            TestResponse::status(302, "Found", "").header("Location", &location)
        });

        let mut fetch_args = vec![origin.url.as_str()];
        fetch_args.extend(args);
        let res = run_fetch(&fetch_args);
        assert_exit(&res, 0);
        assert_eq!(res.stdout, "safe");

        let requests = target.requests();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].header("authorization").is_empty());
    }
}

#[test]
fn cross_origin_redirect_does_not_sign_with_aws_auth() {
    let target = TestServer::start(|req| {
        if !req.header("authorization").is_empty()
            || !req.header("x-amz-date").is_empty()
            || !req.header("x-amz-security-token").is_empty()
        {
            return TestResponse::status(400, "Bad Request", "aws auth leaked");
        }
        TestResponse::ok("safe")
    });
    let location = target.url.clone();
    let origin = TestServer::start(move |_| {
        TestResponse::status(302, "Found", "").header("Location", &location)
    });

    let res = run_fetch_opts(
        FetchOpts {
            env: vec![
                ("AWS_ACCESS_KEY_ID".to_string(), "1234".to_string()),
                ("AWS_SECRET_ACCESS_KEY".to_string(), "5678".to_string()),
                ("AWS_SESSION_TOKEN".to_string(), "session-token".to_string()),
            ],
            ..Default::default()
        },
        &[&origin.url, "--aws-sigv4", "us-east-1/s3"],
    );
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "safe");

    let requests = target.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].header("authorization").is_empty());
    assert!(requests[0].header("x-amz-date").is_empty());
    assert!(requests[0].header("x-amz-security-token").is_empty());
}

#[test]
fn cross_origin_redirect_does_not_retry_digest_auth() {
    let target = TestServer::start(|req| {
        if !req.header("authorization").is_empty() {
            return TestResponse::status(400, "Bad Request", "digest auth leaked");
        }
        TestResponse::status(401, "Unauthorized", "").header(
            "WWW-Authenticate",
            r#"Digest realm="test", nonce="abc123", qop="auth", algorithm="MD5""#,
        )
    });
    let location = target.url.clone();
    let origin = TestServer::start(move |_| {
        TestResponse::status(302, "Found", "").header("Location", &location)
    });

    let res = run_fetch(&[&origin.url, "--digest", "user:pass"]);
    assert_exit(&res, 4);

    let requests = target.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].header("authorization").is_empty());
}

#[test]
fn redirects_range_status_and_timeouts() {
    let server = TestServer::start(|req| match req.path.as_str() {
        "/start" => TestResponse::status(302, "Found", "")
            .header("Location", "/final")
            .header("Connection", "keep-alive"),
        "/final" => TestResponse::ok("redirected"),
        "/range" => {
            assert_eq!(req.header("range"), "bytes=2-5");
            TestResponse::status(206, "Partial Content", "cdef")
        }
        "/missing" => TestResponse::status(404, "Not Found", "missing"),
        _ => TestResponse::ok("ok"),
    });

    let res = run_fetch(&[&format!("{}/start", server.url)]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "redirected");

    let res = run_fetch(&[&format!("{}/start", server.url), "--redirects", "0"]);
    assert_exit(&res, 0);
    assert!(res.stderr.contains("302 Found"));

    let res = run_fetch(&[&format!("{}/range", server.url), "--range", "2-5"]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "cdef");

    let res = run_fetch(&[&format!("{}/missing", server.url)]);
    assert_exit(&res, 4);
    assert_eq!(res.stdout, "missing");

    let res = run_fetch(&[&format!("{}/missing", server.url), "--ignore-status"]);
    assert_exit(&res, 0);
}

#[test]
fn post_to_get_redirect_strips_entity_headers() {
    let server = TestServer::start(|req| match req.path.as_str() {
        "/start" => TestResponse::status(302, "Found", "")
            .header("Location", "/final")
            .header("Connection", "keep-alive"),
        "/final" => {
            if !req.header("content-type").is_empty()
                || !req.header("content-length").is_empty()
                || !req.header("transfer-encoding").is_empty()
            {
                return TestResponse::status(400, "Bad Request", "entity header retained");
            }
            assert_eq!(req.method, "GET");
            assert!(req.body.is_empty());
            TestResponse::ok("clean")
        }
        _ => TestResponse::status(404, "Not Found", "missing"),
    });

    let res = run_fetch(&[
        &format!("{}/start", server.url),
        "--data",
        "payload",
        "--header",
        "Content-Length: 7",
        "--header",
        "Transfer-Encoding: identity",
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "clean");
}

#[test]
fn retry_statuses_and_request_body_replay() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_for_handler = Arc::clone(&attempts);
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let bodies_for_handler = Arc::clone(&bodies);
    let server = TestServer::start(move |req| {
        bodies_for_handler.lock().unwrap().push(req.body_string());
        if attempts_for_handler.fetch_add(1, Ordering::SeqCst) == 0 {
            TestResponse::status(503, "Service Unavailable", "retry")
                .header("Connection", "keep-alive")
        } else {
            TestResponse::ok("done").header("Connection", "keep-alive")
        }
    });

    let res = run_fetch(&[
        &server.url,
        "--retry",
        "1",
        "--retry-delay",
        FAST_RETRY_DELAY,
        "--data",
        "payload",
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "done");
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert_eq!(
        *bodies.lock().unwrap(),
        vec!["payload".to_string(), "payload".to_string()]
    );

    let res = run_fetch(&[
        &server.url,
        "--retry",
        "0",
        "--retry-delay",
        FAST_RETRY_DELAY,
        "--data",
        "payload",
    ]);
    assert_exit(&res, 0);
}

#[test]
fn retry_status_delay_obeys_request_timeout_budget() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_for_handler = Arc::clone(&attempts);
    let server = TestServer::start(move |_| {
        if attempts_for_handler.fetch_add(1, Ordering::SeqCst) == 0 {
            TestResponse::status(503, "Service Unavailable", "retry")
                .header("Connection", "keep-alive")
        } else {
            TestResponse::ok("done").header("Connection", "keep-alive")
        }
    });

    let start = Instant::now();
    let res = run_fetch(&[
        &server.url,
        "--retry",
        "1",
        "--retry-delay",
        "3",
        "--timeout",
        "0.25",
    ]);
    let elapsed = start.elapsed();

    assert_exit(&res, 1);
    assert!(
        res.stderr.contains("request timed out after 250ms"),
        "stderr:\n{}",
        res.stderr
    );
    assert!(
        elapsed < Duration::from_millis(1500),
        "retry delay was not capped; elapsed: {elapsed:?}\nstdout:\n{}\nstderr:\n{}",
        res.stdout,
        res.stderr
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
}

#[test]
fn retry_transport_error_delay_obeys_request_timeout_budget() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind unused port");
    let addr = listener.local_addr().expect("unused port local addr");
    drop(listener);
    let url = format!("http://{addr}");

    let start = Instant::now();
    let res = run_fetch_once(
        FetchOpts::default(),
        &[
            &url,
            "--retry",
            "1",
            "--retry-delay",
            "3",
            "--timeout",
            "0.25",
        ],
    );
    let elapsed = start.elapsed();

    assert_exit(&res, 1);
    assert!(
        res.stderr.contains("request timed out after 250ms"),
        "stderr:\n{}",
        res.stderr
    );
    assert!(
        elapsed < Duration::from_millis(1500),
        "retry delay was not capped; elapsed: {elapsed:?}\nstdout:\n{}\nstderr:\n{}",
        res.stdout,
        res.stderr
    );
}

#[test]
fn retry_status_rejects_stdin_body_replay() {
    let server = TestServer::start(|_| {
        TestResponse::status(503, "Service Unavailable", "retry").header("Connection", "keep-alive")
    });

    let res = run_fetch_opts(
        FetchOpts {
            stdin: Some("payload".to_string()),
            ..Default::default()
        },
        &[
            &server.url,
            "--retry",
            "1",
            "--retry-delay",
            FAST_RETRY_DELAY,
            "--data",
            "@-",
        ],
    );
    assert_exit(&res, 1);
    assert!(
        res.stderr
            .contains("request body from stdin cannot be replayed for retry"),
        "stderr:\n{}",
        res.stderr
    );
}

#[test]
fn retry_after_bodyless_redirect_rejects_original_stdin_body_replay() {
    let server = TestServer::start(|req| match req.path.as_str() {
        "/start" => TestResponse::status(303, "See Other", "")
            .header("Location", "/final")
            .header("Connection", "keep-alive"),
        "/final" => TestResponse::status(503, "Service Unavailable", "retry")
            .header("Connection", "keep-alive"),
        _ => TestResponse::status(404, "Not Found", "missing"),
    });

    let res = run_fetch_opts(
        FetchOpts {
            stdin: Some("payload".to_string()),
            ..Default::default()
        },
        &[
            &format!("{}/start", server.url),
            "-m",
            "POST",
            "--retry",
            "1",
            "--retry-delay",
            FAST_RETRY_DELAY,
            "--data",
            "@-",
        ],
    );
    assert_exit(&res, 1);
    assert!(
        res.stderr
            .contains("request body from stdin cannot be replayed for retry"),
        "stderr:\n{}",
        res.stderr
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 2, "requests: {requests:?}");
    assert_eq!(requests[0].path, "/start");
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].body_string(), "payload");
    assert_eq!(requests[1].path, "/final");
    assert_eq!(requests[1].method, "GET");
    assert!(requests[1].body.is_empty());
    assert_eq!(
        requests.iter().filter(|req| req.path == "/start").count(),
        1,
        "unexpected second initial request: {requests:?}"
    );
}

#[test]
#[cfg_attr(
    windows,
    ignore = "Windows can report a socket abort when the bounded retry drain abandons a large body"
)]
fn retry_status_drain_is_bounded_for_large_error_body() {
    let server = PartialBodyReplayServer::start(503, "Service Unavailable", Vec::new(), "retried");

    let res = run_fetch(&[
        &server.url,
        "--retry",
        "1",
        "--retry-delay",
        FAST_RETRY_DELAY,
        "--timeout",
        "3",
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "retried");
    assert_eq!(server.requests().len(), 2);
}

#[test]
#[cfg_attr(
    windows,
    ignore = "Windows CI can refuse the replay connection before the compressed SSE retry completes"
)]
fn compressed_sse_retry_drains_first_response_before_replay() {
    let mut gzip_sse = GzEncoder::new(Vec::new(), Compression::none());
    gzip_sse.write_all(b"data: compressed\n\n").unwrap();
    let gzip_sse_body = gzip_sse.finish().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind compressed sse retry server");
    listener
        .set_nonblocking(true)
        .expect("set compressed sse retry listener nonblocking");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    let (outcome_tx, outcome_rx) = mpsc::channel();
    let join = thread::spawn(move || {
        let result = (|| -> Result<Duration, String> {
            let mut first_stream = accept_tcp_connection(
                &listener,
                Duration::from_secs(10),
                "first compressed SSE request",
            )?;
            first_stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .map_err(|err| format!("set first read timeout: {err}"))?;
            first_stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .map_err(|err| format!("set first write timeout: {err}"))?;
            let reader_stream = first_stream
                .try_clone()
                .map_err(|err| format!("clone first compressed SSE stream: {err}"))?;
            let mut reader = BufReader::new(reader_stream);
            let first_req = read_request(&mut reader)
                .ok_or_else(|| "read first compressed SSE request".to_string())?;
            if first_req.header("accept-encoding") != "gzip, br, zstd" {
                return Err(format!(
                    "unexpected first Accept-Encoding: {:?}",
                    first_req.header("accept-encoding")
                ));
            }

            write!(
                first_stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n{:x}\r\n",
                gzip_sse_body.len(),
            )
            .map_err(|err| format!("write first compressed SSE headers: {err}"))?;
            first_stream
                .write_all(&gzip_sse_body)
                .and_then(|_| first_stream.write_all(b"\r\n"))
                .and_then(|_| first_stream.flush())
                .map_err(|err| format!("write first compressed SSE chunk: {err}"))?;

            let retry_started_at = Instant::now();
            let mut retry_stream = accept_tcp_connection(
                &listener,
                Duration::from_secs(10),
                "uncompressed SSE retry on a new connection",
            )?;
            let retry_elapsed = retry_started_at.elapsed();
            let _ = first_stream.shutdown(Shutdown::Both);
            retry_stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .map_err(|err| format!("set retry read timeout: {err}"))?;
            retry_stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .map_err(|err| format!("set retry write timeout: {err}"))?;
            let retry_reader_stream = retry_stream
                .try_clone()
                .map_err(|err| format!("clone uncompressed SSE retry stream: {err}"))?;
            let mut retry_reader = BufReader::new(retry_reader_stream);
            let retry_req = read_request(&mut retry_reader)
                .ok_or_else(|| "read uncompressed SSE retry request".to_string())?;
            if !retry_req.header("accept-encoding").is_empty() {
                return Err(format!(
                    "unexpected retry Accept-Encoding on new connection: {:?}",
                    retry_req.header("accept-encoding")
                ));
            }
            write_response(
                &mut retry_stream,
                TestResponse::ok("data: uncompressed\n\n")
                    .header("Content-Type", "text/event-stream")
                    .header("Connection", "close"),
            );
            let _ = retry_stream.shutdown(Shutdown::Both);
            Ok(retry_elapsed)
        })();
        let _ = outcome_tx.send(result);
    });

    let res = run_fetch(&[&url, "--format", "on"]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "event: message\ndata: uncompressed\n\n");
    let retry_elapsed = outcome_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("compressed SSE retry server outcome")
        .expect("compressed SSE retry server error");
    assert!(
        retry_elapsed >= Duration::from_millis(100),
        "compressed SSE retry did not wait for the bounded first-response drain; elapsed {retry_elapsed:?}"
    );
    join.join().unwrap();
}

#[test]
fn output_file_modes_match_go_harness() {
    let server = TestServer::start(|req| match req.path.as_str() {
        "/file.txt" => TestResponse::ok("file-body"),
        "/header" => TestResponse::ok("header-body").header(
            "Content-Disposition",
            "attachment; filename=\"from-header.txt\"",
        ),
        "/missing-header.txt" => TestResponse::ok("missing-header-body"),
        "/invalid-header.txt" => TestResponse::ok("invalid-header-body")
            .header("Content-Disposition", "attachment; filename=\"..\""),
        "/traversal" => TestResponse::ok("bad")
            .header("Content-Disposition", "attachment; filename=\"../bad.txt\""),
        _ => TestResponse::ok("body"),
    });
    let dir = TempDir::new().unwrap();

    let res = run_fetch_opts(
        FetchOpts {
            cwd: Some(dir.path().to_path_buf()),
            ..Default::default()
        },
        &[&format!("{}/file.txt", server.url), "--remote-name"],
    );
    assert_exit(&res, 0);
    assert_eq!(
        fs::read_to_string(dir.path().join("file.txt")).unwrap(),
        "file-body"
    );

    let res = run_fetch_opts(
        FetchOpts {
            cwd: Some(dir.path().to_path_buf()),
            ..Default::default()
        },
        &[
            &format!("{}/header", server.url),
            "--remote-name",
            "--remote-header-name",
        ],
    );
    assert_exit(&res, 0);
    assert_eq!(
        fs::read_to_string(dir.path().join("from-header.txt")).unwrap(),
        "header-body"
    );
    assert!(
        !res.stderr
            .contains("Content-Disposition filename was not usable"),
        "stderr:\n{}",
        res.stderr
    );

    let res = run_fetch_opts(
        FetchOpts {
            cwd: Some(dir.path().to_path_buf()),
            ..Default::default()
        },
        &[
            &format!("{}/missing-header.txt", server.url),
            "--remote-name",
            "--remote-header-name",
        ],
    );
    assert_exit(&res, 0);
    assert_eq!(
        fs::read_to_string(dir.path().join("missing-header.txt")).unwrap(),
        "missing-header-body"
    );
    assert!(
        res.stderr.contains(
            "warning: Content-Disposition filename was not usable; falling back to URL filename"
        ),
        "stderr:\n{}",
        res.stderr
    );

    let res = run_fetch_opts(
        FetchOpts {
            cwd: Some(dir.path().to_path_buf()),
            ..Default::default()
        },
        &[
            &format!("{}/invalid-header.txt", server.url),
            "--remote-name",
            "--remote-header-name",
        ],
    );
    assert_exit(&res, 0);
    assert_eq!(
        fs::read_to_string(dir.path().join("invalid-header.txt")).unwrap(),
        "invalid-header-body"
    );
    assert!(
        res.stderr.contains(
            "warning: Content-Disposition filename was not usable; falling back to URL filename"
        ),
        "stderr:\n{}",
        res.stderr
    );

    let out = dir.path().join("explicit.txt");
    let res = run_fetch(&[
        &format!("{}/file.txt", server.url),
        "--output",
        out.to_str().unwrap(),
    ]);
    assert_exit(&res, 0);
    assert_eq!(fs::read_to_string(&out).unwrap(), "file-body");

    let res = run_fetch(&[
        &format!("{}/file.txt", server.url),
        "--output",
        out.to_str().unwrap(),
    ]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("already exists"));

    let res = run_fetch(&[
        &format!("{}/file.txt", server.url),
        "--output",
        out.to_str().unwrap(),
        "--clobber",
    ]);
    assert_exit(&res, 0);
    assert_eq!(fs::read_to_string(&out).unwrap(), "file-body");

    let res = run_fetch_opts(
        FetchOpts {
            cwd: Some(dir.path().to_path_buf()),
            ..Default::default()
        },
        &[
            &format!("{}/traversal", server.url),
            "--remote-name",
            "--remote-header-name",
        ],
    );
    assert_exit(&res, 0);
    assert_eq!(
        fs::read_to_string(dir.path().join("bad.txt")).unwrap(),
        "bad"
    );
    assert!(!dir.path().join("..").join("bad.txt").exists());
}

#[test]
fn from_curl_parses_common_forms_and_errors() {
    let server = TestServer::start(|req| {
        if req.path.contains("curl=1")
            && req.header("x-curl") == "yes"
            && req.body_string() == "payload"
        {
            TestResponse::ok("curl-ok")
        } else {
            TestResponse::status(400, "Bad Request", "bad curl")
        }
    });

    let curl = format!(
        "curl -X POST -H 'X-Curl: yes' --data payload '{}?curl=1'",
        server.url
    );
    let res = run_fetch(&["--from-curl", &curl]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "curl-ok");

    let res = run_fetch(&["--from-curl", &curl, "http://example.com"]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("--from-curl"));

    let res = run_fetch(&["--from-curl", "curl --not-a-real-flag http://example.com"]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("unsupported curl flag"));

    let netrc_server = TestServer::start(|_| TestResponse::ok("netrc should not be requested"));
    let curl = format!("curl --netrc {}", netrc_server.url);
    let res = run_fetch(&["--from-curl", &curl]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("--netrc"));
    assert!(res.stderr.contains("--basic"));
    assert!(res.stderr.contains("--bearer"));
    assert!(res.stderr.contains("Authorization"));
    assert!(netrc_server.requests().is_empty());
}

#[test]
fn request_construction_host_header_form_and_http_version() {
    let server = TestServer::start(|req| {
        TestResponse::ok(format!(
            "{} {} {}",
            req.method,
            req.path,
            req.header("host")
        ))
    });
    let dir = TempDir::new().unwrap();
    let payload = temp_file(dir.path(), "payload.json", r#"{"ok":true}"#);

    let res = run_fetch(&[
        &format!("{}?z=old", server.url),
        "--method",
        "PUT",
        "-H",
        "X-Custom: value",
        "-q",
        "a=one",
        "-q",
        "z=two",
        "--data",
        &format!("@{}", payload.display()),
    ]);
    assert_exit(&res, 0);
    let req = wait_for_requests(&server, 1).remove(0);
    assert_eq!(req.method, "PUT");
    assert_eq!(req.path, "/?z=old&a=one&z=two");
    assert_eq!(req.header("content-type"), "application/json");
    assert_eq!(req.header("x-custom"), "value");
    assert_eq!(req.body_string(), r#"{"ok":true}"#);

    let res = run_fetch(&["-H", ": value", &server.url]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("invalid value ': value'"));

    let res = run_fetch(&["-H", "Host: vhost.example", &server.url]);
    assert_exit(&res, 0);
    let req = wait_for_requests(&server, 2).remove(1);
    assert_eq!(req.header("host"), "vhost.example");

    let form_server = TestServer::start(|req| {
        if req.body_string().contains("key1=val1")
            && req.body_string().contains("key2=val2")
            && req.header("content-type") == "application/x-www-form-urlencoded"
        {
            TestResponse::ok("")
        } else {
            TestResponse::status(400, "Bad Request", req.body)
        }
    });
    let res = run_fetch(&[&form_server.url, "-f", "key1=val1", "-f", "key2=val2"]);
    assert_exit(&res, 0);
    let req = wait_for_requests(&form_server, 1).remove(0);
    assert_eq!(req.method, "POST");

    let res = run_fetch(&[&server.url, "--http", "1"]);
    assert_exit(&res, 0);
    let res = run_fetch(&[&server.url, "--http", "2"]);
    assert_exit(&res, 1);
    assert!(
        res.stderr.contains(
            "plain HTTP/2 is only supported for gRPC h2c; use https://, --grpc, or --http 1."
        ),
        "{}",
        res.stderr
    );

    let res = run_fetch(&[&server.url, "--http2"]);
    assert_exit(&res, 1);
    assert!(
        res.stderr.contains(
            "plain HTTP/2 is only supported for gRPC h2c; use https://, --grpc, or --http 1."
        ),
        "{}",
        res.stderr
    );
}

#[test]
fn request_query_form_and_multipart_values_preserve_spaces_after_equals() {
    let server = TestServer::start(|_| TestResponse::ok(""));

    let res = run_fetch(&[&server.url, "--query", "q= hello "]);
    assert_exit(&res, 0);
    let req = wait_for_requests(&server, 1).remove(0);
    assert_eq!(req.path, "/?q=+hello+");

    let res = run_fetch(&[&server.url, "--form", "message= hello "]);
    assert_exit(&res, 0);
    let req = wait_for_requests(&server, 2).remove(1);
    assert_eq!(
        req.header("content-type"),
        "application/x-www-form-urlencoded"
    );
    assert_eq!(req.body_string(), "message=+hello+");

    let res = run_fetch(&[&server.url, "--multipart", "note= hello "]);
    assert_exit(&res, 0);
    let req = wait_for_requests(&server, 3).remove(2);
    assert!(
        req.header("content-type")
            .starts_with("multipart/form-data; boundary=")
    );
    let body = req.body_string();
    assert!(body.contains("name=\"note\"\r\n\r\n hello \r\n"), "{body}");
}

#[test]
fn detailed_output_status_range_redirect_and_unix_edges() {
    let statuses = Arc::new(AtomicUsize::new(200));
    let statuses_for_handler = Arc::clone(&statuses);
    let server = TestServer::start(move |_| {
        let status = statuses_for_handler.load(Ordering::SeqCst) as u16;
        TestResponse::status(status, "Status", "body")
    });
    for (status, exit) in [(200, 0), (400, 4), (500, 5), (999, 6)] {
        statuses.store(status, Ordering::SeqCst);
        let res = run_fetch(&[&server.url]);
        assert_exit(&res, exit);
        let res = run_fetch(&[&server.url, "--ignore-status"]);
        assert_exit(&res, 0);
    }

    let expected_range = Arc::new(Mutex::new(String::new()));
    let expected_for_handler = Arc::clone(&expected_range);
    let range_server = TestServer::start(move |req| {
        if req.header("range") == *expected_for_handler.lock().unwrap() {
            TestResponse::ok("")
        } else {
            TestResponse::status(400, "Bad Request", req.header("range"))
        }
    });
    let res = run_fetch(&[&range_server.url, "--range", "bad"]);
    assert_exit(&res, 1);
    for (flag, want) in [
        ("-1023", "bytes=-1023"),
        ("1023-", "bytes=1023-"),
        ("0-1023", "bytes=0-1023"),
    ] {
        *expected_range.lock().unwrap() = want.to_string();
        let res = run_fetch(&[&range_server.url, "--range", flag]);
        assert_exit(&res, 0);
    }

    let redirect_count = Arc::new(AtomicUsize::new(0));
    let redirect_count_for_handler = Arc::clone(&redirect_count);
    let redirect_url = Arc::new(Mutex::new(String::new()));
    let redirect_url_for_handler = Arc::clone(&redirect_url);
    let redirect_server = TestServer::start(move |_| {
        if redirect_count_for_handler
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1))
            .is_ok()
        {
            TestResponse::status(301, "Moved Permanently", "")
                .header("Location", &redirect_url_for_handler.lock().unwrap())
                .header("Connection", "keep-alive")
        } else {
            TestResponse::ok("redirect-ok")
        }
    });
    *redirect_url.lock().unwrap() = redirect_server.url.clone();
    redirect_count.store(1, Ordering::SeqCst);
    let res = run_fetch(&[&redirect_server.url, "--redirects", "0"]);
    assert_exit(&res, 0);
    assert!(res.stderr.contains("301 Moved Permanently"));
    redirect_count.store(2, Ordering::SeqCst);
    let res = run_fetch(&[&redirect_server.url, "--redirects", "1"]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("exceeded maximum number of redirects"));
    assert!(!res.stderr.contains("For more information"));
}

#[test]
fn from_curl_individual_go_cases() {
    let server = TestServer::start(|req| {
        if req.path == "/get" && req.method == "GET" {
            return TestResponse::ok("get");
        }
        if req.path == "/post" && req.method == "POST" && req.body_string() == "data" {
            return TestResponse::ok("post");
        }
        if req.path == "/headers" && req.header("x-test") == "yes" {
            return TestResponse::ok("headers");
        }
        if req.path == "/auth" && req.header("authorization").starts_with("Basic ") {
            let raw = req
                .header("authorization")
                .trim_start_matches("Basic ")
                .to_string();
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(raw)
                .unwrap_or_default();
            return TestResponse::ok(decoded);
        }
        if req.path == "/key-only" {
            return TestResponse::ok("key-only-curl-ok");
        }
        if req.path == "/verbose" {
            return TestResponse::ok("ok").header("X-Test-Header", "visible");
        }
        if req.path == "/retry" {
            return TestResponse::ok("retry");
        }
        if req.path == "/proto-allow" {
            return TestResponse::ok("proto-ok");
        }
        TestResponse::status(400, "Bad Request", format!("{req:?}"))
    });

    for curl in [
        format!("curl {}/get", server.url),
        format!("{}/get", server.url),
    ] {
        let res = run_fetch(&["--from-curl", &curl]);
        assert_exit(&res, 0);
        assert_eq!(res.stdout, "get");
    }
    let res = run_fetch(&["--from-curl", &format!("curl -d data {}/post", server.url)]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "post");
    let res = run_fetch(&[
        "--from-curl",
        &format!("curl -H 'X-Test: yes' {}/headers", server.url),
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "headers");
    let res = run_fetch(&[
        "--from-curl",
        &format!("curl -u user:pass {}/auth", server.url),
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "user:pass");
    let dir = TempDir::new().unwrap();
    let key = temp_file(dir.path(), "curl-client.key", "fake-key");
    let res = run_fetch(&[
        "--from-curl",
        &format!("curl --key {} {}/key-only", key.display(), server.url),
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "key-only-curl-ok");
    let res = run_fetch(&[
        "--from-curl",
        &format!("curl --key {} https://example.com/key-only", key.display()),
    ]);
    assert_exit(&res, 1);
    assert!(
        res.stderr
            .contains("client key requires a client certificate")
    );
    let res = run_fetch(&["--from-curl", &format!("curl -v {}/verbose", server.url)]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "ok");
    assert!(res.stderr.to_ascii_lowercase().contains("x-test-header"));
    let res = run_fetch(&[
        "--from-curl",
        &format!("curl --retry 1 {}/retry", server.url),
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "retry");

    let res = run_fetch(&[
        "--from-curl",
        &format!("curl {}", server.url),
        "--method",
        "POST",
    ]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("--from-curl"));
    let res = run_fetch(&[
        "--from-curl",
        &format!("curl {}", server.url),
        "https://other.example",
    ]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("cannot be used together"));
    let res = run_fetch(&["--from-curl", "curl"]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("URL"));
    let res = run_fetch(&["--from-curl", "curl --unknown-flag https://example.com"]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("unsupported curl flag"));
    let res = run_fetch(&[
        "--from-curl",
        &format!("curl --proto =https {}", server.url),
    ]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("proto"));
    let res = run_fetch(&[
        "--from-curl",
        "curl --proto =https https://example.com",
        "--dry-run",
    ]);
    assert_exit(&res, 0);
    assert!(res.stderr.contains("GET"));
    assert!(res.stderr.contains("example.com"));
    let res = run_fetch(&[
        "--from-curl",
        &format!("curl --proto '=http,https' {}/proto-allow", server.url),
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "proto-ok");
}

#[test]
fn edit_request_body_matches_go_harness() {
    let server = TestServer::start(|req| {
        if req.method == "POST"
            && req.body_string() == r#"{"edited":true}"#
            && req.header("content-type") == "application/json"
        {
            TestResponse::ok("ok")
        } else {
            TestResponse::status(400, "Bad Request", format!("{req:?}"))
        }
    });
    let dir = TempDir::new().unwrap();
    let editor = fake_editor(dir.path(), r#"{"edited":true}"#, 0);
    let res = run_fetch_opts(
        FetchOpts {
            env: vec![
                ("VISUAL".to_string(), String::new()),
                ("EDITOR".to_string(), editor.display().to_string()),
            ],
            ..Default::default()
        },
        &[&server.url, "--edit", "--json", r#"{"template":true}"#],
    );
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "ok");

    let empty_editor = fake_editor(dir.path(), "", 0);
    let res = run_fetch_opts(
        FetchOpts {
            env: vec![
                ("VISUAL".to_string(), String::new()),
                ("EDITOR".to_string(), empty_editor.display().to_string()),
            ],
            ..Default::default()
        },
        &[&server.url, "--edit", "--data", "template"],
    );
    assert_exit(&res, 1);
    assert!(
        res.stderr
            .contains("aborting request due to empty request body after editing")
    );
}

#[test]
fn multipart_form_and_redirect_replay() {
    let seen = Arc::new(AtomicUsize::new(0));
    let seen_for_handler = Arc::clone(&seen);
    let server = TestServer::start(move |req| {
        seen_for_handler.fetch_add(1, Ordering::SeqCst);
        if req.path == "/start" {
            return TestResponse::status(307, "Temporary Redirect", "")
                .header("Location", "/final")
                .header("Connection", "keep-alive");
        }
        if req.path != "/" && req.path != "/final" {
            return TestResponse::status(404, "Not Found", "");
        }
        let ct = req.header("content-type");
        let body = req.body_string();
        if !ct.starts_with("multipart/form-data; boundary=")
            || !body.contains("name=\"key1\"")
            || !body.contains("val1")
            || !body.contains("name=\"file1\"")
            || !body.contains("redirected file")
        {
            return TestResponse::status(400, "Bad Request", format!("{ct}\n{body}"));
        }
        TestResponse::ok("multipart-ok")
    });
    let dir = TempDir::new().unwrap();
    let file = temp_file(dir.path(), "file.jpg", "redirected file");
    let res = run_fetch(&[
        &server.url,
        "-F",
        "key1=val1",
        "-F",
        &format!("file1=@{}", file.display()),
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "multipart-ok");

    let res = run_fetch(&[
        &format!("{}/start", server.url),
        "-m",
        "POST",
        "-F",
        "key1=val1",
        "-F",
        &format!("file1=@{}", file.display()),
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "multipart-ok");
    assert!(seen.load(Ordering::SeqCst) >= 3);
}

#[test]
fn timeout_copy_discard_and_session_cases() {
    let slow = TestServer::start(|_| {
        thread::sleep(Duration::from_millis(250));
        TestResponse::ok("slow")
    });
    let res = run_fetch(&[&slow.url, "-t", "0.0000001"]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("request timed out after 100ns"));
    assert!(!res.stderr.contains("For more information"));

    let copy_server = TestServer::start(|req| {
        if req.path == "/sse" {
            return TestResponse::ok("data: one\n\n").header("Content-Type", "text/event-stream");
        }
        if req.path == "/ndjson" {
            return TestResponse::ok("{\"a\":1}\n{\"b\":2}\n")
                .header("Content-Type", "application/x-ndjson");
        }
        if req.path == "/head" || req.method == "HEAD" {
            return TestResponse::ok("");
        }
        if req.path == "/verbose" {
            return TestResponse::ok("body content").header("X-Test", "value");
        }
        if req.path == "/missing" {
            return TestResponse::status(404, "Not Found", "not found");
        }
        TestResponse::ok("copy-body")
    });
    let clipboard_dir = TempDir::new().unwrap();
    let clipboard_path = clipboard_dir.path().to_string_lossy().into_owned();
    #[cfg(unix)]
    let clipboard_file = {
        let clipboard_file = clipboard_dir.path().join("clipboard.txt");
        for command in ["pbcopy", "wl-copy", "xclip", "xsel"] {
            let script = clipboard_dir.path().join(command);
            fs::write(
                &script,
                format!("#!/bin/sh\n/bin/cat > '{}'\n", clipboard_file.display()),
            )
            .unwrap();
            let mut perms = fs::metadata(&script).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script, perms).unwrap();
        }
        clipboard_file
    };
    let copy_opts = || FetchOpts {
        env: vec![("PATH".to_string(), clipboard_path.clone())],
        ..FetchOpts::default()
    };

    let res = run_fetch_opts(copy_opts(), &[&copy_server.url, "--copy"]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "copy-body");
    #[cfg(unix)]
    assert_eq!(fs::read_to_string(&clipboard_file).unwrap(), "copy-body");
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("copy-output.txt");
    let res = run_fetch_opts(
        copy_opts(),
        &[&copy_server.url, "--copy", "-o", out.to_str().unwrap()],
    );
    assert_exit(&res, 0);
    assert_eq!(fs::read_to_string(&out).unwrap(), "copy-body");
    #[cfg(unix)]
    assert_eq!(fs::read_to_string(&clipboard_file).unwrap(), "copy-body");
    let res = run_fetch_opts(
        copy_opts(),
        &[
            &format!("{}/sse", copy_server.url),
            "--copy",
            "--format",
            "off",
        ],
    );
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "data: one\n\n");
    #[cfg(unix)]
    assert_eq!(
        fs::read_to_string(&clipboard_file).unwrap(),
        "data: one\n\n"
    );
    assert!(!res.stderr.contains("not supported"));
    let res = run_fetch_opts(
        copy_opts(),
        &[
            &format!("{}/ndjson", copy_server.url),
            "--copy",
            "--format",
            "off",
        ],
    );
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "{\"a\":1}\n{\"b\":2}\n");
    #[cfg(unix)]
    assert_eq!(
        fs::read_to_string(&clipboard_file).unwrap(),
        "{\"a\":1}\n{\"b\":2}\n"
    );
    assert!(!res.stderr.contains("not supported"));
    let res = run_fetch_opts(
        copy_opts(),
        &[&format!("{}/head", copy_server.url), "--copy", "-m", "HEAD"],
    );
    assert_exit(&res, 0);
    assert!(res.stdout.is_empty());
    #[cfg(unix)]
    assert_eq!(fs::read_to_string(&clipboard_file).unwrap(), "");
    let res = run_fetch_opts(copy_opts(), &[&copy_server.url, "--copy", "-s"]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "copy-body");
    #[cfg(unix)]
    assert_eq!(fs::read_to_string(&clipboard_file).unwrap(), "copy-body");
    assert!(!res.stderr.contains("200 OK"));

    let res = run_fetch(&[&copy_server.url, "--discard"]);
    assert_exit(&res, 0);
    assert!(res.stdout.is_empty());
    assert!(res.stderr.contains("HTTP/1.1 200 OK"));
    let res = run_fetch(&[&format!("{}/verbose", copy_server.url), "--discard", "-v"]);
    assert_exit(&res, 0);
    assert!(res.stdout.is_empty());
    assert!(res.stderr.to_ascii_lowercase().contains("x-test"));
    let res = run_fetch(&[&copy_server.url, "--discard", "--timing"]);
    assert_exit(&res, 0);
    assert!(res.stdout.is_empty());
    assert!(res.stderr.contains("TTFB"));
    let res = run_fetch(&[&format!("{}/missing", copy_server.url), "--discard"]);
    assert_exit(&res, 4);
    assert!(res.stdout.is_empty());
    let res = run_fetch(&[&copy_server.url, "--discard", "-s"]);
    assert_exit(&res, 0);
    assert!(res.stdout.is_empty());
    assert!(res.stderr.is_empty());
    let direct_out = dir.path().join("discard-output.txt");
    let res = run_fetch(&[
        &copy_server.url,
        "--discard",
        "-o",
        direct_out.to_str().unwrap(),
    ]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("cannot be used together") || res.stderr.contains("exclusive"));
    let res = run_fetch(&[&copy_server.url, "--discard", "--copy"]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("cannot be used together") || res.stderr.contains("exclusive"));
    let res = run_fetch(&[&copy_server.url, "--discard", "-O"]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("cannot be used together") || res.stderr.contains("exclusive"));

    let session_hits = Arc::new(AtomicUsize::new(0));
    let session_hits_for_handler = Arc::clone(&session_hits);
    let session_server = TestServer::start(move |req| {
        if req.path == "/login" {
            session_hits_for_handler.fetch_add(1, Ordering::SeqCst);
            return TestResponse::ok("logged in").header("Set-Cookie", "sid=abc; Path=/");
        }
        if req.path == "/set-expiry" {
            return TestResponse::ok("set")
                .header(
                    "Set-Cookie",
                    "expired=old; Path=/; Expires=Wed, 21 Oct 2015 07:28:00 GMT",
                )
                .header(
                    "Set-Cookie",
                    "valid=yes; Path=/; Expires=Wed, 21 Oct 2037 07:28:00 GMT",
                );
        }
        if req.path == "/check-expiry" {
            let cookie = req.header("cookie");
            if cookie.contains("expired=old") {
                return TestResponse::status(400, "Bad Request", "expired cookie was sent");
            }
            if cookie.contains("valid=yes") {
                return TestResponse::ok("ok");
            }
            return TestResponse::status(400, "Bad Request", "valid cookie missing");
        }
        if req.path.starts_with("/set-isolated") {
            let value = req.path.split("v=").nth(1).unwrap_or_default();
            return TestResponse::ok("set").header("Set-Cookie", &format!("token={value}; Path=/"));
        }
        if req.path == "/get-isolated" {
            let cookie = req.header("cookie");
            if let Some(start) = cookie.find("token=") {
                let value = &cookie[start + "token=".len()..];
                let value = value.split(';').next().unwrap_or(value);
                return TestResponse::ok(value.as_bytes().to_vec());
            }
            return TestResponse::ok("none");
        }
        if req.path == "/dashboard" && req.header("cookie").contains("sid=abc") {
            return TestResponse::ok("welcome");
        }
        TestResponse::status(401, "Unauthorized", "unauthorized")
    });
    let sessions_dir = dir.path().join("sessions");
    let env = vec![(
        "FETCH_INTERNAL_SESSIONS_DIR".to_string(),
        sessions_dir.display().to_string(),
    )];
    let res = run_fetch_opts(
        FetchOpts {
            env: env.clone(),
            ..Default::default()
        },
        &[
            &format!("{}/login", session_server.url),
            "--session",
            "integ",
        ],
    );
    assert_exit(&res, 0);
    let res = run_fetch_opts(
        FetchOpts {
            env,
            ..Default::default()
        },
        &[
            &format!("{}/dashboard", session_server.url),
            "--session",
            "integ",
        ],
    );
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "welcome");
    let res = run_fetch_opts(
        FetchOpts {
            env: vec![(
                "FETCH_INTERNAL_SESSIONS_DIR".to_string(),
                sessions_dir.display().to_string(),
            )],
            ..Default::default()
        },
        &[&format!("{}/dashboard", session_server.url)],
    );
    assert_exit(&res, 4);
    assert_eq!(res.stdout, "unauthorized");

    let env = vec![(
        "FETCH_INTERNAL_SESSIONS_DIR".to_string(),
        sessions_dir.display().to_string(),
    )];
    let res = run_fetch_opts(
        FetchOpts {
            env: env.clone(),
            ..Default::default()
        },
        &[
            &format!("{}/set-expiry", session_server.url),
            "--session",
            "expiry-integ",
        ],
    );
    assert_exit(&res, 0);
    let res = run_fetch_opts(
        FetchOpts {
            env: env.clone(),
            ..Default::default()
        },
        &[
            &format!("{}/check-expiry", session_server.url),
            "--session",
            "expiry-integ",
        ],
    );
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "ok");

    let res = run_fetch_opts(
        FetchOpts {
            env: env.clone(),
            ..Default::default()
        },
        &[
            &format!("{}/set-isolated?v=alpha", session_server.url),
            "--session",
            "sess-a",
        ],
    );
    assert_exit(&res, 0);
    let res = run_fetch_opts(
        FetchOpts {
            env: env.clone(),
            ..Default::default()
        },
        &[
            &format!("{}/set-isolated?v=beta", session_server.url),
            "--session",
            "sess-b",
        ],
    );
    assert_exit(&res, 0);
    let res = run_fetch_opts(
        FetchOpts {
            env: env.clone(),
            ..Default::default()
        },
        &[
            &format!("{}/get-isolated", session_server.url),
            "--session",
            "sess-a",
        ],
    );
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "alpha");
    let res = run_fetch_opts(
        FetchOpts {
            env: env.clone(),
            ..Default::default()
        },
        &[
            &format!("{}/get-isolated", session_server.url),
            "--session",
            "sess-b",
        ],
    );
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "beta");

    let psl_server = TestServer::start(|req| {
        if req.path == "/set" {
            return TestResponse::ok("set")
                .header("Set-Cookie", "token=secret; Domain=github.io; Path=/");
        }
        if req.path == "/check" {
            if req.header("cookie").contains("token=secret") {
                return TestResponse::status(
                    500,
                    "Internal Server Error",
                    "public suffix cookie was sent",
                );
            }
            return TestResponse::ok("clean");
        }
        TestResponse::status(404, "Not Found", "")
    });
    let psl_port = host_port(&psl_server.url)
        .split(':')
        .nth(1)
        .unwrap()
        .to_string();
    let dns_addr = start_udp_dns_server("user.github.io.", Ipv4Addr::new(127, 0, 0, 1));
    let psl_url = format!("http://user.github.io:{psl_port}");
    let psl_env = vec![
        (
            "FETCH_INTERNAL_SESSIONS_DIR".to_string(),
            sessions_dir.display().to_string(),
        ),
        ("HTTP_PROXY".to_string(), String::new()),
        ("HTTPS_PROXY".to_string(), String::new()),
        ("ALL_PROXY".to_string(), String::new()),
        ("NO_PROXY".to_string(), "*".to_string()),
    ];
    let res = run_fetch_opts(
        FetchOpts {
            env: psl_env.clone(),
            ..Default::default()
        },
        &[
            "--dns-server",
            &dns_addr,
            &format!("{psl_url}/set"),
            "--session",
            "psl-integ",
        ],
    );
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "set");
    let res = run_fetch_opts(
        FetchOpts {
            env: psl_env,
            ..Default::default()
        },
        &[
            "--dns-server",
            &dns_addr,
            &format!("{psl_url}/check"),
            "--session",
            "psl-integ",
        ],
    );
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "clean");

    let res = run_fetch(&[&session_server.url, "--session", "../bad"]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("invalid session name"));
}
