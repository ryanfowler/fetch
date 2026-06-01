mod support;

use support::*;

#[test]
fn proxy_config_environment_and_curl_http1_cases() {
    let proxy = TestServer::start(|req| {
        if req.path.starts_with("http://target.example/via-proxy")
            && req.header("x-proxy-test") == "yes"
        {
            return TestResponse::ok(format!("proxied {}", req.path));
        }
        if req
            .path
            .starts_with("http://config-proxy.example/from-config")
        {
            return TestResponse::ok("config proxy");
        }
        if req.path.starts_with("http://env-proxy.example/from-env") {
            return TestResponse::ok("environment proxy");
        }
        if req.path.starts_with("http://curl-proxy.example/from-curl") {
            return TestResponse::ok("curl proxy");
        }
        TestResponse::status(400, "Bad Request", format!("unexpected {}", req.path))
    });

    let res = run_fetch(&[
        "--proxy",
        &proxy.url,
        "--format",
        "off",
        "-H",
        "X-Proxy-Test: yes",
        "http://target.example/via-proxy?x=1",
    ]);
    assert_exit(&res, 0);
    assert!(
        res.stdout
            .contains("proxied http://target.example/via-proxy?x=1")
    );

    let dir = TempDir::new().unwrap();
    let config = dir.path().join("config");
    fs::write(&config, format!("format = off\nproxy = {}\n", proxy.url)).unwrap();
    let res = run_fetch(&[
        "--config",
        config.to_str().unwrap(),
        "http://config-proxy.example/from-config",
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "config proxy");

    let res = run_fetch_opts(
        FetchOpts {
            env: vec![
                ("HTTP_PROXY".to_string(), proxy.url.clone()),
                ("http_proxy".to_string(), proxy.url.clone()),
                ("HTTPS_PROXY".to_string(), String::new()),
                ("https_proxy".to_string(), String::new()),
                ("ALL_PROXY".to_string(), String::new()),
                ("all_proxy".to_string(), String::new()),
                ("NO_PROXY".to_string(), String::new()),
                ("no_proxy".to_string(), String::new()),
                ("REQUEST_METHOD".to_string(), String::new()),
            ],
            ..Default::default()
        },
        &["--format", "off", "http://env-proxy.example/from-env"],
    );
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "environment proxy");

    let cmd = format!(
        "curl --proxy {} http://curl-proxy.example/from-curl",
        proxy.url
    );
    let res = run_fetch(&["--format", "off", "--from-curl", &cmd]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "curl proxy");

    let res = run_fetch(&[
        "--proxy",
        "http://proxy.example:8080",
        "--http",
        "2",
        "https://example.com",
    ]);
    assert_exit(&res, 1);
    assert!(
        res.stderr
            .contains("a proxy can only be used with HTTP/1.1")
    );

    let tls = start_tls_server(|_| TestResponse::ok("unused"));
    let res = run_fetch_opts(
        FetchOpts {
            env: vec![
                (
                    "HTTPS_PROXY".to_string(),
                    "http://proxy.example:8080".to_string(),
                ),
                (
                    "https_proxy".to_string(),
                    "http://proxy.example:8080".to_string(),
                ),
                ("ALL_PROXY".to_string(), String::new()),
                ("all_proxy".to_string(), String::new()),
                ("NO_PROXY".to_string(), String::new()),
                ("no_proxy".to_string(), String::new()),
            ],
            ..Default::default()
        },
        &[
            "--http",
            "2",
            "--ca-cert",
            tls.ca_cert_path.to_str().unwrap(),
            &tls.url,
        ],
    );
    assert_exit(&res, 1);
    assert!(
        res.stderr
            .contains("a proxy can only be used with HTTP/1.1")
    );
}

#[test]
fn https_proxy_tls_ignores_origin_tls_settings() {
    let proxy = start_https_proxy(false);
    let ca = proxy.ca_cert_path.to_str().unwrap();
    let target = "http://origin.example/proxied";

    let res = run_fetch(&[
        "--format",
        "off",
        "--proxy",
        &proxy.url,
        "--ca-cert",
        ca,
        target,
    ]);
    assert_exit(&res, 1);
    assert!(proxy.requests().is_empty());

    let res = run_fetch(&[
        "--format",
        "off",
        "--proxy",
        &proxy.url,
        "--insecure",
        target,
    ]);
    assert_exit(&res, 1);
    assert!(proxy.requests().is_empty());
}

#[test]
fn https_proxy_mtls_does_not_receive_origin_client_certificate() {
    let proxy = start_https_proxy(true);
    let cert = proxy.client_cert_path.to_str().unwrap();
    let key = proxy.client_key_path.to_str().unwrap();
    let target = "http://origin.example/mtls-proxy";

    let res = run_fetch(&[
        "--format",
        "off",
        "--proxy",
        &proxy.url,
        "--insecure",
        "--cert",
        cert,
        "--key",
        key,
        target,
    ]);
    assert_exit(&res, 1);
    assert!(proxy.requests().is_empty());
}

#[test]
fn http3_go_harness_cases() {
    let h3 = start_http3_server(|req| {
        if req.path == "/h3" {
            return H3Response::status(201, "h3 ok").header("Content-Type", "text/plain");
        }
        if req.path == "/h3-zstd" {
            let body = zstd::stream::encode_all("h3 zstd ok".as_bytes(), 0).unwrap();
            return H3Response::ok(body)
                .header("Content-Type", "text/plain")
                .header("Content-Encoding", "zstd")
                .delay_body(Duration::from_millis(100));
        }
        if req.path == "/h3-grpc-trailer-error" {
            return H3Response::ok("")
                .header("Content-Type", "application/grpc+proto")
                .trailer("grpc-status", "7")
                .trailer("grpc-message", "permission denied");
        }
        H3Response::status(404, "not found")
    });
    let res = run_fetch(&[
        &format!("{}/h3?existing=1", h3.url),
        "--http",
        "3",
        "--ca-cert",
        h3.ca_cert_path.to_str().unwrap(),
        "--method",
        "PUT",
        "-H",
        "X-H3: yes",
        "-q",
        "cli=1",
        "-d",
        "payload",
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "h3 ok");
    assert!(res.stderr.contains("HTTP/3.0 201 Created"));
    let req = wait_for_h3_requests(&h3, 1).remove(0);
    assert_eq!(req.method, "PUT");
    assert_eq!(req.path, "/h3");
    assert_eq!(req.query, "existing=1&cli=1");
    assert_eq!(req.header("x-h3"), "yes");
    assert_eq!(req.body_string(), "payload");

    let h3_timing_url = h3.url.replace("127.0.0.1", "localhost");
    let res = run_fetch(&[
        &format!("{}/h3-zstd", h3_timing_url),
        "--http",
        "3",
        "--ca-cert",
        h3.ca_cert_path.to_str().unwrap(),
        "--timing",
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "h3 zstd ok");
    assert!(res.stderr.contains("HTTP/3.0 200 OK"));
    assert!(res.stderr.contains("DNS"));
    assert!(res.stderr.contains("QUIC"));

    let res = run_fetch(&[
        &format!("{}/h3-grpc-trailer-error", h3.url),
        "--http",
        "3",
        "--grpc",
        "--format",
        "off",
        "--ca-cert",
        h3.ca_cert_path.to_str().unwrap(),
    ]);
    assert_exit(&res, 1);
    assert!(res.stdout.is_empty(), "stdout:\n{}", res.stdout);
    assert!(res.stderr.contains("PERMISSION_DENIED"), "{}", res.stderr);
    assert!(res.stderr.contains("permission denied"), "{}", res.stderr);

    let res = run_fetch(&["http://example.com", "--http", "3"]);
    assert_exit(&res, 1);
    assert!(
        res.stderr
            .contains("http3: unsupported protocol scheme: http")
    );

    let res = run_fetch(&[
        "--proxy",
        "http://proxy.example:8080",
        "--http",
        "3",
        "https://example.com",
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
                    "HTTPS_PROXY".to_string(),
                    "http://proxy.example:8080".to_string(),
                ),
                (
                    "https_proxy".to_string(),
                    "http://proxy.example:8080".to_string(),
                ),
                ("ALL_PROXY".to_string(), String::new()),
                ("all_proxy".to_string(), String::new()),
                ("NO_PROXY".to_string(), String::new()),
                ("no_proxy".to_string(), String::new()),
            ],
            ..Default::default()
        },
        &[
            "--http",
            "3",
            "--ca-cert",
            h3.ca_cert_path.to_str().unwrap(),
            &h3.url,
        ],
    );
    assert_exit(&res, 1);
    assert!(
        res.stderr
            .contains("a proxy can only be used with HTTP/1.1")
    );

    let redirect = start_http3_server(|req| {
        if req.path == "/start" {
            return H3Response::status(307, "")
                .header("Location", "/final")
                .header("Content-Type", "text/plain");
        }
        if req.path == "/final" && req.method == "POST" && req.body_string() == "redirect-body" {
            return H3Response::ok("h3 redirected");
        }
        H3Response::status(
            400,
            format!("{} {} {}", req.method, req.path, req.body_string()),
        )
    });
    let res = run_fetch(&[
        &format!("{}/start", redirect.url),
        "--http",
        "3",
        "-vv",
        "--ca-cert",
        redirect.ca_cert_path.to_str().unwrap(),
        "--method",
        "POST",
        "-d",
        "redirect-body",
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "h3 redirected");
    assert!(res.stderr.contains("< HTTP/3.0 307 Temporary Redirect"));
    assert!(!res.stderr.contains("< HTTP/1.1 307 Temporary Redirect"));
    assert!(res.stderr.contains("HTTP/3.0 200 OK"));
    let requests = wait_for_h3_requests(&redirect, 2);
    assert_eq!(requests[0].path, "/start");
    assert_eq!(requests[1].path, "/final");
    assert_eq!(requests[0].body_string(), "redirect-body");
    assert_eq!(requests[1].body_string(), "redirect-body");
    assert_eq!(redirect.connections(), 1);

    let retry_count = Arc::new(AtomicUsize::new(0));
    let retry_count_for_handler = Arc::clone(&retry_count);
    let retry = start_http3_server(move |req| {
        if req.path == "/retry" {
            let n = retry_count_for_handler.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                return H3Response::status(503, "");
            }
            return H3Response::ok("h3 retry ok");
        }
        H3Response::status(404, "")
    });
    let res = run_fetch(&[
        &format!("{}/retry", retry.url),
        "--http",
        "3",
        "--ca-cert",
        retry.ca_cert_path.to_str().unwrap(),
        "--retry",
        "1",
        "--retry-delay",
        FAST_RETRY_DELAY,
        "-d",
        "retry-body",
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "h3 retry ok");
    let requests = wait_for_h3_requests(&retry, 2);
    assert_eq!(requests[0].body_string(), "retry-body");
    assert_eq!(requests[1].body_string(), "retry-body");
    assert_eq!(retry.connections(), 1);

    let session = start_http3_server(|req| {
        if req.path == "/login" {
            return H3Response::ok("logged in").header("Set-Cookie", "h3_session=abc123; Path=/");
        }
        if req.path == "/dashboard" && req.header("cookie").contains("h3_session=abc123") {
            return H3Response::ok("welcome h3");
        }
        H3Response::status(401, "unauthorized")
    });
    let dir = TempDir::new().unwrap();
    let env = vec![(
        "FETCH_INTERNAL_SESSIONS_DIR".to_string(),
        dir.path().display().to_string(),
    )];
    let res = run_fetch_opts(
        FetchOpts {
            env: env.clone(),
            ..Default::default()
        },
        &[
            &format!("{}/login", session.url),
            "--http",
            "3",
            "--ca-cert",
            session.ca_cert_path.to_str().unwrap(),
            "--session",
            "h3-integ",
        ],
    );
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "logged in");
    let res = run_fetch_opts(
        FetchOpts {
            env,
            ..Default::default()
        },
        &[
            &format!("{}/dashboard", session.url),
            "--http",
            "3",
            "--ca-cert",
            session.ca_cert_path.to_str().unwrap(),
            "--session",
            "h3-integ",
        ],
    );
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "welcome h3");
}

#[test]
fn dns_over_https_udp_and_inspect_dns_cases() {
    let doh = TestServer::start(|req| {
        if req.path.contains("/dns-query-nxdomain") {
            return TestResponse::ok(r#"{"Status":3}"#)
                .header("Content-Type", "application/dns-json")
                .header("Connection", "close");
        }
        if req.path.contains("/dns-query") {
            if req.path.contains("name=localhost") {
                return TestResponse::ok(
                    r#"{"Status":0,"Answer":[{"type":1,"data":"127.0.0.1"}]}"#,
                )
                .header("Content-Type", "application/dns-json")
                .header("Connection", "close");
            }
            if req.path.contains("type=AAAA") {
                return TestResponse::ok(
                    r#"{"Status":0,"Answer":[{"type":28,"data":"2001:db8::1","TTL":300}]}"#,
                )
                .header("Content-Type", "application/dns-json")
                .header("Connection", "close");
            }
            if req.path.contains("type=A") {
                return TestResponse::ok(
                    r#"{"Status":0,"Answer":[{"type":5,"data":"alias.example.com.","TTL":120},{"type":1,"data":"192.0.2.1","TTL":60}]}"#,
                )
                .header("Content-Type", "application/dns-json")
                .header("Connection", "close");
            }
            if req.path.contains("type=TXT") {
                return TestResponse::ok(
                    r#"{"Status":0,"Answer":[{"type":16,"data":"v=spf1 -all","TTL":180}]}"#,
                )
                .header("Content-Type", "application/dns-json")
                .header("Connection", "close");
            }
            return TestResponse::ok(r#"{"Status":0}"#)
                .header("Content-Type", "application/dns-json")
                .header("Connection", "close");
        }
        TestResponse::status(204, "No Content", "").header("Connection", "close")
    });
    let port = host_port(&doh.url).split(':').nth(1).unwrap();
    let localhost_url = format!("http://localhost:{port}");

    fn doh_wire_test_response(query: &[u8], answers: Vec<(u16, u32, Vec<u8>)>) -> Vec<u8> {
        let (_, _, question_end) = parse_dns_question(query).expect("valid DNS query");
        let mut response = Vec::new();
        response.extend_from_slice(&query[0..2]);
        response.extend_from_slice(&0x8180u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&query[12..question_end]);
        for (typ, ttl, data) in answers {
            response.extend_from_slice(&[0xc0, 0x0c]);
            response.extend_from_slice(&typ.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&ttl.to_be_bytes());
            response.extend_from_slice(&(data.len() as u16).to_be_bytes());
            response.extend_from_slice(&data);
        }
        response
    }

    let wire_doh = TestServer::start(|req| {
        if req.method != "POST"
            || req.header("accept") != "application/dns-message"
            || req.header("content-type") != "application/dns-message"
        {
            return TestResponse::status(415, "Unsupported Media Type", "")
                .header("Connection", "close");
        }
        let Some((name, qtype, _)) = parse_dns_question(&req.body) else {
            return TestResponse::status(400, "Bad Request", "").header("Connection", "close");
        };
        let answers = if name == "localhost." && qtype == 1 {
            vec![(1, 30, vec![127, 0, 0, 1])]
        } else {
            Vec::new()
        };
        TestResponse::ok(doh_wire_test_response(&req.body, answers))
            .header("Content-Type", "application/dns-message")
            .header("Connection", "close")
    });
    let res = run_fetch(&[
        &localhost_url,
        "--dns-server",
        &format!("{}/dns-query", wire_doh.url),
    ]);
    assert_exit(&res, 0);
    assert!(res.stderr.contains("204 No Content"));
    let wire_requests = wire_doh.requests.lock().unwrap();
    assert_eq!(wire_requests.len(), 2);
    assert!(wire_requests.iter().all(|req| req.method == "POST"));
    assert!(wire_requests.iter().all(|req| req.path == "/dns-query"));

    let res = run_fetch(&[
        &localhost_url,
        "--dns-server",
        &format!("{}/dns-query", doh.url),
    ]);
    assert_exit(&res, 0);
    assert!(res.stderr.contains("204 No Content"));

    let res = run_fetch(&[
        &localhost_url,
        "--dns-server",
        &format!("{}/dns-query-nxdomain", doh.url),
    ]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("no such host"));
    assert!(!res.stderr.contains("For more information"));

    let res = run_fetch(&[
        "--inspect-dns",
        "--dns-server",
        &format!("{}/dns-query", doh.url),
        "https://example.com",
    ]);
    assert_exit(&res, 0);
    assert!(res.stdout.is_empty());
    assert!(res.stderr.contains("DNS lookup: example.com"));
    assert!(
        res.stderr
            .contains(&format!("Resolver: {}/dns-query", doh.url))
    );
    assert!(res.stderr.contains("A\n"));
    assert!(res.stderr.contains("192.0.2.1 (TTL 1m)"));
    assert!(res.stderr.contains("AAAA\n"));
    assert!(res.stderr.contains("2001:db8::1 (TTL 5m)"));
    assert!(res.stderr.contains("alias.example.com. (TTL 2m)"));
    assert!(res.stderr.contains("v=spf1 -all (TTL 3m)"));
    assert!(res.stderr.contains("Addresses: 2"));
    assert!(res.stderr.contains("Records:"));

    let res = run_fetch(&["--silent", "--inspect-dns", "--data", "hi", "127.0.0.1"]);
    assert_exit(&res, 0);
    assert!(res.stdout.is_empty());
    assert!(res.stderr.is_empty());

    let unresponsive_inspect_dns_addr = start_unresponsive_udp_dns_server();
    let res = run_fetch(&[
        "--inspect-dns",
        "--dns-server",
        &unresponsive_inspect_dns_addr,
        "--connect-timeout",
        "0.05",
        "--timeout",
        "1",
        "https://fetch-inspect-dns-timeout.test",
    ]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("request timed out after 50ms"));

    let res = run_fetch(&[
        "--inspect-dns",
        "--dns-server",
        &format!("{}/dns-query", doh.url),
        "--color",
        "on",
        "https://example.com",
    ]);
    assert_exit(&res, 0);
    assert!(res.stdout.is_empty());
    assert!(
        res.stderr
            .contains("\x1b[2m* \x1b[0m\x1b[1m\x1b[36mDNS lookup\x1b[0m")
    );
    assert!(
        res.stderr
            .contains(&format!("\x1b[3m{}/dns-query\x1b[0m", doh.url))
    );
    assert!(res.stderr.contains("\x1b[32m192.0.2.1\x1b[0m"));
    assert!(res.stderr.contains("\x1b[2m(TTL 1m)\x1b[0m"));

    let target = TestServer::start(|req| {
        if req.header("host").starts_with("fetch-dns.test:") {
            TestResponse::ok("udp dns ok")
        } else {
            TestResponse::status(400, "Bad Request", req.header("host"))
        }
    });
    let target_port = host_port(&target.url).split(':').nth(1).unwrap();
    let dns_addr = start_udp_dns_server("fetch-dns.test.", Ipv4Addr::new(127, 0, 0, 1));
    let res = run_fetch(&[
        "--dns-server",
        &dns_addr,
        &format!("http://fetch-dns.test:{target_port}"),
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "udp dns ok");

    let res = run_fetch(&[
        "--dns-server",
        &dns_addr,
        "--timing",
        &format!("http://fetch-dns.test:{target_port}"),
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "udp dns ok");
    assert!(res.stderr.contains("DNS"));
    assert!(res.stderr.contains("TCP"));
    assert!(!res.stderr.contains("Connect"));
    assert!(res.stderr.contains("TTFB"));

    let redirect_location = Arc::new(Mutex::new(String::new()));
    let redirect_location_for_handler = Arc::clone(&redirect_location);
    let redirect_target = TestServer::start(move |req| {
        if req.path == "/start" && req.header("host").starts_with("fetch-redirect-a.test:") {
            return TestResponse::status(302, "Found", "")
                .header("Location", &redirect_location_for_handler.lock().unwrap())
                .header("Connection", "close");
        }
        if req.path == "/final" && req.header("host").starts_with("fetch-redirect-b.test:") {
            return TestResponse::ok("redirect custom dns ok");
        }
        TestResponse::status(400, "Bad Request", req.header("host"))
    });
    let redirect_port = host_port(&redirect_target.url).split(':').nth(1).unwrap();
    *redirect_location.lock().unwrap() =
        format!("http://fetch-redirect-b.test:{redirect_port}/final");
    let redirect_dns_addr = start_udp_dns_server_with_hosts(vec![
        ("fetch-redirect-a.test.", Ipv4Addr::new(127, 0, 0, 1)),
        ("fetch-redirect-b.test.", Ipv4Addr::new(127, 0, 0, 1)),
    ]);
    let res = run_fetch(&[
        "--dns-server",
        &redirect_dns_addr,
        "-vvv",
        &format!("http://fetch-redirect-a.test:{redirect_port}/start"),
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "redirect custom dns ok");
    assert!(res.stderr.contains("* DNS: fetch-redirect-a.test"));
    assert!(res.stderr.contains("* DNS: fetch-redirect-b.test"));
    let requests = redirect_target.requests();
    assert_eq!(requests.len(), 2);
    assert!(
        requests[0]
            .header("host")
            .starts_with("fetch-redirect-a.test:")
    );
    assert!(
        requests[1]
            .header("host")
            .starts_with("fetch-redirect-b.test:")
    );

    let unresponsive_dns_addr = start_unresponsive_udp_dns_server();
    let res = run_fetch(&[
        "--dns-server",
        &unresponsive_dns_addr,
        "--connect-timeout",
        "0.05",
        &format!("http://fetch-dns-timeout.test:{target_port}"),
    ]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("request timed out after 50ms"));
    assert!(!res.stderr.contains("For more information"));
}

#[test]
fn socks_proxy_unix_socket_timing_and_grpc_binary_cases() {
    let server = TestServer::start(|req| {
        if req.path == "/via-socks" || req.path == "/from-curl-socks" {
            return TestResponse::ok(format!("socks {}", req.path));
        }
        if req.path == "/timing" {
            return TestResponse::ok("timed");
        }
        TestResponse::status(404, "Not Found", "")
    });
    let target_addr = host_port(&server.url).to_string();
    let (proxy_url, seen) = start_socks5_proxy(target_addr.clone());

    let res = run_fetch(&[
        "--proxy",
        &proxy_url,
        "--format",
        "off",
        &format!("{}/via-socks", server.url),
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "socks /via-socks");
    assert_socks_seen(&seen, &target_addr);

    let curl = format!(
        "curl --proxy {proxy_url} --silent {}/from-curl-socks",
        server.url
    );
    let res = run_fetch(&["--from-curl", &curl]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "socks /from-curl-socks");
    assert_socks_seen(&seen, &target_addr);

    let dns_port = Url::parse(&server.url).unwrap().port().unwrap();
    let dns_addr = start_udp_dns_server("fetch-socks-dns.test.", Ipv4Addr::new(127, 0, 0, 1));
    let res = run_fetch(&[
        "--dns-server",
        &dns_addr,
        "--proxy",
        &proxy_url,
        "--format",
        "off",
        &format!("http://fetch-socks-dns.test:{dns_port}/via-socks"),
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "socks /via-socks");
    assert_socks_seen(&seen, &target_addr);

    let res = run_fetch(&[&format!("{}/timing", server.url), "--timing"]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "timed");
    assert!(res.stderr.contains("Total") || res.stderr.contains("Timing"));
    assert!(res.stderr.contains("TCP"));
    assert!(res.stderr.contains("█"));
    assert!(res.stderr.contains("─"));
    assert!(!res.stderr.contains("* Connect:"));
    assert!(!res.stderr.contains("* TTFB:"));
    let res = run_fetch(&[&format!("{}/timing", server.url), "-T"]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "timed");
    assert!(res.stderr.contains("Total") || res.stderr.contains("Timing"));
    assert!(res.stderr.contains("█"));
    let res = run_fetch(&[&format!("{}/timing", server.url), "-T", "-vvv"]);
    assert_exit(&res, 0);
    assert!(res.stderr.contains("* TCP:"));
    assert!(!res.stderr.contains("* Connect:"));
    assert!(res.stderr.contains("* TTFB:"));
    assert!(res.stderr.contains("Total") || res.stderr.contains("Timing"));

    let res = run_fetch(&[&format!("{}/timing", server.url), "--timing", "-m", "HEAD"]);
    assert_exit(&res, 0);
    assert!(res.stdout.is_empty());
    assert!(res.stderr.contains("Total") || res.stderr.contains("Timing"));
    assert!(!res.stderr.contains("Body"));

    let retry_hits = Arc::new(AtomicUsize::new(0));
    let retry_hits_for_handler = Arc::clone(&retry_hits);
    let retry_server = TestServer::start(move |_| {
        let n = retry_hits_for_handler.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            TestResponse::status(503, "Service Unavailable", "")
        } else {
            TestResponse::ok("ok")
        }
    });
    let res = run_fetch(&[
        &retry_server.url,
        "--timing",
        "--retry",
        "1",
        "--retry-delay",
        FAST_RETRY_DELAY,
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "ok");
    assert!(res.stderr.contains("Total") || res.stderr.contains("Timing"));
    assert!(res.stderr.contains("█"));
    assert_eq!(retry_hits.load(Ordering::SeqCst), 2);

    #[cfg(unix)]
    {
        use std::os::unix::net::UnixListener;
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("server.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else {
                    break;
                };
                let mut buf = [0_u8; 1024];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhello",
                );
            }
        });
        let res = run_fetch(&["--unix", sock.to_str().unwrap(), "http://unix/"]);
        assert_exit(&res, 0);
        assert_eq!(res.stdout, "hello");
    }

    let mut raw_proto = proto_field_varint(1, 123);
    raw_proto.extend(proto_field_string(2, "hello"));
    let proto_body = raw_proto.clone();
    let grpc_body = grpc_frame(&proto_field_string(1, "grpc test"));
    let grpc_stream = {
        let mut out = grpc_frame(&proto_field_string(1, "message one"));
        out.extend(grpc_frame(&proto_field_string(1, "message two")));
        out.extend(grpc_frame(&proto_field_string(1, "message three")));
        out
    };
    let grpc_gzip = grpc_frame_with_flag(&gzip_bytes(&proto_field_string(1, "gzip grpc")), true);
    let binary = TestServer::start(move |req| match req.path.as_str() {
        "/proto" => {
            TestResponse::ok(proto_body.clone()).header("Content-Type", "application/protobuf")
        }
        "/grpc" => {
            TestResponse::ok(grpc_body.clone()).header("Content-Type", "application/grpc+proto")
        }
        "/grpc-gzip" => TestResponse::ok(grpc_gzip.clone())
            .header("Content-Type", "application/grpc+proto")
            .header("grpc-encoding", "gzip"),
        "/grpc-br" => TestResponse::ok(grpc_frame_with_flag(b"not actually br", true))
            .header("Content-Type", "application/grpc+proto")
            .header("grpc-encoding", "br"),
        "/grpc-stream" => {
            TestResponse::ok(grpc_stream.clone()).header("Content-Type", "application/grpc+proto")
        }
        "/connect-error" => TestResponse::status(
            404,
            "Not Found",
            r#"{"code":"not_found","message":"resource not found"}"#,
        )
        .header("Content-Type", "application/json"),
        _ => TestResponse::status(404, "Not Found", ""),
    });
    let res = run_fetch(&[&format!("{}/proto", binary.url), "--format", "off"]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout.as_bytes(), raw_proto.as_slice());
    let res = run_fetch(&[&format!("{}/proto", binary.url), "--format", "on"]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("123"));
    assert!(res.stdout.contains("hello"));
    let res = run_fetch(&[&format!("{}/grpc", binary.url), "--format", "on"]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("grpc test"));
    let res = run_fetch(&[&format!("{}/grpc-gzip", binary.url), "--format", "on"]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("gzip grpc"));
    let res = run_fetch(&[&format!("{}/grpc-br", binary.url), "--format", "on"]);
    assert_exit(&res, 1);
    assert!(
        res.stderr
            .contains("unsupported gRPC compression encoding: br")
    );
    let res = run_fetch(&[&format!("{}/grpc-stream", binary.url), "--format", "on"]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("message one"));
    assert!(res.stdout.contains("message two"));
    assert!(res.stdout.contains("message three"));
    let res = run_fetch(&[&format!("{}/connect-error", binary.url), "--format", "on"]);
    assert_exit(&res, 4);
    assert!(res.stdout.contains("not_found"));
    assert!(res.stdout.contains("resource not found"));
}

#[test]
fn tls_certificate_validation_inspection_and_bounds_cases() {
    let requests = Arc::new(AtomicUsize::new(0));
    let requests_for_handler = Arc::clone(&requests);
    let tls = start_tls_server(move |_| {
        requests_for_handler.fetch_add(1, Ordering::SeqCst);
        TestResponse::ok("tls-ok")
    });

    let res = run_fetch(&["--retry", "2", "--retry-delay", FAST_RETRY_DELAY, &tls.url]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("certificate"));
    assert!(res.stderr.contains("--insecure"));
    // On macOS, rustls-native-certs can classify this local rcgen chain through
    // a platform OtherError path. Keep the certificate hint assertion here while
    // the retry classifier remains conservative for certificate failures.
    assert_eq!(requests.load(Ordering::SeqCst), 0);

    let res = run_fetch(&["--insecure", &tls.url]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "tls-ok");

    let res = run_fetch(&["--ca-cert", tls.ca_cert_path.to_str().unwrap(), &tls.url]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "tls-ok");

    let res = run_fetch(&[
        "--ca-cert",
        tls.ca_cert_path.to_str().unwrap(),
        "--timing",
        &tls.url,
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "tls-ok");
    assert!(res.stderr.contains("TCP"));
    assert!(res.stderr.contains("TLS"));
    assert!(!res.stderr.contains("Connect"));

    let h2 = start_h2_tls_server(|req| {
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/auto-h2?x=1");
        TestResponse::ok("h2-ok")
    });
    let h2_url = format!("{}/auto-h2?x=1", h2.url);
    let res = run_fetch(&[
        "-v",
        "--ca-cert",
        h2.ca_cert_path.to_str().unwrap(),
        &h2_url,
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "h2-ok");
    assert!(res.stderr.contains("HTTP/2.0 200"));

    let refused_count = Arc::new(AtomicUsize::new(0));
    let refused_count_for_handler = Arc::clone(&refused_count);
    let refused = start_h2_tls_server(move |_req| {
        if refused_count_for_handler.fetch_add(1, Ordering::SeqCst) == 0 {
            return TestResponse::h2_reset(h2::Reason::REFUSED_STREAM);
        }
        TestResponse::ok("h2-retried")
    });
    let res = run_fetch(&[
        "--ca-cert",
        refused.ca_cert_path.to_str().unwrap(),
        "--format",
        "off",
        &refused.url,
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "h2-retried");
    assert_eq!(refused_count.load(Ordering::SeqCst), 2);

    let res = run_fetch(&[
        "--ca-cert",
        tls.ca_cert_path.to_str().unwrap(),
        "--min-tls",
        "1.3",
        "--max-tls",
        "1.3",
        &tls.url,
    ]);
    assert_exit(&res, 0);

    let res = run_fetch(&["--inspect-tls", "--insecure", &tls.url]);
    assert_exit(&res, 0);
    assert!(res.stdout.is_empty());
    assert!(res.stderr.contains("TLS"));
    assert!(res.stderr.contains("Certificate") || res.stderr.contains("certificate"));

    let stalling_tls = start_stalling_proxy("https");
    let res = run_fetch(&[
        "--inspect-tls",
        "--insecure",
        "--connect-timeout",
        "0.05",
        "--timeout",
        "1",
        &stalling_tls,
    ]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("request timed out after 50ms"));

    let dns_addr = start_udp_dns_server("fetch-tls.test.", Ipv4Addr::new(127, 0, 0, 1));
    let tls_url = Url::parse(&tls.url).unwrap();
    let dns_tls_url = format!("https://fetch-tls.test:{}", tls_url.port().unwrap());
    let res = run_fetch(&[
        "--inspect-tls",
        "--dns-server",
        &dns_addr,
        "--insecure",
        &dns_tls_url,
    ]);
    assert_exit(&res, 0);
    assert!(res.stderr.contains("TLS"));
    assert!(!res.stderr.contains("--dns-server"));

    let res = run_fetch(&["--inspect-tls", "http://example.com"]);
    assert_exit(&res, 1);
    assert!(!res.stderr.is_empty());

    let res = run_fetch(&["--inspect-tls", "--timing", "--insecure", &tls.url]);
    assert_exit(&res, 0);
    assert!(res.stderr.contains("timing") || res.stderr.contains("TLS"));
}

#[test]
fn mtls_client_certificate_go_cases() {
    let mtls = start_mtls_server();
    let ca = mtls.ca_cert_path.to_str().unwrap();
    let cert = mtls.client_cert_path.to_str().unwrap();
    let key = mtls.client_key_path.to_str().unwrap();
    let combined = mtls.client_combined_path.to_str().unwrap();

    let res = run_fetch(&["--ca-cert", ca, "--cert", cert, "--key", key, &mtls.url]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "mtls-success");
    assert!(res.stderr.contains("200 OK"));

    let dir = TempDir::new().unwrap();
    let config = dir.path().join("mtls-config-cert");
    fs::write(&config, format!("cert = {cert}\n")).unwrap();
    let res = run_fetch(&[
        "--config",
        config.to_str().unwrap(),
        "--ca-cert",
        ca,
        "--key",
        key,
        &mtls.url,
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "mtls-success");
    assert!(res.stderr.contains("200 OK"));

    let res = run_fetch(&["--ca-cert", ca, "--cert", combined, &mtls.url]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "mtls-success");
    assert!(res.stderr.contains("200 OK"));

    let res = run_fetch(&["--ca-cert", ca, &mtls.url]);
    assert_exit(&res, 1);
    assert!(res.stderr.to_ascii_lowercase().contains("error"));

    let res = run_fetch(&["--ca-cert", ca, "--cert", cert, &mtls.url]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("may require a private key"));

    let res = run_fetch(&["--ca-cert", ca, "--key", key, &mtls.url]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("'--key' requires '--cert'"));

    let res = run_fetch(&["--cert", "/nonexistent/client.crt", "--key", key, &mtls.url]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("does not exist"));

    let res = run_fetch(&[
        "--cert",
        cert,
        "--key",
        "/nonexistent/client.key",
        &mtls.url,
    ]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("does not exist"));
}
