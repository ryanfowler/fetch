mod support;

use std::fs;
use std::net::Ipv4Addr;

use serde_json::Value;
use support::common::{FetchOpts, assert_exit, host_port, run_fetch, run_fetch_opts};
use support::dns::start_udp_dns_server;
use support::http::{TestResponse, TestServer};
use tempfile::TempDir;

#[test]
fn writes_final_exchange_har_without_changing_response_output() {
    let server = TestServer::start(|request| {
        assert_eq!(request.body, b"hello");
        TestResponse::status(201, "Created", "world")
            .header("Content-Type", "text/plain; charset=utf-8")
            .header("Set-Cookie", "a=1")
            .header("Set-Cookie", "b=2")
    });
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("request.har");
    let res = run_fetch(&[
        &format!("{}?first=one&first=two", server.url),
        "--data",
        "hello",
        "--header",
        "X-Test: value",
        "--har",
        path.to_str().unwrap(),
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "world");

    let har: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(har["log"]["version"], "1.2");
    assert_eq!(har["log"]["creator"]["name"], "fetch");
    let entry = &har["log"]["entries"][0];
    assert_eq!(entry["request"]["method"], "POST");
    assert_eq!(entry["request"]["postData"]["text"], "hello");
    assert_eq!(entry["request"]["queryString"][0]["name"], "first");
    assert_eq!(entry["request"]["queryString"][1]["value"], "two");
    assert_eq!(entry["response"]["status"], 201);
    assert_eq!(entry["response"]["content"]["text"], "world");
    assert_eq!(entry["response"]["content"]["size"], 5);
    assert_eq!(entry["response"]["httpVersion"], "HTTP/1.1");
    assert!(entry["serverIPAddress"].as_str().is_some());
    assert!(entry["timings"]["receive"].as_f64().unwrap() >= 0.0);
    let set_cookies = entry["response"]["headers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|header| header["name"].as_str() == Some("set-cookie"))
        .count();
    assert_eq!(set_cookies, 2);
}

#[test]
fn encodes_binary_response_and_honors_clobber() {
    let server = TestServer::start(|_| TestResponse::ok(vec![0, 159, 146, 150]));
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("binary.har");
    fs::write(&path, "existing").unwrap();

    let res = run_fetch(&[&server.url, "--har", path.to_str().unwrap()]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("already exists"));

    let res = run_fetch(&[
        &server.url,
        "--output",
        "-",
        "--har",
        path.to_str().unwrap(),
        "--clobber",
    ]);
    assert_exit(&res, 0);
    let har: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let content = &har["log"]["entries"][0]["response"]["content"];
    assert_eq!(content["encoding"], "base64");
    assert_eq!(content["text"], "AJ+Slg==");
}

#[test]
fn rejects_unsupported_har_destinations_and_modes() {
    for args in [
        vec!["--har", "-", "http://example.com"],
        vec!["--har", "same", "--output", "same", "http://example.com"],
        vec!["--har", "out.har", "--dry-run", "http://example.com"],
        vec!["--har", "out.har", "--inspect-dns", "example.com"],
        vec!["--har", "out.har", "ws://example.com"],
    ] {
        let res = run_fetch(&args);
        assert_exit(&res, 1);
    }
}

#[test]
fn rejects_equivalent_response_and_har_paths_before_clobbering() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let requests = Arc::new(AtomicUsize::new(0));
    let requests_for_server = Arc::clone(&requests);
    let server = TestServer::start(move |_| {
        requests_for_server.fetch_add(1, Ordering::SeqCst);
        TestResponse::ok("response")
    });
    let dir = TempDir::new().unwrap();

    for (output, har) in [
        ("result", "./result".to_string()),
        (
            "result",
            dir.path().join("result").to_string_lossy().into_owned(),
        ),
    ] {
        let target = dir.path().join("result");
        fs::write(&target, "original").unwrap();
        let res = run_fetch_opts(
            FetchOpts {
                cwd: Some(dir.path().to_path_buf()),
                ..FetchOpts::default()
            },
            &[&server.url, "--output", output, "--har", &har, "--clobber"],
        );
        assert_exit(&res, 1);
        assert!(res.stderr.contains("cannot use the same path"));
        assert_eq!(fs::read_to_string(&target).unwrap(), "original");
        assert_eq!(requests.load(Ordering::SeqCst), 0);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        symlink(&real, dir.path().join("alias")).unwrap();
        let target = real.join("response");
        let alias = dir.path().join("alias/response");
        fs::write(&target, "original").unwrap();
        let res = run_fetch(&[
            &server.url,
            "--output",
            target.to_str().unwrap(),
            "--har",
            alias.to_str().unwrap(),
            "--clobber",
        ]);
        assert_exit(&res, 1);
        assert_eq!(fs::read_to_string(target).unwrap(), "original");
        assert_eq!(requests.load(Ordering::SeqCst), 0);
    }

    if filesystem_is_case_insensitive(dir.path()) {
        let lower = "case-result";
        let upper = "CASE-RESULT";
        let res = run_fetch_opts(
            FetchOpts {
                cwd: Some(dir.path().to_path_buf()),
                ..FetchOpts::default()
            },
            &[&server.url, "--output", lower, "--har", upper, "--clobber"],
        );
        assert_exit(&res, 1);
        assert_eq!(requests.load(Ordering::SeqCst), 0);
        assert!(!dir.path().join(lower).exists());
    }
}

#[test]
fn har_enables_runtime_dns_timing() {
    let server = TestServer::start(|_| TestResponse::ok("dns"));
    let port = host_port(&server.url).split(':').nth(1).unwrap();
    let dns = start_udp_dns_server("har-dns.test.", Ipv4Addr::LOCALHOST);
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("dns.har");
    let res = run_fetch(&[
        "--dns-server",
        &dns,
        "--har",
        path.to_str().unwrap(),
        &format!("http://har-dns.test:{port}"),
    ]);
    assert_exit(&res, 0);
    let har: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert!(har["log"]["entries"][0]["timings"]["dns"].as_f64().unwrap() >= 0.0);
}

#[test]
fn digest_har_timing_describes_authenticated_exchange() {
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, SystemTime};

    let challenge_finished = Arc::new(Mutex::new(None));
    let marker = Arc::clone(&challenge_finished);
    let server = TestServer::start(move |request| {
        if request.header("authorization").is_empty() {
            thread::sleep(Duration::from_millis(250));
            *marker.lock().unwrap() = Some(rfc3339(SystemTime::now()));
            return TestResponse::status(401, "Unauthorized", "").header(
                "WWW-Authenticate",
                r#"Digest realm="test", nonce="abc123", qop="auth", algorithm="MD5""#,
            );
        }
        TestResponse::ok("authenticated")
    });
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("digest.har");
    let res = run_fetch(&[
        &server.url,
        "--digest",
        "user:pass",
        "--har",
        path.to_str().unwrap(),
    ]);
    assert_exit(&res, 0);

    let har: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let entry = &har["log"]["entries"][0];
    let marker = challenge_finished.lock().unwrap().clone().unwrap();
    assert!(entry["startedDateTime"].as_str().unwrap() >= marker.as_str());
    assert!(entry["timings"]["wait"].as_f64().unwrap() < 200.0);
    assert!(entry["time"].as_f64().unwrap() < 200.0);
    assert!(
        entry["request"]["headers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|header| header["name"] == "authorization")
    );
}

fn rfc3339(value: std::time::SystemTime) -> String {
    let dt = time::OffsetDateTime::from(value);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
        dt.millisecond()
    )
}

fn filesystem_is_case_insensitive(dir: &std::path::Path) -> bool {
    let lower = dir.join("case-probe");
    let upper = dir.join("CASE-PROBE");
    fs::write(&lower, "probe").unwrap();
    let insensitive = upper.exists();
    fs::remove_file(lower).unwrap();
    insensitive
}
