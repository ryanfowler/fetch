mod support;

use support::*;

#[test]
fn response_formatting_json_ndjson_xml_yaml_html_csv_css_and_sniffing() {
    let server = TestServer::start(|req| match req.path.as_str() {
        "/json" => TestResponse::ok(r#"{"ok":"yes"}"#).header("Content-Type", "application/json"),
        "/ndjson" => TestResponse::ok("{\"a\":1}\n{\"b\":2}\n")
            .header("Content-Type", "application/x-ndjson"),
        "/xml" => TestResponse::ok("<root><child>yes</child></root>")
            .header("Content-Type", "application/xml"),
        "/yaml" => TestResponse::ok("ok: yes\n").header("Content-Type", "application/yaml"),
        "/html" => TestResponse::ok("<html><body><h1>Hello</h1></body></html>")
            .header("Content-Type", "text/html"),
        "/csv" => TestResponse::ok("name,value\none,1\n").header("Content-Type", "text/csv"),
        "/css" => TestResponse::ok("body{color:red}").header("Content-Type", "text/css"),
        "/sse" => TestResponse::ok("data: {\"one\":1}\n\nevent: done\ndata: two\n\n")
            .header("Content-Type", "text/event-stream"),
        "/sniff-json" => TestResponse::ok(r#"{"sniff":true}"#),
        "/sniff-xml" => TestResponse::ok("<root/>"),
        "/plain" => TestResponse::ok("just text"),
        _ => TestResponse::status(404, "Not Found", ""),
    });

    let cases = [
        ("/json", "{\n  \"ok\": \"yes\"\n}\n"),
        ("/ndjson", "{ \"a\": 1 }\n{ \"b\": 2 }\n"),
        ("/xml", "<root>\n  <child>yes</child>\n</root>\n"),
        ("/yaml", "ok: yes\n"),
        (
            "/html",
            "<html>\n  <body>\n    <h1>Hello</h1>\n  </body>\n</html>\n",
        ),
        ("/csv", "name  value\none   1\n"),
        ("/css", "body {\n  color: red;\n}\n"),
        (
            "/sse",
            "event: message\ndata: { \"one\": 1 }\n\nevent: done\ndata: two\n\n",
        ),
        ("/sniff-json", "{\n  \"sniff\": true\n}\n"),
        ("/sniff-xml", "<root></root>\n"),
        ("/plain", "just text"),
    ];

    for (path, expected) in cases {
        let res = run_fetch(&[&format!("{}{}", server.url, path), "--format", "on"]);
        assert_exit(&res, 0);
        assert_eq!(res.stdout, expected, "path {path}");
    }
}

#[cfg(unix)]
#[test]
fn formatted_sse_outputs_events_before_stream_ends() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind streaming sse server");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    let (close_tx, close_rx) = mpsc::channel();
    let join = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept streaming sse request");
        let reader_stream = stream.try_clone().expect("clone streaming sse stream");
        let mut reader = BufReader::new(reader_stream);
        let _ = read_request(&mut reader).expect("read streaming sse request");

        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let first = b"data: {\"one\":1}\n\n";
        write!(stream, "{:x}\r\n", first.len()).unwrap();
        stream.write_all(first).unwrap();
        stream.write_all(b"\r\n").unwrap();
        stream.flush().unwrap();

        let _ = close_rx.recv_timeout(Duration::from_secs(5));
        let second = b"event: done\ndata: two\n\n";
        write!(stream, "{:x}\r\n", second.len()).unwrap();
        stream.write_all(second).unwrap();
        stream.write_all(b"\r\n0\r\n\r\n").unwrap();
        let _ = stream.flush();
        let _ = stream.shutdown(Shutdown::Both);
    });

    let pty = open_pty(24, 80, 800, 480);
    let mut cmd = Command::new(fetch_bin());
    cmd.args([url.as_str(), "--format", "on", "--pager", "off"]);
    cmd.env("TERM", "xterm-256color");
    cmd.env("HTTP_PROXY", "");
    cmd.env("HTTPS_PROXY", "");
    cmd.env("ALL_PROXY", "");
    cmd.env("NO_PROXY", "*");
    configure_pty_child(&mut cmd, &pty.slave);
    let mut child = cmd.spawn().expect("spawn streaming sse fetch under PTY");
    drop(pty.slave);
    let capture = start_pty_capture(&pty.master);

    capture.wait_for("\"one\"", Duration::from_secs(5));
    assert!(
        wait_child(&mut child, Duration::from_millis(100)).is_none(),
        "fetch exited before the SSE stream closed; PTY output:\n{}",
        capture.output()
    );
    close_tx.send(()).unwrap();

    let status = wait_child(&mut child, Duration::from_secs(5))
        .unwrap_or_else(|| {
            let _ = child.kill();
            panic!(
                "fetch did not exit after SSE stream closed; PTY output:\n{}",
                capture.output()
            )
        })
        .expect("wait streaming sse fetch");
    assert!(
        status.success(),
        "fetch exited with {status}; PTY output:\n{}",
        capture.output()
    );
    let output = capture.output();
    assert!(output.contains("\x1b[1m\x1b[36mevent\x1b[0m: done"));
    assert!(output.contains("two"));
    drop(pty.master);
    capture.close();
    join.join().unwrap();
}

#[test]
fn chunked_ndjson_formats_records_split_across_chunks() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind chunked ndjson server");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    let join = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept chunked ndjson request");
        let reader_stream = stream.try_clone().expect("clone chunked ndjson stream");
        let mut reader = BufReader::new(reader_stream);
        let _ = read_request(&mut reader).expect("read chunked ndjson request");
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        for chunk in [
            b"{\"a\":".as_slice(),
            b"1}\n{\"b\"".as_slice(),
            b":2}\n".as_slice(),
        ] {
            write!(stream, "{:x}\r\n", chunk.len()).unwrap();
            stream.write_all(chunk).unwrap();
            stream.write_all(b"\r\n").unwrap();
            stream.flush().unwrap();
        }
        stream.write_all(b"0\r\n\r\n").unwrap();
        let _ = stream.shutdown(Shutdown::Both);
    });

    let res = run_fetch(&[&url, "--format", "on"]);

    join.join().unwrap();
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "{ \"a\": 1 }\n{ \"b\": 2 }\n");
}

#[cfg(unix)]
#[test]
fn formatted_ndjson_outputs_records_before_stream_ends() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind streaming ndjson server");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    let (close_tx, close_rx) = mpsc::channel();
    let join = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept streaming ndjson request");
        let reader_stream = stream.try_clone().expect("clone streaming ndjson stream");
        let mut reader = BufReader::new(reader_stream);
        let _ = read_request(&mut reader).expect("read streaming ndjson request");
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let first = br#"{"event":"started","n":1}
"#;
        write!(stream, "{:x}\r\n", first.len()).unwrap();
        stream.write_all(first).unwrap();
        stream.write_all(b"\r\n").unwrap();
        stream.flush().unwrap();

        let _ = close_rx.recv_timeout(Duration::from_secs(5));
        let second = br#"{"event":"finished","n":2}
"#;
        write!(stream, "{:x}\r\n", second.len()).unwrap();
        stream.write_all(second).unwrap();
        stream.write_all(b"\r\n0\r\n\r\n").unwrap();
        let _ = stream.flush();
        let _ = stream.shutdown(Shutdown::Both);
    });

    let pty = open_pty(24, 80, 800, 480);
    let mut cmd = Command::new(fetch_bin());
    cmd.args([
        url.as_str(),
        "--format",
        "on",
        "--color",
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
    let mut child = cmd.spawn().expect("spawn streaming ndjson fetch under PTY");
    drop(pty.slave);
    let capture = start_pty_capture(&pty.master);

    capture.wait_for(r#"{ "event": "started", "n": 1 }"#, Duration::from_secs(5));
    assert!(
        wait_child(&mut child, Duration::from_millis(100)).is_none(),
        "fetch exited before the NDJSON stream closed; PTY output:\n{}",
        capture.output()
    );
    close_tx.send(()).unwrap();

    let status = wait_child(&mut child, Duration::from_secs(5))
        .unwrap_or_else(|| {
            let _ = child.kill();
            panic!(
                "fetch did not exit after NDJSON stream closed; PTY output:\n{}",
                capture.output()
            )
        })
        .expect("wait streaming ndjson fetch");
    assert!(
        status.success(),
        "fetch exited with {status}; PTY output:\n{}",
        capture.output()
    );
    let output = capture.output();
    assert!(output.contains(r#"{ "event": "started", "n": 1 }"#));
    assert!(output.contains(r#"{ "event": "finished", "n": 2 }"#));
    drop(pty.master);
    capture.close();
    join.join().unwrap();
}

#[cfg(unix)]
#[test]
fn raw_ndjson_outputs_chunks_before_stream_ends() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind streaming ndjson server");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    let (close_tx, close_rx) = mpsc::channel();
    let join = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept streaming ndjson request");
        let reader_stream = stream.try_clone().expect("clone streaming ndjson stream");
        let mut reader = BufReader::new(reader_stream);
        let _ = read_request(&mut reader).expect("read streaming ndjson request");
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let first = br#"{"event":"started"}
"#;
        write!(stream, "{:x}\r\n", first.len()).unwrap();
        stream.write_all(first).unwrap();
        stream.write_all(b"\r\n").unwrap();
        stream.flush().unwrap();

        let _ = close_rx.recv_timeout(Duration::from_secs(5));
        let second = br#"{"event":"finished"}
"#;
        write!(stream, "{:x}\r\n", second.len()).unwrap();
        stream.write_all(second).unwrap();
        stream.write_all(b"\r\n0\r\n\r\n").unwrap();
        let _ = stream.flush();
        let _ = stream.shutdown(Shutdown::Both);
    });

    let pty = open_pty(24, 80, 800, 480);
    let mut cmd = Command::new(fetch_bin());
    cmd.args([url.as_str(), "--format", "off", "--pager", "off"]);
    cmd.env("TERM", "xterm-256color");
    cmd.env("HTTP_PROXY", "");
    cmd.env("HTTPS_PROXY", "");
    cmd.env("ALL_PROXY", "");
    cmd.env("NO_PROXY", "*");
    configure_pty_child(&mut cmd, &pty.slave);
    let mut child = cmd.spawn().expect("spawn streaming ndjson fetch under PTY");
    drop(pty.slave);
    let capture = start_pty_capture(&pty.master);

    capture.wait_for("\"started\"", Duration::from_secs(5));
    assert!(
        wait_child(&mut child, Duration::from_millis(100)).is_none(),
        "fetch exited before the NDJSON stream closed; PTY output:\n{}",
        capture.output()
    );
    close_tx.send(()).unwrap();

    let status = wait_child(&mut child, Duration::from_secs(5))
        .unwrap_or_else(|| {
            let _ = child.kill();
            panic!(
                "fetch did not exit after NDJSON stream closed; PTY output:\n{}",
                capture.output()
            )
        })
        .expect("wait streaming ndjson fetch");
    assert!(
        status.success(),
        "fetch exited with {status}; PTY output:\n{}",
        capture.output()
    );
    let output = capture.output();
    assert!(output.contains("\"started\""));
    assert!(output.contains("\"finished\""));
    drop(pty.master);
    capture.close();
    join.join().unwrap();
}

#[test]
fn sse_explicit_request_timeout_aborts_stream_body() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind explicit sse timeout server");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    let join = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept explicit sse timeout");
        let reader_stream = stream
            .try_clone()
            .expect("clone explicit sse timeout stream");
        let mut reader = BufReader::new(reader_stream);
        let _ = read_request(&mut reader).expect("read explicit sse timeout request");
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        stream.flush().unwrap();
        thread::sleep(Duration::from_millis(500));
        let _ = stream.shutdown(Shutdown::Both);
    });

    let res = run_fetch(&[&url, "--format", "on", "--timeout", "0.1"]);

    join.join().unwrap();
    assert_exit(&res, 1);
    assert!(res.stdout.is_empty(), "stdout:\n{}", res.stdout);
    assert!(
        res.stderr
            .contains("response body error: operation timed out"),
        "stderr:\n{}",
        res.stderr
    );
}

#[test]
fn sse_config_request_timeout_aborts_stream_body() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind config sse timeout server");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    let join = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept config sse timeout");
        let reader_stream = stream.try_clone().expect("clone config sse timeout stream");
        let mut reader = BufReader::new(reader_stream);
        let _ = read_request(&mut reader).expect("read config sse timeout request");
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        stream.flush().unwrap();
        thread::sleep(Duration::from_millis(500));
        let _ = stream.shutdown(Shutdown::Both);
    });

    let dir = TempDir::new().unwrap();
    let config = dir.path().join("config");
    fs::write(&config, "timeout = 0.1\n").unwrap();
    let res = run_fetch(&["--config", config.to_str().unwrap(), &url, "--format", "on"]);

    join.join().unwrap();
    assert_exit(&res, 1);
    assert!(res.stdout.is_empty(), "stdout:\n{}", res.stdout);
    assert!(
        res.stderr
            .contains("response body error: operation timed out"),
        "stderr:\n{}",
        res.stderr
    );
}

#[test]
fn response_body_errors_include_response_context() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind partial response server");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    let join = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept partial response request");
        let reader_stream = stream.try_clone().expect("clone partial response stream");
        let mut reader = BufReader::new(reader_stream);
        let _ = read_request(&mut reader).expect("read partial response request");
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: 64\r\nConnection: close\r\n\r\nshort"
        )
        .unwrap();
        let _ = stream.flush();
        let _ = stream.shutdown(Shutdown::Both);
    });

    let res = run_fetch(&[&url]);

    join.join().unwrap();
    assert_exit(&res, 1);
    assert!(res.stderr.contains("response body error"), "{}", res.stderr);
    assert!(
        !res.stderr.contains("request or response body error"),
        "{}",
        res.stderr
    );
}

#[test]
fn additional_formatting_sse_charset_image_and_compression_cases() {
    let server = TestServer::start(|req| match req.path.as_str() {
        "/sse" => TestResponse::ok(
            ":comment\n\ndata:{\"key\":\"val\"}\n\nevent:ev1\ndata: this is my data\n\n",
        )
        .header("Content-Type", "text/event-stream"),
        "/charset-json" => TestResponse::ok(vec![
            b'{', b'"', b'w', b'o', b'r', b'd', b'"', b':', b'"', b'c', b'a', b'f', 0xe9, b'"',
            b'}',
        ])
        .header("Content-Type", "application/json; charset=iso-8859-1"),
        "/markdown" => TestResponse::ok("# Title\n\nSome **bold** text.\n\n- one\n- two\n")
            .header("Content-Type", "text/markdown"),
        "/image" => TestResponse::ok("raw image bytes").header("Content-Type", "image/png"),
        "/html-sniff" => TestResponse::ok("<!doctype html><html><body>hi</body></html>"),
        _ => TestResponse::status(404, "Not Found", ""),
    });

    let res = run_fetch(&[&format!("{}/sse", server.url), "--format", "on"]);
    assert_exit(&res, 0);
    assert_eq!(
        res.stdout,
        "event: message\ndata: { \"key\": \"val\" }\n\nevent: ev1\ndata: this is my data\n\n"
    );
    let res = run_fetch(&[
        &format!("{}/sse", server.url),
        "--format",
        "on",
        "--color",
        "on",
    ]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("\x1b[1m\x1b[36mevent\x1b[0m: message"));
    assert!(res.stdout.contains("\x1b[1m\x1b[36mdata\x1b[0m: {"));
    assert!(res.stdout.contains("\x1b[34m\x1b[1m\"key\"\x1b[0m"));
    assert!(res.stdout.contains("\x1b[32m\"val\"\x1b[0m"));

    let res = run_fetch(&[&format!("{}/charset-json", server.url), "--format", "on"]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "{\n  \"word\": \"café\"\n}\n");

    let res = run_fetch(&[&format!("{}/markdown", server.url), "--format", "on"]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "# Title\n\nSome bold text.\n\n- one\n- two\n");

    let res = run_fetch(&[
        &format!("{}/image", server.url),
        "--format",
        "on",
        "--image",
        "off",
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "raw image bytes");
    let res = run_fetch(&[&format!("{}/image", server.url), "--image", "bad"]);
    assert_exit(&res, 1);
    assert!(
        res.stderr
            .contains("invalid value 'bad' for option '--image'")
    );

    let res = run_fetch(&[&format!("{}/html-sniff", server.url), "--format", "on"]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("<!DOCTYPE html>") || res.stdout.contains("<!doctype html>"));

    let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
    gzip.write_all(b"this is the test data").unwrap();
    let gzip_body = gzip.finish().unwrap();
    let mut gzip_sse = GzEncoder::new(Vec::new(), Compression::default());
    gzip_sse.write_all(b"data: compressed\n\n").unwrap();
    let gzip_sse_body = gzip_sse.finish().unwrap();
    let mut huge_gzip = GzEncoder::new(Vec::new(), Compression::default());
    huge_gzip
        .write_all(&vec![b' '; 16 * 1024 * 1024 + 1])
        .unwrap();
    let huge_gzip_body = huge_gzip.finish().unwrap();
    let mut brotli_body = Vec::new();
    {
        let mut brotli = brotli::CompressorWriter::new(&mut brotli_body, 4096, 5, 22);
        brotli.write_all(b"this is the test data").unwrap();
    }
    let zstd_body = zstd::encode_all(&b"this is the test data"[..], 0).unwrap();
    let compressed = TestServer::start(move |req| match req.header("accept-encoding").as_str() {
        "gzip, br, zstd" if req.path == "/br" => {
            TestResponse::ok(brotli_body.clone()).header("Content-Encoding", "br")
        }
        "gzip, br, zstd" if req.path == "/zstd" => {
            TestResponse::ok(zstd_body.clone()).header("Content-Encoding", "zstd")
        }
        "gzip, br, zstd" if req.path == "/too-large" => {
            TestResponse::ok(huge_gzip_body.clone()).header("Content-Encoding", "gzip")
        }
        "gzip, br, zstd" if req.path == "/sse" => TestResponse::ok(gzip_sse_body.clone())
            .header("Content-Type", "text/event-stream")
            .header("Content-Encoding", "gzip"),
        "gzip, br, zstd" | "gzip" => {
            TestResponse::ok(gzip_body.clone()).header("Content-Encoding", "gzip")
        }
        "br" => TestResponse::ok(brotli_body.clone()).header("Content-Encoding", "br"),
        "zstd" => TestResponse::ok(zstd_body.clone()).header("Content-Encoding", "zstd"),
        "" if req.path == "/sse" => {
            TestResponse::ok("data: uncompressed\n\n").header("Content-Type", "text/event-stream")
        }
        "" => TestResponse::ok("this is the test data"),
        other => TestResponse::status(
            400,
            "Bad Request",
            format!("unexpected accept-encoding: {other}"),
        ),
    });
    let res = run_fetch(&[&compressed.url, "-v"]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "this is the test data");
    assert!(res.stderr.contains("gzip"));
    let res = run_fetch(&[&format!("{}/sse", compressed.url), "--format", "on"]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "event: message\ndata: uncompressed\n\n");
    let requests = wait_for_requests(&compressed, 3);
    assert_eq!(requests[1].header("accept-encoding"), "gzip, br, zstd");
    assert_eq!(requests[2].header("accept-encoding"), "");
    let res = run_fetch(&[&compressed.url, "--discard"]);
    assert_exit(&res, 0);
    assert!(res.stdout.is_empty());
    assert!(res.stderr.contains("200 OK"));
    let res = run_fetch(&[&format!("{}/too-large", compressed.url), "--format", "on"]);
    assert_exit(&res, 1);
    assert!(res.stdout.is_empty());
    assert!(res.stderr.contains("cannot be buffered"));
    let res = run_fetch(&[&format!("{}/zstd", compressed.url), "-v"]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "this is the test data");
    assert!(res.stderr.contains("zstd"));
    let res = run_fetch(&[&format!("{}/br", compressed.url), "-v"]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "this is the test data");
    assert!(res.stderr.contains("br"));
    let res = run_fetch(&[&compressed.url, "-v", "--compress", "gzip"]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "this is the test data");
    assert!(res.stderr.contains("gzip"));
    let res = run_fetch(&[
        &format!("{}/zstd", compressed.url),
        "-v",
        "--compress",
        "zstd",
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "this is the test data");
    assert!(res.stderr.contains("zstd"));
    let res = run_fetch(&[&compressed.url, "-v", "--compress", "br"]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "this is the test data");
    assert!(res.stderr.contains("br"));
    let res = run_fetch(&[&compressed.url, "-v", "--compress", "brotli"]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "this is the test data");
    assert!(res.stderr.contains("br"));
    let res = run_fetch(&[&compressed.url, "-v", "--compress", "off"]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "this is the test data");
    assert!(!res.stderr.contains("br"));
    assert!(!res.stderr.contains("gzip"));
    assert!(!res.stderr.contains("zstd"));
    let res = run_fetch(&[&compressed.url, "--compress", "bad"]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("invalid value 'bad'"));
}
