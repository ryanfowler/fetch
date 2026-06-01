#![allow(dead_code, unused_imports)]

pub(crate) use base64::Engine;
pub(crate) use bytes::Buf;
pub(crate) use flate2::Compression;
pub(crate) use flate2::write::GzEncoder;
pub(crate) use md5::{Digest as Md5Digest, Md5};
pub(crate) use prost::Message;
pub(crate) use prost_types::{
    DescriptorProto, EnumDescriptorProto, EnumValueDescriptorProto, FieldDescriptorProto,
    FileDescriptorProto, FileDescriptorSet, MethodDescriptorProto, ServiceDescriptorProto,
    field_descriptor_proto,
};
pub(crate) use sha1::Sha1;
pub(crate) use std::collections::HashMap;
pub(crate) use std::env;
pub(crate) use std::fs;
pub(crate) use std::io::{BufRead, BufReader, Read, Write};
pub(crate) use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream, UdpSocket};
pub(crate) use std::path::{Path, PathBuf};
pub(crate) use std::process::{Command, ExitStatus, Stdio};
pub(crate) use std::sync::atomic::{AtomicUsize, Ordering};
pub(crate) use std::sync::{Arc, Mutex, mpsc};
pub(crate) use std::thread;
pub(crate) use std::time::{Duration, Instant};
pub(crate) use tempfile::TempDir;
pub(crate) use url::Url;

pub(crate) const FAST_RETRY_DELAY: &str = "0.000001";
pub(crate) const PARTIAL_REPLAY_BODY_PREFIX_BYTES: usize = 1024 * 1024;

#[cfg(unix)]
pub(crate) use image::ImageEncoder;
#[cfg(unix)]
pub(crate) use std::os::fd::{FromRawFd, RawFd};
#[cfg(unix)]
pub(crate) use std::os::unix::fs::PermissionsExt;

#[derive(Debug)]
pub(crate) struct FetchOutput {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

#[derive(Default)]
pub(crate) struct FetchOpts {
    pub(crate) stdin: Option<String>,
    pub(crate) env: Vec<(String, String)>,
    pub(crate) cwd: Option<PathBuf>,
    pub(crate) bin: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub(crate) struct TestRequest {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) headers: HashMap<String, String>,
    pub(crate) header_lines: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl TestRequest {
    pub(crate) fn header(&self, name: &str) -> String {
        self.headers
            .get(&name.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn header_values(&self, name: &str) -> Vec<String> {
        self.header_lines
            .iter()
            .filter(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
            .collect()
    }

    pub(crate) fn body_string(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

pub(crate) struct TestResponse {
    pub(crate) status: u16,
    pub(crate) reason: &'static str,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
    pub(crate) h2_reset: Option<h2::Reason>,
}

impl TestResponse {
    pub(crate) fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 200,
            reason: "OK",
            headers: Vec::new(),
            body: body.into(),
            h2_reset: None,
        }
    }

    pub(crate) fn status(status: u16, reason: &'static str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            reason,
            headers: Vec::new(),
            body: body.into(),
            h2_reset: None,
        }
    }

    pub(crate) fn h2_reset(reason: h2::Reason) -> Self {
        Self {
            status: 200,
            reason: "OK",
            headers: Vec::new(),
            body: Vec::new(),
            h2_reset: Some(reason),
        }
    }

    pub(crate) fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

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

pub(crate) struct TestServer {
    pub(crate) url: String,
    pub(crate) requests: Arc<Mutex<Vec<TestRequest>>>,
    pub(crate) shutdown: Option<mpsc::Sender<()>>,
    pub(crate) join: Option<thread::JoinHandle<()>>,
}

pub(crate) struct PartialBodyReplayServer {
    pub(crate) url: String,
    pub(crate) requests: Arc<Mutex<Vec<TestRequest>>>,
    pub(crate) join: Option<thread::JoinHandle<()>>,
}

pub(crate) struct TlsTestServer {
    pub(crate) url: String,
    pub(crate) ca_cert_path: PathBuf,
    pub(crate) shutdown: Option<mpsc::Sender<()>>,
    pub(crate) join: Option<thread::JoinHandle<()>>,
}

pub(crate) struct MtlsTestServer {
    pub(crate) url: String,
    pub(crate) ca_cert_path: PathBuf,
    pub(crate) client_cert_path: PathBuf,
    pub(crate) client_key_path: PathBuf,
    pub(crate) client_combined_path: PathBuf,
    pub(crate) shutdown: Option<mpsc::Sender<()>>,
    pub(crate) join: Option<thread::JoinHandle<()>>,
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
    pub(crate) connections: Arc<AtomicUsize>,
}

pub(crate) struct ReflectionGrpcServer {
    pub(crate) url: String,
    pub(crate) ca_cert_path: Option<PathBuf>,
    pub(crate) requests: Arc<Mutex<Vec<TestRequest>>>,
}

impl ReflectionGrpcServer {
    pub(crate) fn requests(&self) -> Vec<TestRequest> {
        self.requests.lock().unwrap().clone()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReflectionBehavior {
    Enabled,
    Disabled,
    V1ErrorResponseUnimplemented,
}

pub(crate) struct ReadCapture {
    pub(crate) buffer: Arc<Mutex<Vec<u8>>>,
    pub(crate) done: mpsc::Receiver<()>,
}

#[cfg(unix)]
pub(crate) struct PtyPair {
    pub(crate) master: fs::File,
    pub(crate) slave: fs::File,
}

#[cfg(unix)]
pub(crate) struct PtyCapture {
    pub(crate) file: fs::File,
    pub(crate) buffer: Arc<Mutex<Vec<u8>>>,
    pub(crate) done: mpsc::Receiver<()>,
}

impl Drop for TlsTestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for MtlsTestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl TestServer {
    pub(crate) fn start(
        handler: impl Fn(TestRequest) -> TestResponse + Send + Sync + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        listener
            .set_nonblocking(true)
            .expect("set test listener nonblocking");
        let url = format!("http://{}", listener.local_addr().expect("local addr"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let handler = Arc::new(handler);
        let (tx, rx) = mpsc::channel();
        let request_log = Arc::clone(&requests);
        let join = thread::spawn(move || {
            loop {
                if rx.try_recv().is_ok() {
                    break;
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let handler = Arc::clone(&handler);
                        let request_log = Arc::clone(&request_log);
                        thread::spawn(move || {
                            let mut writer = stream.try_clone().expect("clone response stream");
                            let mut reader = BufReader::new(stream);
                            while let Some(req) = read_request(&mut reader) {
                                let close = req.header("connection").eq_ignore_ascii_case("close");
                                request_log.lock().unwrap().push(req.clone());
                                let resp = handler(req);
                                write_response(&mut writer, resp);
                                if close {
                                    break;
                                }
                            }
                        });
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            url,
            requests,
            shutdown: Some(tx),
            join: Some(join),
        }
    }

    pub(crate) fn requests(&self) -> Vec<TestRequest> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl PartialBodyReplayServer {
    pub(crate) fn start(
        status: u16,
        reason: &'static str,
        headers: Vec<(&'static str, &'static str)>,
        final_body: &'static str,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind partial body server");
        listener
            .set_nonblocking(true)
            .expect("set partial body listener nonblocking");
        let url = format!("http://{}", listener.local_addr().expect("local addr"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let request_log = Arc::clone(&requests);
        let join = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut first = true;
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                        let reader_stream = stream.try_clone().expect("clone request stream");
                        let mut reader = BufReader::new(reader_stream);
                        let Some(req) = read_request(&mut reader) else {
                            continue;
                        };
                        request_log.lock().unwrap().push(req);
                        if first {
                            first = false;
                            let headers = headers.clone();
                            let _ = write!(stream, "HTTP/1.1 {status} {reason}\r\n");
                            for (name, value) in &headers {
                                let _ = write!(stream, "{name}: {value}\r\n");
                            }
                            let _ = write!(
                                stream,
                                "Content-Length: 1073741824\r\nConnection: close\r\n\r\n"
                            );
                            let body = vec![b'x'; PARTIAL_REPLAY_BODY_PREFIX_BYTES];
                            let _ = stream.write_all(&body);
                            let _ = stream.flush();
                            thread::spawn(move || {
                                let deadline = Instant::now() + Duration::from_secs(5);
                                let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
                                let mut buf = [0_u8; 1024];
                                while Instant::now() < deadline {
                                    match stream.read(&mut buf) {
                                        Ok(0) => break,
                                        Ok(_) => {}
                                        Err(err)
                                            if matches!(
                                                err.kind(),
                                                std::io::ErrorKind::WouldBlock
                                                    | std::io::ErrorKind::TimedOut
                                            ) => {}
                                        Err(_) => break,
                                    }
                                }
                                let _ = stream.shutdown(Shutdown::Both);
                            });
                        } else {
                            write_response(
                                &mut stream,
                                TestResponse::ok(final_body).header("Connection", "close"),
                            );
                            let _ = stream.shutdown(Shutdown::Both);
                            break;
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            url,
            requests,
            join: Some(join),
        }
    }

    pub(crate) fn requests(&self) -> Vec<TestRequest> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for PartialBodyReplayServer {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

pub(crate) fn read_request(reader: &mut impl BufRead) -> Option<TestRequest> {
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).ok()? == 0 {
        return None;
    }
    let request_line = request_line.trim_end_matches(['\r', '\n']);
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let _version = parts.next()?.to_string();

    let mut headers = HashMap::new();
    let mut header_lines = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            return None;
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            header_lines.push((name.clone(), value.clone()));
            headers.insert(name, value);
        }
    }

    let mut body = Vec::new();
    if headers
        .get("transfer-encoding")
        .is_some_and(|v| v.eq_ignore_ascii_case("chunked"))
    {
        loop {
            let mut size_line = String::new();
            reader.read_line(&mut size_line).ok()?;
            let size = usize::from_str_radix(size_line.trim(), 16).ok()?;
            if size == 0 {
                let mut trailer_end = String::new();
                reader.read_line(&mut trailer_end).ok()?;
                break;
            }
            let start = body.len();
            body.resize(start + size, 0);
            reader.read_exact(&mut body[start..]).ok()?;
            let mut crlf = [0; 2];
            reader.read_exact(&mut crlf).ok()?;
        }
    } else {
        let content_length = headers
            .get("content-length")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        if content_length > 0 {
            body.resize(content_length, 0);
            reader.read_exact(&mut body).ok()?;
        }
    }

    Some(TestRequest {
        method,
        path,
        headers,
        header_lines,
        body,
    })
}

pub(crate) fn write_response(stream: &mut impl Write, resp: TestResponse) {
    let mut headers = resp.headers;
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-length"))
    {
        headers.push(("Content-Length".to_string(), resp.body.len().to_string()));
    }
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("connection"))
    {
        headers.push(("Connection".to_string(), "keep-alive".to_string()));
    }
    let _ = write!(stream, "HTTP/1.1 {} {}\r\n", resp.status, resp.reason);
    for (name, value) in headers {
        let _ = write!(stream, "{name}: {value}\r\n");
    }
    let _ = write!(stream, "\r\n");
    let _ = stream.write_all(&resp.body);
    let _ = stream.flush();
}

pub(crate) fn fetch_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_fetch"))
}

pub(crate) fn run_fetch(args: &[&str]) -> FetchOutput {
    run_fetch_opts(FetchOpts::default(), args)
}

pub(crate) fn fetch_version() -> String {
    let res = run_fetch(&["--version"]);
    assert_exit(&res, 0);
    res.stdout
        .trim()
        .strip_prefix("fetch ")
        .expect("version output prefix")
        .to_string()
}

pub(crate) fn run_fetch_opts(opts: FetchOpts, args: &[&str]) -> FetchOutput {
    let can_retry = opts.stdin.is_none() && opts.cwd.is_none();
    let env = opts.env.clone();
    let bin = opts.bin.clone();
    let mut result = run_fetch_once(opts, args);
    for _ in 0..4 {
        if !can_retry || !is_transient_local_server_error(&result) {
            return result;
        }
        thread::sleep(Duration::from_millis(25));
        result = run_fetch_once(
            FetchOpts {
                stdin: None,
                env: env.clone(),
                cwd: None,
                bin: bin.clone(),
            },
            args,
        );
    }
    result
}

pub(crate) fn run_fetch_once(opts: FetchOpts, args: &[&str]) -> FetchOutput {
    let mut cmd = Command::new(opts.bin.clone().unwrap_or_else(fetch_bin));
    cmd.args(args);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.env("NO_COLOR", "");
    cmd.env("HTTP_PROXY", "");
    cmd.env("HTTPS_PROXY", "");
    cmd.env("ALL_PROXY", "");
    cmd.env("NO_PROXY", "*");
    for (key, value) in opts.env {
        cmd.env(key, value);
    }
    if let Some(cwd) = opts.cwd {
        cmd.current_dir(cwd);
    }
    if opts.stdin.is_some() {
        cmd.stdin(Stdio::piped());
    }

    let mut child = cmd.spawn().expect("spawn fetch");
    if let Some(input) = opts.stdin {
        let mut stdin = child.stdin.take().expect("child stdin");
        stdin.write_all(input.as_bytes()).expect("write stdin");
    }
    let start = Instant::now();
    loop {
        if child.try_wait().expect("poll fetch").is_some() {
            break;
        }
        if start.elapsed() > Duration::from_secs(30) {
            let _ = child.kill();
            let out = child.wait_with_output().expect("wait killed fetch");
            return FetchOutput {
                status: out.status,
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: format!(
                    "{}\nfetch test harness timeout after 30s",
                    String::from_utf8_lossy(&out.stderr)
                ),
            };
        }
        thread::sleep(Duration::from_millis(10));
    }
    let out = child.wait_with_output().expect("wait fetch");
    FetchOutput {
        status: out.status,
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

#[cfg(unix)]
pub(crate) fn run_fetch_with_closed_stdout(args: &[&str]) -> FetchOutput {
    let mut fds = [0 as RawFd; 2];
    let pipe_status = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(pipe_status, 0, "create closed stdout pipe");
    let close_status = unsafe { libc::close(fds[0]) };
    assert_eq!(close_status, 0, "close stdout pipe reader");

    let mut cmd = Command::new(fetch_bin());
    cmd.args(args);
    cmd.stdout(unsafe { Stdio::from_raw_fd(fds[1]) });
    cmd.stderr(Stdio::piped());
    cmd.env("NO_COLOR", "");
    cmd.env("HTTP_PROXY", "");
    cmd.env("HTTPS_PROXY", "");
    cmd.env("ALL_PROXY", "");
    cmd.env("NO_PROXY", "*");

    let out = cmd.output().expect("run fetch with closed stdout");
    FetchOutput {
        status: out.status,
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

pub(crate) fn is_transient_local_server_error(res: &FetchOutput) -> bool {
    res.status.code() == Some(1)
        && (res
            .stderr
            .contains("connection closed before message completed")
            || res.stderr.contains("connection was not ready")
            || res.stderr.contains("Connection reset by peer")
            || res.stderr.contains("Connection refused"))
}

pub(crate) fn assert_exit(res: &FetchOutput, code: i32) {
    assert_eq!(
        res.status.code(),
        Some(code),
        "unexpected exit code\nstdout:\n{}\nstderr:\n{}",
        res.stdout,
        res.stderr
    );
}

#[cfg(unix)]
pub(crate) fn assert_no_closed_stdout_panic(res: &FetchOutput) {
    assert_ne!(
        res.status.code(),
        Some(101),
        "closed stdout caused a panic\nstderr:\n{}",
        res.stderr
    );
    assert!(
        !res.stderr.contains("failed printing to stdout"),
        "stderr contains stdout panic message:\n{}",
        res.stderr
    );
    assert!(
        !res.stderr.contains("panicked"),
        "stderr contains panic output:\n{}",
        res.stderr
    );
}

pub(crate) fn temp_file(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, contents).expect("write temp file");
    path
}

#[cfg(not(windows))]
pub(crate) fn update_artifact_name(version: &str) -> String {
    let goos = if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        std::env::consts::OS
    };
    let goarch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    let suffix = if cfg!(target_os = "windows") {
        "zip"
    } else {
        "tar.gz"
    };
    format!("fetch-{version}-{goos}-{goarch}.{suffix}")
}

#[cfg(not(windows))]
pub(crate) fn make_update_artifact(version: &str) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let gz = GzEncoder::new(&mut out, Compression::fast());
        let mut tar = tar::Builder::new(gz);
        let script = format!("#!/bin/sh\necho 'fetch {version}'\n");
        let mut header = tar::Header::new_gnu();
        header.set_size(script.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        tar.append_data(&mut header, "fetch", script.as_bytes())
            .unwrap();
        let gz = tar.into_inner().unwrap();
        gz.finish().unwrap();
    }
    out
}

#[cfg(not(windows))]
pub(crate) fn update_artifact_checksum_line(name: &str, artifact: &[u8]) -> String {
    use sha2::{Digest as Sha2Digest, Sha256};

    let digest = Sha256::digest(artifact);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push(HEX[(byte >> 4) as usize] as char);
        hex.push(HEX[(byte & 0x0f) as usize] as char);
    }
    format!("{hex}  {name}\n")
}

#[cfg(not(windows))]
pub(crate) fn install_update_launcher(path: &Path) {
    let source = fetch_bin();
    if fs::hard_link(&source, path).is_err() {
        fs::copy(&source, path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(path, perms).unwrap();
        }
    }
}

#[cfg(unix)]
pub(crate) fn test_png_bytes() -> Vec<u8> {
    let img = image::ImageBuffer::from_fn(2, 2, |x, y| match (x, y) {
        (0, 0) => image::Rgba([255, 0, 0, 255]),
        (1, 0) => image::Rgba([0, 255, 0, 255]),
        (0, 1) => image::Rgba([0, 0, 255, 255]),
        _ => image::Rgba([255, 255, 255, 255]),
    });
    let mut out = Vec::new();
    image::codecs::png::PngEncoder::new(&mut out)
        .write_image(img.as_raw(), 2, 2, image::ExtendedColorType::Rgba8)
        .unwrap();
    out
}

#[cfg(unix)]
pub(crate) fn image_pty_env(overrides: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut env = vec![
        ("TERM", "xterm-256color"),
        ("COLORTERM", ""),
        ("TERM_PROGRAM", ""),
        ("GHOSTTY_BIN_DIR", ""),
        ("ITERM_SESSION_ID", ""),
        ("KITTY_PID", ""),
        ("KONSOLE_VERSION", ""),
        ("VSCODE_INJECTION", ""),
        ("WEZTERM_EXECUTABLE", ""),
        ("WT_SESSION", ""),
        ("ZELLIJ", ""),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect::<Vec<_>>();
    for (key, value) in overrides {
        if let Some((_, existing)) = env.iter_mut().find(|(k, _)| k == key) {
            *existing = value.to_string();
        } else {
            env.push((key.to_string(), value.to_string()));
        }
    }
    env
}

pub(crate) fn wait_for_requests(server: &TestServer, count: usize) -> Vec<TestRequest> {
    let start = Instant::now();
    loop {
        let requests = server.requests();
        if requests.len() >= count {
            return requests;
        }
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "timed out waiting for {count} requests; got {}",
            requests.len()
        );
        thread::sleep(Duration::from_millis(10));
    }
}

pub(crate) fn wait_for_h3_requests(server: &H3TestServer, count: usize) -> Vec<H3Request> {
    let start = Instant::now();
    loop {
        let requests = server.requests();
        if requests.len() >= count {
            return requests;
        }
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "timed out waiting for {count} HTTP/3 requests; got {}",
            requests.len()
        );
        thread::sleep(Duration::from_millis(10));
    }
}

pub(crate) fn accept_tcp_connection(
    listener: &TcpListener,
    timeout: Duration,
    context: &str,
) -> Result<TcpStream, String> {
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(format!("timed out waiting to accept {context}"));
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(err) => return Err(format!("accept {context}: {err}")),
        }
    }
}

pub(crate) fn start_read_capture<R>(mut reader: R) -> ReadCapture
where
    R: Read + Send + 'static,
{
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let buffer_for_thread = Arc::clone(&buffer);
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut chunk = [0_u8; 1024];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buffer_for_thread
                    .lock()
                    .unwrap()
                    .extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
        let _ = tx.send(());
    });
    ReadCapture { buffer, done: rx }
}

impl ReadCapture {
    pub(crate) fn output(&self) -> String {
        String::from_utf8_lossy(&self.buffer.lock().unwrap()).into_owned()
    }

    pub(crate) fn wait_for(&self, want: &str, timeout: Duration) {
        let start = Instant::now();
        loop {
            if self.output().contains(want) {
                return;
            }
            assert!(
                start.elapsed() < timeout,
                "timed out waiting for captured output {want:?}; output:\n{}",
                self.output()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub(crate) fn close(self) {
        let _ = self.done.recv_timeout(Duration::from_secs(1));
    }
}

#[cfg(unix)]
pub(crate) fn open_pty(rows: u16, cols: u16, xpixel: u16, ypixel: u16) -> PtyPair {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    #[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
    let winsize = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: xpixel,
        ws_ypixel: ypixel,
    };
    #[cfg(not(all(target_os = "linux", not(target_env = "uclibc"))))]
    let mut winsize = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: xpixel,
        ws_ypixel: ypixel,
    };
    #[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
    let winsize_ptr = &winsize;
    #[cfg(not(all(target_os = "linux", not(target_env = "uclibc"))))]
    let winsize_ptr = &mut winsize;
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            winsize_ptr,
        )
    };
    assert_eq!(rc, 0, "openpty failed");
    PtyPair {
        master: unsafe { fs::File::from_raw_fd(master) },
        slave: unsafe { fs::File::from_raw_fd(slave) },
    }
}

#[cfg(unix)]
pub(crate) fn start_pty_capture(file: &fs::File) -> PtyCapture {
    let mut read_file = file.try_clone().unwrap();
    let write_file = file.try_clone().unwrap();
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let buffer_for_thread = Arc::clone(&buffer);
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut responded = false;
        let mut chunk = [0_u8; 1024];
        loop {
            match read_file.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    let needs_cursor_response = {
                        let mut buf = buffer_for_thread.lock().unwrap();
                        buf.extend_from_slice(&chunk[..n]);
                        !responded && buf.windows(4).any(|w| w == b"\x1b[6n")
                    };
                    if needs_cursor_response {
                        responded = true;
                        let mut writer = write_file.try_clone().unwrap();
                        let _ = writer.write_all(b"\x1b[1;1R");
                    }
                }
                Err(_) => break,
            }
        }
        let _ = tx.send(());
    });
    PtyCapture {
        file: file.try_clone().unwrap(),
        buffer,
        done: rx,
    }
}

#[cfg(unix)]
impl PtyCapture {
    pub(crate) fn output(&self) -> String {
        String::from_utf8_lossy(&self.buffer.lock().unwrap()).into_owned()
    }

    pub(crate) fn wait_for(&self, want: &str, timeout: Duration) {
        let start = Instant::now();
        loop {
            if self.output().contains(want) {
                return;
            }
            assert!(
                start.elapsed() < timeout,
                "timed out waiting for PTY output {want:?}; output:\n{}",
                self.output()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub(crate) fn close(self) {
        drop(self.file);
        let _ = self.done.recv_timeout(Duration::from_secs(1));
    }
}

pub(crate) fn wait_child(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Option<std::io::Result<ExitStatus>> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(Ok(status)),
            Ok(None) => {}
            Err(err) => return Some(Err(err)),
        }
        if start.elapsed() > timeout {
            return None;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
pub(crate) fn configure_pty_child(cmd: &mut Command, slave: &fs::File) {
    use std::os::unix::process::CommandExt;
    cmd.stdin(Stdio::from(slave.try_clone().unwrap()));
    cmd.stdout(Stdio::from(slave.try_clone().unwrap()));
    cmd.stderr(Stdio::from(slave.try_clone().unwrap()));
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(0 as RawFd, libc::TIOCSCTTY as libc::c_ulong, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

pub(crate) fn host_port(url: &str) -> &str {
    url.trim_start_matches("http://")
        .trim_start_matches("https://")
}

pub(crate) fn url_host_port(url: &str) -> String {
    let url = Url::parse(url).unwrap();
    format!("{}:{}", url.host_str().unwrap(), url.port().unwrap())
}

pub(crate) fn fake_editor(dir: &Path, body: &str, code: i32) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("fake-editor.sh");
        let escaped = body.replace('\'', "'\\''");
        fs::write(
            &path,
            format!("#!/bin/sh\nprintf '%s' '{escaped}' > \"$1\"\nexit {code}\n"),
        )
        .unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&path, perms).unwrap();
        path
    }
    #[cfg(windows)]
    {
        let path = dir.join("fake-editor.cmd");
        let escaped = body
            .replace('%', "%%")
            .replace('^', "^^")
            .replace('&', "^&");
        fs::write(
            &path,
            format!("@echo off\r\n<nul set /p =\"{escaped}\" > \"%~1\"\r\nexit /b {code}\r\n"),
        )
        .unwrap();
        path
    }
}

pub(crate) fn start_udp_dns_server(host: &'static str, ip: Ipv4Addr) -> String {
    start_udp_dns_server_with_hosts(vec![(host, ip)])
}

pub(crate) fn start_udp_dns_server_with_hosts(records: Vec<(&'static str, Ipv4Addr)>) -> String {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind udp dns server");
    let addr = socket.local_addr().unwrap().to_string();
    thread::spawn(move || {
        let mut buf = [0_u8; 512];
        while let Ok((n, peer)) = socket.recv_from(&mut buf) {
            let Some((name, qtype, question_end)) = parse_dns_question(&buf[..n]) else {
                continue;
            };
            let mut resp = Vec::new();
            resp.extend_from_slice(&buf[..2]);
            resp.extend_from_slice(&[0x81, 0x80]);
            resp.extend_from_slice(&1_u16.to_be_bytes());
            let answer = records
                .iter()
                .find_map(|(host, ip)| (name == *host && qtype == 1).then_some(*ip));
            resp.extend_from_slice(&(if answer.is_some() { 1_u16 } else { 0_u16 }).to_be_bytes());
            resp.extend_from_slice(&0_u16.to_be_bytes());
            resp.extend_from_slice(&0_u16.to_be_bytes());
            resp.extend_from_slice(&buf[12..question_end]);
            if let Some(ip) = answer {
                resp.extend_from_slice(&[0xc0, 0x0c]);
                resp.extend_from_slice(&1_u16.to_be_bytes());
                resp.extend_from_slice(&1_u16.to_be_bytes());
                resp.extend_from_slice(&30_u32.to_be_bytes());
                resp.extend_from_slice(&4_u16.to_be_bytes());
                resp.extend_from_slice(&ip.octets());
            }
            let _ = socket.send_to(&resp, peer);
        }
    });
    addr
}

pub(crate) fn start_unresponsive_udp_dns_server() -> String {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind udp dns server");
    let addr = socket.local_addr().unwrap().to_string();
    thread::spawn(move || {
        let mut buf = [0_u8; 512];
        while socket.recv_from(&mut buf).is_ok() {}
    });
    addr
}

pub(crate) fn start_tls_server(
    handler: impl Fn(TestRequest) -> TestResponse + Send + Sync + 'static,
) -> TlsTestServer {
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
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tls server");
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("https://localhost:{port}");
    let handler = Arc::new(handler);
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
                    let handler = Arc::clone(&handler);
                    thread::spawn(move || {
                        let Ok(conn) = rustls::ServerConnection::new(config) else {
                            return;
                        };
                        let mut tls = rustls::StreamOwned::new(conn, stream);
                        let mut reader = BufReader::new(&mut tls);
                        let Some(req) = read_request(&mut reader) else {
                            return;
                        };
                        let resp = handler(req);
                        let tls = reader.into_inner();
                        write_response(tls, resp);
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    TlsTestServer {
        url,
        ca_cert_path,
        shutdown: Some(tx),
        join: Some(join),
    }
}

pub(crate) fn start_h2_tls_server(
    handler: impl Fn(TestRequest) -> TestResponse + Send + Sync + 'static,
) -> TlsTestServer {
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
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind h2 tls server");
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("https://localhost:{port}");
    let handler: Arc<dyn Fn(TestRequest) -> TestResponse + Send + Sync> = Arc::new(handler);
    let (tx, rx) = mpsc::channel();
    let join = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        loop {
            if rx.try_recv().is_ok() {
                break;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(true);
                    let acceptor = acceptor.clone();
                    let handler = Arc::clone(&handler);
                    runtime.block_on(async move {
                        let Ok(stream) = tokio::net::TcpStream::from_std(stream) else {
                            return;
                        };
                        let Ok(tls) = acceptor.accept(stream).await else {
                            return;
                        };
                        serve_test_h2_connection(tls, handler).await;
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    TlsTestServer {
        url,
        ca_cert_path,
        shutdown: Some(tx),
        join: Some(join),
    }
}

async fn serve_test_h2_connection<T>(
    stream: T,
    handler: Arc<dyn Fn(TestRequest) -> TestResponse + Send + Sync>,
) where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Ok(mut connection) = h2::server::handshake(stream).await else {
        return;
    };
    while let Some(result) = connection.accept().await {
        let Ok((request, respond)) = result else {
            break;
        };
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            handle_test_h2_request(request, respond, handler).await;
        });
    }
}

async fn handle_test_h2_request(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    handler: Arc<dyn Fn(TestRequest) -> TestResponse + Send + Sync>,
) {
    let (parts, mut body) = request.into_parts();
    let mut body_bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let Ok(chunk) = chunk else {
            return;
        };
        body_bytes.extend_from_slice(&chunk);
    }
    let mut headers = HashMap::new();
    let mut header_lines = Vec::new();
    let mut current_name = None;
    for (name, value) in parts.headers {
        if let Some(name) = name {
            current_name = Some(name.as_str().to_ascii_lowercase());
        }
        if let Some(name) = &current_name
            && let Ok(value) = value.to_str()
        {
            let value = value.to_string();
            header_lines.push((name.clone(), value.clone()));
            headers.insert(name.clone(), value);
        }
    }
    let resp = handler(TestRequest {
        method: parts.method.to_string(),
        path: parts
            .uri
            .path_and_query()
            .map(|path| path.as_str())
            .unwrap_or("/")
            .to_string(),
        headers,
        header_lines,
        body: body_bytes,
    });
    if let Some(reason) = resp.h2_reset {
        respond.send_reset(reason);
        return;
    }
    let mut response_headers = resp.headers;
    if !response_headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-length"))
    {
        response_headers.push(("content-length".to_string(), resp.body.len().to_string()));
    }
    let mut builder = http::Response::builder().status(resp.status);
    for (name, value) in response_headers {
        if name.eq_ignore_ascii_case("connection") || name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        builder = builder.header(name, value);
    }
    let Ok(response) = builder.body(()) else {
        return;
    };
    let body_is_empty = resp.body.is_empty();
    let Ok(mut send) = respond.send_response(response, body_is_empty) else {
        return;
    };
    if !body_is_empty {
        let _ = send.send_data(bytes::Bytes::from(resp.body), true);
    }
}

pub(crate) fn start_mtls_server() -> MtlsTestServer {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let dir = TempDir::new().unwrap().keep();

    let ca_key =
        rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
            .unwrap();
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Test CA");
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
        .push(rcgen::DnType::CommonName, "server");
    server_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_params.signed_by(&server_key, &ca_issuer).unwrap();

    let client_key =
        rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
            .unwrap();
    let mut client_params = rcgen::CertificateParams::new(vec!["client".to_string()]).unwrap();
    client_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "client");
    client_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = client_params.signed_by(&client_key, &ca_issuer).unwrap();

    let ca_cert_path = dir.join("ca.crt");
    let client_cert_path = dir.join("client.crt");
    let client_key_path = dir.join("client.key");
    let client_combined_path = dir.join("client-combined.pem");
    fs::write(&ca_cert_path, ca_cert.pem()).unwrap();
    fs::write(&client_cert_path, client_cert.pem()).unwrap();
    fs::write(&client_key_path, client_key.serialize_pem()).unwrap();
    fs::write(
        &client_combined_path,
        format!("{}{}", client_cert.pem(), client_key.serialize_pem()),
    )
    .unwrap();

    let mut client_roots = rustls::RootCertStore::empty();
    client_roots.add(ca_cert.der().clone()).unwrap();
    let client_verifier = rustls::server::WebPkiClientVerifier::builder(client_roots.into())
        .build()
        .unwrap();
    let server_key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()),
    );
    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(vec![server_cert.der().clone()], server_key_der)
        .unwrap();
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mtls server");
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("https://localhost:{port}");
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
                    thread::spawn(move || {
                        let Ok(conn) = rustls::ServerConnection::new(config) else {
                            return;
                        };
                        let mut tls = rustls::StreamOwned::new(conn, stream);
                        let mut reader = BufReader::new(&mut tls);
                        let Some(req) = read_request(&mut reader) else {
                            return;
                        };
                        let resp = if req.path == "/" {
                            TestResponse::ok("mtls-success")
                        } else {
                            TestResponse::status(404, "Not Found", "")
                        };
                        let tls = reader.into_inner();
                        write_response(tls, resp);
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    MtlsTestServer {
        url,
        ca_cert_path,
        client_cert_path,
        client_key_path,
        client_combined_path,
        shutdown: Some(tx),
        join: Some(join),
    }
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
        connections,
    }
}

pub(crate) fn start_reflection_grpc_h2c_server(enable_reflection: bool) -> ReflectionGrpcServer {
    start_reflection_grpc_h2c_server_with_behavior(if enable_reflection {
        ReflectionBehavior::Enabled
    } else {
        ReflectionBehavior::Disabled
    })
}

pub(crate) fn start_reflection_grpc_h2c_v1_error_response_server() -> ReflectionGrpcServer {
    start_reflection_grpc_h2c_server_with_behavior(ReflectionBehavior::V1ErrorResponseUnimplemented)
}

pub(crate) fn start_reflection_grpc_h2c_server_with_behavior(
    behavior: ReflectionBehavior,
) -> ReflectionGrpcServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind h2c grpc server");
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let descriptor = reflection_health_descriptor();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured_requests = Arc::clone(&requests);
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let descriptor = descriptor.clone();
                let requests = Arc::clone(&captured_requests);
                tokio::spawn(async move {
                    serve_reflection_h2_connection(stream, descriptor, behavior, requests).await;
                });
            }
        });
    });
    ReflectionGrpcServer {
        url,
        ca_cert_path: None,
        requests,
    }
}

pub(crate) fn start_reflection_grpc_tls_server(enable_reflection: bool) -> ReflectionGrpcServer {
    start_reflection_grpc_tls_server_with_versions(
        enable_reflection,
        &[&rustls::version::TLS13, &rustls::version::TLS12],
    )
}

pub(crate) fn start_reflection_grpc_tls_server_with_versions(
    enable_reflection: bool,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> ReflectionGrpcServer {
    let behavior = if enable_reflection {
        ReflectionBehavior::Enabled
    } else {
        ReflectionBehavior::Disabled
    };
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
    let mut config = rustls::ServerConfig::builder_with_protocol_versions(versions)
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tls grpc server");
    listener.set_nonblocking(true).unwrap();
    let url = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let descriptor = reflection_health_descriptor();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured_requests = Arc::clone(&requests);
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let descriptor = descriptor.clone();
                let requests = Arc::clone(&captured_requests);
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    serve_reflection_h2_connection(tls, descriptor, behavior, requests).await;
                });
            }
        });
    });
    ReflectionGrpcServer {
        url,
        ca_cert_path: Some(ca_cert_path),
        requests,
    }
}

pub(crate) fn reflection_health_descriptor() -> Vec<u8> {
    let path = write_health_descriptor_set(TempDir::new().unwrap().keep().as_path());
    let fds = fs::read(path).unwrap();
    let set = FileDescriptorSet::decode(fds.as_slice()).unwrap();
    set.file[0].encode_to_vec()
}

async fn serve_reflection_h2_connection<T>(
    stream: T,
    descriptor: Vec<u8>,
    behavior: ReflectionBehavior,
    requests: Arc<Mutex<Vec<TestRequest>>>,
) where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Ok(mut connection) = h2::server::handshake(stream).await else {
        return;
    };
    while let Some(result) = connection.accept().await {
        let Ok((request, respond)) = result else {
            break;
        };
        let descriptor = descriptor.clone();
        let requests = Arc::clone(&requests);
        tokio::spawn(async move {
            handle_reflection_h2_request(request, respond, descriptor, behavior, requests).await;
        });
    }
}

pub(crate) fn start_status_grpc_h2c_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind status grpc server");
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    serve_status_grpc_h2_connection(stream).await;
                });
            }
        });
    });
    url
}

#[cfg(unix)]
pub(crate) fn start_delayed_response_grpc_h2c_server(close_rx: mpsc::Receiver<()>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind delayed grpc server");
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            serve_delayed_response_grpc_h2_connection(stream, close_rx).await;
        });
    });
    url
}

pub(crate) fn start_delayed_bidi_grpc_h2c_server(finish_rx: mpsc::Receiver<()>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind delayed bidi grpc server");
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            serve_delayed_bidi_grpc_h2_connection(stream, finish_rx).await;
        });
    });
    url
}

async fn serve_status_grpc_h2_connection<T>(stream: T)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Ok(mut connection) = h2::server::handshake(stream).await else {
        return;
    };
    while let Some(result) = connection.accept().await {
        let Ok((request, respond)) = result else {
            break;
        };
        tokio::spawn(async move {
            handle_status_grpc_h2_request(request, respond).await;
        });
    }
}

#[cfg(unix)]
async fn serve_delayed_response_grpc_h2_connection<T>(stream: T, close_rx: mpsc::Receiver<()>)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Ok(mut connection) = h2::server::handshake(stream).await else {
        return;
    };
    if let Some(Ok((request, respond))) = connection.accept().await {
        tokio::spawn(async move {
            handle_delayed_response_grpc_h2_request(request, respond, close_rx).await;
        });
    }
    while let Some(result) = connection.accept().await {
        if result.is_err() {
            break;
        }
    }
}

async fn serve_delayed_bidi_grpc_h2_connection<T>(stream: T, finish_rx: mpsc::Receiver<()>)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Ok(mut connection) = h2::server::handshake(stream).await else {
        return;
    };
    if let Some(Ok((request, respond))) = connection.accept().await {
        tokio::spawn(async move {
            handle_delayed_bidi_grpc_h2_request(request, respond, finish_rx).await;
        });
    }
    while let Some(result) = connection.accept().await {
        if result.is_err() {
            break;
        }
    }
}

async fn handle_status_grpc_h2_request(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
) {
    let path = request.uri().path().to_string();
    let mut body = request.into_body();
    while let Some(chunk) = body.data().await {
        if chunk.is_err() {
            return;
        }
    }

    let (payload, status, message) = match path.as_str() {
        "/test.Stream/Events" => {
            let mut frames = grpc_frame(&proto_field_string(1, "first"));
            frames.extend(grpc_frame(&proto_field_string(1, "second")));
            (frames, "0", "")
        }
        "/test.Status/Denied" => (Vec::new(), "7", "permission%20denied"),
        _ => (Vec::new(), "12", "unimplemented"),
    };

    let Ok(response) = http::Response::builder()
        .status(200)
        .header("content-type", "application/grpc+proto")
        .body(())
    else {
        return;
    };
    let Ok(mut send) = respond.send_response(response, false) else {
        return;
    };
    if !payload.is_empty() && send.send_data(bytes::Bytes::from(payload), false).is_err() {
        return;
    }
    let mut trailers = http::HeaderMap::new();
    trailers.insert("grpc-status", http::HeaderValue::from_static(status));
    if !message.is_empty() {
        trailers.insert("grpc-message", http::HeaderValue::from_static(message));
    }
    let _ = send.send_trailers(trailers);
}

#[cfg(unix)]
async fn handle_delayed_response_grpc_h2_request(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    close_rx: mpsc::Receiver<()>,
) {
    let mut body = request.into_body();
    while let Some(chunk) = body.data().await {
        if chunk.is_err() {
            return;
        }
    }

    let Ok(response) = http::Response::builder()
        .status(200)
        .header("content-type", "application/grpc+proto")
        .body(())
    else {
        return;
    };
    let Ok(mut send) = respond.send_response(response, false) else {
        return;
    };
    if send
        .send_data(
            bytes::Bytes::from(grpc_frame(&proto_field_varint(1, 1))),
            false,
        )
        .is_err()
    {
        return;
    }
    wait_for_test_signal(close_rx, Duration::from_secs(5)).await;
    if send
        .send_data(
            bytes::Bytes::from(grpc_frame(&proto_field_varint(1, 2))),
            false,
        )
        .is_err()
    {
        return;
    }
    send_ok_grpc_trailers(send);
}

async fn handle_delayed_bidi_grpc_h2_request(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    finish_rx: mpsc::Receiver<()>,
) {
    let mut body = request.into_body();
    let mut pending = Vec::new();
    while !has_complete_grpc_frame(&pending) {
        match body.data().await {
            Some(Ok(chunk)) => pending.extend_from_slice(&chunk),
            Some(Err(_)) | None => return,
        }
    }

    let Ok(response) = http::Response::builder()
        .status(200)
        .header("content-type", "application/grpc+proto")
        .body(())
    else {
        return;
    };
    let Ok(mut send) = respond.send_response(response, false) else {
        return;
    };
    if send
        .send_data(
            bytes::Bytes::from(grpc_frame(&proto_field_varint(1, 1))),
            false,
        )
        .is_err()
    {
        return;
    }
    wait_for_test_signal(finish_rx, Duration::from_secs(5)).await;
    while let Some(chunk) = body.data().await {
        if chunk.is_err() {
            return;
        }
    }
    send_ok_grpc_trailers(send);
}

pub(crate) fn has_complete_grpc_frame(bytes: &[u8]) -> bool {
    if bytes.len() < 5 {
        return false;
    }
    let len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
    bytes.len() >= 5 + len
}

pub(crate) fn send_ok_grpc_trailers(mut send: h2::SendStream<bytes::Bytes>) {
    let mut trailers = http::HeaderMap::new();
    trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
    let _ = send.send_trailers(trailers);
}

async fn wait_for_test_signal(rx: mpsc::Receiver<()>, timeout: Duration) {
    let _ = tokio::task::spawn_blocking(move || rx.recv_timeout(timeout)).await;
}

async fn handle_reflection_h2_request(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    descriptor: Vec<u8>,
    behavior: ReflectionBehavior,
    requests: Arc<Mutex<Vec<TestRequest>>>,
) {
    let (parts, mut body) = request.into_parts();
    let path = parts.uri.path().to_string();
    let request_path = parts
        .uri
        .path_and_query()
        .map(|path| path.as_str())
        .unwrap_or("/")
        .to_string();
    let mut headers = HashMap::new();
    let mut header_lines = Vec::new();
    let mut current_name = None;
    for (name, value) in parts.headers {
        if let Some(name) = name {
            current_name = Some(name.as_str().to_ascii_lowercase());
        }
        if let Some(name) = &current_name
            && let Ok(value) = value.to_str()
        {
            let value = value.to_string();
            header_lines.push((name.clone(), value.clone()));
            headers.insert(name.clone(), value);
        }
    }
    let mut raw = Vec::new();
    while let Some(chunk) = body.data().await {
        let Ok(chunk) = chunk else {
            return;
        };
        raw.extend_from_slice(&chunk);
    }
    requests.lock().unwrap().push(TestRequest {
        method: parts.method.to_string(),
        path: request_path,
        headers,
        header_lines,
        body: raw.clone(),
    });
    let (headers, payload) = match path.as_str() {
        "/grpc.health.v1.Health/Check" => (
            vec![("content-type", "application/grpc+proto")],
            Some(grpc_frame(&proto_field_varint(1, 1))),
        ),
        "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"
        | "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo" => {
            if behavior == ReflectionBehavior::Disabled {
                (
                    vec![
                        ("content-type", "application/grpc+proto"),
                        ("grpc-status", "12"),
                        ("grpc-message", "reflection disabled"),
                    ],
                    None,
                )
            } else if behavior == ReflectionBehavior::V1ErrorResponseUnimplemented
                && path == "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"
            {
                (
                    vec![("content-type", "application/grpc+proto")],
                    Some(grpc_frame(&reflection_error_response(
                        12,
                        "reflection v1 unavailable",
                    ))),
                )
            } else {
                match reflection_response_for_request(&raw, &descriptor) {
                    Ok(payload) => (
                        vec![("content-type", "application/grpc+proto")],
                        Some(grpc_frame(&payload)),
                    ),
                    Err(_) => (
                        vec![
                            ("content-type", "application/grpc+proto"),
                            ("grpc-status", "5"),
                            ("grpc-message", "symbol not found"),
                        ],
                        None,
                    ),
                }
            }
        }
        _ => (
            vec![
                ("content-type", "application/grpc+proto"),
                ("grpc-status", "12"),
                ("grpc-message", "unimplemented"),
            ],
            None,
        ),
    };
    let mut builder = http::Response::builder().status(200);
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    let Ok(response) = builder.body(()) else {
        return;
    };
    let Ok(mut send) = respond.send_response(response, payload.is_none()) else {
        return;
    };
    if let Some(payload) = payload {
        let _ = send.send_data(bytes::Bytes::from(payload), true);
    }
}

pub(crate) fn reflection_response_for_request(
    raw_frame: &[u8],
    descriptor: &[u8],
) -> Result<Vec<u8>, String> {
    if raw_frame.len() < 5 {
        return Err("invalid reflection request".to_string());
    }
    let len = u32::from_be_bytes([raw_frame[1], raw_frame[2], raw_frame[3], raw_frame[4]]) as usize;
    if raw_frame.len() < 5 + len {
        return Err("invalid reflection request".to_string());
    }
    let raw = &raw_frame[5..5 + len];
    if raw.windows(3).any(|w| w == b"\x3a\x01*") {
        let service = proto_field_string(1, "grpc.health.v1.Health");
        let list = proto_field_bytes(1, &service);
        return Ok(proto_field_bytes(6, &list));
    }
    for symbol in [
        "grpc.health.v1.Health",
        "grpc.health.v1.Health.Check",
        "grpc.health.v1.HealthCheckRequest",
        "grpc.health.v1.HealthCheckResponse",
    ] {
        let needle = proto_field_string(4, symbol);
        if raw.windows(needle.len()).any(|w| w == needle.as_slice()) {
            let fd_resp = proto_field_bytes(1, descriptor);
            return Ok(proto_field_bytes(4, &fd_resp));
        }
    }
    Err("symbol not found".to_string())
}

pub(crate) fn reflection_error_response(code: u64, message: &str) -> Vec<u8> {
    let mut error = proto_field_varint(1, code);
    error.extend(proto_field_string(2, message));
    proto_field_bytes(7, &error)
}

pub(crate) fn parse_dns_question(raw: &[u8]) -> Option<(String, u16, usize)> {
    if raw.len() < 12 {
        return None;
    }
    let mut off = 12;
    let mut labels = Vec::new();
    loop {
        let len = *raw.get(off)? as usize;
        off += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 || off + len > raw.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&raw[off..off + len]).into_owned());
        off += len;
    }
    if off + 4 > raw.len() {
        return None;
    }
    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        format!("{}.", labels.join("."))
    };
    let qtype = u16::from_be_bytes([raw[off], raw[off + 1]]);
    Some((name, qtype, off + 4))
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
                thread::sleep(Duration::from_secs(5));
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

pub(crate) fn grpc_frame(payload: &[u8]) -> Vec<u8> {
    grpc_frame_with_flag(payload, false)
}

pub(crate) fn grpc_frame_with_flag(payload: &[u8], compressed: bool) -> Vec<u8> {
    let mut out = vec![u8::from(compressed); 5 + payload.len()];
    out[1..5].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    out[5..].copy_from_slice(payload);
    out
}

pub(crate) fn gzip_bytes(payload: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(payload).unwrap();
    encoder.finish().unwrap()
}

pub(crate) fn proto_field_string(field: u64, value: &str) -> Vec<u8> {
    proto_field_bytes(field, value.as_bytes())
}

pub(crate) fn proto_field_bytes(field: u64, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(proto_varint((field << 3) | 2));
    out.extend(proto_varint(value.len() as u64));
    out.extend_from_slice(value);
    out
}

pub(crate) fn proto_field_varint(field: u64, value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(proto_varint(field << 3));
    out.extend(proto_varint(value));
    out
}

pub(crate) fn proto_varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

pub(crate) fn write_health_descriptor_set(dir: &Path) -> PathBuf {
    let str_type = field_descriptor_proto::Type::String as i32;
    let enum_type = field_descriptor_proto::Type::Enum as i32;
    let fds = FileDescriptorSet {
        file: vec![FileDescriptorProto {
            name: Some("grpc/health/v1/health.proto".to_string()),
            package: Some("grpc.health.v1".to_string()),
            syntax: Some("proto3".to_string()),
            message_type: vec![
                DescriptorProto {
                    name: Some("HealthCheckRequest".to_string()),
                    field: vec![FieldDescriptorProto {
                        name: Some("service".to_string()),
                        number: Some(1),
                        r#type: Some(str_type),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                DescriptorProto {
                    name: Some("HealthCheckResponse".to_string()),
                    field: vec![FieldDescriptorProto {
                        name: Some("status".to_string()),
                        number: Some(1),
                        r#type: Some(enum_type),
                        type_name: Some(
                            ".grpc.health.v1.HealthCheckResponse.ServingStatus".to_string(),
                        ),
                        ..Default::default()
                    }],
                    enum_type: vec![EnumDescriptorProto {
                        name: Some("ServingStatus".to_string()),
                        value: vec![
                            EnumValueDescriptorProto {
                                name: Some("UNKNOWN".to_string()),
                                number: Some(0),
                                ..Default::default()
                            },
                            EnumValueDescriptorProto {
                                name: Some("SERVING".to_string()),
                                number: Some(1),
                                ..Default::default()
                            },
                        ],
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ],
            service: vec![ServiceDescriptorProto {
                name: Some("Health".to_string()),
                method: vec![MethodDescriptorProto {
                    name: Some("Check".to_string()),
                    input_type: Some(".grpc.health.v1.HealthCheckRequest".to_string()),
                    output_type: Some(".grpc.health.v1.HealthCheckResponse".to_string()),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    let path = dir.join("grpc-health.pb");
    fs::write(&path, fds.encode_to_vec()).unwrap();
    path
}

pub(crate) fn write_stream_descriptor_set(dir: &Path) -> PathBuf {
    let str_type = field_descriptor_proto::Type::String as i32;
    let int64_type = field_descriptor_proto::Type::Int64 as i32;
    let fds = FileDescriptorSet {
        file: vec![FileDescriptorProto {
            name: Some("stream.proto".to_string()),
            package: Some("streampkg".to_string()),
            syntax: Some("proto3".to_string()),
            message_type: vec![
                DescriptorProto {
                    name: Some("StreamRequest".to_string()),
                    field: vec![FieldDescriptorProto {
                        name: Some("value".to_string()),
                        number: Some(1),
                        r#type: Some(str_type),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                DescriptorProto {
                    name: Some("StreamResponse".to_string()),
                    field: vec![FieldDescriptorProto {
                        name: Some("count".to_string()),
                        number: Some(1),
                        r#type: Some(int64_type),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ],
            service: vec![ServiceDescriptorProto {
                name: Some("StreamService".to_string()),
                method: vec![
                    MethodDescriptorProto {
                        name: Some("ClientStream".to_string()),
                        input_type: Some(".streampkg.StreamRequest".to_string()),
                        output_type: Some(".streampkg.StreamResponse".to_string()),
                        client_streaming: Some(true),
                        ..Default::default()
                    },
                    MethodDescriptorProto {
                        name: Some("ServerStream".to_string()),
                        input_type: Some(".streampkg.StreamRequest".to_string()),
                        output_type: Some(".streampkg.StreamResponse".to_string()),
                        server_streaming: Some(true),
                        ..Default::default()
                    },
                    MethodDescriptorProto {
                        name: Some("Bidi".to_string()),
                        input_type: Some(".streampkg.StreamRequest".to_string()),
                        output_type: Some(".streampkg.StreamResponse".to_string()),
                        client_streaming: Some(true),
                        server_streaming: Some(true),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    let path = dir.join("stream.pb");
    fs::write(&path, fds.encode_to_vec()).unwrap();
    path
}

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
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.push(0x81);
    if payload.len() < 126 {
        out.push(payload.len() as u8);
    } else {
        out.push(126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(payload);
    out
}

pub(crate) fn ws_binary_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.push(0x82);
    if payload.len() < 126 {
        out.push(payload.len() as u8);
    } else {
        out.push(126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
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

#[cfg(unix)]
pub(crate) fn run_image_render_pty(env: Vec<(String, String)>) -> String {
    let image = test_png_bytes();
    let server = TestServer::start(move |_| {
        TestResponse::ok(image.clone()).header("Content-Type", "image/png")
    });
    let pty = open_pty(24, 80, 800, 480);
    let mut cmd = Command::new(fetch_bin());
    cmd.args([server.url.as_str(), "--format", "on", "--pager", "off"]);
    cmd.env("HTTP_PROXY", "");
    cmd.env("HTTPS_PROXY", "");
    cmd.env("ALL_PROXY", "");
    cmd.env("NO_PROXY", "*");
    for (key, value) in env {
        cmd.env(key, value);
    }
    configure_pty_child(&mut cmd, &pty.slave);
    let mut child = cmd.spawn().expect("spawn fetch under PTY");
    drop(pty.slave);
    let capture = start_pty_capture(&pty.master);
    let status = wait_child(&mut child, Duration::from_secs(5))
        .unwrap_or_else(|| {
            let _ = child.kill();
            panic!(
                "fetch did not exit after image response; PTY output:\n{}",
                capture.output()
            )
        })
        .expect("wait fetch under PTY");
    assert!(
        status.success(),
        "fetch exited with {status}; PTY output:\n{}",
        capture.output()
    );
    let output = capture.output();
    drop(pty.master);
    capture.close();
    output
}

#[cfg(unix)]
pub(crate) fn install_fake_less(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let less = dir.join("less");
    fs::write(
        &less,
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$FETCH_TEST_LESS_ARGS\"\ncat > \"$FETCH_TEST_LESS_INPUT\"\ncat \"$FETCH_TEST_LESS_INPUT\"\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&less).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&less, perms).unwrap();
    less
}

#[cfg(unix)]
pub(crate) fn run_fetch_pty_with_fake_less(
    extra_args: &[&str],
) -> (String, Option<String>, Option<String>) {
    let server = TestServer::start(|_| TestResponse::ok("pager body\n"));
    let dir = TempDir::new().unwrap();
    install_fake_less(dir.path());
    let less_args = dir.path().join("less.args");
    let less_input = dir.path().join("less.input");
    let path = env::join_paths(
        std::iter::once(dir.path().to_path_buf()).chain(
            env::var_os("PATH")
                .map(|path| env::split_paths(&path).collect::<Vec<_>>())
                .unwrap_or_default(),
        ),
    )
    .unwrap();

    let pty = open_pty(24, 80, 800, 480);
    let mut cmd = Command::new(fetch_bin());
    cmd.arg(server.url.as_str());
    cmd.args(extra_args);
    cmd.env("TERM", "xterm-256color");
    cmd.env("PATH", path);
    cmd.env("FETCH_TEST_LESS_ARGS", &less_args);
    cmd.env("FETCH_TEST_LESS_INPUT", &less_input);
    cmd.env("HTTP_PROXY", "");
    cmd.env("HTTPS_PROXY", "");
    cmd.env("ALL_PROXY", "");
    cmd.env("NO_PROXY", "*");
    configure_pty_child(&mut cmd, &pty.slave);
    let mut child = cmd.spawn().expect("spawn fetch under PTY");
    drop(pty.slave);
    let capture = start_pty_capture(&pty.master);
    let status = wait_child(&mut child, Duration::from_secs(5))
        .unwrap_or_else(|| {
            let _ = child.kill();
            panic!(
                "fetch did not exit after paged response; PTY output:\n{}",
                capture.output()
            )
        })
        .expect("wait fetch under PTY");
    assert!(
        status.success(),
        "fetch exited with {status}; PTY output:\n{}",
        capture.output()
    );
    let output = capture.output();
    drop(pty.master);
    capture.close();
    (
        output,
        fs::read_to_string(less_args).ok(),
        fs::read_to_string(less_input).ok(),
    )
}

#[cfg(unix)]
pub(crate) fn run_binary_pty_with_fake_less(
    extra_args: &[&str],
) -> (String, Option<String>, Option<String>) {
    let server = TestServer::start(|_| TestResponse::ok(b"abc\0def".to_vec()));
    let dir = TempDir::new().unwrap();
    install_fake_less(dir.path());
    let less_args = dir.path().join("less.args");
    let less_input = dir.path().join("less.input");
    let path = env::join_paths(
        std::iter::once(dir.path().to_path_buf()).chain(
            env::var_os("PATH")
                .map(|path| env::split_paths(&path).collect::<Vec<_>>())
                .unwrap_or_default(),
        ),
    )
    .unwrap();

    let pty = open_pty(24, 80, 800, 480);
    let mut cmd = Command::new(fetch_bin());
    cmd.arg(server.url.as_str());
    cmd.args(extra_args);
    cmd.env("TERM", "xterm-256color");
    cmd.env("PATH", path);
    cmd.env("FETCH_TEST_LESS_ARGS", &less_args);
    cmd.env("FETCH_TEST_LESS_INPUT", &less_input);
    cmd.env("HTTP_PROXY", "");
    cmd.env("HTTPS_PROXY", "");
    cmd.env("ALL_PROXY", "");
    cmd.env("NO_PROXY", "*");
    configure_pty_child(&mut cmd, &pty.slave);
    let mut child = cmd.spawn().expect("spawn fetch under PTY");
    drop(pty.slave);
    let capture = start_pty_capture(&pty.master);
    let status = wait_child(&mut child, Duration::from_secs(5))
        .unwrap_or_else(|| {
            let _ = child.kill();
            panic!(
                "fetch did not exit after binary response; PTY output:\n{}",
                capture.output()
            )
        })
        .expect("wait fetch under PTY");
    assert!(
        status.success(),
        "fetch exited with {status}; PTY output:\n{}",
        capture.output()
    );
    let output = capture.output();
    drop(pty.master);
    capture.close();
    (
        output,
        fs::read_to_string(less_args).ok(),
        fs::read_to_string(less_input).ok(),
    )
}

#[cfg(unix)]
pub(crate) fn run_image_pty_with_fake_less(
    env_overrides: Vec<(String, String)>,
) -> (String, Option<String>, Option<String>) {
    let image = test_png_bytes();
    let server = TestServer::start(move |_| {
        TestResponse::ok(image.clone()).header("Content-Type", "image/png")
    });
    let dir = TempDir::new().unwrap();
    install_fake_less(dir.path());
    let less_args = dir.path().join("less.args");
    let less_input = dir.path().join("less.input");
    let path = env::join_paths(
        std::iter::once(dir.path().to_path_buf()).chain(
            env::var_os("PATH")
                .map(|path| env::split_paths(&path).collect::<Vec<_>>())
                .unwrap_or_default(),
        ),
    )
    .unwrap();

    let pty = open_pty(24, 80, 800, 480);
    let mut cmd = Command::new(fetch_bin());
    cmd.args([server.url.as_str(), "--format", "on"]);
    cmd.env("PATH", path);
    cmd.env("FETCH_TEST_LESS_ARGS", &less_args);
    cmd.env("FETCH_TEST_LESS_INPUT", &less_input);
    cmd.env("HTTP_PROXY", "");
    cmd.env("HTTPS_PROXY", "");
    cmd.env("ALL_PROXY", "");
    cmd.env("NO_PROXY", "*");
    for (key, value) in env_overrides {
        cmd.env(key, value);
    }
    configure_pty_child(&mut cmd, &pty.slave);
    let mut child = cmd.spawn().expect("spawn fetch under PTY");
    drop(pty.slave);
    let capture = start_pty_capture(&pty.master);
    let status = wait_child(&mut child, Duration::from_secs(5))
        .unwrap_or_else(|| {
            let _ = child.kill();
            panic!(
                "fetch did not exit after image response; PTY output:\n{}",
                capture.output()
            )
        })
        .expect("wait fetch under PTY");
    assert!(
        status.success(),
        "fetch exited with {status}; PTY output:\n{}",
        capture.output()
    );
    let output = capture.output();
    drop(pty.master);
    capture.close();
    (
        output,
        fs::read_to_string(less_args).ok(),
        fs::read_to_string(less_input).ok(),
    )
}

#[cfg(unix)]
pub(crate) fn run_fetch_with_fake_less(
    extra_args: &[&str],
) -> (FetchOutput, Option<String>, Option<String>) {
    let server = TestServer::start(|_| TestResponse::ok("pager body\n"));
    let dir = TempDir::new().unwrap();
    install_fake_less(dir.path());
    let less_args = dir.path().join("less.args");
    let less_input = dir.path().join("less.input");
    let path = env::join_paths(
        std::iter::once(dir.path().to_path_buf()).chain(
            env::var_os("PATH")
                .map(|path| env::split_paths(&path).collect::<Vec<_>>())
                .unwrap_or_default(),
        ),
    )
    .unwrap();
    let path_string = path.to_string_lossy().into_owned();
    let less_args_string = less_args.to_string_lossy().into_owned();
    let less_input_string = less_input.to_string_lossy().into_owned();
    let mut args = vec![server.url.as_str()];
    args.extend_from_slice(extra_args);

    let output = run_fetch_opts(
        FetchOpts {
            env: vec![
                ("PATH".to_string(), path_string),
                ("FETCH_TEST_LESS_ARGS".to_string(), less_args_string),
                ("FETCH_TEST_LESS_INPUT".to_string(), less_input_string),
            ],
            ..Default::default()
        },
        &args,
    );

    (
        output,
        fs::read_to_string(less_args).ok(),
        fs::read_to_string(less_input).ok(),
    )
}

pub(crate) fn parse_digest_auth_params(input: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut rest = input.trim();
    while !rest.is_empty() {
        let Some((key, after_key)) = rest.split_once('=') else {
            break;
        };
        let key = key.trim().to_ascii_lowercase();
        let after_key = after_key.trim_start();
        let (value, after_value) = if let Some(stripped) = after_key.strip_prefix('"') {
            let mut escaped = false;
            let mut value = String::new();
            let mut end_idx = stripped.len();
            for (idx, ch) in stripped.char_indices() {
                if escaped {
                    value.push(ch);
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    end_idx = idx + 1;
                    break;
                } else {
                    value.push(ch);
                }
            }
            (value, &stripped[end_idx..])
        } else if let Some((value, after)) = after_key.split_once(',') {
            (value.trim().to_string(), after)
        } else {
            (after_key.trim().to_string(), "")
        };
        out.insert(key, value);
        rest = after_value.trim_start();
        if let Some(stripped) = rest.strip_prefix(',') {
            rest = stripped.trim_start();
        }
    }
    out
}

pub(crate) fn md5_hex(input: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(input.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
