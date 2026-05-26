use base64::Engine;
use bytes::Buf;
use flate2::Compression;
use flate2::write::GzEncoder;
use md5::{Digest as Md5Digest, Md5};
use prost::Message;
use prost_types::{
    DescriptorProto, EnumDescriptorProto, EnumValueDescriptorProto, FieldDescriptorProto,
    FileDescriptorProto, FileDescriptorSet, MethodDescriptorProto, ServiceDescriptorProto,
    field_descriptor_proto,
};
use sha1::Sha1;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

const FAST_RETRY_DELAY: &str = "0.000001";
const PARTIAL_REPLAY_BODY_PREFIX_BYTES: usize = 1024 * 1024;

#[cfg(unix)]
use image::ImageEncoder;
#[cfg(unix)]
use std::os::fd::{FromRawFd, RawFd};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[derive(Debug)]
struct FetchOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

#[derive(Default)]
struct FetchOpts {
    stdin: Option<String>,
    env: Vec<(String, String)>,
    cwd: Option<PathBuf>,
    bin: Option<PathBuf>,
}

#[derive(Clone, Debug)]
struct TestRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl TestRequest {
    fn header(&self, name: &str) -> String {
        self.headers
            .get(&name.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default()
    }

    fn body_string(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

struct TestResponse {
    status: u16,
    reason: &'static str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl TestResponse {
    fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 200,
            reason: "OK",
            headers: Vec::new(),
            body: body.into(),
        }
    }

    fn status(status: u16, reason: &'static str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            reason,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

impl H3Request {
    fn header(&self, name: &str) -> String {
        self.headers
            .get(&name.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default()
    }

    fn body_string(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

impl H3Response {
    fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    fn status(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

impl H3TestServer {
    fn requests(&self) -> Vec<H3Request> {
        self.requests.lock().unwrap().clone()
    }
}

struct TestServer {
    url: String,
    requests: Arc<Mutex<Vec<TestRequest>>>,
    shutdown: Option<mpsc::Sender<()>>,
    join: Option<thread::JoinHandle<()>>,
}

struct PartialBodyReplayServer {
    url: String,
    requests: Arc<Mutex<Vec<TestRequest>>>,
    join: Option<thread::JoinHandle<()>>,
}

struct TlsTestServer {
    url: String,
    ca_cert_path: PathBuf,
    shutdown: Option<mpsc::Sender<()>>,
    join: Option<thread::JoinHandle<()>>,
}

struct MtlsTestServer {
    url: String,
    ca_cert_path: PathBuf,
    client_cert_path: PathBuf,
    client_key_path: PathBuf,
    client_combined_path: PathBuf,
    shutdown: Option<mpsc::Sender<()>>,
    join: Option<thread::JoinHandle<()>>,
}

#[derive(Clone, Debug)]
struct H3Request {
    method: String,
    path: String,
    query: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

struct H3Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

struct H3TestServer {
    url: String,
    ca_cert_path: PathBuf,
    requests: Arc<Mutex<Vec<H3Request>>>,
}

struct ReflectionGrpcServer {
    url: String,
    ca_cert_path: Option<PathBuf>,
}

#[cfg(unix)]
struct PtyPair {
    master: fs::File,
    slave: fs::File,
}

#[cfg(unix)]
struct PtyCapture {
    file: fs::File,
    buffer: Arc<Mutex<Vec<u8>>>,
    done: mpsc::Receiver<()>,
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
    fn start(handler: impl Fn(TestRequest) -> TestResponse + Send + Sync + 'static) -> Self {
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

    fn requests(&self) -> Vec<TestRequest> {
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
    fn start(
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

    fn requests(&self) -> Vec<TestRequest> {
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

fn read_request(reader: &mut impl BufRead) -> Option<TestRequest> {
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
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
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
        body,
    })
}

fn write_response(stream: &mut impl Write, resp: TestResponse) {
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

fn fetch_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_fetch"))
}

fn run_fetch(args: &[&str]) -> FetchOutput {
    run_fetch_opts(FetchOpts::default(), args)
}

fn fetch_version() -> String {
    let res = run_fetch(&["--version"]);
    assert_exit(&res, 0);
    res.stdout
        .trim()
        .strip_prefix("fetch ")
        .expect("version output prefix")
        .to_string()
}

fn run_fetch_opts(opts: FetchOpts, args: &[&str]) -> FetchOutput {
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

fn run_fetch_once(opts: FetchOpts, args: &[&str]) -> FetchOutput {
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

fn is_transient_local_server_error(res: &FetchOutput) -> bool {
    res.status.code() == Some(1)
        && (res
            .stderr
            .contains("connection closed before message completed")
            || res.stderr.contains("connection was not ready")
            || res.stderr.contains("Connection reset by peer"))
}

fn assert_exit(res: &FetchOutput, code: i32) {
    assert_eq!(
        res.status.code(),
        Some(code),
        "unexpected exit code\nstdout:\n{}\nstderr:\n{}",
        res.stdout,
        res.stderr
    );
}

fn temp_file(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, contents).expect("write temp file");
    path
}

#[cfg(not(windows))]
fn update_artifact_name(version: &str) -> String {
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
fn make_update_artifact(version: &str) -> Vec<u8> {
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
fn update_artifact_checksum_line(name: &str, artifact: &[u8]) -> String {
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
fn install_update_launcher(path: &Path) {
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
fn test_png_bytes() -> Vec<u8> {
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
fn image_pty_env(overrides: &[(&str, &str)]) -> Vec<(String, String)> {
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

fn wait_for_requests(server: &TestServer, count: usize) -> Vec<TestRequest> {
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

fn wait_for_h3_requests(server: &H3TestServer, count: usize) -> Vec<H3Request> {
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

#[cfg(unix)]
fn open_pty(rows: u16, cols: u16, xpixel: u16, ypixel: u16) -> PtyPair {
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
fn start_pty_capture(file: &fs::File) -> PtyCapture {
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
    fn output(&self) -> String {
        String::from_utf8_lossy(&self.buffer.lock().unwrap()).into_owned()
    }

    fn wait_for(&self, want: &str, timeout: Duration) {
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

    fn close(self) {
        drop(self.file);
        let _ = self.done.recv_timeout(Duration::from_secs(1));
    }
}

#[cfg(unix)]
fn wait_child(
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
fn configure_pty_child(cmd: &mut Command, slave: &fs::File) {
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

fn host_port(url: &str) -> &str {
    url.trim_start_matches("http://")
        .trim_start_matches("https://")
}

fn fake_editor(dir: &Path, body: &str, code: i32) -> PathBuf {
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

fn start_udp_dns_server(host: &'static str, ip: Ipv4Addr) -> String {
    start_udp_dns_server_with_hosts(vec![(host, ip)])
}

fn start_udp_dns_server_with_hosts(records: Vec<(&'static str, Ipv4Addr)>) -> String {
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

fn start_unresponsive_udp_dns_server() -> String {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind udp dns server");
    let addr = socket.local_addr().unwrap().to_string();
    thread::spawn(move || {
        let mut buf = [0_u8; 512];
        while socket.recv_from(&mut buf).is_ok() {}
    });
    addr
}

fn start_tls_server(
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

fn start_mtls_server() -> MtlsTestServer {
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

fn start_http3_server(
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
    let requests_for_thread = Arc::clone(&requests);
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
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
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
                            if !response.body.is_empty()
                                && stream
                                    .send_data(bytes::Bytes::from(response.body))
                                    .await
                                    .is_err()
                            {
                                return;
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
    }
}

fn start_reflection_grpc_h2c_server(enable_reflection: bool) -> ReflectionGrpcServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind h2c grpc server");
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let descriptor = reflection_health_descriptor();
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
                tokio::spawn(async move {
                    serve_reflection_h2_connection(stream, descriptor, enable_reflection).await;
                });
            }
        });
    });
    ReflectionGrpcServer {
        url,
        ca_cert_path: None,
    }
}

fn start_reflection_grpc_tls_server(enable_reflection: bool) -> ReflectionGrpcServer {
    start_reflection_grpc_tls_server_with_versions(
        enable_reflection,
        &[&rustls::version::TLS13, &rustls::version::TLS12],
    )
}

fn start_reflection_grpc_tls_server_with_versions(
    enable_reflection: bool,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> ReflectionGrpcServer {
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
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    serve_reflection_h2_connection(tls, descriptor, enable_reflection).await;
                });
            }
        });
    });
    ReflectionGrpcServer {
        url,
        ca_cert_path: Some(ca_cert_path),
    }
}

fn reflection_health_descriptor() -> Vec<u8> {
    let path = write_health_descriptor_set(TempDir::new().unwrap().keep().as_path());
    let fds = fs::read(path).unwrap();
    let set = FileDescriptorSet::decode(fds.as_slice()).unwrap();
    set.file[0].encode_to_vec()
}

async fn serve_reflection_h2_connection<T>(stream: T, descriptor: Vec<u8>, enable_reflection: bool)
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
        let descriptor = descriptor.clone();
        tokio::spawn(async move {
            handle_reflection_h2_request(request, respond, descriptor, enable_reflection).await;
        });
    }
}

fn start_status_grpc_h2c_server() -> String {
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

async fn handle_reflection_h2_request(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    descriptor: Vec<u8>,
    enable_reflection: bool,
) {
    let path = request.uri().path().to_string();
    let mut body = request.into_body();
    let mut raw = Vec::new();
    while let Some(chunk) = body.data().await {
        let Ok(chunk) = chunk else {
            return;
        };
        raw.extend_from_slice(&chunk);
    }
    let (headers, payload) = match path.as_str() {
        "/grpc.health.v1.Health/Check" => (
            vec![("content-type", "application/grpc+proto")],
            Some(grpc_frame(&proto_field_varint(1, 1))),
        ),
        "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"
        | "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo" => {
            if !enable_reflection {
                (
                    vec![
                        ("content-type", "application/grpc+proto"),
                        ("grpc-status", "12"),
                        ("grpc-message", "reflection disabled"),
                    ],
                    None,
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

fn reflection_response_for_request(raw_frame: &[u8], descriptor: &[u8]) -> Result<Vec<u8>, String> {
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

fn parse_dns_question(raw: &[u8]) -> Option<(String, u16, usize)> {
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

fn start_socks5_proxy(target_addr: String) -> (String, mpsc::Receiver<String>) {
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

fn handle_socks5_conn(mut conn: TcpStream, target_addr: &str, seen: mpsc::Sender<String>) {
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

fn assert_socks_seen(seen: &mpsc::Receiver<String>, want: &str) {
    let got = seen
        .recv_timeout(Duration::from_secs(2))
        .expect("SOCKS proxy was not used");
    assert_eq!(got, want);
}

fn grpc_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0; 5 + payload.len()];
    out[1..5].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    out[5..].copy_from_slice(payload);
    out
}

fn proto_field_string(field: u64, value: &str) -> Vec<u8> {
    proto_field_bytes(field, value.as_bytes())
}

fn proto_field_bytes(field: u64, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(proto_varint((field << 3) | 2));
    out.extend(proto_varint(value.len() as u64));
    out.extend_from_slice(value);
    out
}

fn proto_field_varint(field: u64, value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(proto_varint(field << 3));
    out.extend(proto_varint(value));
    out
}

fn proto_varint(mut value: u64) -> Vec<u8> {
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

fn write_health_descriptor_set(dir: &Path) -> PathBuf {
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

fn write_stream_descriptor_set(dir: &Path) -> PathBuf {
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
                method: vec![MethodDescriptorProto {
                    name: Some("ClientStream".to_string()),
                    input_type: Some(".streampkg.StreamRequest".to_string()),
                    output_type: Some(".streampkg.StreamResponse".to_string()),
                    client_streaming: Some(true),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    let path = dir.join("stream.pb");
    fs::write(&path, fds.encode_to_vec()).unwrap();
    path
}

fn start_ws_echo_server(
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
                        let _ = stream.write_all(&ws_close_frame(b"done"));
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

fn start_wss_echo_server(
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
                        let _ = tls.write_all(&ws_close_frame(b"done"));
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

fn start_ws_multi_echo_server(messages: usize) -> String {
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
                            let msg = read_ws_text(&mut stream);
                            if msg.is_empty() {
                                return;
                            }
                            let _ = stream.write_all(&ws_text_frame(msg.as_bytes()));
                        }
                        let _ = stream.write_all(&ws_close_frame(b"done"));
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

fn start_ws_push_server(
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
                        let _ = stream.write_all(&ws_close_frame(b"done"));
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

fn read_ws_text(reader: &mut impl Read) -> String {
    let mut header = [0_u8; 2];
    if reader.read_exact(&mut header).is_err() {
        return String::new();
    }
    let opcode = header[0] & 0x0f;
    if opcode == 0x8 {
        return String::new();
    }
    let masked = header[1] & 0x80 != 0;
    let mut len = (header[1] & 0x7f) as usize;
    if len == 126 {
        let mut raw = [0_u8; 2];
        if reader.read_exact(&mut raw).is_err() {
            return String::new();
        }
        len = u16::from_be_bytes(raw) as usize;
    }
    let mut mask = [0_u8; 4];
    if masked && reader.read_exact(&mut mask).is_err() {
        return String::new();
    }
    let mut payload = vec![0; len];
    if reader.read_exact(&mut payload).is_err() {
        return String::new();
    }
    if masked {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[i % 4];
        }
    }
    String::from_utf8_lossy(&payload).into_owned()
}

fn ws_text_frame(payload: &[u8]) -> Vec<u8> {
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

fn ws_binary_frame(payload: &[u8]) -> Vec<u8> {
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

fn ws_close_frame(reason: &[u8]) -> Vec<u8> {
    let mut payload = 1000_u16.to_be_bytes().to_vec();
    payload.extend_from_slice(reason);
    let mut out = vec![0x88, payload.len() as u8];
    out.extend(payload);
    out
}

#[cfg(unix)]
fn run_image_render_pty(env: Vec<(String, String)>) -> String {
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
fn install_fake_less(dir: &Path) -> PathBuf {
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
fn run_fetch_pty_with_fake_less(extra_args: &[&str]) -> (String, Option<String>, Option<String>) {
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
fn run_binary_pty_with_fake_less(extra_args: &[&str]) -> (String, Option<String>, Option<String>) {
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
fn run_image_pty_with_fake_less(
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
fn run_fetch_with_fake_less(extra_args: &[&str]) -> (FetchOutput, Option<String>, Option<String>) {
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

#[cfg(unix)]
#[test]
fn terminal_stdout_uses_less_pager_by_default() {
    let (output, less_args, less_input) = run_fetch_pty_with_fake_less(&[]);

    assert!(output.contains("pager body"), "{output:?}");
    assert_eq!(less_args.as_deref(), Some("-FIRX\n"));
    assert_eq!(less_input.as_deref(), Some("pager body\n"));
}

#[cfg(unix)]
#[test]
fn pager_off_writes_terminal_stdout_directly() {
    let (output, less_args, less_input) = run_fetch_pty_with_fake_less(&["--pager", "off"]);

    assert!(output.contains("pager body"), "{output:?}");
    assert!(less_args.is_none(), "pager was invoked: {less_args:?}");
    assert!(less_input.is_none(), "pager received input: {less_input:?}");
}

#[cfg(unix)]
#[test]
fn terminal_stdout_warns_instead_of_printing_binary_response() {
    let (output, less_args, less_input) = run_binary_pty_with_fake_less(&[]);

    assert!(
        output.contains("the response body appears to be binary"),
        "{output:?}"
    );
    assert!(
        output.contains("\x1b[1m\x1b[33mwarning\x1b[0m: "),
        "{output:?}"
    );
    assert!(
        output.contains("To output to the terminal anyway, use '--output -'"),
        "{output:?}"
    );
    assert!(!output.contains("abc\0def"), "{output:?}");
    assert!(less_args.is_none(), "pager was invoked: {less_args:?}");
    assert!(less_input.is_none(), "pager received input: {less_input:?}");
}

#[cfg(unix)]
#[test]
fn terminal_stdout_format_off_warns_instead_of_streaming_binary_response() {
    let (output, less_args, less_input) = run_binary_pty_with_fake_less(&["--format", "off"]);

    assert!(
        output.contains("the response body appears to be binary"),
        "{output:?}"
    );
    assert!(
        output.contains("\x1b[1m\x1b[33mwarning\x1b[0m: "),
        "{output:?}"
    );
    assert!(
        output.contains("To output to the terminal anyway, use '--output -'"),
        "{output:?}"
    );
    assert!(!output.contains("abc\0def"), "{output:?}");
    assert!(less_args.is_none(), "pager was invoked: {less_args:?}");
    assert!(less_input.is_none(), "pager received input: {less_input:?}");
}

#[cfg(unix)]
#[test]
fn pager_on_uses_less_when_stdout_is_not_terminal() {
    let (res, less_args, less_input) = run_fetch_with_fake_less(&["--pager", "on"]);

    assert_exit(&res, 0);
    assert_eq!(res.stdout, "pager body\n");
    assert_eq!(less_args.as_deref(), Some("-FIRX\n"));
    assert_eq!(less_input.as_deref(), Some("pager body\n"));
}

#[cfg(unix)]
#[test]
fn terminal_image_output_bypasses_less_pager() {
    let (output, less_args, less_input) = run_image_pty_with_fake_less(image_pty_env(&[
        ("TERM", "xterm-kitty"),
        ("KITTY_PID", "123"),
    ]));

    assert!(output.contains("\x1b_Gq=2,f=100,a=T,t=d,"), "{output:?}");
    assert!(less_args.is_none(), "pager was invoked: {less_args:?}");
    assert!(less_input.is_none(), "pager received input: {less_input:?}");
}

#[test]
fn help_matches_go_harness_expectations() {
    let res = run_fetch(&["--help"]);
    assert_exit(&res, 0);
    assert!(res.stderr.is_empty(), "stderr: {}", res.stderr);
    assert!(res.stdout.contains("[URL]  The URL to make a request to"));
    assert!(res.stdout.contains("--aws-sigv4 <REGION/SERVICE>"));
    assert!(res.stdout.contains("--format <OPTION>"));
    for line in res.stdout.lines() {
        assert!(line.chars().count() <= 80, "help line too long: {line:?}");
    }
}

#[test]
fn cli_parse_errors_match_go_harness() {
    let cases = [
        (vec![], "<URL> must be provided"),
        (vec!["url1", "url2"], "unexpected argument"),
        (vec!["--invalid"], "error: unknown flag '--invalid'"),
        (
            vec!["--basic", "user:pass", "--bearer", "token"],
            "flags '--basic' and '--bearer' cannot be used together",
        ),
        (vec!["--output"], "argument required for flag '--output'"),
        (
            vec!["--help=1"],
            "flag '--help' does not take any arguments",
        ),
        (
            vec!["--proxy", ":bad", "http://example.com"],
            "missing protocol scheme",
        ),
    ];
    for (args, stderr) in cases {
        let res = run_fetch(&args);
        assert_exit(&res, 1);
        assert!(res.stdout.is_empty(), "stdout: {}", res.stdout);
        assert!(
            res.stderr.contains(stderr),
            "args {args:?}: stderr did not contain {stderr:?}\n{}",
            res.stderr
        );
    }

    let res = run_fetch(&["--color", "on"]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("\x1b[31m\x1b[1merror\x1b[0m"));
    assert!(res.stderr.contains("\x1b[1m--help\x1b[0m"));
}

#[test]
fn shell_completion_matches_go_harness() {
    let res = run_fetch(&["--complete", "bash"]);
    assert_exit(&res, 0);
    assert!(res.stderr.is_empty());
    assert!(res.stdout.contains("_fetch_complete()"));
    assert!(res.stdout.contains("complete -o nosort -o nospace"));

    let res = run_fetch(&["--complete", "fish", "--", "fetch", "--col"]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "--color\tEnable/disable color\n");

    let res = run_fetch(&["--complete", "bash", "--", "fetch", "--color", "o"]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "off \non \n");

    let res = run_fetch(&["--complete", "powershell"]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("completions not supported"));
}

#[test]
fn verbosity_and_color_output() {
    let server =
        TestServer::start(|_| TestResponse::ok("hello").header("X-Custom-Header", "value"));

    let res = run_fetch(&[&server.url]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "hello");
    assert!(res.stderr.contains("HTTP/1.1 200 OK"));
    assert!(!res.stderr.contains("x-custom-header"));

    let res = run_fetch(&[&server.url, "-s"]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "hello");
    assert!(res.stderr.is_empty());

    let res = run_fetch(&[&server.url, "-v"]);
    assert_exit(&res, 0);
    assert!(res.stderr.contains("x-custom-header"));

    let res = run_fetch(&[&server.url, "-vv"]);
    assert_exit(&res, 0);
    assert!(res.stderr.contains("> GET / HTTP/1.1"));
    assert!(res.stderr.contains("> user-agent"));
    assert!(res.stderr.contains("< x-custom-header"));

    let sort_server = TestServer::start(|_| {
        TestResponse::ok("sorted")
            .header("X-Zeta", "last")
            .header("Accept-Ranges", "bytes")
            .header("X-Zeta", "duplicate")
    });
    let res = run_fetch(&[&sort_server.url, "-v", "--sort-headers"]);
    assert_exit(&res, 0);
    let accept = res.stderr.find("accept-ranges: bytes").unwrap();
    let connection = res.stderr.find("connection: keep-alive").unwrap();
    let content_length = res.stderr.find("content-length: 6").unwrap();
    let zeta = res.stderr.find("x-zeta: last").unwrap();
    let duplicate_zeta = res.stderr.find("x-zeta: duplicate").unwrap();
    assert!(accept < connection);
    assert!(connection < content_length);
    assert!(content_length < zeta);
    assert!(zeta < duplicate_zeta);

    let res = run_fetch(&[&server.url, "-vv", "--color", "on"]);
    assert_exit(&res, 0);
    assert!(res.stderr.contains("\x1b[1m\x1b[33mGET\x1b[0m"));
    assert!(res.stderr.contains("\x1b[32m\x1b[1m200\x1b[0m"));

    let res = run_fetch(&[&server.url, "-vvv"]);
    assert_exit(&res, 0);
    assert!(res.stderr.contains("* TCP:"));
    assert!(res.stderr.contains("* TTFB:"));
}

#[test]
fn request_construction_and_data_sources() {
    let server = TestServer::start(|_| TestResponse::ok(""));

    let res = run_fetch(&[&server.url, "--data", "hello"]);
    assert_exit(&res, 0);
    let req = wait_for_requests(&server, 1).remove(0);
    assert_eq!(req.method, "GET");
    assert_eq!(req.body_string(), "hello");
    assert_eq!(req.header("content-type"), "text/plain; charset=utf-8");

    let res = run_fetch(&[&server.url, "--json", r#"{"key":"val"}"#]);
    assert_exit(&res, 0);
    let req = wait_for_requests(&server, 2).remove(1);
    assert_eq!(req.body_string(), r#"{"key":"val"}"#);
    assert_eq!(req.header("content-type"), "application/json");

    let res = run_fetch(&[&server.url, "--xml", "<Tag></Tag>"]);
    assert_exit(&res, 0);
    let req = wait_for_requests(&server, 3).remove(2);
    assert_eq!(req.body_string(), "<Tag></Tag>");
    assert_eq!(req.header("content-type"), "application/xml");

    let dir = TempDir::new().unwrap();
    let file = temp_file(dir.path(), "body.txt", "temp file data");
    let res = run_fetch(&[&server.url, "--data", &format!("@{}", file.display())]);
    assert_exit(&res, 0);
    let req = wait_for_requests(&server, 4).remove(3);
    assert_eq!(req.body_string(), "temp file data");
    assert_eq!(req.header("content-length"), "14");
}

#[test]
fn dry_run_prints_effective_request_without_network() {
    let res = run_fetch(&["-j", r#"{"key":"val1"}"#, "localhost:3000", "--dry-run"]);
    assert_exit(&res, 0);
    assert!(res.stdout.is_empty());
    assert!(res.stderr.contains("GET / HTTP/1.1\n"));
    assert!(res.stderr.contains("accept: application/json, */*;q=0.5"));
    assert!(res.stderr.contains("accept-encoding: gzip, br, zstd\n"));
    assert!(res.stderr.contains("content-length: 14\n"));
    assert!(res.stderr.contains("content-type: application/json\n"));
    assert!(res.stderr.contains("host: localhost:3000\n"));
    assert!(res.stderr.contains("\n\n{\"key\":\"val1\"}"));
    assert!(!res.stderr.contains("> GET"));

    let res = run_fetch(&[
        "-j",
        r#"{"key":"val1"}"#,
        "-H",
        "X-Zeta: last",
        "localhost:3000",
        "--dry-run",
        "--sort-headers",
    ]);
    assert_exit(&res, 0);
    let accept = res
        .stderr
        .find("accept: application/json, */*;q=0.5")
        .unwrap();
    let accept_encoding = res.stderr.find("accept-encoding: gzip, br, zstd").unwrap();
    let content_length = res.stderr.find("content-length: 14").unwrap();
    let content_type = res.stderr.find("content-type: application/json").unwrap();
    let host = res.stderr.find("host: localhost:3000").unwrap();
    let user_agent = res.stderr.find("user-agent: fetch/").unwrap();
    let zeta = res.stderr.find("x-zeta: last").unwrap();
    assert!(accept < accept_encoding);
    assert!(accept_encoding < content_length);
    assert!(content_length < content_type);
    assert!(content_type < host);
    assert!(host < user_agent);
    assert!(user_agent < zeta);
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
fn config_duplicate_host_section_replaces_previous_section() {
    let server = TestServer::start(|req| {
        if req.path.contains("old=1") || !req.path.contains("new=1") {
            return TestResponse::status(400, "Bad Request", "bad query");
        }
        if !req.header("x-old").is_empty() || req.header("x-new") != "yes" {
            return TestResponse::status(400, "Bad Request", "bad header");
        }
        TestResponse::ok("duplicate")
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
            "format = off\n\n[{host}]\nheader = X-Old: yes\nquery = old=1\n\n[{host}]\nheader = X-New: yes\nquery = new=1\n"
        ),
    )
    .unwrap();
    let res = run_fetch(&["--config", config.to_str().unwrap(), &server.url]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "duplicate");
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
fn output_file_modes_match_go_harness() {
    let server = TestServer::start(|req| match req.path.as_str() {
        "/file.txt" => TestResponse::ok("file-body"),
        "/header" => TestResponse::ok("header-body").header(
            "Content-Disposition",
            "attachment; filename=\"from-header.txt\"",
        ),
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
}

#[test]
fn default_scheme_loopback_and_presentation_flags() {
    let server = TestServer::start(|req| {
        if req.path != "/?probe=1" && req.path != "/" {
            return TestResponse::status(400, "Bad Request", "missing query");
        }
        TestResponse::ok(r#"{"ok":"yes"}"#).header("Content-Type", "application/json")
    });
    let target = format!("{}?probe=1", host_port(&server.url));
    let res = run_fetch(&[&target, "--format", "off"]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, r#"{"ok":"yes"}"#);

    let res = run_fetch(&[&server.url, "--format", "on", "--color", "on"]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("\x1b["));
    assert!(res.stdout.contains("yes"));

    let res = run_fetch(&[&server.url, "--format", "on", "--color", "off"]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "{\n  \"ok\": \"yes\"\n}\n");

    let res = run_fetch(&[&server.url, "--format", "off", "--color", "on"]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, r#"{"ok":"yes"}"#);
}

#[test]
fn config_error_and_metadata_edges() {
    let dir = TempDir::new().unwrap();
    let not_cert = dir.path().join("not-client-cert.pem");
    fs::write(
        &not_cert,
        "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n",
    )
    .unwrap();
    let config = dir.path().join("bad-cert-config");
    fs::write(&config, format!("cert = {}\n", not_cert.display())).unwrap();
    let res = run_fetch(&["--config", config.to_str().unwrap(), "http://example.com"]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("config file"));
    assert!(res.stderr.contains("line 1"));
    assert!(res.stderr.contains("invalid client certificate"));

    let config = dir.path().join("key-only-config");
    fs::write(
        &config,
        format!("format = off\nkey = {}\n", not_cert.display()),
    )
    .unwrap();
    let server = TestServer::start(|_| TestResponse::ok("key-only-config-ok"));
    let res = run_fetch(&["--config", config.to_str().unwrap(), &server.url]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "key-only-config-ok");

    let config = dir.path().join("tls-config");
    fs::write(&config, "min-tls = 1.2\nmax-tls = 1.2\n").unwrap();
    let res = run_fetch(&[
        "--config",
        config.to_str().unwrap(),
        "--tls",
        "1.3",
        &server.url,
    ]);
    assert_exit(&res, 1);
    assert!(
        res.stderr
            .contains("min-tls must be less than or equal to max-tls")
    );

    let config = dir.path().join("bad-proxy-config");
    fs::write(&config, "proxy = :bad\n").unwrap();
    let res = run_fetch(&["--config", config.to_str().unwrap(), "http://example.com"]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("config file"));
    assert!(res.stderr.contains("line 1"));
    assert!(res.stderr.contains("invalid value ':bad'"));

    let config = dir.path().join("bad-presentation-config");
    fs::write(&config, "format = nope\n").unwrap();
    for flag in ["--help", "--version", "--buildinfo"] {
        let res = run_fetch(&["--config", config.to_str().unwrap(), flag]);
        assert_exit(&res, 0);
        assert!(res.stderr.is_empty(), "{flag}: {}", res.stderr);
        assert!(!res.stdout.is_empty());
    }
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
    assert_eq!(req.path, "/?a=one&z=old&z=two");
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

    let res = run_fetch(&[&server.url, "--http", "1"]);
    assert_exit(&res, 0);
    let res = run_fetch(&[&server.url, "--http", "2"]);
    assert_exit(&res, 1);
    assert!(res.stderr.contains("http2:"));
}

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
fn http3_go_harness_cases() {
    let h3 = start_http3_server(|req| {
        if req.path == "/h3" {
            return H3Response::status(201, "h3 ok").header("Content-Type", "text/plain");
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
    assert_eq!(req.query, "cli=1&existing=1");
    assert_eq!(req.header("x-h3"), "yes");
    assert_eq!(req.body_string(), "payload");

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
        "--ca-cert",
        redirect.ca_cert_path.to_str().unwrap(),
        "--method",
        "POST",
        "-d",
        "redirect-body",
    ]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "h3 redirected");
    assert!(res.stderr.contains("HTTP/3.0 200 OK"));
    let requests = wait_for_h3_requests(&redirect, 2);
    assert_eq!(requests[0].path, "/start");
    assert_eq!(requests[1].path, "/final");
    assert_eq!(requests[0].body_string(), "redirect-body");
    assert_eq!(requests[1].body_string(), "redirect-body");

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

#[cfg(unix)]
#[test]
fn image_rendering_pty_go_cases() {
    let output = run_image_render_pty(image_pty_env(&[]));
    assert!(output.contains("\x1b[48;5;"), "{output:?}");
    assert!(output.contains("\x1b[38;5;"), "{output:?}");
    assert!(output.contains("▄"), "{output:?}");
    assert!(
        !output.as_bytes().windows(4).any(|w| w == b"\x89PNG"),
        "{output:?}"
    );

    let output = run_image_render_pty(image_pty_env(&[
        ("TERM", "xterm-256color"),
        ("TERM_PROGRAM", "iTerm.app"),
        ("ITERM_SESSION_ID", "fetch-test"),
    ]));
    assert!(
        output.contains("\x1b]1337;File=inline=1;preserveAspectRatio=1;"),
        "{output:?}"
    );
    assert!(
        !output.as_bytes().windows(4).any(|w| w == b"\x89PNG"),
        "{output:?}"
    );

    let output = run_image_render_pty(image_pty_env(&[
        ("TERM", "xterm-kitty"),
        ("KITTY_PID", "123"),
    ]));
    assert!(output.contains("\x1b_Gq=2,f=100,a=T,t=d,"), "{output:?}");
    assert!(output.contains("\x1b\\"), "{output:?}");
    assert!(
        !output.as_bytes().windows(4).any(|w| w == b"\x89PNG"),
        "{output:?}"
    );
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
        if req.body_string() == r#"{"edited":true}"#
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

    let res = run_fetch(&[&format!("{}/timing", server.url), "--timing"]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "timed");
    assert!(res.stderr.contains("Total") || res.stderr.contains("Timing"));
    assert!(res.stderr.contains("TCP"));
    assert!(res.stderr.contains("█"));
    assert!(res.stderr.contains("─"));
    assert!(!res.stderr.contains("* TCP:"));
    assert!(!res.stderr.contains("* TTFB:"));
    let res = run_fetch(&[&format!("{}/timing", server.url), "-T"]);
    assert_exit(&res, 0);
    assert_eq!(res.stdout, "timed");
    assert!(res.stderr.contains("Total") || res.stderr.contains("Timing"));
    assert!(res.stderr.contains("█"));
    let res = run_fetch(&[&format!("{}/timing", server.url), "-T", "-vvv"]);
    assert_exit(&res, 0);
    assert!(res.stderr.contains("* TCP:"));
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
    let binary = TestServer::start(move |req| match req.path.as_str() {
        "/proto" => {
            TestResponse::ok(proto_body.clone()).header("Content-Type", "application/protobuf")
        }
        "/grpc" => {
            TestResponse::ok(grpc_body.clone()).header("Content-Type", "application/grpc+proto")
        }
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

#[cfg(not(windows))]
#[test]
fn self_update_go_harness_cases() {
    let dir = TempDir::new().unwrap();
    let update_bin = dir.path().join("fetch");
    install_update_launcher(&update_bin);
    let auto_update_bin = dir.path().join("fetch-auto");
    install_update_launcher(&auto_update_bin);

    let current_version = fetch_version();
    let latest_version = Arc::new(Mutex::new(current_version.clone()));
    let update_requests = Arc::new(AtomicUsize::new(0));
    let server_url = Arc::new(Mutex::new(String::new()));
    let latest_for_handler = Arc::clone(&latest_version);
    let requests_for_handler = Arc::clone(&update_requests);
    let server_url_for_handler = Arc::clone(&server_url);
    let server = TestServer::start(move |req| {
        requests_for_handler.fetch_add(1, Ordering::SeqCst);
        let version = latest_for_handler.lock().unwrap().clone();
        let artifact_name = update_artifact_name(&version);
        if req.path == "/artifact" {
            return TestResponse::ok(make_update_artifact(&version));
        }
        if req.path == "/artifact.sha256" {
            let artifact = make_update_artifact(&version);
            return TestResponse::ok(update_artifact_checksum_line(&artifact_name, &artifact));
        }
        let base = server_url_for_handler.lock().unwrap().clone();
        let body = format!(
            r#"{{"tag_name":"{version}","assets":[{{"name":"{artifact_name}","browser_download_url":"{base}/artifact"}},{{"name":"{artifact_name}.sha256","browser_download_url":"{base}/artifact.sha256"}}]}}"#
        );
        TestResponse::ok(body).header("Content-Type", "application/json")
    });
    *server_url.lock().unwrap() = server.url.clone();

    let env = vec![("FETCH_INTERNAL_UPDATE_URL".to_string(), server.url.clone())];
    let opts = |bin: &Path, env: Vec<(String, String)>| FetchOpts {
        bin: Some(bin.to_path_buf()),
        env,
        ..Default::default()
    };

    let original_modified = fs::metadata(&update_bin).unwrap().modified().unwrap();
    let res = run_fetch_opts(opts(&update_bin, env.clone()), &[&server.url, "--update"]);
    assert_exit(&res, 0);
    assert!(res.stderr.contains("Already using the latest version"));
    assert_eq!(
        fs::read_dir(dir.path()).unwrap().count(),
        2,
        "unexpected update temp files"
    );
    assert_eq!(
        fs::metadata(&update_bin).unwrap().modified().unwrap(),
        original_modified
    );

    *latest_version.lock().unwrap() = "v999.0.0-test".to_string();
    let dry_same_modified = fs::metadata(&update_bin).unwrap().modified().unwrap();
    *latest_version.lock().unwrap() = current_version;
    let res = run_fetch_opts(
        opts(&update_bin, env.clone()),
        &[&server.url, "--update", "--dry-run"],
    );
    assert_exit(&res, 0);
    assert!(res.stderr.contains("Already using the latest version"));
    assert_eq!(
        fs::metadata(&update_bin).unwrap().modified().unwrap(),
        dry_same_modified
    );

    *latest_version.lock().unwrap() = "v999.0.0-test".to_string();
    let dry_new_modified = fs::metadata(&update_bin).unwrap().modified().unwrap();
    let res = run_fetch_opts(
        opts(&update_bin, env.clone()),
        &[&server.url, "--update", "--dry-run"],
    );
    assert_exit(&res, 0);
    assert!(res.stderr.contains("Update available"));
    assert!(res.stderr.contains("v999.0.0-test"));
    assert!(!res.stderr.contains("Updated fetch:"));
    assert!(!res.stderr.contains("Downloading"));
    assert_eq!(
        fs::metadata(&update_bin).unwrap().modified().unwrap(),
        dry_new_modified
    );

    let before_metadata_requests = update_requests.load(Ordering::SeqCst);
    let before_metadata_modified = fs::metadata(&update_bin).unwrap().modified().unwrap();
    let mut metadata_env = env.clone();
    metadata_env.push((
        "FETCH_INTERNAL_SYNC_AUTO_UPDATE".to_string(),
        "1".to_string(),
    ));
    let res = run_fetch_opts(
        opts(&update_bin, metadata_env),
        &["--version", "--auto-update", "0s"],
    );
    assert_exit(&res, 0);
    assert_eq!(
        update_requests.load(Ordering::SeqCst),
        before_metadata_requests,
        "metadata command started an auto-update request"
    );
    assert_eq!(
        fs::metadata(&update_bin).unwrap().modified().unwrap(),
        before_metadata_modified
    );

    let res = run_fetch_opts(opts(&update_bin, env.clone()), &[&server.url, "--update"]);
    assert_exit(&res, 0);
    assert!(res.stderr.contains("Updated fetch:"));
    assert!(res.stderr.contains("Changelog:"));
    assert_eq!(
        fs::read_dir(dir.path()).unwrap().count(),
        2,
        "unexpected update temp files"
    );
    assert_ne!(
        fs::metadata(&update_bin).unwrap().modified().unwrap(),
        original_modified
    );

    let res = run_fetch_opts(opts(&update_bin, env.clone()), &["--version"]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("fetch v999.0.0-test"));

    *latest_version.lock().unwrap() = "v1000.0.0-test".to_string();
    let auto_update_modified = fs::metadata(&auto_update_bin).unwrap().modified().unwrap();
    let mut sync_auto_update_env = env.clone();
    sync_auto_update_env.push((
        "FETCH_INTERNAL_SYNC_AUTO_UPDATE".to_string(),
        "1".to_string(),
    ));
    let res = run_fetch_opts(
        opts(&auto_update_bin, sync_auto_update_env),
        &[&server.url, "--auto-update", "0s"],
    );
    assert_exit(&res, 0);
    assert_ne!(
        fs::metadata(&auto_update_bin).unwrap().modified().unwrap(),
        auto_update_modified
    );

    let res = run_fetch_opts(opts(&auto_update_bin, env), &["--version"]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("fetch v1000.0.0-test"));
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

    let res = run_fetch(&[&ws_url, "--method", "POST", "--dry-run"]);
    assert_exit(&res, 0);
    assert!(res.stderr.contains("GET / HTTP/1.1"));

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

#[cfg(unix)]
#[test]
fn request_ctrl_c_reports_signal_go_case() {
    let (started_tx, started_rx) = mpsc::channel();
    let release = Arc::new(AtomicUsize::new(0));
    let release_for_handler = Arc::clone(&release);
    let started = Arc::new(AtomicUsize::new(0));
    let started_for_handler = Arc::clone(&started);
    let server = TestServer::start(move |_| {
        if started_for_handler.fetch_add(1, Ordering::SeqCst) == 0 {
            let _ = started_tx.send(());
        }
        while release_for_handler.load(Ordering::SeqCst) == 0 {
            thread::sleep(Duration::from_millis(10));
        }
        TestResponse::ok("late")
    });

    let mut cmd = Command::new(fetch_bin());
    cmd.args([server.url.as_str(), "--pager", "off"]);
    cmd.env("HTTP_PROXY", "");
    cmd.env("HTTPS_PROXY", "");
    cmd.env("ALL_PROXY", "");
    cmd.env("NO_PROXY", "*");
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn fetch for signal test");

    started_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("request did not reach server");
    let rc = unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) };
    assert_eq!(rc, 0, "failed to send SIGINT");
    let status = wait_child(&mut child, Duration::from_secs(5))
        .unwrap_or_else(|| {
            let _ = child.kill();
            panic!("fetch did not exit after SIGINT")
        })
        .expect("wait fetch after SIGINT");
    release.store(1, Ordering::SeqCst);
    let output = child.wait_with_output().expect("collect signal output");
    assert_eq!(status.code(), Some(1));
    assert!(
        output.stdout.is_empty(),
        "stdout = {:?}, want empty",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("received signal: interrupt"),
        "stderr = {stderr:?}, want signal error"
    );
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

#[test]
fn grpc_reflection_h2c_go_cases() {
    let server = start_reflection_grpc_h2c_server(true);
    let res = run_fetch(&["--grpc-list", &server.url]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("grpc.health.v1.Health"));

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

fn parse_digest_auth_params(input: &str) -> HashMap<String, String> {
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

fn md5_hex(input: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(input.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
