use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;
use url::Url;
use wait_timeout::ChildExt;

#[cfg(unix)]
use std::os::fd::{FromRawFd, RawFd};

pub(crate) const FAST_RETRY_DELAY: &str = "0.000001";

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

pub(crate) struct ReadCapture {
    pub(crate) buffer: Arc<Mutex<Vec<u8>>>,
    pub(crate) done: mpsc::Receiver<()>,
}

pub(crate) fn fetch_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_fetch"))
}

fn isolate_http3_cache(cmd: &mut Command) -> TempDir {
    let cache_dir = TempDir::new().expect("create isolated HTTP/3 cache dir");
    cmd.env("FETCH_INTERNAL_HTTP3_CACHE_DIR", cache_dir.path());
    cache_dir
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
    let mut delay_ms: u64 = 25;
    for _ in 0..9 {
        if !can_retry || !is_transient_local_server_error(&result) {
            return result;
        }
        thread::sleep(Duration::from_millis(delay_ms));
        delay_ms = (delay_ms * 2).min(1000);
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
    cmd.env_remove("PAGER");
    cmd.env_remove("LESS");
    cmd.env_remove("NO_PAGER");
    cmd.env("HTTP_PROXY", "");
    cmd.env("HTTPS_PROXY", "");
    cmd.env("ALL_PROXY", "");
    cmd.env("NO_PROXY", "*");
    let _http3_cache_dir = isolate_http3_cache(&mut cmd);
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

    // Drain both pipes while the child runs so a verbose command cannot block on
    // a full pipe. wait_timeout avoids adding up to 10ms of polling latency to
    // every short-lived CLI invocation in the integration suite.
    let mut stdout = child.stdout.take().expect("child stdout");
    let stdout_reader = thread::spawn(move || {
        let mut output = Vec::new();
        stdout.read_to_end(&mut output).expect("read fetch stdout");
        output
    });
    let mut stderr = child.stderr.take().expect("child stderr");
    let stderr_reader = thread::spawn(move || {
        let mut output = Vec::new();
        stderr.read_to_end(&mut output).expect("read fetch stderr");
        output
    });

    let timed_out = child
        .wait_timeout(Duration::from_secs(15))
        .expect("wait for fetch")
        .is_none();
    if timed_out {
        let _ = child.kill();
    }
    let status = child.wait().expect("wait fetch");
    let stdout = stdout_reader.join().expect("join fetch stdout reader");
    let stderr = stderr_reader.join().expect("join fetch stderr reader");
    let mut stderr = String::from_utf8_lossy(&stderr).into_owned();
    if timed_out {
        stderr.push_str("\nfetch test harness timeout after 15s");
    }
    FetchOutput {
        status,
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr,
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
    let _http3_cache_dir = isolate_http3_cache(&mut cmd);

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

pub(crate) fn wait_child(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Option<std::io::Result<ExitStatus>> {
    match child.wait_timeout(timeout) {
        Ok(Some(status)) => Some(Ok(status)),
        Ok(None) => None,
        Err(err) => Some(Err(err)),
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
