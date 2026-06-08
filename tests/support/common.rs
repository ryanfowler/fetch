use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use url::Url;

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
