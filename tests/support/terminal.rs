#![cfg(unix)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use image::ImageEncoder;
use tempfile::TempDir;

use super::common::{FetchOpts, FetchOutput, fetch_bin, run_fetch_opts, wait_child};
use super::http::{TestResponse, TestServer};
use super::pty::{configure_pty_child, open_pty, start_pty_capture};

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
