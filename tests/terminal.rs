mod support;

use support::*;

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
