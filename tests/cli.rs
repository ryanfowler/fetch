mod support;

use std::fs;
#[cfg(unix)]
use std::io::Write;
use std::path::Path;
#[cfg(unix)]
use std::process::Command;
#[cfg(unix)]
use std::time::Duration;
use support::common::{FetchOpts, assert_exit, host_port, run_fetch, run_fetch_opts};
#[cfg(unix)]
use support::common::{assert_no_closed_stdout_panic, fetch_bin, run_fetch_with_closed_stdout};
#[cfg(unix)]
use support::grpc::{start_reflection_grpc_h2c_server, write_health_descriptor_set};
use support::http::{TestResponse, TestServer};
#[cfg(unix)]
use support::pty::{configure_pty_child, open_pty, start_pty_capture};
use tempfile::TempDir;

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
fn verbose_help_prints_cli_reference() {
    let res = run_fetch(&["-v", "--help", "--pager", "off"]);
    assert_exit(&res, 0);
    assert!(res.stderr.is_empty(), "stderr: {}", res.stderr);
    assert!(res.stdout.contains("# CLI Reference"));
    assert!(res.stdout.contains("## Usage"));
    assert!(res.stdout.contains("### -v, --verbose"));
}

#[test]
fn verbose_help_colorizes_markdown_when_color_is_forced() {
    let res = run_fetch(&["-v", "--help", "--pager", "off", "--color", "on"]);
    assert_exit(&res, 0);
    assert!(res.stderr.is_empty(), "stderr: {}", res.stderr);
    assert!(res.stdout.contains("\x1b["), "stdout was not colorized");
    assert!(res.stdout.contains("CLI Reference"));
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

#[cfg(unix)]
#[test]
fn metadata_and_grpc_discovery_handle_closed_stdout_without_panic() {
    for args in [
        vec!["--help"],
        vec!["--version"],
        vec!["--complete", "bash"],
    ] {
        let res = run_fetch_with_closed_stdout(&args);
        assert_no_closed_stdout_panic(&res);
    }

    let dir = TempDir::new().unwrap();
    let health_desc = write_health_descriptor_set(dir.path());
    let health_desc = health_desc.to_str().unwrap();
    for args in [
        vec!["--grpc-list", "--proto-desc", health_desc],
        vec![
            "--grpc-describe",
            "grpc.health.v1.Health",
            "--proto-desc",
            health_desc,
            "http://127.0.0.1:1",
        ],
    ] {
        let res = run_fetch_with_closed_stdout(&args);
        assert_no_closed_stdout_panic(&res);
    }

    let server = start_reflection_grpc_h2c_server(true);
    for args in [
        vec!["--grpc-list", &server.url],
        vec![
            "--grpc-describe",
            "grpc.health.v1.Health/Check",
            &server.url,
        ],
    ] {
        let res = run_fetch_with_closed_stdout(&args);
        assert_no_closed_stdout_panic(&res);
    }
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
    assert!(!res.stderr.contains("* Connect:"));
    assert!(res.stderr.contains("* TTFB:"));
}

#[test]
fn dry_run_prints_effective_request_without_network() {
    let res = run_fetch(&["-j", r#"{"key":"val1"}"#, "localhost:3000", "--dry-run"]);
    assert_exit(&res, 0);
    assert!(res.stdout.is_empty());
    assert!(res.stderr.contains("POST / HTTP/1.1\n"));
    assert!(res.stderr.contains("url: http://localhost:3000/\n"));
    assert!(res.stderr.contains("accept: application/json, */*;q=0.5"));
    assert!(res.stderr.contains("accept-encoding: gzip, br, zstd\n"));
    assert!(res.stderr.contains("content-length: 14\n"));
    assert!(res.stderr.contains("content-type: application/json\n"));
    assert!(res.stderr.contains("host: localhost:3000\n"));
    assert!(res.stderr.contains("\n\n{\"key\":\"val1\"}"));
    assert!(!res.stderr.contains("> POST"));

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

    let res = run_fetch(&[
        "localhost:3000",
        "--data",
        "hello",
        "-H",
        "Content-Length: 99",
        "--dry-run",
    ]);
    assert_exit(&res, 0);
    assert!(res.stderr.contains("content-length: 99\n"));
    assert!(!res.stderr.contains("content-length: 5\n"));
    assert_eq!(res.stderr.matches("content-length:").count(), 1);

    let res = run_fetch(&["example.com:8080/path?debug=true", "--dry-run"]);
    assert_exit(&res, 0);
    assert!(
        res.stderr
            .contains("url: https://example.com:8080/path?debug=true\n")
    );

    let res = run_fetch(&[
        "localhost:3000",
        "--data",
        "hello",
        "-H",
        "Transfer-Encoding: chunked",
        "--dry-run",
    ]);
    assert_exit(&res, 0);
    assert!(res.stderr.contains("transfer-encoding: chunked\n"));
    assert!(!res.stderr.contains("content-length:"));

    let res = run_fetch_opts(
        FetchOpts {
            env: vec![
                ("HTTP_PROXY".to_string(), ":bad".to_string()),
                ("http_proxy".to_string(), ":bad".to_string()),
            ],
            ..Default::default()
        },
        &["-j", r#"{"key":"val1"}"#, "localhost:3000", "--dry-run"],
    );
    assert_exit(&res, 0);
    assert!(res.stderr.contains("POST / HTTP/1.1\n"));
}

#[test]
fn dry_run_truncates_large_file_body_preview() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("large.txt");
    let tail = "FILE_TAIL_SHOULD_NOT_APPEAR";
    fs::write(&path, format!("{}{}", "a".repeat(2048), tail)).unwrap();

    let data_arg = format!("@{}", path.display());
    let res = run_fetch(&["localhost:3000", "--data", &data_arg, "--dry-run"]);

    assert_exit(&res, 0);
    assert!(res.stdout.is_empty());
    assert!(res.stderr.contains(&"a".repeat(1024)));
    assert!(res.stderr.contains("truncated after 1024 bytes"));
    assert!(!res.stderr.contains(tail), "stderr:\n{}", res.stderr);
    assert!(
        res.stderr.len() < 1800,
        "dry-run body preview was not bounded:\n{}",
        res.stderr
    );
}

#[test]
fn dry_run_truncates_large_stdin_body_preview() {
    let tail = "STDIN_TAIL_SHOULD_NOT_APPEAR";
    let res = run_fetch_opts(
        FetchOpts {
            stdin: Some(format!("{}{}", "s".repeat(2048), tail)),
            ..Default::default()
        },
        &["localhost:3000", "--data", "@-", "--dry-run"],
    );

    assert_exit(&res, 0);
    assert!(res.stdout.is_empty());
    assert!(res.stderr.contains(&"s".repeat(1024)));
    assert!(res.stderr.contains("truncated after 1024 bytes"));
    assert!(!res.stderr.contains(tail), "stderr:\n{}", res.stderr);
    assert!(
        res.stderr.len() < 1800,
        "dry-run stdin preview was not bounded:\n{}",
        res.stderr
    );
}

#[test]
fn dry_run_truncates_multipart_file_body_preview() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("part.txt");
    let tail = "MULTIPART_TAIL_SHOULD_NOT_APPEAR";
    fs::write(&path, format!("{}{}", "m".repeat(2048), tail)).unwrap();

    let field = format!("file=@{}", path.display());
    let res = run_fetch(&["localhost:3000", "--multipart", &field, "--dry-run"]);

    assert_exit(&res, 0);
    assert!(res.stdout.is_empty());
    assert!(res.stderr.contains("multipart/form-data; boundary="));
    assert!(
        res.stderr
            .contains("Content-Disposition: form-data; name=\"file\"; filename=\"part.txt\"")
    );
    assert!(res.stderr.contains("truncated after 1024 bytes"));
    assert!(!res.stderr.contains(tail), "stderr:\n{}", res.stderr);
    assert!(
        res.stderr.len() < 1900,
        "dry-run multipart preview was not bounded:\n{}",
        res.stderr
    );
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

    let res = run_fetch(&["--config", config.to_str().unwrap(), "https://example.com"]);
    assert_exit(&res, 1);
    assert!(
        res.stderr
            .contains("client key requires a client certificate")
    );

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
fn bundled_skill_can_be_printed_and_installed_offline_for_pi() {
    let skill = run_fetch(&["--skill"]);
    assert_exit(&skill, 0);
    let normalized_skill = skill.stdout.replace("\r\n", "\n");
    assert!(normalized_skill.starts_with("---\nname: fetch\n"));

    let home = TempDir::new().unwrap();
    let home_value = home.path().to_string_lossy().into_owned();
    let installed = run_fetch_opts(
        FetchOpts {
            env: vec![("HOME".to_string(), home_value)],
            ..FetchOpts::default()
        },
        &["--install-skill", "pi"],
    );
    assert_exit(&installed, 0);
    let destination = home.path().join(".pi/agent/skills/fetch");
    assert_eq!(
        fs::read_to_string(destination.join("SKILL.md")).unwrap(),
        skill.stdout
    );
    let metadata = fs::read_to_string(destination.join(".fetch-skill.json")).unwrap();
    assert!(metadata.contains("\"skill_version\": \"1\""));
    assert!(metadata.contains("\"fetch_version\""));
}

#[test]
fn skill_install_default_uses_generic_agents_location() {
    let home = TempDir::new().unwrap();
    let result = run_fetch_opts(
        FetchOpts {
            env: vec![(
                "HOME".to_string(),
                home.path().to_string_lossy().into_owned(),
            )],
            ..FetchOpts::default()
        },
        &["--install-skill"],
    );
    assert_exit(&result, 0);
    assert!(home.path().join(".agents/skills/fetch/SKILL.md").is_file());
    assert!(!home.path().join(".codex").exists());
    assert!(!home.path().join(".pi").exists());
}

#[test]
fn skill_actions_reject_options_that_would_be_ignored() {
    for args in [
        &["--skill", "--update"][..],
        &["--skill", "--scope", "project"],
        &["--skill", "--header", "x-test: true"],
        &["--install-skill", "--method", "POST"],
        &["--uninstall-skill", "--complete", "bash"],
    ] {
        let result = run_fetch(args);
        assert_exit(&result, 1);
        assert!(
            result.stderr.contains("cannot be used"),
            "unexpected error for {args:?}: {}",
            result.stderr
        );
    }
}

#[test]
fn skill_install_dry_run_and_modification_guard_are_safe() {
    let home = TempDir::new().unwrap();
    let home_value = home.path().to_string_lossy().into_owned();
    let opts = || FetchOpts {
        env: vec![("HOME".to_string(), home_value.clone())],
        ..FetchOpts::default()
    };

    let dry_run = run_fetch_opts(opts(), &["--install-skill", "all", "--dry-run"]);
    assert_exit(&dry_run, 0);
    let dry_run_stderr = dry_run.stderr.replace('\\', "/");
    for path in [
        ".agents/skills/fetch",
        ".codex/skills/fetch",
        ".claude/skills/fetch",
        ".gemini/skills/fetch",
        ".pi/agent/skills/fetch",
    ] {
        assert!(dry_run_stderr.contains(path), "missing destination {path}");
    }
    assert!(!home.path().join(".agents").exists());

    assert_exit(&run_fetch_opts(opts(), &["--install-skill", "all"]), 0);
    for path in [
        ".agents/skills/fetch/SKILL.md",
        ".codex/skills/fetch/SKILL.md",
        ".claude/skills/fetch/SKILL.md",
        ".gemini/skills/fetch/SKILL.md",
        ".pi/agent/skills/fetch/SKILL.md",
    ] {
        assert!(home.path().join(path).is_file(), "missing installed {path}");
    }
    let skill = home.path().join(".pi/agent/skills/fetch/SKILL.md");
    fs::write(&skill, "locally modified\n").unwrap();
    let guarded = run_fetch_opts(opts(), &["--install-skill", "pi"]);
    assert_exit(&guarded, 1);
    assert!(guarded.stderr.contains("refusing to overwrite modified"));

    assert_exit(
        &run_fetch_opts(opts(), &["--install-skill", "pi", "--force"]),
        0,
    );
    assert_ne!(fs::read_to_string(skill).unwrap(), "locally modified\n");
}

#[test]
fn uninstalling_missing_project_skill_does_not_create_files() {
    let project = TempDir::new().unwrap();
    let result = run_fetch_opts(
        FetchOpts {
            cwd: Some(project.path().to_path_buf()),
            ..FetchOpts::default()
        },
        &["--uninstall-skill", "pi", "--scope", "project"],
    );
    assert_exit(&result, 0);
    let stderr = result.stderr.replace('\\', "/");
    assert!(stderr.contains(".pi/skills/fetch"));
    assert!(stderr.contains("nothing to remove"));
    assert!(
        fs::read_dir(project.path()).unwrap().next().is_none(),
        "missing-skill uninstall changed the project directory"
    );
}

#[cfg(unix)]
#[test]
fn skill_uninstall_rechecks_modifications_after_confirmation() {
    let home = TempDir::new().unwrap();
    let home_value = home.path().to_string_lossy().into_owned();
    let installed = run_fetch_opts(
        FetchOpts {
            env: vec![("HOME".to_string(), home_value.clone())],
            ..FetchOpts::default()
        },
        &["--install-skill", "pi"],
    );
    assert_exit(&installed, 0);

    let pair = open_pty(24, 100, 0, 0);
    let capture = start_pty_capture(&pair.master);
    let mut command = Command::new(fetch_bin());
    command.args(["--uninstall-skill", "pi"]);
    command.env("HOME", &home_value).env("NO_COLOR", "");
    configure_pty_child(&mut command, &pair.slave);
    let mut child = command.spawn().unwrap();
    drop(pair.slave);

    capture.wait_for("Uninstall the fetch skill? [y/N]", Duration::from_secs(5));
    let skill = home.path().join(".pi/agent/skills/fetch/SKILL.md");
    fs::write(&skill, "modified while confirmation was pending\n").unwrap();
    let mut input = capture.file.try_clone().unwrap();
    input.write_all(b"y\n").unwrap();

    let status = child.wait().unwrap();
    assert!(!status.success());
    assert!(skill.exists(), "modified installation was removed");
    assert!(capture.output().contains("refusing to remove modified"));
    capture.close();
}

#[test]
fn integration_support_stays_domain_split() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let support_mod = fs::read_to_string(root.join("tests/support/mod.rs")).unwrap();
    assert!(
        support_mod.lines().count() <= 40,
        "tests/support/mod.rs should stay as a small domain-module index"
    );
    for module in [
        "auth",
        "common",
        "dns",
        "grpc",
        "http",
        "http3",
        "proxy",
        "pty",
        "terminal",
        "tls",
        "update",
        "websocket",
    ] {
        assert!(
            support_mod.contains(&format!("pub(crate) mod {module};")),
            "missing support::{module} declaration"
        );
    }

    let wildcard_support_import = ["use support", "::*;"].concat();
    for entry in fs::read_dir(root.join("tests")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let contents = fs::read_to_string(&path).unwrap();
        assert!(
            !contents.contains(&wildcard_support_import),
            "{} should import helpers from specific support modules",
            path.display()
        );
    }
}
