use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PagerCommand {
    pub(super) program: String,
    pub(super) args: Vec<String>,
    pub(super) is_fallback: bool,
}

pub(super) struct StdoutBody {
    pub(super) bytes: Vec<u8>,
    pub(super) content_type: ContentType,
    pub(super) content_type_label: String,
}

pub(super) fn write_stdout_bytes(cli: &Cli, body: &StdoutBody) -> Result<(), FetchError> {
    let stdout_is_terminal = core::stdio().stdout_is_terminal();
    if should_warn_for_terminal_binary_stdout(cli, &body.bytes, stdout_is_terminal) {
        write_warning(cli, &binary_response_warning(&body.content_type_label));
        return Ok(());
    }

    if should_page_stdout(cli, &body.bytes, body.content_type, stdout_is_terminal) {
        return write_stdout_bytes_with_pager(&body.bytes);
    }

    core::write_stdout(&body.bytes)?;
    Ok(())
}

pub(super) fn should_page_stdout(
    cli: &Cli,
    bytes: &[u8],
    content_type: ContentType,
    stdout_is_terminal: bool,
) -> bool {
    let pager_allowed = !bytes.is_empty() && content_type != ContentType::Image;
    pager_allowed
        && match crate::cli::PagerMode::from_cli(cli) {
            crate::cli::PagerMode::Auto => stdout_is_terminal && !pager_disabled_by_env(),
            crate::cli::PagerMode::On => true,
            crate::cli::PagerMode::Off => false,
        }
}

pub(super) fn write_stdout_bytes_with_pager(bytes: &[u8]) -> Result<(), FetchError> {
    let pager = pager_command();
    let mut child = match std::process::Command::new(&pager.program)
        .args(&pager.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(child) => child,
        Err(err) if pager.is_fallback && err.kind() == ErrorKind::NotFound => {
            core::write_stdout(bytes)?;
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };

    if let Some(mut stdin) = child.stdin.take() {
        match stdin.write_all(bytes) {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::BrokenPipe => {}
            Err(err) => return Err(err.into()),
        }
    }

    let status = child.wait()?;
    if !status.success() {
        return Err(FetchError::Runtime(format!("pager exited with {status}")));
    }

    Ok(())
}

#[derive(Clone, Copy)]
pub(super) enum StdoutStreamTarget {
    Direct,
    Pager,
}

pub(super) fn stdout_stream_target(
    cli: &Cli,
    headers: &HeaderMap,
    stdout_is_terminal: bool,
) -> Option<StdoutStreamTarget> {
    if core::format_enabled(cli.format.as_deref(), stdout_is_terminal) {
        return None;
    }

    let is_image = response_header_content_type(headers) == ContentType::Image;
    match crate::cli::PagerMode::from_cli(cli) {
        crate::cli::PagerMode::Auto
            if stdout_is_terminal && !is_image && !pager_disabled_by_env() =>
        {
            Some(StdoutStreamTarget::Pager)
        }
        crate::cli::PagerMode::On if !is_image => Some(StdoutStreamTarget::Pager),
        crate::cli::PagerMode::Auto | crate::cli::PagerMode::Off | crate::cli::PagerMode::On => {
            Some(StdoutStreamTarget::Direct)
        }
    }
}

pub(super) fn pager_command() -> PagerCommand {
    pager_command_with_env(|name| std::env::var_os(name).and_then(os_string_to_string))
}

fn pager_disabled_by_env() -> bool {
    std::env::var_os("NO_PAGER").is_some()
}

fn os_string_to_string(value: std::ffi::OsString) -> Option<String> {
    value.into_string().ok()
}

fn pager_command_with_env<F>(mut get_env: F) -> PagerCommand
where
    F: FnMut(&str) -> Option<String>,
{
    if let Some(value) = get_env("PAGER") {
        let args = split_command_args(&value);
        if let Some((program, args)) = args.split_first() {
            return PagerCommand {
                program: program.clone(),
                args: args.to_vec(),
                is_fallback: false,
            };
        }
    }

    PagerCommand {
        program: "less".to_string(),
        args: if get_env("LESS").is_some() {
            Vec::new()
        } else {
            vec!["-FIRX".to_string()]
        },
        is_fallback: true,
    }
}

fn split_command_args(value: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut cur = Vec::new();
    let bytes = value.trim().as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        match bytes[idx] {
            b' ' | b'\t' => {
                if !cur.is_empty() {
                    args.push(String::from_utf8_lossy(&cur).into_owned());
                    cur.clear();
                }
                idx += 1;
            }
            b'\'' | b'"' => {
                let quote = bytes[idx];
                idx += 1;
                while idx < bytes.len() && bytes[idx] != quote {
                    cur.push(bytes[idx]);
                    idx += 1;
                }
                if idx < bytes.len() {
                    idx += 1;
                }
            }
            ch => {
                cur.push(ch);
                idx += 1;
            }
        }
    }
    if !cur.is_empty() {
        args.push(String::from_utf8_lossy(&cur).into_owned());
    }
    args
}

pub(super) fn response_header_content_type(headers: &HeaderMap) -> ContentType {
    let content_type = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    content_type::get_content_type(content_type).0
}

pub(super) fn response_header_content_type_label(headers: &HeaderMap) -> String {
    headers
        .get(http::header::CONTENT_TYPE)
        .map(|value| {
            value
                .to_str()
                .unwrap_or("<invalid content-type>")
                .to_owned()
        })
        .unwrap_or_else(|| "<none>".to_owned())
}

pub(super) fn binary_response_warning(content_type: &str) -> String {
    format!(
        "the response body appears to be binary (content type: {content_type})\n\nUse '-o file' to save it, '-o - > file' to redirect raw bytes, or '--image off' to disable terminal image rendering."
    )
}

pub(super) fn terminal_binary_stdout_guard_enabled(cli: &Cli, stdout_is_terminal: bool) -> bool {
    stdout_is_terminal && cli.output.as_deref() != Some("-")
}

pub(super) fn should_warn_for_terminal_binary_stdout(
    cli: &Cli,
    bytes: &[u8],
    stdout_is_terminal: bool,
) -> bool {
    terminal_binary_stdout_guard_enabled(cli, stdout_is_terminal) && !is_printable(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    use clap::Parser;

    #[test]
    fn terminal_binary_stdout_guard_requires_terminal_and_allows_forced_stdout() {
        let cli = Cli::try_parse_from(["fetch", "https://example.com"]).unwrap();
        assert!(should_warn_for_terminal_binary_stdout(
            &cli,
            b"abc\0def",
            true
        ));
        assert!(!should_warn_for_terminal_binary_stdout(
            &cli,
            b"abc\0def",
            false
        ));
        assert!(!should_warn_for_terminal_binary_stdout(
            &cli,
            b"plain text",
            true
        ));

        let forced = Cli::try_parse_from(["fetch", "-o", "-", "https://example.com"]).unwrap();
        assert!(!should_warn_for_terminal_binary_stdout(
            &forced,
            b"abc\0def",
            true
        ));
    }

    #[test]
    fn binary_response_warning_includes_content_type_and_alternatives() {
        let warning = binary_response_warning("application/octet-stream");
        assert!(warning.contains("content type: application/octet-stream"));
        assert!(warning.contains("-o file"));
        assert!(warning.contains("-o - > file"));
        assert!(warning.contains("--image off"));
    }

    #[test]
    fn pager_command_uses_pager_or_less_fallback() {
        let got = pager_command_with_env(|_| None);
        assert_eq!(
            got,
            PagerCommand {
                program: "less".to_string(),
                args: vec!["-FIRX".to_string()],
                is_fallback: true,
            }
        );

        let got = pager_command_with_env(|name| match name {
            "LESS" => Some("-SR".to_string()),
            _ => None,
        });
        assert_eq!(
            got,
            PagerCommand {
                program: "less".to_string(),
                args: Vec::new(),
                is_fallback: true,
            }
        );

        let got = pager_command_with_env(|name| match name {
            "PAGER" => Some(r#""/usr/local/bin/my pager" --plain"#.to_string()),
            _ => None,
        });
        assert_eq!(
            got,
            PagerCommand {
                program: "/usr/local/bin/my pager".to_string(),
                args: vec!["--plain".to_string()],
                is_fallback: false,
            }
        );
    }

    #[test]
    fn pager_auto_uses_stdout_terminal_and_skips_images() {
        let cli = Cli::try_parse_from(["fetch", "https://example.com"]).unwrap();
        assert!(!should_page_stdout(
            &cli,
            b"\x1b_Gq=2,f=100,a=T,t=d,s=1,v=1,m=0;AAAA\x1b\\\n",
            ContentType::Image,
            true,
        ));
        assert!(should_page_stdout(
            &cli,
            b"{\"ok\":true}\n",
            ContentType::Json,
            true,
        ));
        assert!(!should_page_stdout(
            &cli,
            b"{\"ok\":true}\n",
            ContentType::Json,
            false,
        ));
    }

    #[test]
    fn pager_on_forces_pager_for_non_terminal_stdout() {
        let cli = Cli::try_parse_from(["fetch", "--pager", "on", "https://example.com"]).unwrap();
        assert!(should_page_stdout(
            &cli,
            b"{\"ok\":true}\n",
            ContentType::Json,
            false,
        ));
    }

    #[test]
    fn pager_off_disables_pager_for_terminal_stdout() {
        let cli = Cli::try_parse_from(["fetch", "--pager", "off", "https://example.com"]).unwrap();
        assert!(!should_page_stdout(
            &cli,
            b"{\"ok\":true}\n",
            ContentType::Json,
            true,
        ));
    }

    #[test]
    fn stdout_streaming_follows_format_and_pager_modes() {
        let headers = HeaderMap::new();
        let cli = Cli::try_parse_from(["fetch", "https://example.com"]).unwrap();
        assert!(matches!(
            stdout_stream_target(&cli, &headers, false),
            Some(StdoutStreamTarget::Direct)
        ));
        assert!(stdout_stream_target(&cli, &headers, true).is_none());

        let cli = Cli::try_parse_from(["fetch", "--format", "off", "https://example.com"]).unwrap();
        assert!(matches!(
            stdout_stream_target(&cli, &headers, false),
            Some(StdoutStreamTarget::Direct)
        ));
        assert!(matches!(
            stdout_stream_target(&cli, &headers, true),
            Some(StdoutStreamTarget::Pager)
        ));

        let cli = Cli::try_parse_from([
            "fetch",
            "--format",
            "off",
            "--pager",
            "off",
            "https://example.com",
        ])
        .unwrap();
        assert!(matches!(
            stdout_stream_target(&cli, &headers, true),
            Some(StdoutStreamTarget::Direct)
        ));

        let cli = Cli::try_parse_from([
            "fetch",
            "--format",
            "off",
            "--pager",
            "on",
            "https://example.com",
        ])
        .unwrap();
        assert!(matches!(
            stdout_stream_target(&cli, &headers, false),
            Some(StdoutStreamTarget::Pager)
        ));

        let cli = Cli::try_parse_from(["fetch", "--format", "on", "https://example.com"]).unwrap();
        assert!(stdout_stream_target(&cli, &headers, false).is_none());

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("image/png"));
        let cli = Cli::try_parse_from(["fetch", "--format", "off", "https://example.com"]).unwrap();
        assert!(matches!(
            stdout_stream_target(&cli, &headers, true),
            Some(StdoutStreamTarget::Direct)
        ));
    }
}
