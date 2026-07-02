use std::io::{ErrorKind, Write};
use std::process::Stdio;

use crate::cli::{Cli, PagerMode};
use crate::core;
use crate::error::FetchError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PagerCommand {
    pub(crate) program: String,
    pub(crate) args: Vec<String>,
    pub(crate) is_fallback: bool,
}

fn should_page_text(cli: &Cli, bytes: &[u8], stdout_is_terminal: bool) -> bool {
    !bytes.is_empty()
        && match PagerMode::from_cli(cli) {
            PagerMode::Auto => stdout_is_terminal && !disabled_by_env(),
            PagerMode::On => true,
            PagerMode::Off => false,
        }
}

pub(crate) fn write_text(cli: &Cli, bytes: &[u8]) -> Result<(), FetchError> {
    if should_page_text(cli, bytes, core::stdio().stdout_is_terminal()) {
        write_bytes(bytes)
    } else {
        core::write_stdout(bytes)?;
        Ok(())
    }
}

pub(crate) fn write_bytes(bytes: &[u8]) -> Result<(), FetchError> {
    let pager = command();
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

pub(crate) fn command() -> PagerCommand {
    command_with_env(|name| std::env::var_os(name).and_then(os_string_to_string))
}

pub(crate) fn disabled_by_env() -> bool {
    std::env::var_os("NO_PAGER").is_some()
}

fn os_string_to_string(value: std::ffi::OsString) -> Option<String> {
    value.into_string().ok()
}

pub(crate) fn command_with_env<F>(mut get_env: F) -> PagerCommand
where
    F: FnMut(&str) -> Option<String>,
{
    if let Some(value) = get_env("PAGER") {
        let args = shlex::split(&value).unwrap_or_default();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pager_command_uses_pager_or_less_fallback() {
        let got = command_with_env(|_| None);
        assert_eq!(
            got,
            PagerCommand {
                program: "less".to_string(),
                args: vec!["-FIRX".to_string()],
                is_fallback: true,
            }
        );

        let got = command_with_env(|name| match name {
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

        let got = command_with_env(|name| match name {
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
    fn pager_command_uses_shlex_for_pager_environment() {
        let got = command_with_env(|name| match name {
            "PAGER" => Some(r#"less --prompt='fetch > ' --pattern=a\ b"#.to_string()),
            _ => None,
        });
        assert_eq!(
            got,
            PagerCommand {
                program: "less".to_string(),
                args: vec!["--prompt=fetch > ".to_string(), "--pattern=a b".to_string(),],
                is_fallback: false,
            }
        );
    }

    #[test]
    fn pager_command_falls_back_for_invalid_pager_environment() {
        let got = command_with_env(|name| match name {
            "PAGER" => Some(r#"less "unterminated"#.to_string()),
            _ => None,
        });
        assert_eq!(
            got,
            PagerCommand {
                program: "less".to_string(),
                args: vec!["-FIRX".to_string()],
                is_fallback: true,
            }
        );
    }
}
