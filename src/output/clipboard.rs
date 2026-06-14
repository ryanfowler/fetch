use crate::duration::format_go_duration;

use std::env;
use std::fmt;
use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

pub const MAX_CLIPBOARD_BYTES: usize = 1024 * 1024;
const CLIPBOARD_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const CLIPBOARD_COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug, Eq, PartialEq)]
pub enum CopyOutcome {
    Copied { command: String },
    SkippedTooLarge { limit: usize },
    Unavailable,
    Failed { command: String, message: String },
}

impl fmt::Display for CopyOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Copied { .. } => Ok(()),
            Self::SkippedTooLarge { limit } => {
                write!(
                    f,
                    "response body exceeds {} bytes; not copied to clipboard",
                    limit
                )
            }
            Self::Unavailable => write!(
                f,
                "unable to copy response body to clipboard: no clipboard command found"
            ),
            Self::Failed { command, message } => write!(
                f,
                "unable to copy response body to clipboard with '{command}': {message}"
            ),
        }
    }
}

#[derive(Debug, Default)]
pub struct Capture {
    bytes: Vec<u8>,
    too_large: bool,
}

impl Capture {
    pub fn push(&mut self, bytes: &[u8]) {
        if self.too_large || bytes.is_empty() {
            return;
        }
        if self.bytes.len().saturating_add(bytes.len()) > MAX_CLIPBOARD_BYTES {
            self.bytes.clear();
            self.too_large = true;
            return;
        }
        self.bytes.extend_from_slice(bytes);
    }

    pub fn copy(self) -> CopyOutcome {
        if self.too_large {
            return CopyOutcome::SkippedTooLarge {
                limit: MAX_CLIPBOARD_BYTES,
            };
        }
        copy_bytes(&self.bytes)
    }
}

pub fn copy_bytes(bytes: &[u8]) -> CopyOutcome {
    if bytes.len() > MAX_CLIPBOARD_BYTES {
        return CopyOutcome::SkippedTooLarge {
            limit: MAX_CLIPBOARD_BYTES,
        };
    }
    let Some(command) = detect_command() else {
        return CopyOutcome::Unavailable;
    };
    write_to_command(&command, bytes)
}

#[derive(Clone, Debug)]
struct ClipboardCommand {
    program: &'static str,
    args: &'static [&'static str],
}

impl ClipboardCommand {
    fn label(&self) -> String {
        self.program.to_string()
    }
}

fn detect_command() -> Option<ClipboardCommand> {
    candidates()
        .into_iter()
        .find(|command| command_exists(command.program))
}

fn candidates() -> Vec<ClipboardCommand> {
    let mut commands = Vec::new();

    #[cfg(target_os = "macos")]
    {
        commands.push(ClipboardCommand {
            program: "pbcopy",
            args: &[],
        });
    }

    #[cfg(target_os = "linux")]
    {
        commands.push(ClipboardCommand {
            program: "wl-copy",
            args: &[],
        });
        commands.push(ClipboardCommand {
            program: "xclip",
            args: &["-selection", "clipboard"],
        });
        commands.push(ClipboardCommand {
            program: "xsel",
            args: &["--clipboard", "--input"],
        });
    }

    #[cfg(windows)]
    {
        commands.push(ClipboardCommand {
            program: "clip.exe",
            args: &[],
        });
    }

    commands
}

fn command_exists(program: &str) -> bool {
    if program.contains('/') || program.contains('\\') {
        return Path::new(program).is_file();
    }

    let Some(path) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&path).any(|dir| dir.join(program).is_file())
}

fn write_to_command(command: &ClipboardCommand, bytes: &[u8]) -> CopyOutcome {
    write_to_command_with_timeout(command, bytes, CLIPBOARD_COMMAND_TIMEOUT)
}

fn write_to_command_with_timeout(
    command: &ClipboardCommand,
    bytes: &[u8],
    timeout: Duration,
) -> CopyOutcome {
    let mut child = match Command::new(command.program)
        .args(command.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            return CopyOutcome::Failed {
                command: command.label(),
                message: err.to_string(),
            };
        }
    };

    let started_at = Instant::now();
    let write_rx = write_stdin_async(
        child
            .stdin
            .take()
            .expect("clipboard command stdin is piped"),
        bytes.to_vec(),
    );
    match wait_for_stdin_write(&write_rx, started_at, timeout) {
        Ok(()) => {}
        Err(CopyFailure::TimedOut) => {
            return timeout_child(command, &mut child, timeout);
        }
        Err(CopyFailure::Failed(message)) => {
            let _ = child.kill();
            let _ = child.wait();
            return CopyOutcome::Failed {
                command: command.label(),
                message,
            };
        }
    }

    match wait_for_child(&mut child, started_at, timeout) {
        Ok(Some(status)) if status.success() => CopyOutcome::Copied {
            command: command.label(),
        },
        Ok(Some(status)) => CopyOutcome::Failed {
            command: command.label(),
            message: format!("command exited with {status}"),
        },
        Ok(None) => timeout_child(command, &mut child, timeout),
        Err(err) => CopyOutcome::Failed {
            command: command.label(),
            message: err.to_string(),
        },
    }
}

enum CopyFailure {
    TimedOut,
    Failed(String),
}

fn write_stdin_async(
    mut stdin: std::process::ChildStdin,
    bytes: Vec<u8>,
) -> Receiver<std::io::Result<()>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(stdin.write_all(&bytes));
    });
    rx
}

fn wait_for_stdin_write(
    rx: &Receiver<std::io::Result<()>>,
    started_at: Instant,
    timeout: Duration,
) -> Result<(), CopyFailure> {
    let Some(remaining) = remaining_timeout(started_at, timeout) else {
        return Err(CopyFailure::TimedOut);
    };
    match rx.recv_timeout(remaining) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(CopyFailure::Failed(err.to_string())),
        Err(RecvTimeoutError::Timeout) => Err(CopyFailure::TimedOut),
        Err(RecvTimeoutError::Disconnected) => Err(CopyFailure::Failed(
            "clipboard stdin writer exited without reporting a result".to_string(),
        )),
    }
}

fn timeout_child(command: &ClipboardCommand, child: &mut Child, timeout: Duration) -> CopyOutcome {
    let _ = child.kill();
    let _ = child.wait();
    CopyOutcome::Failed {
        command: command.label(),
        message: format!("command timed out after {}", format_go_duration(timeout)),
    }
}

fn wait_for_child(
    child: &mut Child,
    started_at: Instant,
    timeout: Duration,
) -> std::io::Result<Option<ExitStatus>> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        let Some(remaining) = remaining_timeout(started_at, timeout) else {
            return Ok(None);
        };
        thread::sleep(CLIPBOARD_COMMAND_POLL_INTERVAL.min(remaining));
    }
}

fn remaining_timeout(started_at: Instant, timeout: Duration) -> Option<Duration> {
    timeout.checked_sub(started_at.elapsed())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn capture_skips_bodies_larger_than_limit() {
        let mut capture = Capture::default();
        capture.push(&vec![b'a'; MAX_CLIPBOARD_BYTES]);
        capture.push(b"b");

        assert_eq!(
            capture.copy(),
            CopyOutcome::SkippedTooLarge {
                limit: MAX_CLIPBOARD_BYTES
            }
        );
    }

    #[test]
    fn copy_bytes_skips_bodies_larger_than_limit_before_detection() {
        assert_eq!(
            copy_bytes(&vec![b'a'; MAX_CLIPBOARD_BYTES + 1]),
            CopyOutcome::SkippedTooLarge {
                limit: MAX_CLIPBOARD_BYTES
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_to_command_sends_bytes_to_stdin() {
        let dir = tempfile::TempDir::new().unwrap();
        let output = dir.path().join("clipboard.txt");
        let script = dir.path().join("fake-clipboard");
        std::fs::write(
            &script,
            format!("#!/bin/sh\n/bin/cat > '{}'\n", output.display()),
        )
        .unwrap();
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();

        let program = Box::leak(script.to_string_lossy().into_owned().into_boxed_str());
        let command = ClipboardCommand { program, args: &[] };

        assert_eq!(
            write_to_command(&command, b"clipboard-body"),
            CopyOutcome::Copied {
                command: script.to_string_lossy().into_owned()
            }
        );
        assert_eq!(std::fs::read(&output).unwrap(), b"clipboard-body");
    }

    #[cfg(unix)]
    #[test]
    fn write_to_command_times_out_hung_command_after_stdin() {
        static ARGS: &[&str] = &["-c", "/bin/cat >/dev/null; exec /bin/sleep 5"];
        let command = ClipboardCommand {
            program: "/bin/sh",
            args: ARGS,
        };
        let timeout = Duration::from_millis(100);
        let started_at = Instant::now();

        assert_eq!(
            write_to_command_with_timeout(&command, b"clipboard-body", timeout),
            CopyOutcome::Failed {
                command: "/bin/sh".to_string(),
                message: "command timed out after 100ms".to_string()
            }
        );
        assert!(
            started_at.elapsed() < Duration::from_secs(2),
            "clipboard command timeout took {:?}",
            started_at.elapsed()
        );
    }
}
