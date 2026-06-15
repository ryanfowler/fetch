use std::env;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::duration::format_go_duration;

use super::ImageError;
use super::decode::{DecodedImage, decode_image_std};
use super::orientation::orient_image;

const TEMP_IMAGE_DIR_CREATE_ATTEMPTS: u32 = 100;
const IMAGE_PATH_ARG: &str = "IMAGE_PATH";
const ADAPTOR_TIMEOUT: Duration = Duration::from_secs(10);
const ADAPTOR_STDOUT_CAP: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy)]
struct Adaptor {
    name: &'static str,
    args: &'static [&'static str],
    env: &'static [(&'static str, &'static str)],
    orientation_applied: bool,
}

const ADAPTORS: &[Adaptor] = &[
    Adaptor {
        name: "vips",
        args: &["copy", IMAGE_PATH_ARG, ".jpeg"],
        env: &[("VIPS_MAX_MEM", "512MB")],
        orientation_applied: false,
    },
    Adaptor {
        name: "magick",
        args: &[IMAGE_PATH_ARG, "-flatten", "-auto-orient", "jpeg:-"],
        env: &[("MAGICK_MEMORY_LIMIT", "512MiB")],
        orientation_applied: true,
    },
    Adaptor {
        name: "ffmpeg",
        args: &[
            "-nostdin",
            "-hide_banner",
            "-loglevel",
            "error",
            "-protocol_whitelist",
            "file,pipe",
            "-i",
            IMAGE_PATH_ARG,
            "-frames:v",
            "1",
            "-f",
            "image2pipe",
            "-vcodec",
            "mjpeg",
            "pipe:1",
        ],
        env: &[],
        orientation_applied: true,
    },
];

pub(crate) fn decode_with_adaptors(bytes: &[u8]) -> Result<DecodedImage, ImageError> {
    let dir = TempImageDir::create()?;
    let image_path = dir.path.join("fetch-temp-image");
    write_temp_image_file(&image_path, bytes)?;

    for adaptor in ADAPTORS {
        if let Ok(decoded) = decode_adaptor(&image_path, *adaptor) {
            return Ok(decoded);
        }
    }
    Err(ImageError::Message("unable to decode image".to_string()))
}

fn decode_adaptor(path: &Path, adaptor: Adaptor) -> Result<DecodedImage, ImageError> {
    let mut cmd = Command::new(adaptor.name);
    for arg in adaptor.args {
        if *arg == IMAGE_PATH_ARG {
            cmd.arg(path);
        } else {
            cmd.arg(arg);
        }
    }
    for (key, value) in adaptor.env {
        cmd.env(key, value);
    }
    let output = run_adaptor(cmd, adaptor.name)?;
    if !output.status.success() {
        return Err(ImageError::Message(format!(
            "{} exited with {}",
            adaptor.name, output.status
        )));
    }
    if output.stdout_truncated {
        return Err(ImageError::Message(format!(
            "{} produced more than {} bytes",
            adaptor.name, ADAPTOR_STDOUT_CAP
        )));
    }
    let img = decode_image_std(&output.stdout)?;
    let img = if adaptor.orientation_applied {
        img
    } else {
        orient_image(&output.stdout, img)
    };
    Ok(DecodedImage::already_oriented(img))
}

#[derive(Debug)]
struct AdaptorOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stdout_truncated: bool,
}

fn run_adaptor(cmd: Command, name: &str) -> Result<AdaptorOutput, ImageError> {
    run_adaptor_with_timeout(cmd, name, ADAPTOR_TIMEOUT)
}

fn run_adaptor_with_timeout(
    mut cmd: Command,
    name: &str,
    timeout: Duration,
) -> Result<AdaptorOutput, ImageError> {
    prepare_adaptor_command(&mut cmd);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ImageError::Message(format!("{name} stdout unavailable")))?;
    let stdout_reader = thread::spawn(move || read_capped(stdout, ADAPTOR_STDOUT_CAP));
    let deadline = Instant::now() + timeout;

    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            terminate_adaptor(&mut child);
            if stdout_reader.is_finished() {
                let _ = stdout_reader.join();
            }
            return Err(ImageError::Message(format!(
                "{name} timed out after {}",
                format_go_duration(timeout)
            )));
        }
        thread::sleep(Duration::from_millis(10));
    };

    let (stdout, stdout_truncated) = stdout_reader
        .join()
        .map_err(|_| ImageError::Message(format!("{name} stdout reader panicked")))??;
    Ok(AdaptorOutput {
        status,
        stdout,
        stdout_truncated,
    })
}

#[cfg(unix)]
fn prepare_adaptor_command(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;

    cmd.process_group(0);
}

#[cfg(not(unix))]
fn prepare_adaptor_command(_cmd: &mut Command) {}

fn terminate_adaptor(child: &mut Child) {
    kill_adaptor_process_group(child);
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
fn kill_adaptor_process_group(child: &Child) {
    if let Ok(pid) = i32::try_from(child.id()) {
        // The adapter is spawned as a process-group leader, so this also catches helpers it starts.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
}

#[cfg(not(unix))]
fn kill_adaptor_process_group(_child: &Child) {}

fn read_capped<R: Read>(mut reader: R, cap: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let mut out = Vec::new();
    let mut truncated = false;
    let mut buf = [0; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let remaining = cap.saturating_sub(out.len());
        if remaining > 0 {
            let keep = remaining.min(n);
            out.extend_from_slice(&buf[..keep]);
        }
        if n > remaining {
            truncated = true;
        }
    }
    Ok((out, truncated))
}

struct TempImageDir {
    path: PathBuf,
}

impl TempImageDir {
    fn create() -> std::io::Result<Self> {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        Self::create_with_stamp(&env::temp_dir(), stamp)
    }

    fn create_with_stamp(dir: &Path, stamp: u128) -> std::io::Result<Self> {
        let pid = std::process::id();
        for attempt in 0..TEMP_IMAGE_DIR_CREATE_ATTEMPTS {
            let path = dir.join(format!("fetch-image-{pid}-{stamp}-{attempt}"));
            match create_temp_image_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(err),
            }
        }

        Err(std::io::Error::new(
            ErrorKind::AlreadyExists,
            "unable to create unique temporary image directory",
        ))
    }
}

impl Drop for TempImageDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(unix)]
fn create_temp_image_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    std::fs::DirBuilder::new().mode(0o700).create(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn create_temp_image_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir(path)
}

#[cfg(unix)]
fn write_temp_image_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)
}

#[cfg(not(unix))]
fn write_temp_image_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[cfg(unix)]
    #[test]
    fn external_decode_temp_paths_use_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempImageDir::create().unwrap();
        let dir_mode = std::fs::metadata(&dir.path).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);

        let image_path = dir.path.join("fetch-temp-image");
        write_temp_image_file(&image_path, b"secret image bytes").unwrap();

        let file_mode = std::fs::metadata(&image_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);
        assert_eq!(std::fs::read(&image_path).unwrap(), b"secret image bytes");
    }

    #[test]
    fn external_decode_temp_dir_creation_retries_existing_candidates() {
        let root = tempfile::tempdir().unwrap();
        let stamp = 42;
        let stale = root
            .path()
            .join(format!("fetch-image-{}-{stamp}-0", std::process::id()));
        create_temp_image_dir(&stale).unwrap();

        let dir = TempImageDir::create_with_stamp(root.path(), stamp).unwrap();
        let expected = format!("fetch-image-{}-{stamp}-1", std::process::id());

        assert_eq!(
            dir.path.file_name().and_then(|name| name.to_str()),
            Some(expected.as_str())
        );
        assert!(stale.exists());
    }

    #[test]
    fn capped_reader_preserves_limit_and_drains_input() {
        let (out, truncated) = read_capped(Cursor::new(b"abcdef"), 4).unwrap();
        assert_eq!(out, b"abcd");
        assert!(truncated);

        let (out, truncated) = read_capped(Cursor::new(b"abc"), 4).unwrap();
        assert_eq!(out, b"abc");
        assert!(!truncated);
    }

    #[cfg(unix)]
    #[test]
    fn adaptor_timeout_does_not_wait_for_inherited_stdout() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 5 >&1 & sleep 5"]);
        let started_at = Instant::now();

        let err = run_adaptor_with_timeout(command, "fake-adaptor", Duration::from_millis(100))
            .unwrap_err()
            .to_string();

        assert!(err.contains("fake-adaptor timed out after"), "{err}");
        assert!(
            started_at.elapsed() < Duration::from_secs(2),
            "adapter timeout took {:?}",
            started_at.elapsed()
        );
    }
}
