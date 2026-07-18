use std::env;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::mpsc;
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
}

#[derive(Debug)]
enum StdoutResult {
    Complete(std::io::Result<Vec<u8>>),
    CapExceeded,
    TimedOut,
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
    let process_group = AdaptorProcessGroup::attach(&mut child)?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ImageError::Message(format!("{name} stdout unavailable")))?;
    let deadline = Instant::now() + timeout;
    let (stdout_tx, stdout_rx) = mpsc::sync_channel(1);
    let stdout_reader = thread::spawn(move || {
        let _ = stdout_tx.send(read_capped_until(stdout, ADAPTOR_STDOUT_CAP, deadline));
    });

    let mut status = None;
    let stdout_result = loop {
        if status.is_none() {
            status = child.try_wait()?;
        }
        match stdout_rx.try_recv() {
            Ok(result) => break result,
            Err(mpsc::TryRecvError::Disconnected) => {
                let _ = stdout_reader.join();
                terminate_adaptor(&mut child, &process_group);
                return Err(ImageError::Message(format!(
                    "{name} stdout reader panicked"
                )));
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }

        let now = Instant::now();
        if now >= deadline {
            break StdoutResult::TimedOut;
        }
        thread::sleep((deadline - now).min(Duration::from_millis(10)));
    };

    match stdout_result {
        StdoutResult::Complete(stdout) => {
            let stdout = match stdout {
                Ok(stdout) => stdout,
                Err(err) => {
                    terminate_adaptor(&mut child, &process_group);
                    stdout_reader.join().map_err(|_| {
                        ImageError::Message(format!("{name} stdout reader panicked"))
                    })?;
                    return Err(err.into());
                }
            };
            while status.is_none() {
                let now = Instant::now();
                if now >= deadline {
                    terminate_adaptor(&mut child, &process_group);
                    stdout_reader.join().map_err(|_| {
                        ImageError::Message(format!("{name} stdout reader panicked"))
                    })?;
                    return Err(adaptor_timeout_error(name, timeout));
                }
                status = child.try_wait()?;
                if status.is_none() {
                    thread::sleep((deadline - now).min(Duration::from_millis(10)));
                }
            }
            stdout_reader
                .join()
                .map_err(|_| ImageError::Message(format!("{name} stdout reader panicked")))?;
            Ok(AdaptorOutput {
                status: status.expect("status was checked above"),
                stdout,
            })
        }
        StdoutResult::CapExceeded => {
            terminate_adaptor(&mut child, &process_group);
            stdout_reader
                .join()
                .map_err(|_| ImageError::Message(format!("{name} stdout reader panicked")))?;
            Err(ImageError::Message(format!(
                "{name} produced more than {ADAPTOR_STDOUT_CAP} bytes"
            )))
        }
        StdoutResult::TimedOut => {
            terminate_adaptor(&mut child, &process_group);
            stdout_reader
                .join()
                .map_err(|_| ImageError::Message(format!("{name} stdout reader panicked")))?;
            Err(adaptor_timeout_error(name, timeout))
        }
    }
}

#[cfg(unix)]
fn prepare_adaptor_command(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;

    cmd.process_group(0);
}

#[cfg(windows)]
fn prepare_adaptor_command(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;

    // Assigning the process to its job before its primary thread runs prevents
    // short-lived adapters and early helpers from escaping the job.
    cmd.creation_flags(CREATE_SUSPENDED);
}

fn adaptor_timeout_error(name: &str, timeout: Duration) -> ImageError {
    ImageError::Message(format!(
        "{name} timed out after {}",
        format_go_duration(timeout)
    ))
}

fn terminate_adaptor(child: &mut Child, process_group: &AdaptorProcessGroup) {
    process_group.terminate(child);
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
struct AdaptorProcessGroup;

#[cfg(unix)]
impl AdaptorProcessGroup {
    fn attach(_child: &mut Child) -> std::io::Result<Self> {
        Ok(Self)
    }

    fn terminate(&self, child: &Child) {
        if let Ok(pid) = i32::try_from(child.id()) {
            // The adapter is spawned as a process-group leader, so this also catches helpers it starts.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
    }
}

#[cfg(windows)]
struct AdaptorProcessGroup {
    job: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl AdaptorProcessGroup {
    fn attach(child: &mut Child) -> std::io::Result<Self> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };

        // SAFETY: all pointers are null or point to initialized values for the duration of each call.
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                std::mem::size_of_val(&info) as u32,
            ) == 0
                || AssignProcessToJobObject(job, child.as_raw_handle()) == 0
            {
                let err = std::io::Error::last_os_error();
                windows_sys::Win32::Foundation::CloseHandle(job);
                let _ = child.kill();
                let _ = child.wait();
                return Err(err);
            }
            if let Err(err) = resume_primary_thread(child.id()) {
                windows_sys::Win32::Foundation::CloseHandle(job);
                let _ = child.kill();
                let _ = child.wait();
                return Err(err);
            }
            Ok(Self { job })
        }
    }

    fn terminate(&self, _child: &Child) {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;
        // SAFETY: self.job remains valid until Drop.
        unsafe {
            TerminateJobObject(self.job, 1);
        }
    }
}

#[cfg(windows)]
fn resume_primary_thread(process_id: u32) -> std::io::Result<()> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};

    // CreateProcess has completed, but CREATE_SUSPENDED guarantees that the
    // process still has only its primary thread and has not executed user code.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }

        let mut entry = THREADENTRY32::default();
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        let mut found = Thread32First(snapshot, &mut entry) != 0;
        while found {
            if entry.th32OwnerProcessID == process_id {
                let thread = OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID);
                if thread.is_null() {
                    let err = std::io::Error::last_os_error();
                    CloseHandle(snapshot);
                    return Err(err);
                }
                let resumed = ResumeThread(thread);
                let err = if resumed == u32::MAX {
                    Some(std::io::Error::last_os_error())
                } else {
                    None
                };
                CloseHandle(thread);
                CloseHandle(snapshot);
                return err.map_or(Ok(()), Err);
            }
            found = Thread32Next(snapshot, &mut entry) != 0;
        }

        CloseHandle(snapshot);
        Err(std::io::Error::new(
            ErrorKind::NotFound,
            "unable to find suspended adapter thread",
        ))
    }
}

#[cfg(windows)]
impl Drop for AdaptorProcessGroup {
    fn drop(&mut self) {
        // Closing a kill-on-close job also removes any helpers left after the adapter exits.
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.job);
        }
    }
}

#[cfg(unix)]
fn read_capped_until(mut reader: ChildStdout, cap: usize, deadline: Instant) -> StdoutResult {
    use std::os::fd::AsRawFd;

    let fd = reader.as_raw_fd();
    // SAFETY: fd is owned by reader and stays valid for the duration of this function.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return StdoutResult::Complete(Err(std::io::Error::last_os_error()));
    }
    read_capped_polling(
        |buf| reader.read(buf),
        cap,
        deadline,
        |err| err.kind() == ErrorKind::WouldBlock,
    )
}

#[cfg(windows)]
fn read_capped_until(mut reader: ChildStdout, cap: usize, deadline: Instant) -> StdoutResult {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{ERROR_BROKEN_PIPE, ERROR_HANDLE_EOF, GetLastError};
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;

    let handle = reader.as_raw_handle();
    read_capped_polling(
        |buf| {
            let mut available = 0_u32;
            // SAFETY: handle is the live child stdout pipe and output pointers are valid.
            let ok = unsafe {
                PeekNamedPipe(
                    handle,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut available,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                // SAFETY: reads the thread-local error from PeekNamedPipe.
                return match unsafe { GetLastError() } {
                    ERROR_BROKEN_PIPE | ERROR_HANDLE_EOF => Ok(0),
                    _ => Err(std::io::Error::last_os_error()),
                };
            }
            if available == 0 {
                return Err(std::io::Error::from(ErrorKind::WouldBlock));
            }
            let read_len = buf.len().min(available as usize);
            reader.read(&mut buf[..read_len])
        },
        cap,
        deadline,
        |err| err.kind() == ErrorKind::WouldBlock,
    )
}

fn read_capped_polling<F, W>(
    mut read: F,
    cap: usize,
    deadline: Instant,
    would_block: W,
) -> StdoutResult
where
    F: FnMut(&mut [u8]) -> std::io::Result<usize>,
    W: Fn(&std::io::Error) -> bool,
{
    let mut out = Vec::new();
    let mut buf = [0; 8192];
    loop {
        if Instant::now() >= deadline {
            return StdoutResult::TimedOut;
        }
        match read(&mut buf) {
            Ok(0) => return StdoutResult::Complete(Ok(out)),
            Ok(n) => {
                let remaining = cap.saturating_sub(out.len());
                if n > remaining {
                    return StdoutResult::CapExceeded;
                }
                out.extend_from_slice(&buf[..n]);
            }
            Err(err) if would_block(&err) => thread::sleep(Duration::from_millis(5)),
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            Err(err) => return StdoutResult::Complete(Err(err)),
        }
    }
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
    fn capped_reader_stops_immediately() {
        let mut first_read = true;
        let result = read_capped_polling(
            |buf| {
                assert!(first_read, "reader was drained after exceeding the cap");
                first_read = false;
                buf[..6].copy_from_slice(b"abcdef");
                Ok(6)
            },
            4,
            Instant::now() + Duration::from_secs(1),
            |_| false,
        );
        assert!(matches!(result, StdoutResult::CapExceeded));
    }

    #[cfg(unix)]
    #[test]
    fn adaptor_timeout_does_not_wait_for_inherited_stdout() {
        let mut command = Command::new("/bin/sh");
        // The shell exits immediately while its descendant keeps stdout open.
        command.args(["-c", "sleep 5 >&1 &"]);
        assert_adapter_times_out_promptly(command);
    }

    #[cfg(windows)]
    #[test]
    fn adaptor_job_catches_immediate_stdout_inheriting_child() {
        let mut command = Command::new("cmd");
        // `start /B` launches ping asynchronously with the shell's stdout handle.
        command.args([
            "/D",
            "/S",
            "/C",
            "start \"\" /B ping -n 6 127.0.0.1 & exit /B 0",
        ]);
        assert_adapter_times_out_promptly(command);
    }

    #[cfg(any(unix, windows))]
    fn assert_adapter_times_out_promptly(command: Command) {
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
