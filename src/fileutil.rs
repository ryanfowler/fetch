use std::io;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::iter;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};

pub fn atomic_replace_file(
    temp_path: impl AsRef<Path>,
    target_path: impl AsRef<Path>,
) -> io::Result<()> {
    atomic_replace_file_impl(temp_path.as_ref(), target_path.as_ref())
}

pub fn atomic_write_new_file(
    temp_path: impl AsRef<Path>,
    target_path: impl AsRef<Path>,
) -> io::Result<()> {
    atomic_write_new_file_impl(temp_path.as_ref(), target_path.as_ref())
}

pub fn expand_home(path: &str) -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    expand_home_with(path, home.as_deref())
}

fn expand_home_with(path: &str, home: Option<&Path>) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = home
    {
        return home.join(rest);
    }
    PathBuf::from(path)
}

#[derive(Debug)]
pub struct FileLock {
    file: std::fs::File,
}

impl FileLock {
    pub fn try_acquire(path: impl AsRef<Path>) -> io::Result<Option<Self>> {
        let file = open_lock_file(path.as_ref())?;
        if try_lock_file(&file)? {
            Ok(Some(Self { file }))
        } else {
            Ok(None)
        }
    }

    pub fn acquire_with_timeout<E, F, G>(
        path: impl AsRef<Path>,
        timeout: Duration,
        on_contention: F,
        timeout_error: G,
    ) -> Result<Self, E>
    where
        E: From<io::Error>,
        F: FnMut(),
        G: FnOnce(Duration) -> E,
    {
        acquire_lock_with_timeout(path.as_ref(), timeout, on_contention, timeout_error)
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = unlock_file(&self.file);
    }
}

fn acquire_lock_with_timeout<E, F, G>(
    path: &Path,
    timeout: Duration,
    mut on_contention: F,
    timeout_error: G,
) -> Result<FileLock, E>
where
    E: From<io::Error>,
    F: FnMut(),
    G: FnOnce(Duration) -> E,
{
    let file = open_lock_file(path).map_err(E::from)?;
    let started_at = Instant::now();

    for attempt in 0.. {
        if try_lock_file(&file).map_err(E::from)? {
            return Ok(FileLock { file });
        }
        if started_at.elapsed() >= timeout {
            return Err(timeout_error(timeout));
        }

        if attempt == 0 {
            on_contention();
        }
        let multiplier = (attempt + 1).min(10) as u64;
        let sleep = Duration::from_millis(multiplier * 50);
        let remaining = timeout.saturating_sub(started_at.elapsed());
        thread::sleep(sleep.min(remaining));
    }

    unreachable!("file lock acquisition loop is unbounded by the iterator")
}

fn open_lock_file(path: &Path) -> io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(not(windows))]
fn atomic_replace_file_impl(temp_path: &Path, target_path: &Path) -> io::Result<()> {
    std::fs::rename(temp_path, target_path)?;
    sync_parent_dir(target_path)
}

#[cfg(windows)]
fn atomic_replace_file_impl(temp_path: &Path, target_path: &Path) -> io::Result<()> {
    move_file_ex(
        temp_path,
        target_path,
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
    )
}

#[cfg(not(windows))]
fn atomic_write_new_file_impl(temp_path: &Path, target_path: &Path) -> io::Result<()> {
    std::fs::hard_link(temp_path, target_path)?;
    sync_parent_dir(target_path)?;
    let _ = std::fs::remove_file(temp_path);
    sync_parent_dir(temp_path)
}

#[cfg(windows)]
fn atomic_write_new_file_impl(temp_path: &Path, target_path: &Path) -> io::Result<()> {
    move_file_ex(temp_path, target_path, MOVEFILE_WRITE_THROUGH)
}

#[cfg(windows)]
fn move_file_ex(temp_path: &Path, target_path: &Path, flags: u32) -> io::Result<()> {
    let src = to_wide(temp_path);
    let dst = to_wide(target_path);
    // SAFETY: the UTF-16 buffers are NUL-terminated and live for the duration
    // of the call. MoveFileExW does not retain these pointers.
    let ok = unsafe { MoveFileExW(src.as_ptr(), dst.as_ptr(), flags) };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn to_wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect()
}

#[cfg(not(windows))]
fn sync_parent_dir(path: &Path) -> io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(unix)]
fn try_lock_file(file: &std::fs::File) -> io::Result<bool> {
    use std::os::fd::AsRawFd;

    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return Ok(true);
    }

    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EWOULDBLOCK) || err.raw_os_error() == Some(libc::EAGAIN) {
        Ok(false)
    } else {
        Err(err)
    }
}

#[cfg(unix)]
fn unlock_file(file: &std::fs::File) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn try_lock_file(file: &std::fs::File) -> io::Result<bool> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION;
    use windows_sys::Win32::Storage::FileSystem::{
        LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;

    let mut overlapped = OVERLAPPED::default();
    // SAFETY: the file handle is valid for this File and overlapped points to writable storage.
    let ok = unsafe {
        LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if ok != 0 {
        return Ok(true);
    }

    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) {
        Ok(false)
    } else {
        Err(err)
    }
}

#[cfg(windows)]
fn unlock_file(file: &std::fs::File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
    use windows_sys::Win32::System::IO::OVERLAPPED;

    let mut overlapped = OVERLAPPED::default();
    // SAFETY: the file handle is valid for this File and overlapped points to writable storage.
    let ok = unsafe { UnlockFileEx(file.as_raw_handle(), 0, u32::MAX, u32::MAX, &mut overlapped) };
    if ok != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(unix, windows)))]
fn try_lock_file(_file: &std::fs::File) -> io::Result<bool> {
    Ok(true)
}

#[cfg(not(any(unix, windows)))]
fn unlock_file(_file: &std::fs::File) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_home_expands_leading_home_segment() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");

        assert_eq!(
            expand_home_with("~/fetch.conf", Some(&home)),
            home.join("fetch.conf")
        );
    }

    #[test]
    fn expand_home_leaves_other_paths_unchanged() {
        let home = Path::new("/home/me");

        assert_eq!(
            expand_home_with("~fetch.conf", Some(home)),
            PathBuf::from("~fetch.conf")
        );
        assert_eq!(
            expand_home_with("fetch.conf", Some(home)),
            PathBuf::from("fetch.conf")
        );
        assert_eq!(
            expand_home_with("~/fetch.conf", None),
            PathBuf::from("~/fetch.conf")
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn file_lock_try_acquire_returns_none_when_held() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("held.lock");
        let _held = FileLock::try_acquire(&path).unwrap().unwrap();

        assert!(FileLock::try_acquire(&path).unwrap().is_none());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn file_lock_acquire_with_timeout_returns_mapped_timeout_when_held() {
        #[derive(Debug, PartialEq, Eq)]
        enum TestError {
            Io(String),
            Timeout(Duration),
        }

        impl From<io::Error> for TestError {
            fn from(err: io::Error) -> Self {
                Self::Io(err.to_string())
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("held.lock");
        let _held = FileLock::try_acquire(&path).unwrap().unwrap();
        let started_at = Instant::now();

        let err = FileLock::acquire_with_timeout(
            &path,
            Duration::from_millis(10),
            || {},
            TestError::Timeout,
        )
        .unwrap_err();

        assert_eq!(err, TestError::Timeout(Duration::from_millis(10)));
        assert!(started_at.elapsed() < Duration::from_secs(1));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn file_lock_acquire_with_timeout_calls_contention_hook_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("held.lock");
        let _held = FileLock::try_acquire(&path).unwrap().unwrap();
        let mut contentions = 0;

        let result: Result<FileLock, io::Error> = FileLock::acquire_with_timeout(
            &path,
            Duration::from_millis(10),
            || {
                contentions += 1;
            },
            |timeout| io::Error::new(io::ErrorKind::TimedOut, format!("{timeout:?}")),
        );

        assert!(result.is_err());
        assert_eq!(contentions, 1);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn file_lock_acquire_with_timeout_waits_until_lock_is_released() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("held.lock");
        let held = FileLock::try_acquire(&path).unwrap().unwrap();
        let path_for_waiter = path.clone();
        let (tx, rx) = std::sync::mpsc::channel();

        let join = std::thread::spawn(move || {
            FileLock::acquire_with_timeout(
                path_for_waiter,
                Duration::from_secs(2),
                || {
                    let _ = tx.send(());
                },
                |timeout| io::Error::new(io::ErrorKind::TimedOut, format!("{timeout:?}")),
            )
        });

        rx.recv_timeout(Duration::from_secs(1)).unwrap();
        drop(held);
        let waited_lock = join.join().unwrap().unwrap();
        drop(waited_lock);

        assert!(FileLock::try_acquire(&path).unwrap().is_some());
    }

    #[test]
    fn test_atomic_replace_file_replaces_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let target_path = dir.path().join("target.txt");
        let temp_path = dir.path().join("temp.txt");
        std::fs::write(&target_path, b"old").unwrap();
        std::fs::write(&temp_path, b"new").unwrap();

        atomic_replace_file(&temp_path, &target_path).unwrap();

        assert_eq!(std::fs::read(&target_path).unwrap(), b"new");
        assert!(std::fs::metadata(&temp_path).is_err());
    }

    #[test]
    fn test_atomic_write_new_file_creates_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let target_path = dir.path().join("target.txt");
        let temp_path = dir.path().join("temp.txt");
        std::fs::write(&temp_path, b"new").unwrap();

        atomic_write_new_file(&temp_path, &target_path).unwrap();

        assert_eq!(std::fs::read(&target_path).unwrap(), b"new");
        assert!(std::fs::metadata(&temp_path).is_err());
    }

    #[test]
    fn test_atomic_write_new_file_does_not_replace_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let target_path = dir.path().join("target.txt");
        let temp_path = dir.path().join("temp.txt");
        std::fs::write(&target_path, b"old").unwrap();
        std::fs::write(&temp_path, b"new").unwrap();

        let err = atomic_write_new_file(&temp_path, &target_path).unwrap_err();

        assert!(matches!(
            err.kind(),
            io::ErrorKind::AlreadyExists | io::ErrorKind::PermissionDenied
        ));
        assert_eq!(std::fs::read(&target_path).unwrap(), b"old");
        assert!(std::fs::metadata(&temp_path).is_ok());
    }
}
