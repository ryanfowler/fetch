use std::io;
use std::path::Path;

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

#[cfg(not(windows))]
fn atomic_replace_file_impl(temp_path: &Path, target_path: &Path) -> io::Result<()> {
    std::fs::rename(temp_path, target_path)
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
    let _ = std::fs::remove_file(temp_path);
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

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
