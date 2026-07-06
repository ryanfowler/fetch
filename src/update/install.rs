use std::path::{Path, PathBuf};

#[cfg(windows)]
use std::process::Command;
#[cfg(windows)]
use std::time::Duration;

use super::unique_suffix;
use crate::error::FetchError;

#[cfg(any(windows, test))]
const RELOCATED_SUFFIX: &str = ".__relocated.exe";
#[cfg(any(windows, test))]
const SELF_DELETE_SUFFIX: &str = ".__selfdelete.exe";
#[cfg(any(windows, test))]
const TEMP_EXE_SUFFIX: &str = ".__temp.exe";
#[cfg(windows)]
const SELF_DELETE_ENV: &str = "FETCH_INTERNAL_UPDATE_SELF_DELETE";

#[cfg(windows)]
pub fn maybe_run_self_delete_helper() -> Option<i32> {
    let data = std::env::var(SELF_DELETE_ENV).ok()?;
    let exe_path = std::env::current_exe().ok()?;
    if !path_has_suffix(&exe_path, SELF_DELETE_SUFFIX) {
        return None;
    }

    match run_self_delete_helper(&data) {
        Ok(()) => Some(0),
        Err(_) => Some(1),
    }
}

#[cfg(not(windows))]
pub fn maybe_run_self_delete_helper() -> Option<i32> {
    None
}

pub(super) struct UpdateTempDir {
    path: PathBuf,
}

impl UpdateTempDir {
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for UpdateTempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

pub(super) fn create_update_temp_dir() -> Result<UpdateTempDir, FetchError> {
    let base = std::env::temp_dir();
    for _ in 0..100 {
        let path = base.join(format!("fetch-update-{}", unique_suffix()));
        match create_private_dir(&path) {
            Ok(()) => return Ok(UpdateTempDir { path }),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        }
    }

    Err(FetchError::Message(
        "unable to create unique temporary update directory".to_string(),
    ))
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    std::fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir(path)
}

#[cfg(windows)]
pub(super) fn self_replace(exe_path: &Path, new_exe_path: &Path) -> Result<(), FetchError> {
    let dir = exe_path.parent().unwrap_or_else(|| Path::new("."));
    let temp_exe_path = copy_file_to_new_temp(dir, TEMP_EXE_SUFFIX, new_exe_path)?;

    let old_exe_path = match rename_to_unique_temp(exe_path, dir, RELOCATED_SUFFIX) {
        Ok(path) => path,
        Err(err) => {
            let _ = std::fs::remove_file(&temp_exe_path);
            return Err(err);
        }
    };

    if let Err(err) = std::fs::rename(&temp_exe_path, exe_path) {
        return match std::fs::rename(&old_exe_path, exe_path) {
            Ok(()) => Err(err.into()),
            Err(rollback_err) => Err(FetchError::Message(format!(
                "{err}; rollback failed: {rollback_err}"
            ))),
        };
    }

    schedule_self_deletion_on_shutdown(&old_exe_path)
}

#[cfg(not(windows))]
pub(super) fn self_replace(exe_path: &Path, new_exe_path: &Path) -> Result<(), FetchError> {
    let dir = exe_path.parent().unwrap_or_else(|| Path::new("."));
    let temp_path = copy_file_to_new_temp(dir, ".__temp", new_exe_path)?;

    if let Err(err) = crate::fileutil::atomic_replace_file(&temp_path, exe_path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(err.into());
    }

    Ok(())
}

fn create_temp_file_path(dir: &Path, suffix: &str) -> PathBuf {
    dir.join(format!(".fetch.{}{suffix}", unique_suffix()))
}

const TEMP_FILE_ATTEMPTS: usize = 100;

fn copy_file_to_new_temp(dir: &Path, suffix: &str, src: &Path) -> Result<PathBuf, FetchError> {
    for _ in 0..TEMP_FILE_ATTEMPTS {
        let path = create_temp_file_path(dir, suffix);
        match copy_file_exclusive(&path, src) {
            Ok(()) => return Ok(path),
            Err(FetchError::Io(err)) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                continue;
            }
            Err(err) => return Err(err),
        }
    }

    Err(FetchError::Message(
        "unable to create unique temporary update file".to_string(),
    ))
}

#[cfg(windows)]
fn rename_to_unique_temp(src: &Path, dir: &Path, suffix: &str) -> Result<PathBuf, FetchError> {
    for _ in 0..TEMP_FILE_ATTEMPTS {
        let path = create_temp_file_path(dir, suffix);
        match std::fs::rename(src, &path) {
            Ok(()) => return Ok(path),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        }
    }

    Err(FetchError::Message(
        "unable to create unique temporary update file".to_string(),
    ))
}

fn copy_file_exclusive(dst: &Path, src: &Path) -> Result<(), FetchError> {
    let metadata = std::fs::metadata(src)?;
    let mut src_file = std::fs::File::open(src)?;
    let mut dst_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dst)?;

    if let Err(err) = std::io::copy(&mut src_file, &mut dst_file) {
        let _ = std::fs::remove_file(dst);
        return Err(err.into());
    }
    if let Err(err) = dst_file.set_permissions(metadata.permissions()) {
        let _ = std::fs::remove_file(dst);
        return Err(err.into());
    }
    if let Err(err) = dst_file.sync_all() {
        let _ = std::fs::remove_file(dst);
        return Err(err.into());
    }
    Ok(())
}

#[cfg(windows)]
fn schedule_self_deletion_on_shutdown(exe_path: &Path) -> Result<(), FetchError> {
    let mut delete_path = exe_path.to_path_buf();
    let mut exe_dir = exe_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let relocated_exe_path = create_temp_file_path(&std::env::temp_dir(), RELOCATED_SUFFIX);
    if std::fs::rename(exe_path, &relocated_exe_path).is_ok() {
        delete_path = relocated_exe_path;
        exe_dir = std::env::temp_dir();
    }

    let self_delete_path = copy_file_to_new_temp(&exe_dir, SELF_DELETE_SUFFIX, &delete_path)?;

    let self_delete_handle = open_delete_on_close_handle(&self_delete_path)?;
    let duplicated_parent = duplicate_current_process_handle()?;
    let spawn_result = spawn_self_delete_helper(&self_delete_path, duplicated_parent, &delete_path);
    std::thread::sleep(Duration::from_millis(100));

    // SAFETY: handles were returned by successful Win32 handle-opening APIs.
    unsafe {
        use windows_sys::Win32::Foundation::CloseHandle;
        CloseHandle(duplicated_parent);
        CloseHandle(self_delete_handle);
    }

    spawn_result
}

#[cfg(windows)]
fn run_self_delete_helper(data: &str) -> Result<(), FetchError> {
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
    use windows_sys::Win32::Storage::FileSystem::DeleteFileW;
    use windows_sys::Win32::System::Threading::{INFINITE, WaitForSingleObject};

    let (parent_handle, original_path) = parse_self_delete_env_value(data)
        .ok_or_else(|| FetchError::Message("invalid self-delete state".to_string()))?;
    let parent_handle = parent_handle as windows_sys::Win32::Foundation::HANDLE;

    // SAFETY: parent_handle is supplied by this executable's update launcher.
    let wait_result = unsafe { WaitForSingleObject(parent_handle, INFINITE) };
    if wait_result != WAIT_OBJECT_0 {
        return Err("waiting for update parent process failed".into());
    }

    let original_wide = path_to_wide(&original_path);
    // SAFETY: original_wide is null-terminated and points to valid memory.
    let deleted = unsafe { DeleteFileW(original_wide.as_ptr()) };
    if deleted == 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    let _ = Command::new("cmd.exe")
        .args(["/c", "exit"])
        .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
        .spawn();
    Ok(())
}

#[cfg(windows)]
fn open_delete_on_close_handle(
    path: &Path,
) -> Result<windows_sys::Win32::Foundation::HANDLE, FetchError> {
    use windows_sys::Win32::Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_DELETE_ON_CLOSE, FILE_SHARE_DELETE, FILE_SHARE_READ, OPEN_EXISTING,
    };

    let path_wide = path_to_wide(path);
    let security = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };

    // SAFETY: path_wide is null-terminated and security points to a valid SECURITY_ATTRIBUTES.
    let handle = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            &security,
            OPEN_EXISTING,
            FILE_FLAG_DELETE_ON_CLOSE,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(handle)
    }
}

#[cfg(windows)]
fn duplicate_current_process_handle() -> Result<windows_sys::Win32::Foundation::HANDLE, FetchError>
{
    use windows_sys::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    // SAFETY: GetCurrentProcess returns a pseudo-handle valid in this process.
    let current = unsafe { GetCurrentProcess() };
    let mut duplicated: HANDLE = std::ptr::null_mut();
    // SAFETY: all handles refer to the current process and duplicated points to writable storage.
    let ok = unsafe {
        DuplicateHandle(
            current,
            current,
            current,
            &mut duplicated,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if ok == 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(duplicated)
    }
}

#[cfg(windows)]
fn spawn_self_delete_helper(
    self_delete_path: &Path,
    parent_handle: windows_sys::Win32::Foundation::HANDLE,
    original_path: &Path,
) -> Result<(), FetchError> {
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

    Command::new(self_delete_path)
        .env(
            SELF_DELETE_ENV,
            self_delete_env_value(parent_handle as usize, original_path),
        )
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()?;
    Ok(())
}

#[cfg(any(windows, test))]
fn self_delete_env_value(parent_handle: usize, original_path: &Path) -> String {
    format!("{parent_handle}_{}", original_path.display())
}

#[cfg(any(windows, test))]
fn parse_self_delete_env_value(value: &str) -> Option<(usize, PathBuf)> {
    let (handle, path) = value.split_once('_')?;
    let handle = handle.parse::<usize>().ok()?;
    Some((handle, PathBuf::from(path)))
}

#[cfg(any(windows, test))]
fn path_has_suffix(path: &Path, suffix: &str) -> bool {
    path.to_string_lossy().ends_with(suffix)
}

#[cfg(windows)]
fn path_to_wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

pub(super) fn current_exe() -> Result<PathBuf, FetchError> {
    let path = std::env::current_exe()?;
    std::fs::canonicalize(path).map_err(Into::into)
}

#[cfg(unix)]
pub(super) fn can_replace_file(path: &Path) -> bool {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    for _ in 0..TEMP_FILE_ATTEMPTS {
        let temp_path = dir.join(format!(".fetch-update-{}", unique_suffix()));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(file) => {
                drop(file);
                return std::fs::remove_file(temp_path).is_ok();
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return false,
        }
    }

    false
}

#[cfg(not(unix))]
pub(super) fn can_replace_file(_path: &Path) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::super::archive::fetch_filename;
    use super::*;
    use std::path::{Path, PathBuf};

    #[cfg(not(windows))]
    #[test]
    fn non_windows_self_replace_keeps_unpacked_source() {
        let exe_dir = tempfile::tempdir().unwrap();
        let unpack_dir = tempfile::tempdir().unwrap();
        let exe_path = exe_dir.path().join(fetch_filename());
        let new_exe_path = unpack_dir.path().join(fetch_filename());
        std::fs::write(&exe_path, b"old executable").unwrap();
        std::fs::write(&new_exe_path, b"new executable").unwrap();

        self_replace(&exe_path, &new_exe_path).unwrap();

        assert_eq!(std::fs::read(&exe_path).unwrap(), b"new executable");
        assert_eq!(std::fs::read(&new_exe_path).unwrap(), b"new executable");
        assert!(std::fs::read_dir(exe_dir.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".fetch.")
        }));
    }

    #[test]
    fn windows_self_delete_env_value_round_trips_paths_with_underscores() {
        let path = PathBuf::from(r"C:\Program Files\fetch_cli\fetch.__relocated.exe");
        let value = self_delete_env_value(12345, &path);

        let (handle, parsed_path) = parse_self_delete_env_value(&value).unwrap();

        assert_eq!(handle, 12345);
        assert_eq!(parsed_path, path);
    }

    #[test]
    fn windows_self_delete_env_value_rejects_invalid_handle() {
        assert!(parse_self_delete_env_value("abc_C:\\fetch.exe").is_none());
        assert!(parse_self_delete_env_value("12345").is_none());
    }

    #[test]
    fn windows_temp_paths_use_go_self_replace_suffixes() {
        let dir = Path::new("C:\\fetch");

        let temp = create_temp_file_path(dir, TEMP_EXE_SUFFIX);
        let relocated = create_temp_file_path(dir, RELOCATED_SUFFIX);
        let self_delete = create_temp_file_path(dir, SELF_DELETE_SUFFIX);

        assert!(path_has_suffix(&temp, TEMP_EXE_SUFFIX));
        assert!(path_has_suffix(&relocated, RELOCATED_SUFFIX));
        assert!(path_has_suffix(&self_delete, SELF_DELETE_SUFFIX));
        assert!(
            temp.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".fetch.")
        );
    }

    #[test]
    fn update_temp_dir_is_removed_on_drop() {
        let path = {
            let dir = create_update_temp_dir().unwrap();
            let path = dir.path().to_path_buf();
            assert!(path.exists());
            path
        };

        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn update_temp_dir_is_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = create_update_temp_dir().unwrap();

        let mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn test_can_replace_file_read_only_file_writable_directory() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fetch");
        std::fs::write(&path, b"binary").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o555)).unwrap();

        assert!(can_replace_file(&path));
    }
}
