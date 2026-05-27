use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use flate2::read::GzDecoder;
use futures_util::StreamExt;
use reqwest::header::{ACCEPT, USER_AGENT};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::cli::Cli;
use crate::core;
use crate::error::{FetchError, write_warning_with_color};
use crate::output::progress::{self, BarCounter, ProgressPrinter, SpinnerCounter};

#[cfg(any(windows, test))]
const RELOCATED_SUFFIX: &str = ".__relocated.exe";
#[cfg(any(windows, test))]
const SELF_DELETE_SUFFIX: &str = ".__selfdelete.exe";
#[cfg(any(windows, test))]
const TEMP_EXE_SUFFIX: &str = ".__temp.exe";
#[cfg(windows)]
const SELF_DELETE_ENV: &str = "FETCH_INTERNAL_UPDATE_SELF_DELETE";
const MAX_UPDATE_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_UPDATE_CHECKSUM_BYTES: u64 = 1024;

#[derive(Debug, Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<Asset>,
}

#[derive(Debug, Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

#[derive(Debug, PartialEq, Eq)]
struct ReleaseArtifact<'a> {
    archive_name: &'a str,
    archive_url: &'a str,
    checksum_url: &'a str,
}

pub async fn execute(cli: &Cli) -> Result<i32, FetchError> {
    let timeout = cli
        .timeout
        .map(|seconds| crate::duration::duration_from_seconds("timeout", seconds))
        .transpose()?;
    let mut builder = reqwest::Client::builder().use_rustls_tls();
    if let Some(timeout) = timeout {
        builder = builder.timeout(timeout);
    }
    let client = builder.build()?;

    let cache_dir = cache_dir()?;
    let _lock = acquire_update_lock(&cache_dir, true, cli.silent, cli.color.as_deref())?
        .ok_or_else(|| FetchError::Message("unable to acquire update lock".to_string()))?;
    let result = update_inner(&client, cli.silent, cli.dry_run).await;
    record_last_attempt_time(&cache_dir);
    result?;
    Ok(0)
}

pub fn maybe_spawn_auto_update(value: &str) {
    let Some(interval) = parse_auto_update_interval(value) else {
        return;
    };
    if should_attempt_update(interval).is_ok_and(|ok| !ok) {
        return;
    }

    let Ok(path) = current_exe() else {
        return;
    };
    let mut command = Command::new(path);
    command
        .args(["--update", "--timeout=300", "--silent"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if std::env::var_os("FETCH_INTERNAL_SYNC_AUTO_UPDATE").is_some() {
        let _ = command.status();
    } else {
        let _ = command.spawn();
    }
}

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

async fn update_inner(
    client: &reqwest::Client,
    silent: bool,
    dry_run: bool,
) -> Result<(), FetchError> {
    let exe_path = current_exe()?;
    if !can_replace_file(&exe_path) {
        return Err(format!(
            "the current process does not have write permission to '{}'",
            exe_path.display()
        )
        .into());
    }
    let version = core::version();

    write_msg(silent, "Fetching latest release...\n");
    let latest = latest_release(client).await?;

    if latest.tag_name == version {
        if !silent {
            eprintln!("Already using the latest version ({}).", latest.tag_name);
        }
        return Ok(());
    }

    if dry_run {
        if !silent {
            eprintln!("Update available: {version} -> {}", latest.tag_name);
        }
        return Ok(());
    }

    let release_artifact = release_artifact(&latest).ok_or_else(|| {
        FetchError::Message(format!(
            "no release artifact and checksum found for {}/{}",
            goos(),
            goarch()
        ))
    })?;
    if !silent {
        eprintln!("Downloading {}\n", latest.tag_name);
    }

    let artifact = download_artifact(client, release_artifact.archive_url, silent).await?;
    let checksum = download_checksum(client, release_artifact.checksum_url).await?;
    verify_artifact_checksum(release_artifact.archive_name, &artifact, &checksum)?;

    let temp_dir = std::env::temp_dir().join(format!("fetch-update-{}", unique_suffix()));
    std::fs::create_dir_all(&temp_dir)?;
    let unpack_result = unpack_artifact(&temp_dir, release_artifact.archive_name, &artifact);
    if let Err(err) = unpack_result {
        let _ = std::fs::remove_dir_all(&temp_dir);
        return Err(err);
    }

    let src = temp_dir.join(fetch_filename());
    let replace_result = self_replace(&exe_path, &src);
    let _ = std::fs::remove_dir_all(&temp_dir);
    replace_result?;

    write_update_success(silent, version, &latest.tag_name);
    Ok(())
}

async fn latest_release(client: &reqwest::Client) -> Result<Release, FetchError> {
    let url = format!(
        "{}/repos/ryanfowler/fetch/releases/latest",
        update_url().trim_end_matches('/')
    );
    let response = update_get(client, url).send().await?;
    if !response.status().is_success() {
        return Err(format!(
            "unable to fetch the latest release: received status: {}",
            response.status().as_u16()
        )
        .into());
    }
    let release: Release = response
        .json()
        .await
        .map_err(|err| FetchError::Message(format!("unable to fetch the latest release: {err}")))?;
    if release.tag_name.is_empty() {
        return Err("unable to fetch the latest release: no tag found".into());
    }
    Ok(release)
}

async fn download_artifact(
    client: &reqwest::Client,
    artifact_url: &str,
    silent: bool,
) -> Result<Vec<u8>, FetchError> {
    download_artifact_with_limit(client, artifact_url, silent, MAX_UPDATE_ARTIFACT_BYTES).await
}

async fn download_artifact_with_limit(
    client: &reqwest::Client,
    artifact_url: &str,
    silent: bool,
    max_artifact_bytes: u64,
) -> Result<Vec<u8>, FetchError> {
    let response = update_get(client, artifact_url).send().await?;
    if !response.status().is_success() {
        return Err(format!(
            "fetching artifact: downloading artifact: received status: {}",
            response.status().as_u16()
        )
        .into());
    }

    if let Some(len) = response.content_length()
        && len > max_artifact_bytes
    {
        return Err(format!("update artifact is too large: {len} bytes").into());
    }

    let content_length = response
        .content_length()
        .and_then(|value| i64::try_from(value).ok())
        .unwrap_or(-1);
    let mut progress = UpdateDownloadProgress::maybe_start(silent, content_length);
    let capacity = response
        .content_length()
        .unwrap_or(0)
        .min(max_artifact_bytes) as usize;
    let mut artifact = Vec::with_capacity(capacity);

    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(err) => {
                progress.finish();
                return Err(err.into());
            }
        };
        if artifact.len().saturating_add(chunk.len()) > max_artifact_bytes as usize {
            progress.finish();
            return Err("update artifact exceeded maximum allowed size".into());
        }
        progress.add(chunk.len());
        artifact.extend_from_slice(&chunk);
    }
    progress.finish();

    Ok(artifact)
}

async fn download_checksum(
    client: &reqwest::Client,
    checksum_url: &str,
) -> Result<String, FetchError> {
    let response = update_get(client, checksum_url).send().await?;
    if !response.status().is_success() {
        return Err(format!(
            "fetching artifact checksum: received status: {}",
            response.status().as_u16()
        )
        .into());
    }

    if let Some(len) = response.content_length()
        && len > MAX_UPDATE_CHECKSUM_BYTES
    {
        return Err(format!("update artifact checksum is too large: {len} bytes").into());
    }

    let mut checksum = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if checksum.len().saturating_add(chunk.len()) > MAX_UPDATE_CHECKSUM_BYTES as usize {
            return Err("update artifact checksum exceeded maximum allowed size".into());
        }
        checksum.extend_from_slice(&chunk);
    }

    let checksum = String::from_utf8(checksum).map_err(|_| {
        FetchError::Message("update artifact checksum is not valid UTF-8".to_string())
    })?;
    parse_sha256_checksum(&checksum)
}

fn parse_sha256_checksum(contents: &str) -> Result<String, FetchError> {
    let digest: String = contents.trim_start().chars().take(64).collect();
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("update artifact checksum does not start with a SHA-256 digest".into());
    }
    Ok(digest.to_ascii_lowercase())
}

fn verify_artifact_checksum(
    artifact_name: &str,
    artifact: &[u8],
    expected: &str,
) -> Result<(), FetchError> {
    let actual = sha256_hex(artifact);
    if actual != expected {
        return Err(FetchError::Message(format!(
            "update artifact checksum mismatch for {artifact_name}: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex_encode(&digest)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn update_get(client: &reqwest::Client, url: impl reqwest::IntoUrl) -> reqwest::RequestBuilder {
    client
        .get(url)
        .header(USER_AGENT, core::user_agent())
        .header(ACCEPT, core::DEFAULT_ACCEPT_HEADER)
}

enum UpdateDownloadProgress {
    Bar {
        counter: BarCounter,
        printer: ProgressPrinter,
    },
    Spinner {
        counter: SpinnerCounter,
        printer: ProgressPrinter,
    },
    None,
}

impl UpdateDownloadProgress {
    fn maybe_start(silent: bool, content_length: i64) -> Self {
        if silent || !core::stdio().stderr_is_terminal() {
            return Self::None;
        }
        Self::new_for_terminal(ProgressPrinter::stderr_with_color(false), content_length)
    }

    fn new_for_terminal(printer: ProgressPrinter, content_length: i64) -> Self {
        if content_length > 0 {
            Self::Bar {
                counter: BarCounter::new(printer.clone(), content_length),
                printer,
            }
        } else {
            Self::Spinner {
                counter: SpinnerCounter::new(printer.clone()),
                printer,
            }
        }
    }

    fn add(&self, bytes: usize) {
        match self {
            Self::Bar { counter, .. } => counter.add(bytes as i64),
            Self::Spinner { counter, .. } => counter.add(bytes as i64),
            Self::None => {}
        }
    }

    fn finish(&mut self) {
        match self {
            Self::Bar { counter, printer } => {
                counter.stop();
                progress::clear_line(printer, 60);
            }
            Self::Spinner { counter, printer } => {
                counter.stop();
                progress::clear_line(printer, 40);
            }
            Self::None => {}
        }
    }
}

fn release_artifact(release: &Release) -> Option<ReleaseArtifact<'_>> {
    release_artifact_for_platform(release, goos(), goarch())
}

fn release_artifact_for_platform<'a>(
    release: &'a Release,
    goos: &str,
    goarch: &str,
) -> Option<ReleaseArtifact<'a>> {
    let want = format!(
        "fetch-{}-{}-{}.{}",
        release.tag_name,
        goos,
        goarch,
        artifact_suffix_for_goos(goos)
    );
    let archive = release.assets.iter().find(|asset| asset.name == want)?;
    let checksum_name = format!("{want}.sha256");
    let checksum = release
        .assets
        .iter()
        .find(|asset| asset.name == checksum_name)?;
    Some(ReleaseArtifact {
        archive_name: archive.name.as_str(),
        archive_url: archive.browser_download_url.as_str(),
        checksum_url: checksum.browser_download_url.as_str(),
    })
}

fn unpack_artifact(dir: &Path, archive_name: &str, data: &[u8]) -> Result<(), FetchError> {
    if archive_name.ends_with(".zip") {
        unpack_zip_artifact(dir, data)
    } else if archive_name.ends_with(".tar.gz") || archive_name.ends_with(".tgz") {
        unpack_tar_gz_artifact(dir, data)
    } else {
        Err(format!("unsupported self-update archive format: {archive_name}").into())
    }
}

fn unpack_tar_gz_artifact(dir: &Path, data: &[u8]) -> Result<(), FetchError> {
    let decoder = GzDecoder::new(data);
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().into_owned();
        let out = dir.join(safe_archive_path(&path)?);
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if entry.header().entry_type().is_dir() {
            std::fs::create_dir_all(&out)?;
            continue;
        }
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let mut file = std::fs::File::create(&out)?;
        std::io::copy(&mut entry, &mut file)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = entry.header().mode().unwrap_or(0o755);
            std::fs::set_permissions(&out, std::fs::Permissions::from_mode(mode))?;
        }
    }
    Ok(())
}

fn unpack_zip_artifact(dir: &Path, data: &[u8]) -> Result<(), FetchError> {
    let reader = std::io::Cursor::new(data);
    let mut archive =
        zip::ZipArchive::new(reader).map_err(|err| FetchError::Message(format!("zip: {err}")))?;

    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|err| FetchError::Message(format!("zip: {err}")))?;
        let out = dir.join(safe_archive_path(file.name())?);

        if file.is_dir() {
            std::fs::create_dir_all(&out)?;
            continue;
        }
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut out_file = std::fs::File::create(&out)?;
        std::io::copy(&mut file, &mut out_file)?;

        #[cfg(unix)]
        if let Some(mode) = file.unix_mode() {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&out, std::fs::Permissions::from_mode(mode & 0o777))?;
        }
    }

    Ok(())
}

fn safe_archive_path(name: &str) -> Result<PathBuf, FetchError> {
    if name.is_empty()
        || name.starts_with('/')
        || name.starts_with('\\')
        || has_windows_drive_prefix(name)
    {
        return Err(format!("refusing to unpack unsafe path '{name}'").into());
    }

    let mut out = PathBuf::new();
    for component in name.split(['/', '\\']) {
        match component {
            "" | "." => {}
            ".." => return Err(format!("refusing to unpack unsafe path '{name}'").into()),
            value => out.push(value),
        }
    }

    if out.as_os_str().is_empty() {
        return Err(format!("refusing to unpack unsafe path '{name}'").into());
    }
    Ok(out)
}

fn has_windows_drive_prefix(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic()
}

#[cfg(windows)]
fn self_replace(exe_path: &Path, new_exe_path: &Path) -> Result<(), FetchError> {
    let dir = exe_path.parent().unwrap_or_else(|| Path::new("."));
    let temp_exe_path = create_temp_file_path(dir, TEMP_EXE_SUFFIX);
    copy_file(&temp_exe_path, new_exe_path)?;

    let old_exe_path = create_temp_file_path(dir, RELOCATED_SUFFIX);
    std::fs::rename(exe_path, &old_exe_path).map_err(|err| {
        let _ = std::fs::remove_file(&temp_exe_path);
        FetchError::from(err)
    })?;

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
fn self_replace(exe_path: &Path, new_exe_path: &Path) -> Result<(), FetchError> {
    let dir = exe_path.parent().unwrap_or_else(|| Path::new("."));
    let temp_path = create_temp_file_path(dir, ".__temp");
    if let Err(err) = copy_file(&temp_path, new_exe_path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(err);
    }

    if let Err(err) = crate::fileutil::atomic_replace_file(&temp_path, exe_path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(err.into());
    }

    Ok(())
}

fn create_temp_file_path(dir: &Path, suffix: &str) -> PathBuf {
    dir.join(format!(".fetch.{}{suffix}", unique_suffix()))
}

fn copy_file(dst: &Path, src: &Path) -> Result<(), FetchError> {
    let metadata = std::fs::metadata(src)?;
    std::fs::copy(src, dst)?;
    std::fs::set_permissions(dst, metadata.permissions())?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dst)?;
    file.sync_all()?;
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

    let self_delete_path = create_temp_file_path(&exe_dir, SELF_DELETE_SUFFIX);
    copy_file(&self_delete_path, &delete_path)?;

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

fn write_update_success(silent: bool, old_version: &str, new_version: &str) {
    if silent {
        return;
    }
    eprintln!("Updated fetch: {old_version} -> {new_version}");

    let compare_ref = changelog_compare_ref(old_version);
    if !compare_ref.is_empty() {
        eprintln!(
            "\nChangelog: https://github.com/ryanfowler/fetch/compare/{compare_ref}...{new_version}"
        );
    }
}

fn write_msg(silent: bool, message: &str) {
    if !silent {
        eprint!("{message}");
    }
}

fn current_exe() -> Result<PathBuf, FetchError> {
    let path = std::env::current_exe()?;
    std::fs::canonicalize(path).map_err(Into::into)
}

fn update_url() -> String {
    std::env::var("FETCH_INTERNAL_UPDATE_URL")
        .unwrap_or_else(|_| "https://api.github.com".to_string())
}

fn fetch_filename() -> &'static str {
    if cfg!(windows) { "fetch.exe" } else { "fetch" }
}

fn artifact_suffix_for_goos(goos: &str) -> &'static str {
    match goos {
        "windows" => "zip",
        _ => "tar.gz",
    }
}

fn goos() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "freebsd") {
        "freebsd"
    } else if cfg!(target_os = "openbsd") {
        "openbsd"
    } else if cfg!(target_os = "netbsd") {
        "netbsd"
    } else {
        std::env::consts::OS
    }
}

fn goarch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "x86" => "386",
        "aarch64" => "arm64",
        "arm" => "arm",
        "riscv64" => "riscv64",
        "powerpc64" => "ppc64",
        "powerpc64le" => "ppc64le",
        "s390x" => "s390x",
        arch => arch,
    }
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("{}-{nanos}", std::process::id())
}

fn parse_auto_update_interval(value: &str) -> Option<Duration> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    match value {
        "false" | "FALSE" | "False" | "f" | "F" | "0" | "off" | "no" | "never" => return None,
        "true" | "TRUE" | "True" | "t" | "T" | "1" | "on" | "yes" => {
            return Some(Duration::from_secs(24 * 60 * 60));
        }
        "0s" | "0sec" | "0secs" | "0m" => return Some(Duration::ZERO),
        _ => {}
    }

    crate::duration::parse_duration_interval(value)
}

fn changelog_compare_ref(old_version: &str) -> String {
    if is_version_tag(old_version) {
        old_version.to_string()
    } else {
        vcs_revision().unwrap_or_default()
    }
}

fn is_version_tag(value: &str) -> bool {
    if value.len() < 6 || !value.starts_with('v') {
        return false;
    }

    let mut dots = 0;
    let bytes = value.as_bytes();
    for i in 1..bytes.len() {
        match bytes[i] {
            b'.' => {
                if i == 1 || i == bytes.len() - 1 || bytes[i - 1] == b'.' {
                    return false;
                }
                dots += 1;
            }
            b'0'..=b'9' => {}
            _ => return false,
        }
    }
    dots == 2
}

fn vcs_revision() -> Option<String> {
    option_env!("FETCH_VCS_REVISION").and_then(|value| {
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    })
}

#[derive(Debug, Serialize, Deserialize)]
struct Metadata {
    last_attempt_at: String,
}

fn record_last_attempt_time(dir: &Path) {
    let _ = update_last_attempt_time(dir, SystemTime::now());
}

fn should_attempt_update(interval: Duration) -> Result<bool, FetchError> {
    let dir = cache_dir()?;
    should_attempt_update_in(&dir, interval)
}

fn should_attempt_update_in(dir: &Path, interval: Duration) -> Result<bool, FetchError> {
    let Some(_lock) = acquire_update_lock(dir, false, true, None)? else {
        return Ok(false);
    };
    let path = dir.join("metadata.json");
    let data = match std::fs::read(&path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(err) => return Err(err.into()),
    };

    let metadata: Metadata = match serde_json::from_slice(&data) {
        Ok(metadata) => metadata,
        Err(_) => return Ok(true),
    };
    let last_attempt_at = match OffsetDateTime::parse(&metadata.last_attempt_at, &Rfc3339) {
        Ok(value) => value,
        Err(_) => return Ok(true),
    };
    let now = OffsetDateTime::now_utc();
    let elapsed = (now - last_attempt_at).try_into().unwrap_or(Duration::ZERO);
    Ok(elapsed > interval)
}

fn cache_dir() -> Result<PathBuf, FetchError> {
    let base = user_cache_dir().ok_or_else(|| {
        FetchError::Message("unable to determine user cache directory".to_string())
    })?;
    let dir = base.join("fetch");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn user_cache_dir() -> Option<PathBuf> {
    if cfg!(target_os = "windows") {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join("Library").join("Caches"))
    } else if let Some(cache) = std::env::var_os("XDG_CACHE_HOME") {
        Some(PathBuf::from(cache))
    } else {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache"))
    }
}

fn update_last_attempt_time(dir: &Path, now: SystemTime) -> Result<(), FetchError> {
    let timestamp = OffsetDateTime::from(now)
        .to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(|err| FetchError::Message(err.to_string()))?;
    let data = serde_json::to_vec(&Metadata {
        last_attempt_at: timestamp,
    })
    .map_err(|err| FetchError::Message(err.to_string()))?;

    std::fs::create_dir_all(dir)?;
    let path = dir.join("metadata.json");
    let tmp = dir.join(format!(".metadata-{}.tmp", unique_suffix()));
    std::fs::write(&tmp, data)?;
    if let Err(err) = crate::fileutil::atomic_replace_file(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err.into());
    }
    Ok(())
}

struct UpdateLock {
    file: std::fs::File,
}

impl Drop for UpdateLock {
    fn drop(&mut self) {
        let _ = unlock_file(&self.file);
    }
}

fn acquire_update_lock(
    dir: &Path,
    block: bool,
    silent: bool,
    color: Option<&str>,
) -> Result<Option<UpdateLock>, FetchError> {
    std::fs::create_dir_all(dir)?;
    let file = open_lock_file(&dir.join(".update-lock"))?;

    for attempt in 0.. {
        if try_lock_file(&file)? {
            return Ok(Some(UpdateLock { file }));
        }
        if !block {
            return Ok(None);
        }

        if attempt == 0 && !silent {
            write_warning_with_color("waiting on lock to begin updating", color);
        }
        let multiplier = (attempt + 1).min(10) as u64;
        thread::sleep(Duration::from_millis(multiplier * 50));
    }

    unreachable!("update lock acquisition loop is unbounded")
}

fn open_lock_file(path: &Path) -> Result<std::fs::File, FetchError> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

#[cfg(unix)]
fn try_lock_file(file: &std::fs::File) -> Result<bool, FetchError> {
    use std::os::fd::AsRawFd;

    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return Ok(true);
    }

    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EWOULDBLOCK) || err.raw_os_error() == Some(libc::EAGAIN) {
        Ok(false)
    } else {
        Err(err.into())
    }
}

#[cfg(unix)]
fn unlock_file(file: &std::fs::File) -> Result<(), FetchError> {
    use std::os::fd::AsRawFd;

    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

#[cfg(windows)]
fn try_lock_file(file: &std::fs::File) -> Result<bool, FetchError> {
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

    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) {
        Ok(false)
    } else {
        Err(err.into())
    }
}

#[cfg(windows)]
fn unlock_file(file: &std::fs::File) -> Result<(), FetchError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
    use windows_sys::Win32::System::IO::OVERLAPPED;

    let mut overlapped = OVERLAPPED::default();
    // SAFETY: the file handle is valid for this File and overlapped points to writable storage.
    let ok = unsafe { UnlockFileEx(file.as_raw_handle(), 0, u32::MAX, u32::MAX, &mut overlapped) };
    if ok != 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

#[cfg(not(any(unix, windows)))]
fn try_lock_file(_file: &std::fs::File) -> Result<bool, FetchError> {
    Ok(true)
}

#[cfg(not(any(unix, windows)))]
fn unlock_file(_file: &std::fs::File) -> Result<(), FetchError> {
    Ok(())
}

#[cfg(unix)]
fn can_replace_file(path: &Path) -> bool {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let temp_path = dir.join(format!(".fetch-update-{}", unique_suffix()));
    match std::fs::File::create(&temp_path) {
        Ok(file) => {
            drop(file);
            std::fs::remove_file(temp_path).is_ok()
        }
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn can_replace_file(_path: &Path) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::{BufRead, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use tar::{Builder, Header};

    #[derive(Clone)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn memory_printer() -> (ProgressPrinter, Arc<Mutex<Vec<u8>>>) {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        (
            ProgressPrinter::new(SharedBuffer(buffer.clone()), false),
            buffer,
        )
    }

    fn start_artifact_response(
        headers: Vec<(&'static str, String)>,
        chunks: Vec<Vec<u8>>,
    ) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let join = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                    break;
                }
            }

            write!(stream, "HTTP/1.1 200 OK\r\nConnection: close\r\n").unwrap();
            for (name, value) in headers {
                write!(stream, "{name}: {value}\r\n").unwrap();
            }
            write!(stream, "\r\n").unwrap();
            for chunk in chunks {
                stream.write_all(&chunk).unwrap();
            }
        });
        (url, join)
    }

    #[test]
    fn update_requests_use_go_client_headers() {
        let client = reqwest::Client::builder().use_rustls_tls().build().unwrap();

        let request = update_get(
            &client,
            "https://api.github.com/repos/ryanfowler/fetch/releases/latest",
        )
        .build()
        .unwrap();

        assert_eq!(
            request
                .headers()
                .get(USER_AGENT)
                .and_then(|v| v.to_str().ok()),
            Some(core::user_agent().as_str())
        );
        assert_eq!(
            request.headers().get(ACCEPT).and_then(|v| v.to_str().ok()),
            Some(core::DEFAULT_ACCEPT_HEADER)
        );
    }

    #[tokio::test]
    async fn download_artifact_rejects_content_length_above_limit() {
        let (url, join) =
            start_artifact_response(vec![("Content-Length", "11".to_string())], Vec::new());
        let client = reqwest::Client::builder().use_rustls_tls().build().unwrap();

        let err = download_artifact_with_limit(&client, &url, true, 10)
            .await
            .unwrap_err();
        join.join().unwrap();

        assert!(
            err.to_string()
                .contains("update artifact is too large: 11 bytes")
        );
    }

    #[tokio::test]
    async fn download_artifact_rejects_stream_above_limit() {
        let (url, join) = start_artifact_response(
            Vec::new(),
            vec![b"12345".to_vec(), b"67890".to_vec(), b"!".to_vec()],
        );
        let client = reqwest::Client::builder().use_rustls_tls().build().unwrap();

        let err = download_artifact_with_limit(&client, &url, true, 10)
            .await
            .unwrap_err();
        join.join().unwrap();

        assert!(
            err.to_string()
                .contains("update artifact exceeded maximum allowed size")
        );
    }

    #[test]
    fn release_artifact_matches_go_platform_names() {
        let archive_name = format!(
            "fetch-v1.2.3-{}-{}.{}",
            goos(),
            goarch(),
            artifact_suffix_for_goos(goos())
        );
        let release = Release {
            tag_name: "v1.2.3".to_string(),
            assets: vec![
                Asset {
                    name: archive_name.clone(),
                    browser_download_url: "https://example.test/artifact".to_string(),
                },
                Asset {
                    name: format!("{archive_name}.sha256"),
                    browser_download_url: "https://example.test/artifact.sha256".to_string(),
                },
            ],
        };

        assert_eq!(
            release_artifact(&release),
            Some(ReleaseArtifact {
                archive_name: archive_name.as_str(),
                archive_url: "https://example.test/artifact",
                checksum_url: "https://example.test/artifact.sha256",
            })
        );
    }

    #[test]
    fn release_artifact_uses_zip_for_windows_release_assets() {
        let release = Release {
            tag_name: "v1.2.3".to_string(),
            assets: vec![
                Asset {
                    name: "fetch-v1.2.3-linux-amd64.tar.gz".to_string(),
                    browser_download_url: "https://example.test/linux".to_string(),
                },
                Asset {
                    name: "fetch-v1.2.3-windows-amd64.zip".to_string(),
                    browser_download_url: "https://example.test/windows".to_string(),
                },
                Asset {
                    name: "fetch-v1.2.3-windows-amd64.zip.sha256".to_string(),
                    browser_download_url: "https://example.test/windows.sha256".to_string(),
                },
            ],
        };

        assert_eq!(
            release_artifact_for_platform(&release, "windows", "amd64"),
            Some(ReleaseArtifact {
                archive_name: "fetch-v1.2.3-windows-amd64.zip",
                archive_url: "https://example.test/windows",
                checksum_url: "https://example.test/windows.sha256",
            })
        );
        assert_eq!(
            release_artifact_for_platform(&release, "windows", "arm64"),
            None
        );
    }

    #[test]
    fn release_artifact_requires_checksum_sidecar() {
        let release = Release {
            tag_name: "v1.2.3".to_string(),
            assets: vec![Asset {
                name: "fetch-v1.2.3-linux-amd64.tar.gz".to_string(),
                browser_download_url: "https://example.test/linux".to_string(),
            }],
        };

        assert_eq!(
            release_artifact_for_platform(&release, "linux", "amd64"),
            None
        );
    }

    #[test]
    fn update_artifact_checksum_accepts_valid_sidecar_digest() {
        let artifact = b"verified release bytes";
        let checksum = format!(
            "{}  fetch-v1.2.3-linux-amd64.tar.gz\n",
            sha256_hex(artifact)
        );

        let parsed = parse_sha256_checksum(&checksum).unwrap();

        verify_artifact_checksum("fetch-v1.2.3-linux-amd64.tar.gz", artifact, &parsed).unwrap();
    }

    #[test]
    fn update_artifact_checksum_rejects_wrong_digest() {
        let artifact = b"tampered release bytes";
        let checksum = "0000000000000000000000000000000000000000000000000000000000000000";

        let err = verify_artifact_checksum("fetch-v1.2.3-linux-amd64.tar.gz", artifact, checksum)
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("update artifact checksum mismatch")
        );
    }

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
    fn auto_update_zero_interval_is_due() {
        assert!(parse_auto_update_interval("0s").is_some());
        assert!(parse_auto_update_interval("0sec").is_some());
        assert_eq!(parse_auto_update_interval("0"), None);
    }

    #[test]
    fn test_is_version_tag() {
        let tests = [
            ("v1.2.3", true),
            ("v0.0.0", true),
            ("v10.20.30", true),
            ("v100.200.300", true),
            ("v(dev)", false),
            ("v0.0.0-20231215164305-abcdef123456", false),
            ("1.2.3", false),
            ("v1.2", false),
            ("v1.2.3.4", false),
            ("v.1.2", false),
            ("v1..2", false),
            ("v1.2.", false),
            ("", false),
            ("v", false),
            ("vx.y.z", false),
            ("v1.2.3-rc1", false),
            ("v1.2.3+meta", false),
        ];

        for (input, want) in tests {
            assert_eq!(is_version_tag(input), want, "is_version_tag({input:?})");
        }
    }

    #[test]
    fn update_last_attempt_time_overwrites_existing_metadata() {
        let dir = tempfile::tempdir().unwrap();

        update_last_attempt_time(dir.path(), UNIX_EPOCH + Duration::from_secs(100)).unwrap();
        update_last_attempt_time(dir.path(), UNIX_EPOCH + Duration::from_secs(200)).unwrap();

        let data = std::fs::read_to_string(dir.path().join("metadata.json")).unwrap();
        assert_eq!(data, r#"{"last_attempt_at":"1970-01-01T00:03:20Z"}"#);
    }

    #[test]
    fn auto_update_interval_parses_go_bool_and_duration_values() {
        assert_eq!(
            parse_auto_update_interval("true"),
            Some(Duration::from_secs(24 * 60 * 60))
        );
        assert_eq!(
            parse_auto_update_interval("1h30m"),
            Some(Duration::from_secs(90 * 60))
        );
        assert_eq!(
            parse_auto_update_interval("1.5h"),
            Some(Duration::from_secs(90 * 60))
        );
        assert_eq!(
            parse_auto_update_interval("+30m"),
            Some(Duration::from_secs(30 * 60))
        );
        assert_eq!(
            parse_auto_update_interval("1d"),
            Some(Duration::from_secs(24 * 60 * 60))
        );
        assert_eq!(
            parse_auto_update_interval("250ms"),
            Some(Duration::from_millis(250))
        );
        assert_eq!(parse_auto_update_interval("false"), None);
        assert_eq!(parse_auto_update_interval("-1h"), None);
        assert_eq!(parse_auto_update_interval("garbage"), None);
    }

    #[test]
    fn update_download_progress_bar_clears_line_on_finish() {
        let (printer, buffer) = memory_printer();
        let mut progress = UpdateDownloadProgress::new_for_terminal(printer, 13);

        progress.add(13);
        progress.finish();

        let output = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
        assert!(output.contains("100%"));
        assert!(
            output.ends_with("\r                                                            \r"),
            "{output:?}"
        );
    }

    #[test]
    fn update_download_progress_spinner_clears_line_on_finish() {
        let (printer, buffer) = memory_printer();
        let mut progress = UpdateDownloadProgress::new_for_terminal(printer, -1);

        progress.add(17);
        progress.finish();

        let output = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
        assert!(output.contains("17B"));
        assert!(output.ends_with("\r                                        \r"));
    }

    #[cfg(unix)]
    #[test]
    fn update_lock_nonblocking_returns_none_when_held() {
        let dir = tempfile::tempdir().unwrap();
        let _held = acquire_update_lock(dir.path(), true, true, None)
            .unwrap()
            .unwrap();

        assert!(
            acquire_update_lock(dir.path(), false, true, None)
                .unwrap()
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn should_attempt_update_returns_false_when_lock_is_held() {
        let dir = tempfile::tempdir().unwrap();
        let _held = acquire_update_lock(dir.path(), true, true, None)
            .unwrap()
            .unwrap();

        assert!(!should_attempt_update_in(dir.path(), Duration::ZERO).unwrap());
    }

    #[test]
    fn should_attempt_update_uses_metadata_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        update_last_attempt_time(dir.path(), SystemTime::now()).unwrap();

        assert!(!should_attempt_update_in(dir.path(), Duration::from_secs(60)).unwrap());
        assert!(should_attempt_update_in(dir.path(), Duration::ZERO).unwrap());
    }

    #[test]
    fn test_unpack_zip_artifact_path_traversal() {
        let tests = [
            ("normal file", "fetch.exe", false),
            ("path traversal with ..", "../escape.txt", true),
            (
                "deep path traversal",
                "../../Windows/System32/malicious.dll",
                true,
            ),
            ("absolute path", "C:/Windows/System32/malicious.dll", true),
            (
                "absolute unix path",
                "/Windows/System32/malicious.dll",
                true,
            ),
            ("backslash traversal", "..\\escape.txt", true),
            (
                "absolute backslash path",
                "\\Windows\\System32\\bad.dll",
                true,
            ),
        ];

        for (name, filename, want_err) in tests {
            let archive = create_zip(&[(filename, b"content".as_slice(), false)]);
            let dir = tempfile::tempdir().unwrap();
            let err = unpack_zip_artifact(dir.path(), &archive).err();
            assert_eq!(err.is_some(), want_err, "{name}");
            if !want_err {
                assert!(dir.path().join(filename).exists(), "{name}");
            }
        }
    }

    #[test]
    fn test_unpack_zip_artifact_explicit_directory_entry() {
        let archive = create_zip(&[
            ("bin/", b"".as_slice(), true),
            ("bin/fetch.exe", b"content".as_slice(), false),
        ]);
        let dir = tempfile::tempdir().unwrap();

        unpack_zip_artifact(dir.path(), &archive).unwrap();

        assert!(dir.path().join("bin").join("fetch.exe").exists());
    }

    #[test]
    fn test_unpack_zip_artifact_truncates_existing_regular_file() {
        let archive = create_zip(&[("fetch.exe", b"short".as_slice(), false)]);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("fetch.exe"), b"longer content").unwrap();

        unpack_zip_artifact(dir.path(), &archive).unwrap();

        assert_eq!(
            std::fs::read_to_string(dir.path().join("fetch.exe")).unwrap(),
            "short"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_unpack_artifact_path_traversal() {
        let tests = [
            ("normal file", "fetch", false),
            ("path traversal with ..", "../escape.txt", true),
            ("deep path traversal", "../../etc/passwd", true),
            ("absolute path", "/etc/passwd", true),
        ];

        for (name, filename, want_err) in tests {
            let archive = create_tar_gz(&[(filename, b"content".as_slice(), 0o644, false)]);
            let dir = tempfile::tempdir().unwrap();
            let err =
                unpack_artifact(dir.path(), "fetch-v1.2.3-linux-amd64.tar.gz", &archive).err();
            assert_eq!(err.is_some(), want_err, "{name}");
            if !want_err {
                assert!(dir.path().join(filename).exists(), "{name}");
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_unpack_artifact_explicit_directory_entry() {
        let archive = create_tar_gz(&[
            ("bin/", b"".as_slice(), 0o755, true),
            ("bin/fetch", b"content".as_slice(), 0o755, false),
        ]);
        let dir = tempfile::tempdir().unwrap();

        unpack_artifact(dir.path(), "fetch-v1.2.3-linux-amd64.tar.gz", &archive).unwrap();

        assert!(dir.path().join("bin").join("fetch").exists());
    }

    #[cfg(unix)]
    #[test]
    fn test_unpack_artifact_truncates_existing_regular_file() {
        let archive = create_tar_gz(&[
            ("fetch", b"longer content".as_slice(), 0o755, false),
            ("fetch", b"short".as_slice(), 0o755, false),
        ]);
        let dir = tempfile::tempdir().unwrap();

        unpack_artifact(dir.path(), "fetch-v1.2.3-linux-amd64.tar.gz", &archive).unwrap();

        assert_eq!(
            std::fs::read_to_string(dir.path().join("fetch")).unwrap(),
            "short"
        );
    }

    #[test]
    fn test_unpack_artifact_dispatches_zip_by_suffix() {
        let archive = create_zip(&[("fetch.exe", b"content".as_slice(), false)]);
        let dir = tempfile::tempdir().unwrap();

        unpack_artifact(dir.path(), "fetch-v1.2.3-windows-amd64.zip", &archive).unwrap();

        assert_eq!(
            std::fs::read_to_string(dir.path().join("fetch.exe")).unwrap(),
            "content"
        );
    }

    #[test]
    fn test_unpack_artifact_rejects_unknown_suffix() {
        let dir = tempfile::tempdir().unwrap();

        let err =
            unpack_artifact(dir.path(), "fetch-v1.2.3-plan9-amd64.bin", b"content").unwrap_err();

        assert!(
            err.to_string()
                .contains("unsupported self-update archive format")
        );
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

    #[cfg(unix)]
    fn create_tar_gz(entries: &[(&str, &[u8], u32, bool)]) -> Vec<u8> {
        let mut data = Vec::new();
        {
            let encoder = GzEncoder::new(&mut data, Compression::default());
            let mut builder = Builder::new(encoder);
            for (name, content, mode, is_dir) in entries {
                let mut header = Header::new_old();
                let name_bytes = name.as_bytes();
                header.as_old_mut().name[..name_bytes.len()].copy_from_slice(name_bytes);
                header.set_mode(*mode);
                header.set_size(if *is_dir { 0 } else { content.len() as u64 });
                if *is_dir {
                    header.set_entry_type(tar::EntryType::Directory);
                }
                header.set_cksum();
                if *is_dir {
                    builder.append(&header, &[][..]).unwrap();
                } else {
                    builder.append(&header, *content).unwrap();
                }
            }
            builder.finish().unwrap();
        }
        data
    }

    fn create_zip(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let cursor = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        for (name, content, is_dir) in entries {
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .unix_permissions(if *is_dir { 0o755 } else { 0o644 });
            if *is_dir {
                writer.add_directory(*name, options).unwrap();
            } else {
                writer.start_file(*name, options).unwrap();
                writer.write_all(content).unwrap();
            }
        }
        writer.finish().unwrap().into_inner()
    }
}
