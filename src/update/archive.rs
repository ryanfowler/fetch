use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

use super::client::{Release, UpdateClient, UpdateStreamingResponse, update_get_stream};
use crate::core;
use crate::duration::TimeoutBudget;
use crate::error::FetchError;
use crate::http::transport;
use crate::output::progress::{self, BarCounter, ProgressPrinter, SpinnerCounter};

const MAX_UPDATE_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_UPDATE_CHECKSUM_BYTES: u64 = 1024;
const MAX_UPDATE_UNPACKED_BYTES: u64 = MAX_UPDATE_ARTIFACT_BYTES * 4;
const MAX_UPDATE_ARCHIVE_ENTRIES: usize = 128;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct ReleaseArtifact<'a> {
    pub(super) archive_name: &'a str,
    pub(super) archive_url: &'a str,
    pub(super) checksum_url: &'a str,
}

pub(super) async fn download_and_unpack_artifact(
    client: &UpdateClient<'_>,
    archive_name: &str,
    artifact_url: &str,
    unpack_dir: &Path,
    scratch_dir: &Path,
    silent: bool,
) -> Result<String, FetchError> {
    download_and_unpack_artifact_with_limit(
        client,
        archive_name,
        artifact_url,
        unpack_dir,
        scratch_dir,
        silent,
        MAX_UPDATE_ARTIFACT_BYTES,
    )
    .await
}

async fn download_and_unpack_artifact_with_limit(
    client: &UpdateClient<'_>,
    archive_name: &str,
    artifact_url: &str,
    unpack_dir: &Path,
    scratch_dir: &Path,
    silent: bool,
    max_artifact_bytes: u64,
) -> Result<String, FetchError> {
    if archive_name.ends_with(".zip") {
        let archive_path = scratch_dir.join("artifact.zip");
        let actual = download_artifact_to_file_with_limit(
            client,
            artifact_url,
            &archive_path,
            silent,
            max_artifact_bytes,
        )
        .await?;
        unpack_zip_artifact_from_file(unpack_dir, &archive_path)?;
        Ok(actual)
    } else if archive_name.ends_with(".tar.gz") || archive_name.ends_with(".tgz") {
        download_and_unpack_tar_gz_artifact_with_limit(
            client,
            artifact_url,
            unpack_dir,
            silent,
            max_artifact_bytes,
        )
        .await
    } else {
        Err(format!("unsupported self-update archive format: {archive_name}").into())
    }
}

async fn download_artifact_to_file_with_limit(
    client: &UpdateClient<'_>,
    artifact_url: &str,
    archive_path: &Path,
    silent: bool,
    max_artifact_bytes: u64,
) -> Result<String, FetchError> {
    let response = update_get_stream(client, artifact_url).await?;
    let content_length = validate_artifact_response(&response, max_artifact_bytes)?;
    let mut progress = UpdateDownloadProgress::maybe_start(silent, content_length);
    let result =
        write_artifact_response_to_file(response, archive_path, &mut progress, max_artifact_bytes)
            .await;
    progress.finish();
    result
}

async fn download_and_unpack_tar_gz_artifact_with_limit(
    client: &UpdateClient<'_>,
    artifact_url: &str,
    unpack_dir: &Path,
    silent: bool,
    max_artifact_bytes: u64,
) -> Result<String, FetchError> {
    let response = update_get_stream(client, artifact_url).await?;
    let content_length = validate_artifact_response(&response, max_artifact_bytes)?;
    let mut progress = UpdateDownloadProgress::maybe_start(silent, content_length);
    let result =
        unpack_tar_gz_response(response, unpack_dir, &mut progress, max_artifact_bytes).await;
    progress.finish();
    result
}

fn validate_artifact_response(
    response: &UpdateStreamingResponse,
    max_artifact_bytes: u64,
) -> Result<i64, FetchError> {
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

    Ok(response
        .content_length()
        .and_then(|value| i64::try_from(value).ok())
        .unwrap_or(-1))
}

async fn write_artifact_response_to_file(
    response: UpdateStreamingResponse,
    archive_path: &Path,
    progress: &mut UpdateDownloadProgress,
    max_artifact_bytes: u64,
) -> Result<String, FetchError> {
    let mut file = tokio::fs::File::create(archive_path).await?;
    let mut hasher = Sha256::new();
    let mut received = 0u64;
    let budget = response.budget;
    let (mut body, _) = response.response.into_body_with_deadline();

    while let Some(data) = next_update_body_data(budget, &mut body).await? {
        account_artifact_chunk(
            &mut received,
            data.len(),
            max_artifact_bytes,
            "update artifact exceeded maximum allowed size",
        )?;
        hasher.update(&data);
        progress.add(data.len());
        file.write_all(&data).await?;
    }
    file.flush().await?;

    Ok(finish_sha256_hex(hasher))
}

async fn unpack_tar_gz_response(
    response: UpdateStreamingResponse,
    unpack_dir: &Path,
    progress: &mut UpdateDownloadProgress,
    max_artifact_bytes: u64,
) -> Result<String, FetchError> {
    let (tx, rx) = mpsc::channel::<bytes::Bytes>(8);
    let unpack_dir = unpack_dir.to_path_buf();
    let unpack_task = tokio::task::spawn_blocking(move || {
        unpack_tar_gz_artifact_from_reader(
            &unpack_dir,
            ChannelReader::new(rx),
            ArchiveExtractionLimits::default(),
        )
    });

    let mut hasher = Sha256::new();
    let mut received = 0u64;
    let budget = response.budget;
    let (mut body, _) = response.response.into_body_with_deadline();

    while let Some(data) = match next_update_body_data(budget, &mut body).await {
        Ok(data) => data,
        Err(err) => {
            drop(tx);
            let _ = finish_unpack_task(unpack_task).await;
            return Err(err);
        }
    } {
        if let Err(err) = account_artifact_chunk(
            &mut received,
            data.len(),
            max_artifact_bytes,
            "update artifact exceeded maximum allowed size",
        ) {
            drop(tx);
            let _ = finish_unpack_task(unpack_task).await;
            return Err(err);
        }
        hasher.update(&data);
        progress.add(data.len());
        if tx.send(data).await.is_err() {
            finish_unpack_task(unpack_task).await?;
            return Err(FetchError::Message(
                "self-update archive unpack task ended before download completed".to_string(),
            ));
        }
    }

    drop(tx);
    finish_unpack_task(unpack_task).await?;
    Ok(finish_sha256_hex(hasher))
}

async fn next_update_body_data(
    budget: TimeoutBudget,
    body: &mut transport::Body,
) -> Result<Option<bytes::Bytes>, FetchError> {
    while let Some(frame) = budget
        .run(Box::pin(async {
            match body.frame().await {
                Some(Ok(frame)) => Ok(Some(frame)),
                Some(Err(err)) => Err(FetchError::Runtime(format!("response body error: {err}"))),
                None => Ok(None),
            }
        }))
        .await?
    {
        if let Ok(data) = frame.into_data()
            && !data.is_empty()
        {
            return Ok(Some(data));
        }
    }
    Ok(None)
}

fn account_artifact_chunk(
    received: &mut u64,
    chunk_len: usize,
    max_artifact_bytes: u64,
    limit_error: &'static str,
) -> Result<(), FetchError> {
    let chunk = u64::try_from(chunk_len).unwrap_or(u64::MAX);
    if received.saturating_add(chunk) > max_artifact_bytes {
        return Err(limit_error.into());
    }
    *received = received.saturating_add(chunk);
    Ok(())
}

async fn finish_unpack_task(
    task: tokio::task::JoinHandle<Result<(), FetchError>>,
) -> Result<(), FetchError> {
    task.await.map_err(|err| {
        FetchError::Runtime(format!("self-update archive unpack task failed: {err}"))
    })?
}

pub(super) async fn download_checksum(
    client: &UpdateClient<'_>,
    checksum_url: &str,
) -> Result<String, FetchError> {
    let response = update_get_stream(client, checksum_url).await?;
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

    let response = response
        .into_buffered_with_limit(
            Some(MAX_UPDATE_CHECKSUM_BYTES),
            "update artifact checksum exceeded maximum allowed size",
        )
        .await?;

    if response.body().len() > MAX_UPDATE_CHECKSUM_BYTES as usize {
        return Err("update artifact checksum exceeded maximum allowed size".into());
    }

    let checksum = String::from_utf8(response.body().to_vec()).map_err(|_| {
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

pub(super) fn verify_artifact_checksum(
    artifact_name: &str,
    actual: &str,
    expected: &str,
) -> Result<(), FetchError> {
    if actual != expected {
        return Err(FetchError::Message(format!(
            "update artifact checksum mismatch for {artifact_name}: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

#[cfg(test)]
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    finish_sha256_hex(hasher)
}

fn finish_sha256_hex(hasher: Sha256) -> String {
    let digest = hasher.finalize();
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

struct ChannelReader {
    rx: mpsc::Receiver<bytes::Bytes>,
    current: Option<bytes::Bytes>,
    offset: usize,
}

impl ChannelReader {
    fn new(rx: mpsc::Receiver<bytes::Bytes>) -> Self {
        Self {
            rx,
            current: None,
            offset: 0,
        }
    }
}

impl std::io::Read for ChannelReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }

        loop {
            if let Some(current) = &self.current {
                if self.offset < current.len() {
                    let remaining = &current[self.offset..];
                    let len = remaining.len().min(out.len());
                    out[..len].copy_from_slice(&remaining[..len]);
                    self.offset += len;
                    if self.offset == current.len() {
                        self.current = None;
                        self.offset = 0;
                    }
                    return Ok(len);
                }
                self.current = None;
                self.offset = 0;
            }

            match self.rx.blocking_recv() {
                Some(bytes) if bytes.is_empty() => {}
                Some(bytes) => self.current = Some(bytes),
                None => return Ok(0),
            }
        }
    }
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

pub(super) fn release_artifact(release: &Release) -> Option<ReleaseArtifact<'_>> {
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

#[cfg(test)]
fn unpack_artifact(dir: &Path, archive_name: &str, data: &[u8]) -> Result<(), FetchError> {
    if archive_name.ends_with(".zip") {
        unpack_zip_artifact(dir, data)
    } else if archive_name.ends_with(".tar.gz") || archive_name.ends_with(".tgz") {
        unpack_tar_gz_artifact(dir, data)
    } else {
        Err(format!("unsupported self-update archive format: {archive_name}").into())
    }
}

#[cfg(test)]
fn unpack_tar_gz_artifact(dir: &Path, data: &[u8]) -> Result<(), FetchError> {
    unpack_tar_gz_artifact_with_limits(dir, data, ArchiveExtractionLimits::default())
}

#[cfg(test)]
fn unpack_tar_gz_artifact_with_limits(
    dir: &Path,
    data: &[u8],
    limits: ArchiveExtractionLimits,
) -> Result<(), FetchError> {
    unpack_tar_gz_artifact_from_reader(dir, data, limits)
}

fn unpack_tar_gz_artifact_from_reader<R: std::io::Read>(
    dir: &Path,
    reader: R,
    limits: ArchiveExtractionLimits,
) -> Result<(), FetchError> {
    let decoder = GzDecoder::new(reader);
    let mut archive = tar::Archive::new(decoder);
    let mut state = ArchiveExtractionState::new(limits);
    for entry in archive.entries()? {
        let mut entry = entry?;
        state.account_entry()?;
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
        copy_archive_entry_to_file(&mut entry, &out, &mut state)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = entry.header().mode().unwrap_or(0o755) & 0o777;
            std::fs::set_permissions(&out, std::fs::Permissions::from_mode(mode))?;
        }
    }
    Ok(())
}

#[cfg(test)]
fn unpack_zip_artifact(dir: &Path, data: &[u8]) -> Result<(), FetchError> {
    unpack_zip_artifact_with_limits(dir, data, ArchiveExtractionLimits::default())
}

#[cfg(test)]
fn unpack_zip_artifact_with_limits(
    dir: &Path,
    data: &[u8],
    limits: ArchiveExtractionLimits,
) -> Result<(), FetchError> {
    let reader = std::io::Cursor::new(data);
    unpack_zip_artifact_from_reader(dir, reader, limits)
}

fn unpack_zip_artifact_from_file(dir: &Path, path: &Path) -> Result<(), FetchError> {
    let file = std::fs::File::open(path)?;
    unpack_zip_artifact_from_reader(dir, file, ArchiveExtractionLimits::default())
}

fn unpack_zip_artifact_from_reader<R: std::io::Read + std::io::Seek>(
    dir: &Path,
    reader: R,
    limits: ArchiveExtractionLimits,
) -> Result<(), FetchError> {
    let mut archive =
        zip::ZipArchive::new(reader).map_err(|err| FetchError::Message(format!("zip: {err}")))?;
    let mut state = ArchiveExtractionState::new(limits);

    for index in 0..archive.len() {
        state.account_entry()?;
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

        copy_archive_entry_to_file(&mut file, &out, &mut state)?;

        #[cfg(unix)]
        if let Some(mode) = file.unix_mode() {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&out, std::fs::Permissions::from_mode(mode & 0o777))?;
        }
    }

    Ok(())
}

#[derive(Clone, Copy)]
struct ArchiveExtractionLimits {
    max_entries: usize,
    max_uncompressed_bytes: u64,
}

impl Default for ArchiveExtractionLimits {
    fn default() -> Self {
        Self {
            max_entries: MAX_UPDATE_ARCHIVE_ENTRIES,
            max_uncompressed_bytes: MAX_UPDATE_UNPACKED_BYTES,
        }
    }
}

struct ArchiveExtractionState {
    limits: ArchiveExtractionLimits,
    entries: usize,
    uncompressed_bytes: u64,
}

impl ArchiveExtractionState {
    fn new(limits: ArchiveExtractionLimits) -> Self {
        Self {
            limits,
            entries: 0,
            uncompressed_bytes: 0,
        }
    }

    fn account_entry(&mut self) -> Result<(), FetchError> {
        self.entries = self.entries.checked_add(1).ok_or_else(|| {
            FetchError::Message("self-update archive entry count overflowed".to_string())
        })?;
        if self.entries > self.limits.max_entries {
            return Err(FetchError::Message(format!(
                "self-update archive contains too many entries: maximum allowed is {}",
                self.limits.max_entries
            )));
        }
        Ok(())
    }

    fn account_bytes(&mut self, bytes: u64) -> Result<(), FetchError> {
        self.uncompressed_bytes = self.uncompressed_bytes.saturating_add(bytes);
        if self.uncompressed_bytes > self.limits.max_uncompressed_bytes {
            return Err(FetchError::Message(format!(
                "self-update archive uncompressed data exceeded maximum allowed size of {} bytes",
                self.limits.max_uncompressed_bytes
            )));
        }
        Ok(())
    }

    fn remaining_bytes(&self) -> u64 {
        self.limits
            .max_uncompressed_bytes
            .saturating_sub(self.uncompressed_bytes)
    }
}

fn copy_archive_entry_to_file<R: std::io::Read>(
    reader: &mut R,
    out: &Path,
    state: &mut ArchiveExtractionState,
) -> Result<u64, FetchError> {
    let mut file = std::fs::File::create(out)?;
    match copy_archive_entry_bounded(reader, &mut file, state) {
        Ok(bytes) => Ok(bytes),
        Err(err) => {
            drop(file);
            let _ = std::fs::remove_file(out);
            Err(err)
        }
    }
}

fn copy_archive_entry_bounded<R: std::io::Read, W: std::io::Write>(
    reader: &mut R,
    writer: &mut W,
    state: &mut ArchiveExtractionState,
) -> Result<u64, FetchError> {
    let remaining = state.remaining_bytes();
    let mut limited = std::io::Read::take(&mut *reader, remaining.saturating_add(1));
    let copied = std::io::copy(&mut limited, writer)?;
    state.account_bytes(copied)?;
    Ok(copied)
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
            value if has_unsafe_windows_archive_component(value) => {
                return Err(format!("refusing to unpack unsafe path '{name}'").into());
            }
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

fn has_unsafe_windows_archive_component(component: &str) -> bool {
    if component.contains(':') {
        return true;
    }

    let normalized = component.trim_end_matches([' ', '.']);
    if normalized.len() != component.len() {
        return true;
    }
    let raw_basename = normalized
        .split_once('.')
        .map_or(normalized, |(base, _)| base);
    let basename = raw_basename.trim_end_matches([' ', '.']);
    if basename.len() != raw_basename.len() {
        return true;
    }
    if basename.is_empty() {
        return true;
    }
    let uppercase = basename.to_ascii_uppercase();
    matches!(uppercase.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || matches!(
            uppercase.as_bytes(),
            [b'C', b'O', b'M', b'1'..=b'9'] | [b'L', b'P', b'T', b'1'..=b'9']
        )
}

pub(super) fn fetch_filename() -> &'static str {
    if cfg!(windows) { "fetch.exe" } else { "fetch" }
}

fn artifact_suffix_for_goos(goos: &str) -> &'static str {
    match goos {
        "windows" => "zip",
        _ => "tar.gz",
    }
}

pub(super) fn goos() -> &'static str {
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

pub(super) fn goarch() -> &'static str {
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

#[cfg(test)]
mod tests {
    use super::super::client::{Asset, UpdateClient, UpdateStreamingResponse};
    #[cfg(unix)]
    use super::super::test_support::create_tar_gz;
    use super::super::test_support::{create_zip, memory_printer, start_artifact_response};
    use super::*;
    use crate::duration::TimeoutBudget;
    use crate::http::transport;
    use http::{HeaderMap, StatusCode};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Poll;
    use std::time::Instant;

    #[tokio::test]
    async fn download_artifact_rejects_content_length_above_limit() {
        let (url, join) =
            start_artifact_response(vec![("Content-Length", "11".to_string())], Vec::new());
        let client = UpdateClient::test_allow_insecure_http(None);
        let dir = tempfile::tempdir().unwrap();

        let err = download_and_unpack_artifact_with_limit(
            &client,
            "fetch-v1.2.3-linux-amd64.tar.gz",
            &url,
            dir.path(),
            dir.path(),
            true,
            10,
        )
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
        let client = UpdateClient::test_allow_insecure_http(None);
        let dir = tempfile::tempdir().unwrap();

        let err = download_and_unpack_artifact_with_limit(
            &client,
            "fetch-v1.2.3-linux-amd64.tar.gz",
            &url,
            dir.path(),
            dir.path(),
            true,
            10,
        )
        .await
        .unwrap_err();
        join.join().unwrap();

        assert!(
            err.to_string()
                .contains("update artifact exceeded maximum allowed size")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn download_artifact_streams_tar_gz_to_unpack_dir_and_hashes() {
        let archive = create_tar_gz(&[("fetch", b"content".as_slice(), 0o755, false)]);
        let expected = sha256_hex(&archive);
        let (url, join) = start_artifact_response(
            Vec::new(),
            archive.chunks(3).map(|chunk| chunk.to_vec()).collect(),
        );
        let client = UpdateClient::test_allow_insecure_http(None);
        let dir = tempfile::tempdir().unwrap();

        let actual = download_and_unpack_artifact_with_limit(
            &client,
            "fetch-v1.2.3-linux-amd64.tar.gz",
            &url,
            dir.path(),
            dir.path(),
            true,
            MAX_UPDATE_ARTIFACT_BYTES,
        )
        .await
        .unwrap();
        join.join().unwrap();

        assert_eq!(actual, expected);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("fetch")).unwrap(),
            "content"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unpack_tar_gz_response_stops_downloading_after_unpack_fails() {
        const TAIL_CHUNKS: usize = 64;
        const TAIL_CHUNK_LEN: usize = 64 * 1024;

        let archive = create_tar_gz(&[("../escape.txt", b"bad".as_slice(), 0o644, false)]);
        let pulled_chunks = Arc::new(AtomicUsize::new(0));
        let stream_pulled_chunks = Arc::clone(&pulled_chunks);
        let mut first_chunk = Some(bytes::Bytes::from(archive));
        let mut tail_remaining = TAIL_CHUNKS;
        let stream = futures_util::stream::poll_fn(move |_| {
            if let Some(chunk) = first_chunk.take() {
                stream_pulled_chunks.fetch_add(1, Ordering::SeqCst);
                return Poll::Ready(Some(Ok::<_, std::io::Error>(chunk)));
            }
            if tail_remaining == 0 {
                return Poll::Ready(None);
            }
            tail_remaining -= 1;
            stream_pulled_chunks.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Some(Ok::<_, std::io::Error>(bytes::Bytes::from(vec![
                b'x';
                TAIL_CHUNK_LEN
            ]))))
        });
        let response = UpdateStreamingResponse {
            response: transport::Response::test(
                StatusCode::OK,
                HeaderMap::new(),
                transport::Body::wrap_stream(stream),
            ),
            budget: TimeoutBudget::started_at(None, Instant::now()),
        };
        let dir = tempfile::tempdir().unwrap();
        let mut progress = UpdateDownloadProgress::None;

        let err = unpack_tar_gz_response(
            response,
            dir.path(),
            &mut progress,
            MAX_UPDATE_ARTIFACT_BYTES,
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("refusing to unpack unsafe path '../escape.txt'"),
            "{err}"
        );
        let pulled = pulled_chunks.load(Ordering::SeqCst);
        assert!(
            pulled < TAIL_CHUNKS + 1,
            "expected early unpack failure to stop the download, pulled {pulled} of {} chunks",
            TAIL_CHUNKS + 1
        );
    }

    #[tokio::test]
    async fn download_artifact_streams_zip_to_temp_file_and_hashes() {
        let archive = create_zip(&[("fetch.exe", b"content".as_slice(), false)]);
        let expected = sha256_hex(&archive);
        let (url, join) = start_artifact_response(
            Vec::new(),
            archive.chunks(3).map(|chunk| chunk.to_vec()).collect(),
        );
        let client = UpdateClient::test_allow_insecure_http(None);
        let dir = tempfile::tempdir().unwrap();
        let unpack_dir = dir.path().join("unpacked");
        std::fs::create_dir(&unpack_dir).unwrap();

        let actual = download_and_unpack_artifact_with_limit(
            &client,
            "fetch-v1.2.3-windows-amd64.zip",
            &url,
            &unpack_dir,
            dir.path(),
            true,
            MAX_UPDATE_ARTIFACT_BYTES,
        )
        .await
        .unwrap();
        join.join().unwrap();

        assert_eq!(actual, expected);
        assert_eq!(
            std::fs::read_to_string(unpack_dir.join("fetch.exe")).unwrap(),
            "content"
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
        let actual = sha256_hex(artifact);

        verify_artifact_checksum("fetch-v1.2.3-linux-amd64.tar.gz", &actual, &parsed).unwrap();
    }

    #[test]
    fn update_artifact_checksum_rejects_wrong_digest() {
        let artifact = b"tampered release bytes";
        let checksum = "0000000000000000000000000000000000000000000000000000000000000000";
        let actual = sha256_hex(artifact);

        let err = verify_artifact_checksum("fetch-v1.2.3-linux-amd64.tar.gz", &actual, checksum)
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("update artifact checksum mismatch")
        );
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
            ("alternate data stream", "fetch.exe:ads", true),
            ("reserved device name", "CON", true),
            ("reserved device name with extension", "dir/NUL.txt", true),
            (
                "reserved device name with trailing dot",
                "dir/COM1./fetch.exe",
                true,
            ),
            (
                "reserved device name with trailing space before extension",
                "dir/NUL .txt",
                true,
            ),
            ("all-dot windows component", "dir/.../fetch.exe", true),
            ("trailing-dot component", "fetch.exe.", true),
            ("trailing-space component", "fetch.exe ", true),
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

    #[test]
    fn test_unpack_zip_artifact_rejects_expanded_size_limit_and_removes_partial_binary() {
        let readme = vec![b'a'; 10];
        let binary = vec![b'b'; 10];
        let archive = create_zip(&[
            ("README.txt", readme.as_slice(), false),
            ("fetch.exe", binary.as_slice(), false),
        ]);
        let dir = tempfile::tempdir().unwrap();

        let err = unpack_zip_artifact_with_limits(
            dir.path(),
            &archive,
            ArchiveExtractionLimits {
                max_entries: 4,
                max_uncompressed_bytes: 16,
            },
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("uncompressed data exceeded maximum allowed size"),
            "{err}"
        );
        assert!(!dir.path().join("fetch.exe").exists());
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

    #[cfg(unix)]
    #[test]
    fn test_unpack_tar_gz_artifact_masks_special_permission_bits() {
        use std::os::unix::fs::PermissionsExt;

        let archive = create_tar_gz(&[("fetch", b"content".as_slice(), 0o4755, false)]);
        let dir = tempfile::tempdir().unwrap();

        unpack_artifact(dir.path(), "fetch-v1.2.3-linux-amd64.tar.gz", &archive).unwrap();

        let mode = std::fs::metadata(dir.path().join("fetch"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o755);
    }

    #[cfg(unix)]
    #[test]
    fn test_unpack_tar_gz_artifact_rejects_expanded_size_limit_and_removes_partial_binary() {
        let readme = vec![b'a'; 10];
        let binary = vec![b'b'; 10];
        let archive = create_tar_gz(&[
            ("README.txt", readme.as_slice(), 0o644, false),
            ("fetch", binary.as_slice(), 0o755, false),
        ]);
        let dir = tempfile::tempdir().unwrap();

        let err = unpack_tar_gz_artifact_with_limits(
            dir.path(),
            &archive,
            ArchiveExtractionLimits {
                max_entries: 4,
                max_uncompressed_bytes: 16,
            },
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("uncompressed data exceeded maximum allowed size"),
            "{err}"
        );
        assert!(!dir.path().join("fetch").exists());
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
}
