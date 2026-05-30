use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use reqwest::header::{CONTENT_DISPOSITION, HeaderMap};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use url::Url;

use crate::core;
use crate::fileutil;
use crate::output::progress::{
    Bar, BarCounter, ProgressPrinter, Spinner, SpinnerCounter, emit_native_progress,
    write_final_progress,
};

pub mod clipboard;
pub mod progress;

#[derive(Debug, Error)]
pub enum OutputError {
    #[error(
        "unable to infer a file name for the output\n\nTo specify an exact path, try '--output <PATH>'"
    )]
    UnableToInferFileName,
    #[error("invalid filename: '{0}'")]
    InvalidFilename(String),
    #[error("file '{0}' already exists\n\nTo overwrite existing files, try '--clobber'")]
    FileExists(String),
    #[error("unable to check output file '{path}': {source}")]
    FileCheck {
        path: String,
        source: std::io::Error,
    },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Clone)]
pub struct WriteProgress {
    printer: Option<ProgressPrinter>,
    stderr_is_terminal: bool,
    stdout_is_terminal: bool,
    total_bytes: Option<i64>,
}

impl WriteProgress {
    pub fn disabled() -> Self {
        Self {
            printer: None,
            stderr_is_terminal: false,
            stdout_is_terminal: false,
            total_bytes: None,
        }
    }

    pub fn stdio(color_setting: Option<&str>, total_bytes: Option<i64>) -> Self {
        let stdio = core::stdio();
        Self::with_printer(
            ProgressPrinter::stderr(color_setting),
            stdio.stderr_is_terminal(),
            stdio.stdout_is_terminal(),
            total_bytes,
        )
    }

    pub fn with_printer(
        printer: ProgressPrinter,
        stderr_is_terminal: bool,
        stdout_is_terminal: bool,
        total_bytes: Option<i64>,
    ) -> Self {
        Self {
            printer: Some(printer),
            stderr_is_terminal,
            stdout_is_terminal,
            total_bytes,
        }
    }
}

pub fn resolve_output_path(
    output: Option<&str>,
    remote_name: bool,
    remote_header_name: bool,
    url: &Url,
    headers: &HeaderMap,
) -> Result<Option<String>, OutputError> {
    if let Some(path) = output {
        if path == "-" {
            return Ok(None);
        }
        return Ok(Some(path.to_string()));
    }
    if !remote_name {
        return Ok(None);
    }

    if remote_header_name
        && let Some(filename) = content_disposition_filename(headers)
        && let Ok(filename) = sanitize_filename(&filename)
    {
        return Ok(Some(filename));
    }

    if let Some(filename) = filename_from_url_path(url) {
        return Ok(Some(filename));
    }

    if let Some(host) = url.host_str()
        && !host.is_empty()
    {
        return Ok(Some(host.to_string()));
    }

    Err(OutputError::UnableToInferFileName)
}

pub async fn write_output(path: &str, bytes: &[u8], clobber: bool) -> Result<(), OutputError> {
    write_output_with_progress(path, bytes, clobber, WriteProgress::disabled()).await
}

pub async fn write_output_with_progress(
    path: &str,
    bytes: &[u8],
    clobber: bool,
    progress: WriteProgress,
) -> Result<(), OutputError> {
    let mut reader = std::io::Cursor::new(bytes);
    write_output_reader(path, &mut reader, clobber, progress).map(|_| ())
}

pub fn write_output_reader<R: Read>(
    path: &str,
    reader: &mut R,
    clobber: bool,
    progress: WriteProgress,
) -> Result<i64, OutputError> {
    let target = Path::new(path);
    if !clobber {
        check_output_file(target)?;
    }

    let absolute_target = absolute_path(target)?;
    let (temp_path, temp_file) = create_download_temp(&absolute_target)?;
    let temp_guard = DownloadTempGuard::new(temp_path);
    let mut temp_file = temp_file;

    let progress_summary = write_temp_body(
        &mut temp_file,
        reader,
        &progress,
        absolute_target.to_string_lossy().as_ref(),
    )?;
    if let Err(err) = temp_file.sync_all() {
        return Err(OutputError::Io(err));
    }
    drop(temp_file);

    let install_result = if clobber {
        fileutil::atomic_replace_file(temp_guard.path(), &absolute_target)
    } else {
        fileutil::atomic_write_new_file(temp_guard.path(), &absolute_target)
    };
    match install_result {
        Ok(()) => {
            if let Some(summary) = progress_summary.summary {
                summary.finish();
            }
            Ok(progress_summary.bytes_written)
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(OutputError::FileExists(path.to_string()))
        }
        Err(err) => Err(OutputError::FileCheck {
            path: path.to_string(),
            source: err,
        }),
    }
}

pub async fn write_output_async_reader<R: AsyncRead + Unpin>(
    path: &str,
    reader: &mut R,
    clobber: bool,
    progress: WriteProgress,
) -> Result<i64, OutputError> {
    let target = Path::new(path);
    if !clobber {
        check_output_file(target)?;
    }

    let absolute_target = absolute_path(target)?;
    let (temp_path, temp_file) = create_download_temp(&absolute_target)?;
    let temp_guard = DownloadTempGuard::new(temp_path);
    let mut temp_file = tokio::fs::File::from_std(temp_file);

    let progress_summary = write_temp_body_async(
        &mut temp_file,
        reader,
        &progress,
        absolute_target.to_string_lossy().as_ref(),
    )
    .await?;
    if let Err(err) = temp_file.sync_all().await {
        return Err(OutputError::Io(err));
    }
    drop(temp_file);

    let install_result = if clobber {
        fileutil::atomic_replace_file(temp_guard.path(), &absolute_target)
    } else {
        fileutil::atomic_write_new_file(temp_guard.path(), &absolute_target)
    };
    match install_result {
        Ok(()) => {
            if let Some(summary) = progress_summary.summary {
                summary.finish();
            }
            Ok(progress_summary.bytes_written)
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(OutputError::FileExists(path.to_string()))
        }
        Err(err) => Err(OutputError::FileCheck {
            path: path.to_string(),
            source: err,
        }),
    }
}

fn check_output_file(path: &Path) -> Result<(), OutputError> {
    match std::fs::metadata(path) {
        Ok(_) => Err(OutputError::FileExists(path.to_string_lossy().into_owned())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(OutputError::FileCheck {
            path: path.to_string_lossy().into_owned(),
            source: err,
        }),
    }
}

fn absolute_path(path: &Path) -> Result<PathBuf, OutputError> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn create_download_temp(target: &Path) -> Result<(PathBuf, File), OutputError> {
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    let base = target
        .file_name()
        .map(|name| name.to_string_lossy())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "fetch".into());
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();

    for attempt in 0..100u32 {
        let candidate = dir.join(format!(
            "{base}.{}.{}.{}.download",
            std::process::id(),
            seed,
            attempt
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => return Ok((candidate, file)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(OutputError::Io(err)),
        }
    }

    Err(OutputError::FileCheck {
        path: target.to_string_lossy().into_owned(),
        source: std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "unable to create unique temporary output file",
        ),
    })
}

struct DownloadTempGuard {
    path: PathBuf,
}

impl DownloadTempGuard {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for DownloadTempGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn write_temp_body<R: Read>(
    file: &mut File,
    reader: &mut R,
    progress: &WriteProgress,
    display_path: &str,
) -> Result<WriteOutcome, OutputError> {
    let Some(printer) = progress.printer.clone() else {
        let bytes_written = std::io::copy(reader, file)?;
        file.flush()?;
        return Ok(WriteOutcome {
            bytes_written: i64::try_from(bytes_written).unwrap_or(i64::MAX),
            summary: None,
        });
    };

    let start = Instant::now();
    let summary = if progress.stderr_is_terminal {
        write_with_terminal_progress(file, reader, progress, &printer, display_path)?
    } else {
        let bytes_written = std::io::copy(reader, file)?;
        let bytes_written = i64::try_from(bytes_written).unwrap_or(i64::MAX);
        ProgressSummary {
            printer,
            bytes_read: bytes_written,
            elapsed: start.elapsed(),
            to_clear: -1,
            display_path: display_path.to_string(),
            clear_native: false,
        }
    };
    let bytes_written = summary.bytes_read;
    file.flush()?;
    Ok(WriteOutcome {
        bytes_written,
        summary: Some(summary),
    })
}

async fn write_temp_body_async<R: AsyncRead + Unpin>(
    file: &mut tokio::fs::File,
    reader: &mut R,
    progress: &WriteProgress,
    display_path: &str,
) -> Result<WriteOutcome, OutputError> {
    let Some(printer) = progress.printer.clone() else {
        let bytes_written = tokio::io::copy(reader, file).await?;
        file.flush().await?;
        return Ok(WriteOutcome {
            bytes_written: i64::try_from(bytes_written).unwrap_or(i64::MAX),
            summary: None,
        });
    };

    let start = Instant::now();
    let summary = if progress.stderr_is_terminal {
        write_with_terminal_progress_async(file, reader, progress, &printer, display_path).await?
    } else {
        let bytes_written = tokio::io::copy(reader, file).await?;
        let bytes_written = i64::try_from(bytes_written).unwrap_or(i64::MAX);
        ProgressSummary {
            printer,
            bytes_read: bytes_written,
            elapsed: start.elapsed(),
            to_clear: -1,
            display_path: display_path.to_string(),
            clear_native: false,
        }
    };
    let bytes_written = summary.bytes_read;
    file.flush().await?;
    Ok(WriteOutcome {
        bytes_written,
        summary: Some(summary),
    })
}

struct ProgressSummary {
    printer: ProgressPrinter,
    bytes_read: i64,
    elapsed: std::time::Duration,
    to_clear: i32,
    display_path: String,
    clear_native: bool,
}

struct WriteOutcome {
    bytes_written: i64,
    summary: Option<ProgressSummary>,
}

impl ProgressSummary {
    fn finish(self) {
        if self.clear_native {
            emit_native_progress(&self.printer, 0, 0);
        }
        write_final_progress(
            &self.printer,
            self.bytes_read,
            self.elapsed,
            self.to_clear,
            &self.display_path,
        );
    }
}

async fn write_with_terminal_progress_async<R: AsyncRead + Unpin>(
    file: &mut tokio::fs::File,
    reader: &mut R,
    progress: &WriteProgress,
    printer: &ProgressPrinter,
    display_path: &str,
) -> Result<ProgressSummary, OutputError> {
    if progress.total_bytes.unwrap_or(-1) > 0 {
        let native_printer = printer.clone();
        let stdout_is_terminal = progress.stdout_is_terminal;
        let mut counter = BarCounter::new_with_on_render(
            printer.clone(),
            progress.total_bytes.unwrap_or(-1),
            Some(move |percent| {
                if stdout_is_terminal {
                    emit_native_progress(&native_printer, 1, percent);
                }
            }),
        );
        copy_async_with_progress(reader, file, |bytes| counter.add(bytes)).await?;
        let (bytes_read, elapsed) = counter.stop();
        Ok(ProgressSummary {
            printer: printer.clone(),
            bytes_read,
            elapsed,
            to_clear: 32,
            display_path: display_path.to_string(),
            clear_native: progress.stdout_is_terminal,
        })
    } else {
        let native_printer = printer.clone();
        let stdout_is_terminal = progress.stdout_is_terminal;
        let mut counter = SpinnerCounter::new_with_on_start(
            printer.clone(),
            Some(move || {
                if stdout_is_terminal {
                    emit_native_progress(&native_printer, 3, 0);
                }
            }),
        );
        copy_async_with_progress(reader, file, |bytes| counter.add(bytes)).await?;
        let (bytes_read, elapsed) = counter.stop();
        Ok(ProgressSummary {
            printer: printer.clone(),
            bytes_read,
            elapsed,
            to_clear: 20,
            display_path: display_path.to_string(),
            clear_native: progress.stdout_is_terminal,
        })
    }
}

async fn copy_async_with_progress<R, W, F>(
    reader: &mut R,
    writer: &mut W,
    mut on_chunk: F,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: FnMut(i64),
{
    let mut buf = vec![0; 16 * 1024];
    let mut written = 0u64;
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return Ok(written);
        }
        writer.write_all(&buf[..n]).await?;
        written = written.saturating_add(n as u64);
        on_chunk(i64::try_from(n).unwrap_or(i64::MAX));
    }
}

fn write_with_terminal_progress<R: Read>(
    file: &mut File,
    reader: &mut R,
    progress: &WriteProgress,
    printer: &ProgressPrinter,
    display_path: &str,
) -> Result<ProgressSummary, OutputError> {
    if progress.total_bytes.unwrap_or(-1) > 0 {
        let native_printer = printer.clone();
        let stdout_is_terminal = progress.stdout_is_terminal;
        let mut reader = Bar::new_with_on_render(
            reader,
            printer.clone(),
            progress.total_bytes.unwrap_or(-1),
            Some(move |percent| {
                if stdout_is_terminal {
                    emit_native_progress(&native_printer, 1, percent);
                }
            }),
        );
        std::io::copy(&mut reader, file)?;
        let (bytes_read, elapsed) = reader.stop();
        Ok(ProgressSummary {
            printer: printer.clone(),
            bytes_read,
            elapsed,
            to_clear: 32,
            display_path: display_path.to_string(),
            clear_native: progress.stdout_is_terminal,
        })
    } else {
        let native_printer = printer.clone();
        let stdout_is_terminal = progress.stdout_is_terminal;
        let mut reader = Spinner::new_with_on_start(
            reader,
            printer.clone(),
            Some(move || {
                if stdout_is_terminal {
                    emit_native_progress(&native_printer, 3, 0);
                }
            }),
        );
        std::io::copy(&mut reader, file)?;
        let (bytes_read, elapsed) = reader.stop();
        Ok(ProgressSummary {
            printer: printer.clone(),
            bytes_read,
            elapsed,
            to_clear: 20,
            display_path: display_path.to_string(),
            clear_native: progress.stdout_is_terminal,
        })
    }
}

fn filename_from_url_path(url: &Url) -> Option<String> {
    let mut path = url.path();
    while !path.is_empty() {
        let (before, after) = cut_last(path, "/");
        path = before;
        if after.is_empty() {
            continue;
        }
        if let Ok(filename) = sanitize_filename(after) {
            return Some(filename);
        }
    }
    None
}

fn sanitize_filename(filename: &str) -> Result<String, OutputError> {
    let Some(base) = filename.rsplit(['/', '\\']).next() else {
        return Err(OutputError::InvalidFilename(filename.to_string()));
    };
    if base.is_empty()
        || base == "."
        || base == ".."
        || base.chars().any(char::is_control)
        || looks_like_windows_drive_path(base)
        || is_windows_reserved_filename(base)
    {
        return Err(OutputError::InvalidFilename(filename.to_string()));
    }
    Ok(base.to_string())
}

fn looks_like_windows_drive_path(filename: &str) -> bool {
    let mut chars = filename.chars();
    matches!(
        (chars.next(), chars.next()),
        (Some(letter), Some(':')) if letter.is_ascii_alphabetic()
    )
}

fn is_windows_reserved_filename(filename: &str) -> bool {
    let name = filename
        .split_once('.')
        .map_or(filename, |(before_dot, _)| before_dot)
        .trim_end_matches([' ', '.'])
        .to_ascii_uppercase();

    let bytes = name.as_bytes();
    matches!(
        name.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || (bytes.len() == 4
        && (bytes.starts_with(b"COM") || bytes.starts_with(b"LPT"))
        && matches!(bytes[3], b'1'..=b'9'))
}

fn content_disposition_filename(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(CONTENT_DISPOSITION)?.to_str().ok()?;
    parse_content_disposition_filename(value)
}

fn parse_content_disposition_filename(value: &str) -> Option<String> {
    let mut filename = None;
    let mut filename_star = None;

    for part in split_parameters(value).into_iter().skip(1) {
        let Some((key, raw_value)) = part.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = parse_parameter_value(raw_value.trim());
        if key.eq_ignore_ascii_case("filename") {
            filename = Some(value);
        } else if key.eq_ignore_ascii_case("filename*") {
            filename_star = decode_rfc5987_value(&value);
        }
    }

    filename_star.or(filename)
}

fn split_parameters(value: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quote = false;
    let mut escaped = false;

    for (idx, ch) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_quote => escaped = true,
            '"' => in_quote = !in_quote,
            ';' if !in_quote => {
                parts.push(value[start..idx].trim());
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(value[start..].trim());
    parts
}

fn parse_parameter_value(value: &str) -> String {
    let Some(rest) = value.strip_prefix('"') else {
        return value.to_string();
    };

    let mut out = String::new();
    let mut escaped = false;
    for ch in rest.chars() {
        if escaped {
            out.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => break,
            _ => out.push(ch),
        }
    }
    out
}

fn decode_rfc5987_value(value: &str) -> Option<String> {
    let (charset, rest) = value.split_once('\'')?;
    let (_language, encoded) = rest.split_once('\'')?;
    if !charset.eq_ignore_ascii_case("utf-8") && !charset.eq_ignore_ascii_case("us-ascii") {
        return None;
    }
    let bytes = percent_decode(encoded)?;
    String::from_utf8(bytes).ok()
}

fn percent_decode(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes[idx] == b'%' {
            let hi = bytes.get(idx + 1).and_then(|byte| hex_value(*byte))?;
            let lo = bytes.get(idx + 2).and_then(|byte| hex_value(*byte))?;
            out.push((hi << 4) | lo);
            idx += 3;
        } else {
            out.push(bytes[idx]);
            idx += 1;
        }
    }
    Some(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn cut_last<'a>(value: &'a str, separator: &str) -> (&'a str, &'a str) {
    if let Some(idx) = value.rfind(separator) {
        (&value[..idx], &value[idx + separator.len()..])
    } else {
        (value, "")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::io::ReadBuf;

    #[derive(Clone)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct PendingAfterPartial {
        wrote: bool,
    }

    impl AsyncRead for PendingAfterPartial {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.wrote {
                Poll::Pending
            } else {
                self.wrote = true;
                buf.put_slice(b"partial");
                Poll::Ready(Ok(()))
            }
        }
    }

    #[test]
    fn test_sanitize_filename() {
        let tests = [
            ("simple filename", "file.txt", Ok("file.txt")),
            (
                "path traversal with ../ prefix",
                "../file.txt",
                Ok("file.txt"),
            ),
            (
                "path traversal with multiple ../ prefixes",
                "../../../tmp/file.txt",
                Ok("file.txt"),
            ),
            ("backslash path", r"dir\file.txt", Ok("file.txt")),
            (
                "mixed slash and backslash path",
                r"dir/subdir\file.txt",
                Ok("file.txt"),
            ),
            (
                "mixed backslash and slash path",
                r"dir\subdir/file.txt",
                Ok("file.txt"),
            ),
            ("absolute path", "/tmp/file.txt", Ok("file.txt")),
            ("absolute windows path", r"C:\tmp\file.txt", Ok("file.txt")),
            ("nested path", "dir/subdir/file.txt", Ok("file.txt")),
            ("empty string", "", Err(())),
            ("single dot", ".", Err(())),
            ("double dot", "..", Err(())),
            ("path ending with slash", "dir/", Err(())),
            ("path ending with backslash", r"dir\", Err(())),
            ("control character", "bad\nname.txt", Err(())),
            ("windows reserved name", "CON", Err(())),
            ("windows reserved name with extension", "nul.txt", Err(())),
            ("windows drive-relative path", "C:evil.txt", Err(())),
            ("windows drive prefix", "D:", Err(())),
            ("hidden file", ".hidden", Ok(".hidden")),
        ];

        for (name, input, expected) in tests {
            let result = sanitize_filename(input);
            match expected {
                Ok(expected) => assert_eq!(result.unwrap(), expected, "{name}"),
                Err(()) => assert!(result.is_err(), "{name}"),
            }
        }
    }

    #[test]
    fn remote_name_uses_url_path_component() {
        let url = Url::parse("http://example.com/dir/path_to_file.txt?ignored=yes").unwrap();
        let headers = HeaderMap::new();

        let path = resolve_output_path(None, true, false, &url, &headers)
            .unwrap()
            .unwrap();

        assert_eq!(path, "path_to_file.txt");
    }

    #[test]
    fn remote_name_ignores_content_disposition_without_remote_header_name() {
        let url = Url::parse("http://example.com/url-filename.txt").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_DISPOSITION,
            r#"attachment; filename="cd-filename.txt""#.parse().unwrap(),
        );

        let path = resolve_output_path(None, true, false, &url, &headers)
            .unwrap()
            .unwrap();

        assert_eq!(path, "url-filename.txt");
    }

    #[test]
    fn remote_header_name_uses_content_disposition_filename() {
        let url = Url::parse("http://example.com/url-filename.txt").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_DISPOSITION,
            r#"attachment; filename="cd-filename.txt""#.parse().unwrap(),
        );

        let path = resolve_output_path(None, true, true, &url, &headers)
            .unwrap()
            .unwrap();

        assert_eq!(path, "cd-filename.txt");
    }

    #[test]
    fn remote_header_name_sanitizes_content_disposition_filename() {
        let url = Url::parse("http://example.com/fallback.txt").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_DISPOSITION,
            r#"attachment; filename="../../../tmp/malicious.txt""#
                .parse()
                .unwrap(),
        );

        let path = resolve_output_path(None, true, true, &url, &headers)
            .unwrap()
            .unwrap();

        assert_eq!(path, "malicious.txt");
    }

    #[test]
    fn remote_header_name_sanitizes_mixed_content_disposition_separators() {
        let url = Url::parse("http://example.com/fallback.txt").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_DISPOSITION,
            r#"attachment; filename="dir/subdir\\evil.txt""#.parse().unwrap(),
        );

        let path = resolve_output_path(None, true, true, &url, &headers)
            .unwrap()
            .unwrap();

        assert_eq!(path, "evil.txt");
    }

    #[test]
    fn remote_header_name_falls_back_to_url_on_invalid_content_disposition_filename() {
        let url = Url::parse("http://example.com/fallback.txt").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_DISPOSITION,
            r#"attachment; filename="..""#.parse().unwrap(),
        );

        let path = resolve_output_path(None, true, true, &url, &headers)
            .unwrap()
            .unwrap();

        assert_eq!(path, "fallback.txt");
    }

    #[test]
    fn remote_name_falls_back_to_hostname() {
        let url = Url::parse("http://example.com/").unwrap();
        let headers = HeaderMap::new();

        let path = resolve_output_path(None, true, false, &url, &headers)
            .unwrap()
            .unwrap();

        assert_eq!(path, "example.com");
    }

    #[test]
    fn direct_stdout_skips_file_path() {
        let url = Url::parse("http://example.com/file.txt").unwrap();
        let headers = HeaderMap::new();

        let path = resolve_output_path(Some("-"), false, false, &url, &headers).unwrap();

        assert_eq!(path, None);
    }

    #[test]
    fn content_disposition_filename_decodes_quoted_and_extended_values() {
        assert_eq!(
            parse_content_disposition_filename(r#"attachment; filename="space name.txt""#),
            Some("space name.txt".to_string())
        );
        assert_eq!(
            parse_content_disposition_filename(r#"attachment; filename*=UTF-8''space%20name.txt"#),
            Some("space name.txt".to_string())
        );
    }

    #[test]
    fn content_disposition_filename_prefers_extended_value() {
        assert_eq!(
            parse_content_disposition_filename(
                r#"attachment; filename="legacy.txt"; filename*=UTF-8''extended.txt"#
            ),
            Some("extended.txt".to_string())
        );
    }

    #[test]
    fn content_disposition_filename_skips_malformed_parameters() {
        assert_eq!(
            parse_content_disposition_filename(r#"attachment; bad-param; filename="ok.txt""#),
            Some("ok.txt".to_string())
        );
    }

    #[tokio::test]
    async fn write_output_overwrites_existing_file_with_clobber() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("download.txt");
        std::fs::write(&path, b"old").unwrap();

        write_output(path.to_str().unwrap(), b"new", true)
            .await
            .unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }

    #[tokio::test]
    async fn write_output_does_not_overwrite_existing_file_without_clobber() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("download.txt");
        std::fs::write(&path, b"old").unwrap();

        let err = write_output(path.to_str().unwrap(), b"new", false)
            .await
            .unwrap_err();

        assert!(matches!(err, OutputError::FileExists(_)));
        assert_eq!(std::fs::read(&path).unwrap(), b"old");
    }

    #[tokio::test]
    async fn write_output_emits_static_progress_summary_when_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("download.txt");
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let printer = ProgressPrinter::new(SharedBuffer(buffer.clone()), false);
        let progress = WriteProgress::with_printer(printer, false, false, Some(3));

        write_output_with_progress(path.to_str().unwrap(), b"new", false, progress)
            .await
            .unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        let output = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
        assert!(output.contains("Downloaded 3B in "), "{output:?}");
        assert!(
            output.contains(path.to_str().unwrap()),
            "progress output missing absolute path: {output:?}"
        );
    }

    #[tokio::test]
    async fn write_output_async_reader_removes_temp_when_cancelled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("download.txt");
        let mut reader = PendingAfterPartial { wrote: false };

        let result = tokio::time::timeout(
            Duration::from_millis(10),
            write_output_async_reader(
                path.to_str().unwrap(),
                &mut reader,
                false,
                WriteProgress::disabled(),
            ),
        )
        .await;

        assert!(result.is_err());
        assert!(!path.exists());
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(".download"))
            })
            .collect();
        assert!(leftovers.is_empty(), "leftover temp files: {leftovers:?}");
    }
}
