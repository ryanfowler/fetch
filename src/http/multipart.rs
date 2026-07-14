use std::future::Future;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::Stream;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

use crate::format::content_type;

#[derive(Debug, Error)]
pub enum MultipartError {
    #[error("file does not exist: '{0}'")]
    FileDoesNotExist(String),
    #[error("file is not a regular file; use @- to stream stdin: '{0}'")]
    FileIsNotRegular(String),
    #[error("invalid multipart {kind}: value contains ASCII control character")]
    InvalidDispositionValue { kind: &'static str },
    #[error("multipart body is too large to compute Content-Length")]
    BodyTooLarge,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct Multipart {
    fields: Vec<Field>,
    boundary: String,
}

#[derive(Debug, Clone)]
struct Field {
    header: String,
    value: FieldValue,
}

#[derive(Debug, Clone)]
enum FieldValue {
    Text(String),
    File(FilePart),
}

#[derive(Debug, Clone)]
struct FilePart {
    path: PathBuf,
    len: u64,
}

impl Multipart {
    pub fn from_cli_fields(values: &[String]) -> Result<Option<Self>, MultipartError> {
        if values.is_empty() {
            return Ok(None);
        }

        let mut fields = Vec::with_capacity(values.len());
        for raw in values {
            let (name, value) = raw.split_once('=').unwrap_or((raw, ""));
            let name = name.trim().to_string();
            validate_multipart_disposition_value("field name", &name)?;
            let field = if let Some(path) = value.strip_prefix('@') {
                let path = crate::fileutil::expand_home(path);
                file_field(&name, path)?
            } else {
                text_field(&name, value)
            };
            fields.push(field);
        }

        Ok(Some(Self {
            fields,
            boundary: random_boundary(),
        }))
    }

    pub fn content_type(&self) -> String {
        format!("multipart/form-data; boundary={}", self.boundary)
    }

    pub fn open(&self) -> Result<Vec<u8>, MultipartError> {
        let mut out = Vec::new();
        self.write_to(&mut out)?;
        Ok(out)
    }

    pub fn preview(&self, limit: usize) -> Result<(Vec<u8>, bool), MultipartError> {
        let total_len = self.content_len()?;
        let truncated = total_len > u64::try_from(limit).unwrap_or(u64::MAX);
        let capacity = usize::try_from(total_len).unwrap_or(usize::MAX).min(limit);
        let mut out = Vec::with_capacity(capacity);

        for field in &self.fields {
            append_preview(&mut out, limit, b"--");
            append_preview(&mut out, limit, self.boundary.as_bytes());
            append_preview(&mut out, limit, b"\r\n");
            if out.len() >= limit {
                return Ok((out, truncated));
            }

            match &field.value {
                FieldValue::Text(value) => {
                    append_preview(&mut out, limit, field.header.as_bytes());
                    append_preview(&mut out, limit, value.as_bytes());
                    append_preview(&mut out, limit, b"\r\n");
                }
                FieldValue::File(file) => {
                    append_preview(&mut out, limit, field.header.as_bytes());
                    if out.len() < limit {
                        let remaining = limit - out.len();
                        let mut input = open_file_part(file)?;
                        let read_limit = file.len.min(u64::try_from(remaining).unwrap_or(u64::MAX));
                        let copied = Read::by_ref(&mut input)
                            .take(read_limit)
                            .read_to_end(&mut out)?;
                        if u64::try_from(copied).unwrap_or(u64::MAX) != read_limit {
                            return Err(premature_file_eof().into());
                        }
                    }
                    append_preview(&mut out, limit, b"\r\n");
                }
            }

            if out.len() >= limit {
                return Ok((out, truncated));
            }
        }

        append_preview(&mut out, limit, b"--");
        append_preview(&mut out, limit, self.boundary.as_bytes());
        append_preview(&mut out, limit, b"--\r\n");
        Ok((out, truncated))
    }

    pub fn write_to<W: Write>(&self, mut out: W) -> Result<(), MultipartError> {
        for field in &self.fields {
            out.write_all(b"--")?;
            out.write_all(self.boundary.as_bytes())?;
            out.write_all(b"\r\n")?;

            match &field.value {
                FieldValue::Text(value) => {
                    out.write_all(field.header.as_bytes())?;
                    out.write_all(value.as_bytes())?;
                    out.write_all(b"\r\n")?;
                }
                FieldValue::File(file) => {
                    out.write_all(field.header.as_bytes())?;
                    let input = open_file_part(file)?;
                    copy_file_exact(input, &mut out, file.len)?;
                    out.write_all(b"\r\n")?;
                }
            }
        }

        out.write_all(b"--")?;
        out.write_all(self.boundary.as_bytes())?;
        out.write_all(b"--\r\n")?;
        Ok(())
    }

    pub fn content_len(&self) -> Result<u64, MultipartError> {
        self.content_len_with_file_len(|file| Ok(file.len))
    }

    fn content_len_with_file_len(
        &self,
        mut file_len: impl FnMut(&FilePart) -> Result<u64, MultipartError>,
    ) -> Result<u64, MultipartError> {
        let mut len = 0_u64;
        for field in &self.fields {
            add_len(&mut len, 2)?;
            add_usize_len(&mut len, self.boundary.len())?;
            add_len(&mut len, 2)?;
            match &field.value {
                FieldValue::Text(value) => {
                    add_usize_len(&mut len, field.header.len())?;
                    add_usize_len(&mut len, value.len())?;
                }
                FieldValue::File(file) => {
                    add_usize_len(&mut len, field.header.len())?;
                    add_len(&mut len, file_len(file)?)?;
                }
            }
            add_len(&mut len, 2)?;
        }
        add_len(&mut len, 2)?;
        add_usize_len(&mut len, self.boundary.len())?;
        add_len(&mut len, 4)?;
        Ok(len)
    }

    pub fn stream(&self) -> MultipartStream {
        MultipartStream {
            multipart: self.clone(),
            index: 0,
            state: MultipartStreamState::Field,
        }
    }
}

fn add_len(len: &mut u64, amount: u64) -> Result<(), MultipartError> {
    *len = len
        .checked_add(amount)
        .ok_or(MultipartError::BodyTooLarge)?;
    Ok(())
}

fn add_usize_len(len: &mut u64, amount: usize) -> Result<(), MultipartError> {
    let amount = u64::try_from(amount).map_err(|_| MultipartError::BodyTooLarge)?;
    add_len(len, amount)
}

fn append_preview(out: &mut Vec<u8>, limit: usize, bytes: &[u8]) {
    let remaining = limit.saturating_sub(out.len());
    out.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
}

fn random_boundary() -> String {
    format!("fetch-{:032x}", rand::random::<u128>())
}

fn validate_file_path(path: &Path) -> Result<std::fs::Metadata, MultipartError> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(MultipartError::FileDoesNotExist(path.display().to_string()));
        }
        Err(err) => return Err(err.into()),
    };
    if !metadata.file_type().is_file() {
        return Err(MultipartError::FileIsNotRegular(path.display().to_string()));
    }
    Ok(metadata)
}

fn validate_opened_file_part(
    file: &FilePart,
    metadata: &std::fs::Metadata,
) -> Result<(), MultipartError> {
    if !metadata.file_type().is_file() {
        return Err(MultipartError::FileIsNotRegular(
            file.path.display().to_string(),
        ));
    }
    if metadata.len() != file.len {
        return Err(MultipartError::Io(std::io::Error::other(format!(
            "file '{}' changed size while preparing the multipart body",
            file.path.display()
        ))));
    }
    Ok(())
}

fn open_file_part(file: &FilePart) -> Result<std::fs::File, MultipartError> {
    let opened = std::fs::File::open(&file.path)?;
    validate_opened_file_part(file, &opened.metadata()?)?;
    Ok(opened)
}

fn premature_file_eof() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "multipart file ended before its expected length",
    )
}

fn copy_file_exact(
    input: impl Read,
    out: &mut impl Write,
    expected_len: u64,
) -> Result<(), MultipartError> {
    let copied = std::io::copy(&mut input.take(expected_len), out)?;
    if copied != expected_len {
        return Err(premature_file_eof().into());
    }
    Ok(())
}

async fn open_file_part_async(file: &FilePart) -> Result<tokio::fs::File, MultipartError> {
    let opened = tokio::fs::File::open(&file.path).await?;
    validate_opened_file_part(file, &opened.metadata().await?)?;
    Ok(opened)
}

fn escape_multipart_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn text_header(name: &str) -> String {
    format!(
        "Content-Disposition: form-data; name=\"{}\"\r\n\r\n",
        escape_multipart_string(name)
    )
}

fn text_field(name: &str, value: &str) -> Field {
    Field {
        header: text_header(name),
        value: FieldValue::Text(value.to_string()),
    }
}

fn file_field(name: &str, path: PathBuf) -> Result<Field, MultipartError> {
    let metadata = validate_file_path(&path)?;
    let filename = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    validate_multipart_disposition_value("filename", &filename)?;
    let content_type = detect_content_type(&path)?;

    Ok(Field {
        header: file_header(name, &filename, content_type),
        value: FieldValue::File(FilePart {
            path,
            len: metadata.len(),
        }),
    })
}

fn file_header(name: &str, filename: &str, content_type: &str) -> String {
    format!(
        "Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\nContent-Type: {}\r\n\r\n",
        escape_multipart_string(name),
        escape_multipart_string(filename),
        content_type,
    )
}

fn validate_multipart_disposition_value(
    kind: &'static str,
    value: &str,
) -> Result<(), MultipartError> {
    if value.chars().any(|ch| ch.is_ascii_control()) {
        return Err(MultipartError::InvalidDispositionValue { kind });
    }
    Ok(())
}

fn detect_content_type(path: &Path) -> Result<&'static str, MultipartError> {
    if let Some(content_type) = content_type::request_content_type_for_path(path) {
        return Ok(content_type);
    }
    let mut file = std::fs::File::open(path)?;
    let mut bytes = [0_u8; 512];
    let len = file.read(&mut bytes)?;
    Ok(sniff_content_type(&bytes[..len]))
}

fn sniff_content_type(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(b"\xff\xd8\xff") {
        "image/jpeg"
    } else if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        "image/png"
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        "image/gif"
    } else if bytes.starts_with(b"%PDF-") {
        "application/pdf"
    } else {
        "application/octet-stream"
    }
}

pub struct MultipartStream {
    multipart: Multipart,
    index: usize,
    state: MultipartStreamState,
}

type OpenFileFuture = Pin<Box<dyn Future<Output = Result<tokio::fs::File, MultipartError>> + Send>>;

enum MultipartStreamState {
    Field,
    OpeningFile {
        header: Bytes,
        open: OpenFileFuture,
    },
    File {
        file: tokio::io::Take<tokio::fs::File>,
        remaining: u64,
    },
    FileCrlf,
    Done,
}

impl Stream for MultipartStream {
    type Item = Result<Bytes, MultipartError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match &mut self.state {
                MultipartStreamState::Field => {
                    if self.index >= self.multipart.fields.len() {
                        self.state = MultipartStreamState::Done;
                        let closing = format!("--{}--\r\n", self.multipart.boundary);
                        return Poll::Ready(Some(Ok(Bytes::from(closing))));
                    }

                    let field = &self.multipart.fields[self.index];
                    match &field.value {
                        FieldValue::Text(value) => {
                            let mut chunk = Vec::new();
                            chunk.extend_from_slice(b"--");
                            chunk.extend_from_slice(self.multipart.boundary.as_bytes());
                            chunk.extend_from_slice(b"\r\n");
                            chunk.extend_from_slice(field.header.as_bytes());
                            chunk.extend_from_slice(value.as_bytes());
                            chunk.extend_from_slice(b"\r\n");
                            self.index += 1;
                            return Poll::Ready(Some(Ok(Bytes::from(chunk))));
                        }
                        FieldValue::File(file) => {
                            let mut chunk = Vec::new();
                            chunk.extend_from_slice(b"--");
                            chunk.extend_from_slice(self.multipart.boundary.as_bytes());
                            chunk.extend_from_slice(b"\r\n");
                            chunk.extend_from_slice(field.header.as_bytes());
                            let file_part = file.clone();
                            self.state = MultipartStreamState::OpeningFile {
                                header: Bytes::from(chunk),
                                open: Box::pin(
                                    async move { open_file_part_async(&file_part).await },
                                ),
                            };
                            continue;
                        }
                    }
                }
                MultipartStreamState::OpeningFile { header, open } => {
                    let file = match open.as_mut().poll(cx) {
                        Poll::Ready(Ok(file)) => file,
                        Poll::Ready(Err(err)) => {
                            self.state = MultipartStreamState::Done;
                            return Poll::Ready(Some(Err(err)));
                        }
                        Poll::Pending => return Poll::Pending,
                    };
                    let header = std::mem::replace(header, Bytes::new());
                    let file_len = match &self.multipart.fields[self.index].value {
                        FieldValue::File(file) => file.len,
                        FieldValue::Text(_) => 0,
                    };
                    self.state = MultipartStreamState::File {
                        file: file.take(file_len),
                        remaining: file_len,
                    };
                    return Poll::Ready(Some(Ok(header)));
                }
                MultipartStreamState::File { file, remaining } => {
                    if *remaining == 0 {
                        self.state = MultipartStreamState::FileCrlf;
                        continue;
                    }
                    let mut bytes = [0_u8; 8192];
                    let read_len = bytes
                        .len()
                        .min(usize::try_from(*remaining).unwrap_or(usize::MAX));
                    let mut read_buf = ReadBuf::new(&mut bytes[..read_len]);
                    match Pin::new(file).poll_read(cx, &mut read_buf) {
                        Poll::Ready(Ok(())) if read_buf.filled().is_empty() => {
                            self.state = MultipartStreamState::Done;
                            return Poll::Ready(Some(Err(premature_file_eof().into())));
                        }
                        Poll::Ready(Ok(())) => {
                            *remaining = remaining.saturating_sub(read_buf.filled().len() as u64);
                            return Poll::Ready(Some(Ok(Bytes::copy_from_slice(
                                read_buf.filled(),
                            ))));
                        }
                        Poll::Ready(Err(err)) => {
                            self.state = MultipartStreamState::Done;
                            return Poll::Ready(Some(Err(err.into())));
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
                MultipartStreamState::FileCrlf => {
                    self.index += 1;
                    self.state = MultipartStreamState::Field;
                    return Poll::Ready(Some(Ok(Bytes::from_static(b"\r\n"))));
                }
                MultipartStreamState::Done => return Poll::Ready(None),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;

    #[test]
    fn multipart_small_json_file_uses_detected_content_type() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.json");
        std::fs::write(&path, br#"{"key":"val"}"#).unwrap();
        let multipart = Multipart::from_cli_fields(&[format!("key1=@{}", path.display())])
            .unwrap()
            .unwrap();

        let body = String::from_utf8(multipart.open().unwrap()).unwrap();

        assert!(body.contains("Content-Type: application/json"));
        assert!(body.contains("filename=\"payload.json\""));
        assert!(body.contains(r#"{"key":"val"}"#));
    }

    #[test]
    fn multipart_file_uses_base_name_in_content_disposition() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret").join("report.pdf");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"%PDF-1.7").unwrap();
        let multipart = Multipart::from_cli_fields(&[format!("file=@{}", path.display())])
            .unwrap()
            .unwrap();

        let body = String::from_utf8(multipart.open().unwrap()).unwrap();

        assert!(body.contains("filename=\"report.pdf\""));
        assert!(body.contains("Content-Type: application/pdf"));
        assert!(!body.contains("secret/report.pdf"));
    }

    #[test]
    fn multipart_file_without_extension_is_sniffed() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            file.path(),
            [b"\xff\xd8\xff".as_slice(), &[0; 512]].concat(),
        )
        .unwrap();
        let multipart = Multipart::from_cli_fields(&[format!("file=@{}", file.path().display())])
            .unwrap()
            .unwrap();
        let body = multipart.open().unwrap();
        let body_text = String::from_utf8_lossy(&body);

        assert!(body_text.contains("Content-Type: image/jpeg"));
        assert!(body.windows(3).any(|window| window == b"\xff\xd8\xff"));
    }

    #[test]
    fn multipart_open_replays_with_stable_boundary() {
        let multipart = Multipart::from_cli_fields(&["field=value".to_string()])
            .unwrap()
            .unwrap();

        let first = multipart.open().unwrap();
        let second = multipart.open().unwrap();

        assert_eq!(first, second);
        let body = String::from_utf8(first).unwrap();
        assert!(body.contains("name=\"field\""));
        assert!(body.contains("value"));
        assert!(multipart.content_type().contains(&multipart.boundary));
    }

    #[test]
    fn multipart_content_len_matches_open_body_len() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.txt");
        std::fs::write(&path, b"file payload").unwrap();
        let multipart = Multipart::from_cli_fields(&[
            "field=value".to_string(),
            format!("file=@{}", path.display()),
        ])
        .unwrap()
        .unwrap();
        let body = multipart.open().unwrap();

        assert_eq!(multipart.content_len().unwrap(), body.len() as u64);
    }

    #[test]
    fn multipart_preview_rechecks_captured_file_len() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.txt");
        std::fs::write(&path, b"old").unwrap();
        let multipart = Multipart::from_cli_fields(&[format!("file=@{}", path.display())])
            .unwrap()
            .unwrap();
        std::fs::write(&path, b"new contents").unwrap();

        let err = multipart.preview(1024).unwrap_err();

        assert!(err.to_string().contains("changed size"));
    }

    #[test]
    fn copy_file_exact_rejects_a_short_reader() {
        let mut out = Vec::new();

        let err = copy_file_exact(std::io::Cursor::new(b"short"), &mut out, 10).unwrap_err();

        assert!(matches!(
            err,
            MultipartError::Io(ref err) if err.kind() == std::io::ErrorKind::UnexpectedEof
        ));
    }

    #[tokio::test]
    async fn multipart_stream_rejects_file_truncated_after_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.txt");
        std::fs::write(&path, b"expected payload").unwrap();
        let multipart = Multipart::from_cli_fields(&[format!("file=@{}", path.display())])
            .unwrap()
            .unwrap();
        let mut stream = multipart.stream();

        assert!(stream.next().await.unwrap().is_ok());
        std::fs::write(&path, b"").unwrap();
        let err = stream.next().await.unwrap().unwrap_err();

        assert!(matches!(
            err,
            MultipartError::Io(ref err) if err.kind() == std::io::ErrorKind::UnexpectedEof
        ));
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn multipart_stream_is_terminal_after_file_open_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.txt");
        std::fs::write(&path, b"payload").unwrap();
        let multipart = Multipart::from_cli_fields(&[format!("file=@{}", path.display())])
            .unwrap()
            .unwrap();
        std::fs::remove_file(path).unwrap();
        let mut stream = multipart.stream();

        assert!(stream.next().await.unwrap().is_err());
        assert!(stream.next().await.is_none());
    }

    #[test]
    fn multipart_content_len_reports_body_too_large_on_overflow() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.txt");
        std::fs::write(&path, b"x").unwrap();
        let multipart = Multipart::from_cli_fields(&[format!("file=@{}", path.display())])
            .unwrap()
            .unwrap();

        let err = multipart
            .content_len_with_file_len(|_| Ok(u64::MAX))
            .unwrap_err();

        assert!(matches!(err, MultipartError::BodyTooLarge));
    }

    #[test]
    fn multipart_text_field_preserves_value_spaces_after_equals() {
        let multipart = Multipart::from_cli_fields(&[" note = hello ".to_string()])
            .unwrap()
            .unwrap();

        let body = String::from_utf8(multipart.open().unwrap()).unwrap();

        assert!(body.contains("name=\"note\""));
        assert!(body.contains("\r\n\r\n hello \r\n"));
    }

    #[test]
    fn multipart_validates_file_fields() {
        let missing = tempfile::tempdir().unwrap().path().join("missing.txt");
        let err =
            Multipart::from_cli_fields(&[format!("file=@{}", missing.display())]).unwrap_err();
        assert!(err.to_string().contains("file does not exist"));

        let dir = tempfile::tempdir().unwrap();
        let err =
            Multipart::from_cli_fields(&[format!("file=@{}", dir.path().display())]).unwrap_err();
        assert!(err.to_string().contains("file is not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn multipart_rejects_non_regular_file_fields() {
        let err = Multipart::from_cli_fields(&["file=@/dev/null".to_string()]).unwrap_err();

        assert!(err.to_string().contains("file is not a regular file"));
    }

    #[test]
    fn multipart_rejects_control_characters_in_field_names() {
        let err = Multipart::from_cli_fields(&["name\r\nX-Evil: 1=value".to_string()]).unwrap_err();

        assert!(err.to_string().contains("invalid multipart field name"));
    }

    #[cfg(unix)]
    #[test]
    fn multipart_rejects_control_characters_in_filenames() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evil\nname.txt");
        std::fs::write(&path, b"payload").unwrap();
        let err = Multipart::from_cli_fields(&[format!("file=@{}", path.display())]).unwrap_err();

        assert!(err.to_string().contains("invalid multipart filename"));
    }
}
