use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MultipartError {
    #[error("file does not exist: '{0}'")]
    FileDoesNotExist(String),
    #[error("file is a directory: '{0}'")]
    FileIsDirectory(String),
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
    name: String,
    value: FieldValue,
}

#[derive(Debug, Clone)]
enum FieldValue {
    Text(String),
    File(PathBuf),
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
            let value = value.trim();
            let value = if let Some(path) = value.strip_prefix('@') {
                let path = expand_home(path);
                validate_file(&path)?;
                FieldValue::File(PathBuf::from(path))
            } else {
                FieldValue::Text(value.to_string())
            };
            fields.push(Field { name, value });
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
        for field in &self.fields {
            out.extend_from_slice(b"--");
            out.extend_from_slice(self.boundary.as_bytes());
            out.extend_from_slice(b"\r\n");

            match &field.value {
                FieldValue::Text(value) => {
                    out.extend_from_slice(b"Content-Disposition: form-data; name=\"");
                    out.extend_from_slice(escape_multipart_string(&field.name).as_bytes());
                    out.extend_from_slice(b"\"\r\n\r\n");
                    out.extend_from_slice(value.as_bytes());
                    out.extend_from_slice(b"\r\n");
                }
                FieldValue::File(path) => {
                    let bytes = std::fs::read(path)?;
                    let filename = path
                        .file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    let content_type = detect_content_type(path, &bytes);

                    out.extend_from_slice(b"Content-Disposition: form-data; name=\"");
                    out.extend_from_slice(escape_multipart_string(&field.name).as_bytes());
                    out.extend_from_slice(b"\"; filename=\"");
                    out.extend_from_slice(escape_multipart_string(&filename).as_bytes());
                    out.extend_from_slice(b"\"\r\n");
                    out.extend_from_slice(b"Content-Type: ");
                    out.extend_from_slice(content_type.as_bytes());
                    out.extend_from_slice(b"\r\n\r\n");
                    out.extend_from_slice(&bytes);
                    out.extend_from_slice(b"\r\n");
                }
            }
        }

        out.extend_from_slice(b"--");
        out.extend_from_slice(self.boundary.as_bytes());
        out.extend_from_slice(b"--\r\n");
        Ok(out)
    }
}

fn random_boundary() -> String {
    format!("fetch-{:032x}", rand::random::<u128>())
}

fn validate_file(path: &str) -> Result<(), MultipartError> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(MultipartError::FileDoesNotExist(path.to_string()));
        }
        Err(err) => return Err(err.into()),
    };
    if metadata.is_dir() {
        return Err(MultipartError::FileIsDirectory(path.to_string()));
    }
    Ok(())
}

fn expand_home(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return format!("{}/{}", home.to_string_lossy(), rest);
    }
    path.to_string()
}

fn escape_multipart_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn detect_content_type(path: &Path, bytes: &[u8]) -> &'static str {
    if let Some(content_type) = detect_type_by_extension(path) {
        return content_type;
    }
    sniff_content_type(bytes)
}

fn detect_type_by_extension(path: &Path) -> Option<&'static str> {
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("jpg" | "jpeg") => Some("image/jpeg"),
        Some("png") => Some("image/png"),
        Some("gif") => Some("image/gif"),
        Some("webp") => Some("image/webp"),
        Some("avif") => Some("image/avif"),
        Some("heic" | "heif") => Some("image/heif"),
        Some("jxl") => Some("image/jxl"),
        Some("tif" | "tiff") => Some("image/tiff"),
        Some("bmp") => Some("image/bmp"),
        Some("ico") => Some("image/x-icon"),
        Some("svg") => Some("image/svg+xml"),
        Some("pdf") => Some("application/pdf"),
        Some("json") => Some("application/json"),
        Some("xml") => Some("application/xml"),
        Some("yaml" | "yml") => Some("application/yaml"),
        Some("html" | "htm") => Some("text/html; charset=utf-8"),
        Some("css") => Some("text/css; charset=utf-8"),
        Some("csv") => Some("text/csv; charset=utf-8"),
        Some("txt" | "text") => Some("text/plain; charset=utf-8"),
        _ => None,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn multipart_validates_file_fields() {
        let missing = tempfile::tempdir().unwrap().path().join("missing.txt");
        let err =
            Multipart::from_cli_fields(&[format!("file=@{}", missing.display())]).unwrap_err();
        assert!(err.to_string().contains("file does not exist"));

        let dir = tempfile::tempdir().unwrap();
        let err =
            Multipart::from_cli_fields(&[format!("file=@{}", dir.path().display())]).unwrap_err();
        assert!(err.to_string().contains("file is a directory"));
    }
}
