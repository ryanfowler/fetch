use std::fmt;
use std::io::Read;

use flate2::read::GzDecoder;
use reqwest::header::HeaderMap;

use crate::grpc::framing;

pub const ACCEPT_ENCODING: &str = "gzip";
const ENCODING_HEADER: &str = "grpc-encoding";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageEncoding {
    Identity,
    Gzip,
    Unsupported(String),
    Invalid(String),
}

impl MessageEncoding {
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let Some(value) = headers.get(ENCODING_HEADER) else {
            return Self::Identity;
        };
        match value.to_str() {
            Ok(value) => Self::from_name(value),
            Err(err) => Self::Invalid(err.to_string()),
        }
    }

    pub fn from_name(value: &str) -> Self {
        let value = value.trim();
        if value.is_empty() || value.eq_ignore_ascii_case("identity") {
            Self::Identity
        } else if value.eq_ignore_ascii_case("gzip") {
            Self::Gzip
        } else {
            Self::Unsupported(value.to_ascii_lowercase())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodingError(String);

impl fmt::Display for EncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for EncodingError {}

pub fn decompress_frame(
    frame: &framing::Frame,
    encoding: &MessageEncoding,
) -> Result<Vec<u8>, EncodingError> {
    if !frame.compressed {
        return Ok(frame.data.clone());
    }

    match encoding {
        MessageEncoding::Gzip => decompress_gzip(&frame.data),
        MessageEncoding::Identity => Err(EncodingError(
            "compressed gRPC message uses unsupported grpc-encoding: identity".to_string(),
        )),
        MessageEncoding::Unsupported(encoding) => Err(EncodingError(format!(
            "unsupported gRPC compression encoding: {encoding}"
        ))),
        MessageEncoding::Invalid(err) => Err(EncodingError(format!(
            "invalid grpc-encoding response header: {err}"
        ))),
    }
}

fn decompress_gzip(bytes: &[u8]) -> Result<Vec<u8>, EncodingError> {
    let mut reader = GzDecoder::new(bytes).take(framing::MAX_MESSAGE_SIZE as u64 + 1);
    let mut decoded = Vec::new();
    reader
        .read_to_end(&mut decoded)
        .map_err(|err| EncodingError(format!("gzip gRPC message decompression failed: {err}")))?;
    if decoded.len() > framing::MAX_MESSAGE_SIZE {
        return Err(EncodingError(format!(
            "decompressed gRPC message too large: {} bytes",
            decoded.len()
        )));
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use reqwest::header::HeaderValue;
    use std::io::Write;

    #[test]
    fn parses_grpc_encoding_header() {
        assert_eq!(MessageEncoding::from_name(""), MessageEncoding::Identity);
        assert_eq!(
            MessageEncoding::from_name("identity"),
            MessageEncoding::Identity
        );
        assert_eq!(MessageEncoding::from_name("GZip"), MessageEncoding::Gzip);
        assert_eq!(
            MessageEncoding::from_name("br"),
            MessageEncoding::Unsupported("br".to_string())
        );
    }

    #[test]
    fn parses_grpc_encoding_from_headers() {
        let mut headers = HeaderMap::new();
        assert_eq!(
            MessageEncoding::from_headers(&headers),
            MessageEncoding::Identity
        );

        headers.insert("grpc-encoding", HeaderValue::from_static("gzip"));
        assert_eq!(
            MessageEncoding::from_headers(&headers),
            MessageEncoding::Gzip
        );
    }

    #[test]
    fn decompresses_gzip_frame() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"\x08\x2a").unwrap();
        let compressed = encoder.finish().unwrap();
        let frame = framing::Frame {
            data: compressed,
            compressed: true,
        };

        let decoded = decompress_frame(&frame, &MessageEncoding::Gzip).unwrap();

        assert_eq!(decoded, b"\x08\x2a");
    }

    #[test]
    fn names_unsupported_compressed_encoding() {
        let frame = framing::Frame {
            data: b"payload".to_vec(),
            compressed: true,
        };

        let err =
            decompress_frame(&frame, &MessageEncoding::Unsupported("br".to_string())).unwrap_err();

        assert_eq!(err.to_string(), "unsupported gRPC compression encoding: br");
    }
}
