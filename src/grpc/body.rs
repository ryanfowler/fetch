use http::header::HeaderMap;

use crate::error::FetchError;
use crate::grpc::encoding::{self, MessageEncoding};
use crate::grpc::framing;
use crate::http::transport::{Body, read_body_frame};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FramedBody {
    pub messages: Vec<Vec<u8>>,
    pub trailers: HeaderMap,
}

pub async fn read_framed_body(
    body: Body,
    message_encoding: &MessageEncoding,
) -> Result<FramedBody, FetchError> {
    read_framed_body_with_deadline(body, message_encoding, None).await
}

pub(crate) async fn read_framed_body_with_deadline(
    mut body: Body,
    message_encoding: &MessageEncoding,
    deadline: Option<tokio::time::Instant>,
) -> Result<FramedBody, FetchError> {
    let mut decoder = framing::FrameDecoder::new();
    let mut messages = Vec::new();
    let mut trailers = HeaderMap::new();

    while let Some(frame) = read_body_frame(&mut body, deadline).await? {
        match frame.into_data() {
            Ok(data) => {
                for frame in decoder
                    .push(&data)
                    .map_err(|err| FetchError::Message(err.to_string()))?
                {
                    let data = encoding::decompress_frame(&frame, message_encoding)
                        .map_err(|err| FetchError::Message(err.to_string()))?;
                    messages.push(data);
                }
            }
            Err(frame) => {
                if let Ok(frame_trailers) = frame.into_trailers() {
                    trailers = frame_trailers;
                }
            }
        }
    }

    decoder
        .finish()
        .map_err(|err| FetchError::Message(err.to_string()))?;
    Ok(FramedBody { messages, trailers })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reader_rejects_oversized_message_from_header() {
        let body = Body::wrap_stream(futures_util::stream::iter([Ok::<_, std::io::Error>(
            bytes::Bytes::from_static(&[0x00, 0x04, 0x00, 0x00, 0x01]),
        )]));

        let err = read_framed_body(body, &MessageEncoding::Identity)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("gRPC message too large"));
    }

    #[tokio::test]
    async fn reader_decodes_gzip_messages() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, b"\x3a\x01*").unwrap();
        let compressed = encoder.finish().unwrap();
        let body = Body::wrap_stream(futures_util::stream::iter([Ok::<_, std::io::Error>(
            bytes::Bytes::from(framing::frame(&compressed, true).unwrap()),
        )]));

        let body = read_framed_body(body, &MessageEncoding::Gzip)
            .await
            .unwrap();

        assert_eq!(body.messages, [b"\x3a\x01*".to_vec()]);
    }

    #[tokio::test]
    async fn reader_names_unsupported_compression() {
        let body = Body::wrap_stream(futures_util::stream::iter([Ok::<_, std::io::Error>(
            bytes::Bytes::from(framing::frame(b"payload", true).unwrap()),
        )]));

        let err = read_framed_body(body, &MessageEncoding::Unsupported("br".to_string()))
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "unsupported gRPC compression encoding: br");
    }

    #[tokio::test]
    async fn reader_applies_body_deadline() {
        let body = Body::wrap_stream(futures_util::stream::pending::<
            Result<bytes::Bytes, std::io::Error>,
        >());
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(10);

        let err = read_framed_body_with_deadline(body, &MessageEncoding::Identity, Some(deadline))
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "operation timed out");
    }
}
