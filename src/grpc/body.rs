use http::header::HeaderMap;

use crate::error::FetchError;
use crate::grpc::encoding::{self, MessageEncoding};
use crate::grpc::framing;
use crate::http::transport::{Body, BodyDeadline, read_body_frame};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FramedBody {
    pub messages: Vec<Vec<u8>>,
    pub trailers: HeaderMap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FramedBodyLimits {
    context: &'static str,
    max_messages: usize,
    max_total_message_bytes: usize,
}

impl FramedBodyLimits {
    pub(crate) const fn new(
        context: &'static str,
        max_messages: usize,
        max_total_message_bytes: usize,
    ) -> Self {
        Self {
            context,
            max_messages,
            max_total_message_bytes,
        }
    }
}

pub async fn read_framed_body(
    body: Body,
    message_encoding: &MessageEncoding,
) -> Result<FramedBody, FetchError> {
    read_framed_body_with_deadline(body, message_encoding, None).await
}

pub(crate) async fn read_framed_body_with_deadline(
    body: Body,
    message_encoding: &MessageEncoding,
    deadline: Option<BodyDeadline>,
) -> Result<FramedBody, FetchError> {
    read_framed_body_with_deadline_and_limits(body, message_encoding, deadline, None).await
}

pub(crate) async fn read_framed_body_with_deadline_and_limits(
    mut body: Body,
    message_encoding: &MessageEncoding,
    deadline: Option<BodyDeadline>,
    limits: Option<FramedBodyLimits>,
) -> Result<FramedBody, FetchError> {
    let mut decoder = framing::FrameDecoder::new();
    let mut messages = Vec::new();
    let mut total_message_bytes = 0_usize;
    let mut trailers = HeaderMap::new();

    while let Some(frame) = read_body_frame(&mut body, deadline.as_ref()).await? {
        match frame.into_data() {
            Ok(data) => {
                for frame in decoder
                    .push(&data)
                    .map_err(|err| FetchError::Message(err.to_string()))?
                {
                    let data = encoding::decompress_frame(&frame, message_encoding)
                        .map_err(|err| FetchError::Message(err.to_string()))?;
                    push_message(&mut messages, &mut total_message_bytes, data, limits)?;
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

fn push_message(
    messages: &mut Vec<Vec<u8>>,
    total_message_bytes: &mut usize,
    data: Vec<u8>,
    limits: Option<FramedBodyLimits>,
) -> Result<(), FetchError> {
    if let Some(limits) = limits {
        let next_message_count = messages.len() + 1;
        if next_message_count > limits.max_messages {
            return Err(FetchError::Message(format!(
                "{} contains too many messages: limit is {}",
                limits.context, limits.max_messages
            )));
        }

        let next_total = total_message_bytes.checked_add(data.len()).ok_or_else(|| {
            FetchError::Message(format!(
                "{} exceeds decoded message limit: limit is {} bytes",
                limits.context, limits.max_total_message_bytes
            ))
        })?;
        if next_total > limits.max_total_message_bytes {
            return Err(FetchError::Message(format!(
                "{} exceeds decoded message limit: {} bytes received, limit is {} bytes",
                limits.context, next_total, limits.max_total_message_bytes
            )));
        }
        *total_message_bytes = next_total;
    }

    messages.push(data);
    Ok(())
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
        let deadline = BodyDeadline::new(std::time::Duration::from_millis(10));

        let err = read_framed_body_with_deadline(body, &MessageEncoding::Identity, Some(deadline))
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "request timed out after 10ms");
    }

    #[tokio::test]
    async fn reader_applies_total_message_limit_across_many_small_frames() {
        let mut payload = Vec::new();
        for _ in 0..5 {
            payload.extend(framing::frame(b"abc", false).unwrap());
        }
        let body = Body::wrap_stream(futures_util::stream::iter([Ok::<_, std::io::Error>(
            bytes::Bytes::from(payload),
        )]));
        let limits = FramedBodyLimits::new("gRPC reflection response", usize::MAX, 12);

        let err = read_framed_body_with_deadline_and_limits(
            body,
            &MessageEncoding::Identity,
            None,
            Some(limits),
        )
        .await
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "gRPC reflection response exceeds decoded message limit: 15 bytes received, limit is 12 bytes"
        );
    }

    #[tokio::test]
    async fn reader_applies_message_count_limit() {
        let mut payload = Vec::new();
        for _ in 0..3 {
            payload.extend(framing::frame(b"abc", false).unwrap());
        }
        let body = Body::wrap_stream(futures_util::stream::iter([Ok::<_, std::io::Error>(
            bytes::Bytes::from(payload),
        )]));
        let limits = FramedBodyLimits::new("gRPC reflection response", 2, usize::MAX);

        let err = read_framed_body_with_deadline_and_limits(
            body,
            &MessageEncoding::Identity,
            None,
            Some(limits),
        )
        .await
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "gRPC reflection response contains too many messages: limit is 2"
        );
    }
}
