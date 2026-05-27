use std::fmt;

use crate::grpc::encoding::{self, MessageEncoding};
use crate::grpc::framing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcFormatError(String);

impl fmt::Display for GrpcFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for GrpcFormatError {}

pub fn format_grpc_stream(
    buf: &[u8],
    message_encoding: &MessageEncoding,
) -> Result<String, GrpcFormatError> {
    let frames = framing::read_frames(buf).map_err(|err| GrpcFormatError(err.to_string()))?;
    let mut out = String::new();

    for (idx, frame) in frames.iter().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        out.push_str(&format_grpc_frame(frame, message_encoding)?);
    }

    Ok(out)
}

pub fn format_grpc_frame(
    frame: &framing::Frame,
    message_encoding: &MessageEncoding,
) -> Result<String, GrpcFormatError> {
    let data = encoding::decompress_frame(frame, message_encoding)
        .map_err(|err| GrpcFormatError(err.to_string()))?;
    crate::format::protobuf::format_protobuf(&data).map_err(|err| GrpcFormatError(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::framing::frame;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    #[test]
    fn test_format_grpc_stream_single_frame() {
        let proto_data = append_bytes(append_varint(Vec::new(), 1, 42), 2, b"hello");
        let output = format_grpc_stream(
            &frame(&proto_data, false).unwrap(),
            &MessageEncoding::Identity,
        )
        .unwrap();
        assert!(output.contains("1:"));
        assert!(output.contains("42"));
        assert!(output.contains("2:"));
        assert!(output.contains("\"hello\""));
    }

    #[test]
    fn test_format_grpc_stream_multiple_frames() {
        let frame1 = frame(&append_varint(Vec::new(), 1, 100), false).unwrap();
        let frame2 = frame(&append_varint(Vec::new(), 1, 200), false).unwrap();
        let frame3 = frame(&append_varint(Vec::new(), 1, 300), false).unwrap();

        let mut stream = Vec::new();
        stream.extend_from_slice(&frame1);
        stream.extend_from_slice(&frame2);
        stream.extend_from_slice(&frame3);

        let output = format_grpc_stream(&stream, &MessageEncoding::Identity).unwrap();
        assert!(output.contains("100"));
        assert!(output.contains("200"));
        assert!(output.contains("300"));
    }

    #[test]
    fn test_format_grpc_stream_empty_stream_and_message() {
        assert_eq!(
            format_grpc_stream(&[], &MessageEncoding::Identity).unwrap(),
            ""
        );
        assert_eq!(
            format_grpc_stream(&frame(&[], false).unwrap(), &MessageEncoding::Identity).unwrap(),
            ""
        );
    }

    #[test]
    fn test_format_grpc_stream_gzip_compressed_frame() {
        let proto_data = append_bytes(Vec::new(), 1, b"compressed payload");
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&proto_data).unwrap();
        let compressed = encoder.finish().unwrap();

        let out =
            format_grpc_stream(&frame(&compressed, true).unwrap(), &MessageEncoding::Gzip).unwrap();

        assert!(out.contains("\"compressed payload\""));
    }

    #[test]
    fn test_format_grpc_stream_unsupported_compressed_frame() {
        let err = format_grpc_stream(
            &frame(b"compressed payload", true).unwrap(),
            &MessageEncoding::Unsupported("br".to_string()),
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported gRPC compression encoding: br")
        );
    }

    #[test]
    fn test_format_grpc_stream_error_mid_stream() {
        let mut stream = frame(&append_varint(Vec::new(), 1, 42), false).unwrap();
        stream.extend_from_slice(&[0x00, 0x00]);
        assert!(format_grpc_stream(&stream, &MessageEncoding::Identity).is_err());
    }

    #[test]
    fn test_format_grpc_stream_multiple_frames_with_multi_field_messages() {
        let msg1 = append_bytes(append_varint(Vec::new(), 1, 10), 2, b"first");
        let msg2 = append_bytes(append_varint(Vec::new(), 1, 20), 2, b"second");

        let mut stream = Vec::new();
        stream.extend_from_slice(&frame(&msg1, false).unwrap());
        stream.extend_from_slice(&frame(&msg2, false).unwrap());

        let output = format_grpc_stream(&stream, &MessageEncoding::Identity).unwrap();
        assert!(output.contains("10"));
        assert!(output.contains("\"first\""));
        assert!(output.contains("20"));
        assert!(output.contains("\"second\""));
    }

    fn append_varint(mut bytes: Vec<u8>, field_number: u64, value: u64) -> Vec<u8> {
        append_tag(&mut bytes, field_number, 0);
        append_raw_varint(&mut bytes, value);
        bytes
    }

    fn append_bytes(mut bytes: Vec<u8>, field_number: u64, value: &[u8]) -> Vec<u8> {
        append_tag(&mut bytes, field_number, 2);
        append_raw_varint(&mut bytes, value.len() as u64);
        bytes.extend_from_slice(value);
        bytes
    }

    fn append_tag(bytes: &mut Vec<u8>, field_number: u64, wire_type: u64) {
        append_raw_varint(bytes, (field_number << 3) | wire_type);
    }

    fn append_raw_varint(bytes: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            bytes.push(((value as u8) & 0x7f) | 0x80);
            value >>= 7;
        }
        bytes.push(value as u8);
    }
}
