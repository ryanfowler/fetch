use std::fmt;

use prost_reflect::{DynamicMessage, MessageDescriptor, SerializeOptions};

use crate::core::Printer;
use crate::format::json;
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

pub fn format_grpc_stream_with_descriptor_to(
    buf: &[u8],
    desc: &MessageDescriptor,
    message_encoding: &MessageEncoding,
    out: &mut Printer,
) -> Result<(), GrpcFormatError> {
    let frames = framing::read_frames(buf)
        .map_err(|err| GrpcFormatError(format!("failed to read gRPC stream: {err}")))?;
    for frame in &frames {
        format_grpc_frame_with_descriptor_to(frame, desc, message_encoding, out)?;
    }
    Ok(())
}

pub fn format_grpc_frame_with_descriptor_to(
    frame: &framing::Frame,
    desc: &MessageDescriptor,
    message_encoding: &MessageEncoding,
    out: &mut Printer,
) -> Result<(), GrpcFormatError> {
    let data = encoding::decompress_frame(frame, message_encoding)
        .map_err(|err| GrpcFormatError(err.to_string()))?;
    let msg = decode_dynamic_message(data.as_slice(), desc)?;
    let value = dynamic_message_to_json_value(&msg)?;
    json::format_json_value_to(&value, out);
    Ok(())
}

fn decode_dynamic_message(
    bytes: &[u8],
    desc: &MessageDescriptor,
) -> Result<DynamicMessage, GrpcFormatError> {
    DynamicMessage::decode(desc.clone(), bytes)
        .map_err(|err| GrpcFormatError(format!("failed to decode protobuf message: {err}")))
}

fn dynamic_message_to_json_value(
    msg: &DynamicMessage,
) -> Result<serde_json::Value, GrpcFormatError> {
    let options = SerializeOptions::new().use_proto_field_name(true);
    msg.serialize_with_options(serde_json::value::Serializer, &options)
        .map_err(|err| GrpcFormatError(format!("failed to format protobuf JSON: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::framing::frame;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use prost::Message;
    use prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        field_descriptor_proto::{Label, Type},
    };
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

    #[test]
    fn descriptor_stream_outputs_proto_json() {
        let desc = test_response_descriptor();
        let body = frame(b"\x08\x03", false).unwrap();
        let mut out = Printer::new(false);

        format_grpc_stream_with_descriptor_to(&body, &desc, &MessageEncoding::Identity, &mut out)
            .unwrap();

        assert_eq!(out.into_string().unwrap(), "{\n  \"count\": \"3\"\n}\n");
    }

    #[test]
    fn descriptor_stream_decodes_gzip_messages() {
        let desc = test_response_descriptor();
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"\x08\x03").unwrap();
        let body = frame(&encoder.finish().unwrap(), true).unwrap();
        let mut out = Printer::new(false);

        format_grpc_stream_with_descriptor_to(&body, &desc, &MessageEncoding::Gzip, &mut out)
            .unwrap();

        assert!(out.into_string().unwrap().contains("\"count\": \"3\""));
    }

    #[test]
    fn descriptor_stream_preserves_empty_messages() {
        let desc = test_response_descriptor();
        let mut body = frame(&[], false).unwrap();
        body.extend_from_slice(&frame(b"\x08\x03", false).unwrap());
        let mut out = Printer::new(false);

        format_grpc_stream_with_descriptor_to(&body, &desc, &MessageEncoding::Identity, &mut out)
            .unwrap();

        assert_eq!(out.into_string().unwrap(), "{}\n{\n  \"count\": \"3\"\n}\n");
    }

    #[test]
    fn descriptor_frame_uses_json_color_policy() {
        let desc = test_response_descriptor();
        let body = frame(b"\x08\x03", false).unwrap();
        let frames = framing::read_frames(&body).unwrap();
        let mut out = Printer::new(true);

        format_grpc_frame_with_descriptor_to(
            &frames[0],
            &desc,
            &MessageEncoding::Identity,
            &mut out,
        )
        .unwrap();

        let out = out.into_string().unwrap();
        assert!(out.contains("\x1b[34m\x1b[1mcount\x1b[0m"));
        assert!(out.contains("\x1b[32m3\x1b[0m"));
    }

    fn test_response_descriptor() -> MessageDescriptor {
        let fds = FileDescriptorSet {
            file: vec![FileDescriptorProto {
                name: Some("stream.proto".to_string()),
                package: Some("streampkg".to_string()),
                syntax: Some("proto3".to_string()),
                message_type: vec![DescriptorProto {
                    name: Some("StreamResponse".to_string()),
                    field: vec![FieldDescriptorProto {
                        name: Some("count".to_string()),
                        number: Some(1),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::Int64 as i32),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        let pool = prost_reflect::DescriptorPool::decode(fds.encode_to_vec().as_slice()).unwrap();
        pool.get_message_by_name("streampkg.StreamResponse")
            .unwrap()
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
