use prost::Message;
use prost_reflect::{DynamicMessage, MessageDescriptor, MethodDescriptor, SerializeOptions};
use serde::de::IntoDeserializer;

use crate::error::FetchError;
use crate::grpc::encoding::{self, MessageEncoding};
use crate::grpc::framing;
use crate::proto::ProtoError;

pub(crate) fn grpc_request_body(
    body: crate::http::RequestBody,
    method: Option<&MethodDescriptor>,
) -> Result<crate::http::RequestBody, FetchError> {
    let Some(method) = method else {
        return frame_raw_body(body);
    };

    if method.is_client_streaming() {
        let Some(body) = body else {
            return Ok(None);
        };
        return Ok(Some(
            crate::http::RequestBodyPayload::from_grpc_json_stream(
                body,
                method.input(),
                Some(grpc_content_type()),
            ),
        ));
    }

    let limit_error = grpc_request_body_limit_error();
    let raw = if let Some((bytes, _)) =
        crate::http::request_body_into_bytes_limited(body, framing::MAX_MESSAGE_SIZE, &limit_error)?
    {
        json_to_protobuf(&bytes, &method.input())
            .map_err(|err| FetchError::Message(err.to_string()))?
    } else {
        Vec::new()
    };
    Ok(Some(crate::http::RequestBodyPayload::from_bytes(
        framing::frame(&raw, false).map_err(|err| FetchError::Message(err.to_string()))?,
        Some(grpc_content_type()),
    )))
}

pub fn format_grpc_stream_with_descriptor(
    bytes: &[u8],
    desc: &MessageDescriptor,
    message_encoding: &MessageEncoding,
) -> Result<String, ProtoError> {
    let frames = framing::read_frames(bytes)
        .map_err(|err| ProtoError::Message(format!("failed to read gRPC stream: {err}")))?;
    let mut out = String::new();
    let mut wrote_any = false;
    for frame in &frames {
        let formatted = format_grpc_frame_with_descriptor(frame, desc, message_encoding)?;
        if wrote_any && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&formatted);
        wrote_any = true;
    }
    Ok(out)
}

pub fn format_grpc_frame_with_descriptor(
    frame: &framing::Frame,
    desc: &MessageDescriptor,
    message_encoding: &MessageEncoding,
) -> Result<String, ProtoError> {
    let data = encoding::decompress_frame(frame, message_encoding)
        .map_err(|err| ProtoError::Message(err.to_string()))?;
    let msg = decode_dynamic_message(data.as_slice(), desc)?;
    let mut formatted = String::from_utf8(serialize_dynamic_message_json(&msg, true)?)
        .map_err(|err| ProtoError::Message(format!("failed to format protobuf JSON: {err}")))?;
    formatted.push('\n');
    Ok(formatted)
}

pub fn json_to_protobuf(json: &[u8], desc: &MessageDescriptor) -> Result<Vec<u8>, ProtoError> {
    let mut deserializer = serde_json::Deserializer::from_slice(json);
    let options = prost_reflect::DeserializeOptions::new().deny_unknown_fields(false);
    let msg = DynamicMessage::deserialize_with_options(desc.clone(), &mut deserializer, &options)
        .map_err(|err| ProtoError::Message(err.to_string()))?;
    deserializer
        .end()
        .map_err(|err| ProtoError::Message(err.to_string()))?;
    Ok(msg.encode_to_vec())
}

pub fn protobuf_to_json(bytes: &[u8], desc: &MessageDescriptor) -> Result<Vec<u8>, ProtoError> {
    let msg = decode_dynamic_message(bytes, desc)?;
    serialize_dynamic_message_json(&msg, true)
}

pub fn protobuf_to_json_compact(
    bytes: &[u8],
    desc: &MessageDescriptor,
) -> Result<Vec<u8>, ProtoError> {
    let msg = decode_dynamic_message(bytes, desc)?;
    serialize_dynamic_message_json(&msg, false)
}

pub(crate) fn json_value_to_grpc_frame(
    value: serde_json::Value,
    desc: &MessageDescriptor,
) -> Result<Vec<u8>, ProtoError> {
    let deserializer = value.into_deserializer();
    let options = prost_reflect::DeserializeOptions::new().deny_unknown_fields(false);
    let msg = match DynamicMessage::deserialize_with_options(desc.clone(), deserializer, &options) {
        Ok(msg) => msg,
        Err(err) => {
            return Err(ProtoError::Message(format!(
                "failed to convert JSON to protobuf: {err}"
            )));
        }
    };
    framing::frame(&msg.encode_to_vec(), false).map_err(|err| ProtoError::Message(err.to_string()))
}

fn frame_raw_body(body: crate::http::RequestBody) -> Result<crate::http::RequestBody, FetchError> {
    let limit_error = grpc_request_body_limit_error();
    let raw = crate::http::request_body_into_bytes_limited(
        body,
        framing::MAX_MESSAGE_SIZE,
        &limit_error,
    )?
    .map(|(bytes, _)| bytes)
    .unwrap_or_default();
    Ok(Some(crate::http::RequestBodyPayload::from_bytes(
        framing::frame(&raw, false).map_err(|err| FetchError::Message(err.to_string()))?,
        Some(grpc_content_type()),
    )))
}

fn grpc_request_body_limit_error() -> String {
    format!(
        "gRPC request body exceeds maximum of {} bytes",
        framing::MAX_MESSAGE_SIZE
    )
}

fn decode_dynamic_message(
    bytes: &[u8],
    desc: &MessageDescriptor,
) -> Result<DynamicMessage, ProtoError> {
    DynamicMessage::decode(desc.clone(), bytes)
        .map_err(|err| ProtoError::Message(format!("failed to decode protobuf message: {err}")))
}

fn serialize_dynamic_message_json(
    msg: &DynamicMessage,
    pretty: bool,
) -> Result<Vec<u8>, ProtoError> {
    let options = SerializeOptions::new().use_proto_field_name(true);
    if pretty {
        let mut serializer = serde_json::Serializer::pretty(Vec::new());
        msg.serialize_with_options(&mut serializer, &options)
            .map_err(|err| ProtoError::Message(format!("failed to format protobuf JSON: {err}")))?;
        return Ok(serializer.into_inner());
    }

    let mut serializer = serde_json::Serializer::new(Vec::new());
    msg.serialize_with_options(&mut serializer, &options)
        .map_err(|err| ProtoError::Message(format!("failed to format protobuf JSON: {err}")))?;
    Ok(serializer.into_inner())
}

fn grpc_content_type() -> String {
    crate::grpc::headers::PROTO_CONTENT_TYPE.to_string()
}
