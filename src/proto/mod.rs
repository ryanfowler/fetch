use prost::Message;
use prost_reflect::{
    Cardinality, DescriptorPool, DynamicMessage, FieldDescriptor, Kind, MessageDescriptor,
    MethodDescriptor, SerializeOptions, ServiceDescriptor,
};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::FetchError;
use crate::grpc::framing;

#[derive(Debug, Clone)]
pub struct Schema {
    pool: DescriptorPool,
}

impl Schema {
    pub fn from_descriptor_set(bytes: &[u8]) -> Result<Self, ProtoError> {
        let pool = DescriptorPool::decode(bytes).map_err(|err| {
            ProtoError::Message(format!("failed to create file descriptors: {err}"))
        })?;
        Ok(Self { pool })
    }

    pub fn from_file_descriptor_protos(files: &[Vec<u8>]) -> Result<Self, ProtoError> {
        let mut pool = DescriptorPool::new();
        let mut seen = std::collections::BTreeSet::new();
        for file in files {
            let name = reflected_file_name(file)?;
            if !seen.insert(name) {
                continue;
            }
            pool.decode_file_descriptor_proto(file.as_slice())
                .map_err(|err| {
                    ProtoError::Message(format!("failed to decode reflected descriptor: {err}"))
                })?;
        }
        Ok(Self { pool })
    }

    pub fn load_descriptor_set_file(path: &str) -> Result<Self, FetchError> {
        let bytes = std::fs::read(path).map_err(|err| {
            FetchError::Message(format!("failed to read descriptor set file: {err}"))
        })?;
        Self::from_descriptor_set(&bytes).map_err(|err| FetchError::Message(err.to_string()))
    }

    pub fn find_method(&self, full_name: &str) -> Result<MethodDescriptor, ProtoError> {
        let (service_name, method_name) = split_method_name(full_name)?;
        let service = self
            .pool
            .get_service_by_name(service_name)
            .ok_or_else(|| ProtoError::Message(format!("service not found: {service_name}")))?;
        let method = service
            .methods()
            .find(|method| method.name() == method_name);
        method.ok_or_else(|| {
            ProtoError::Message(format!(
                "method {method_name} not found in service {service_name}"
            ))
        })
    }

    pub fn find_service(&self, name: &str) -> Option<ServiceDescriptor> {
        self.pool.get_service_by_name(name.trim_start_matches('.'))
    }

    pub fn find_message(&self, name: &str) -> Option<MessageDescriptor> {
        self.pool.get_message_by_name(name.trim_start_matches('.'))
    }

    pub fn messages(&self) -> Vec<String> {
        let mut messages: Vec<_> = self
            .pool
            .all_messages()
            .map(|message| message.full_name().to_string())
            .collect();
        messages.sort();
        messages
    }

    pub fn services(&self) -> Vec<String> {
        let mut services: Vec<_> = self
            .pool
            .services()
            .map(|service| service.full_name().to_string())
            .collect();
        services.sort();
        services
    }
}

pub fn execute_local_discovery(cli: &crate::cli::Cli) -> Result<i32, FetchError> {
    let Some(schema) = load_local_schema(cli)? else {
        return Err("gRPC discovery requires --proto-file or --proto-desc".into());
    };

    if cli.grpc_list {
        for service in schema.services() {
            println!("{service}");
        }
        return Ok(0);
    }

    if let Some(symbol) = cli.grpc_describe.as_deref() {
        print!("{}", describe_symbol(&schema, symbol)?);
        return Ok(0);
    }

    Err("gRPC discovery requires --grpc-list or --grpc-describe".into())
}

pub fn load_local_schema(cli: &crate::cli::Cli) -> Result<Option<Schema>, FetchError> {
    let proto_files = proto_file_paths(&cli.proto_files);
    if !proto_files.is_empty() {
        return compile_protos(&proto_files, &cli.proto_imports)
            .map(Some)
            .map_err(|err| FetchError::Message(err.to_string()));
    }
    cli.proto_desc
        .as_deref()
        .map(Schema::load_descriptor_set_file)
        .transpose()
}

pub fn proto_file_paths(values: &[String]) -> Vec<String> {
    values
        .iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

pub fn compile_protos(
    proto_files: &[String],
    import_paths: &[String],
) -> Result<Schema, ProtoError> {
    let descriptor_path = TempDescriptorSet::create()?;
    let mut command = Command::new("protoc");
    command
        .arg(format!(
            "--descriptor_set_out={}",
            descriptor_path.path().display()
        ))
        .arg("--include_imports");

    if import_paths.is_empty() {
        for dir in default_proto_import_paths(proto_files)? {
            command.arg(format!("-I={}", dir.display()));
        }
    } else {
        for import in import_paths {
            command.arg(format!("-I={import}"));
        }
    }
    for file in proto_files {
        command.arg(file);
    }

    let output = command.output().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            ProtoError::ProtocNotFound
        } else {
            ProtoError::Message(format!("failed to run protoc: {err}"))
        }
    })?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let message = if message.is_empty() {
            exit_status_message(output.status)
        } else {
            message
        };
        return Err(ProtoError::Protoc(message));
    }

    let bytes = std::fs::read(descriptor_path.path())
        .map_err(|err| ProtoError::Message(format!("failed to read descriptor set file: {err}")))?;
    Schema::from_descriptor_set(&bytes)
}

pub fn method_for_url(schema: &Schema, url: &url::Url) -> Result<MethodDescriptor, FetchError> {
    schema
        .find_method(url.path().trim_start_matches('/'))
        .map_err(|err| FetchError::Message(err.to_string()))
}

pub(crate) fn grpc_request_body(
    body: crate::http::RequestBody,
    method: Option<&MethodDescriptor>,
) -> Result<crate::http::RequestBody, FetchError> {
    let Some(method) = method else {
        return frame_raw_body(body);
    };

    if method.is_client_streaming() {
        let Some((bytes, _)) = crate::http::request_body_into_bytes(body)? else {
            return Ok(None);
        };
        return stream_json_to_grpc_frames(&bytes, &method.input())
            .map(|bytes| {
                Some(crate::http::RequestBodyPayload::from_bytes(
                    bytes,
                    Some(grpc_content_type()),
                ))
            })
            .map_err(|err| FetchError::Message(err.to_string()));
    }

    let raw = if let Some((bytes, _)) = crate::http::request_body_into_bytes(body)? {
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
) -> Result<String, ProtoError> {
    let frames = framing::read_frames(bytes)
        .map_err(|err| ProtoError::Message(format!("failed to read gRPC stream: {err}")))?;
    let mut out = String::new();
    for (index, frame) in frames.iter().enumerate() {
        if frame.compressed {
            return Err(ProtoError::Message(
                "compressed gRPC messages are not supported".to_string(),
            ));
        }
        if frame.data.is_empty() {
            continue;
        }
        if index > 0 && !out.ends_with('\n') {
            out.push('\n');
        }
        let msg = decode_dynamic_message(frame.data.as_slice(), desc)?;
        let mut formatted = String::from_utf8(serialize_dynamic_message_json(&msg, true)?)
            .map_err(|err| ProtoError::Message(format!("failed to format protobuf JSON: {err}")))?;
        formatted.push('\n');
        out.push_str(&formatted);
    }
    Ok(out)
}

pub fn describe_symbol(schema: &Schema, symbol: &str) -> Result<String, FetchError> {
    if symbol.contains('/') {
        let method = schema
            .find_method(symbol)
            .map_err(|_| FetchError::Message(format!("symbol not found: {symbol}")))?;
        return Ok(render_method_description(&method));
    }

    if let Some(service) = schema.find_service(symbol) {
        return Ok(render_service_description(&service));
    }
    if let Ok(method) = schema.find_method(symbol) {
        return Ok(render_method_description(&method));
    }
    if let Some(message) = schema.find_message(symbol) {
        return Ok(render_message_description(&message));
    }
    Err(format!("symbol not found: {symbol}").into())
}

fn render_service_description(service: &ServiceDescriptor) -> String {
    let mut out = format!("service {}\n", service.full_name());
    for method in service.methods() {
        out.push('\n');
        out.push_str(method.name());
        out.push('\n');
        out.push_str("  rpc: ");
        out.push_str(rpc_type(&method));
        out.push('\n');
        out.push_str("  request: ");
        out.push_str(method.input().full_name());
        out.push('\n');
        out.push_str("  response: ");
        out.push_str(method.output().full_name());
        out.push('\n');
    }
    out
}

fn render_method_description(method: &MethodDescriptor) -> String {
    let mut out = format!(
        "method {}/{}\n",
        method.parent_service().full_name(),
        method.name()
    );
    out.push_str("rpc: ");
    out.push_str(rpc_type(method));
    out.push('\n');
    out.push_str("request: ");
    out.push_str(method.input().full_name());
    out.push('\n');
    out.push_str("response: ");
    out.push_str(method.output().full_name());
    out.push('\n');
    out
}

fn render_message_description(message: &MessageDescriptor) -> String {
    let mut out = format!("message {}\n", message.full_name());
    for field in message.fields() {
        out.push('\n');
        out.push_str(&format!(
            "{}  {}  {}  {}\n",
            field.number(),
            field.name(),
            field_label(&field),
            field_type(&field)
        ));
    }
    out
}

fn rpc_type(method: &MethodDescriptor) -> &'static str {
    match (method.is_client_streaming(), method.is_server_streaming()) {
        (true, true) => "bidi-stream",
        (true, false) => "client-stream",
        (false, true) => "server-stream",
        (false, false) => "unary",
    }
}

fn field_label(field: &FieldDescriptor) -> &'static str {
    if field.is_list() {
        return "repeated";
    }
    match field.cardinality() {
        Cardinality::Required => "required",
        Cardinality::Optional => "optional",
        Cardinality::Repeated => "repeated",
    }
}

fn field_type(field: &FieldDescriptor) -> String {
    match field.kind() {
        Kind::Message(message) => message.full_name().to_string(),
        Kind::Enum(en) => en.full_name().to_string(),
        Kind::Double => "double".to_string(),
        Kind::Float => "float".to_string(),
        Kind::Int32 => "int32".to_string(),
        Kind::Int64 => "int64".to_string(),
        Kind::Uint32 => "uint32".to_string(),
        Kind::Uint64 => "uint64".to_string(),
        Kind::Sint32 => "sint32".to_string(),
        Kind::Sint64 => "sint64".to_string(),
        Kind::Fixed32 => "fixed32".to_string(),
        Kind::Fixed64 => "fixed64".to_string(),
        Kind::Sfixed32 => "sfixed32".to_string(),
        Kind::Sfixed64 => "sfixed64".to_string(),
        Kind::Bool => "bool".to_string(),
        Kind::String => "string".to_string(),
        Kind::Bytes => "bytes".to_string(),
    }
}

fn frame_raw_body(body: crate::http::RequestBody) -> Result<crate::http::RequestBody, FetchError> {
    let raw = crate::http::request_body_into_bytes(body)?
        .map(|(bytes, _)| bytes)
        .unwrap_or_default();
    Ok(Some(crate::http::RequestBodyPayload::from_bytes(
        framing::frame(&raw, false).map_err(|err| FetchError::Message(err.to_string()))?,
        Some(grpc_content_type()),
    )))
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

pub fn stream_json_to_grpc_frames(
    json_stream: &[u8],
    desc: &MessageDescriptor,
) -> Result<Vec<u8>, ProtoError> {
    let mut out = Vec::new();
    let stream = serde_json::Deserializer::from_slice(json_stream).into_iter::<serde_json::Value>();
    let options = prost_reflect::DeserializeOptions::new().deny_unknown_fields(false);
    for value in stream {
        let value = value
            .map_err(|err| ProtoError::Message(format!("failed to decode JSON message: {err}")))?;
        let value_text = value.to_string();
        let mut deserializer = serde_json::Deserializer::from_str(&value_text);
        let msg =
            DynamicMessage::deserialize_with_options(desc.clone(), &mut deserializer, &options)
                .map_err(|err| {
                    ProtoError::Message(format!("failed to convert JSON to protobuf: {err}"))
                })?;
        deserializer
            .end()
            .map_err(|err| ProtoError::Message(format!("failed to decode JSON message: {err}")))?;
        let frame = framing::frame(&msg.encode_to_vec(), false)
            .map_err(|err| ProtoError::Message(err.to_string()))?;
        out.extend_from_slice(&frame);
    }
    Ok(out)
}

fn split_method_name(full_name: &str) -> Result<(&str, &str), ProtoError> {
    let full_name = full_name.trim_start_matches('/');
    if let Some((service, method)) = full_name.rsplit_once('/') {
        if !service.is_empty() && !method.is_empty() {
            return Ok((service, method));
        }
    } else if let Some((service, method)) = full_name.rsplit_once('.')
        && !service.is_empty()
        && !method.is_empty()
    {
        return Ok((service, method));
    }
    Err(ProtoError::Message(format!(
        "invalid method name format: {full_name} (expected 'Service/Method' or 'Service.Method')"
    )))
}

fn grpc_content_type() -> String {
    "application/grpc+proto".to_string()
}

fn reflected_file_name(file: &[u8]) -> Result<String, ProtoError> {
    let mut raw = file;
    while !raw.is_empty() {
        let (field, wire) = read_key(&mut raw)?;
        if field == 1 && wire == 2 {
            return read_len_string(&mut raw);
        }
        skip_wire_value(wire, &mut raw)?;
    }
    Err(ProtoError::Message(
        "reflected descriptor is missing a file name".to_string(),
    ))
}

fn default_proto_import_paths(proto_files: &[String]) -> Result<Vec<PathBuf>, ProtoError> {
    let cwd = std::env::current_dir()
        .map_err(|err| ProtoError::Message(format!("failed to get current directory: {err}")))?;
    let mut seen = std::collections::HashSet::new();
    let mut dirs = Vec::new();
    for file in proto_files {
        let path = Path::new(file);
        let dir = path
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let abs = if dir.is_absolute() {
            dir.to_path_buf()
        } else {
            cwd.join(dir)
        };
        if seen.insert(abs.clone()) {
            dirs.push(abs);
        }
    }
    Ok(dirs)
}

fn exit_status_message(status: std::process::ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("exit status {code}"),
        None => "process terminated by signal".to_string(),
    }
}

struct TempDescriptorSet {
    path: PathBuf,
}

impl TempDescriptorSet {
    fn create() -> Result<Self, ProtoError> {
        let temp_dir = std::env::temp_dir();
        let pid = std::process::id();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        for attempt in 0..100 {
            let path = temp_dir.join(format!("fetch-proto-{pid}-{nanos}-{attempt}.pb"));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => {
                    drop(file);
                    return Ok(Self { path });
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(ProtoError::Message(format!(
                        "failed to create temp file: {err}"
                    )));
                }
            }
        }
        Err(ProtoError::Message(
            "failed to create temp file: too many collisions".to_string(),
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDescriptorSet {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn read_key(raw: &mut &[u8]) -> Result<(u64, u8), ProtoError> {
    let key = read_varint(raw)?;
    Ok((key >> 3, (key & 0x07) as u8))
}

fn read_varint(raw: &mut &[u8]) -> Result<u64, ProtoError> {
    let mut value = 0_u64;
    for shift in (0..64).step_by(7) {
        let Some((&byte, rest)) = raw.split_first() else {
            return Err(ProtoError::Message(
                "unexpected EOF while reading varint".to_string(),
            ));
        };
        *raw = rest;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(ProtoError::Message("varint overflows uint64".to_string()))
}

fn read_len_bytes(raw: &mut &[u8]) -> Result<Vec<u8>, ProtoError> {
    let len = usize::try_from(read_varint(raw)?)
        .map_err(|_| ProtoError::Message("length overflows usize".to_string()))?;
    if raw.len() < len {
        return Err(ProtoError::Message(
            "unexpected EOF while reading bytes".to_string(),
        ));
    }
    let out = raw[..len].to_vec();
    *raw = &raw[len..];
    Ok(out)
}

fn read_len_string(raw: &mut &[u8]) -> Result<String, ProtoError> {
    String::from_utf8(read_len_bytes(raw)?)
        .map_err(|err| ProtoError::Message(format!("invalid UTF-8 string: {err}")))
}

fn skip_wire_value(wire: u8, raw: &mut &[u8]) -> Result<(), ProtoError> {
    match wire {
        0 => {
            read_varint(raw)?;
        }
        1 => skip_fixed(raw, 8)?,
        2 => {
            let len = usize::try_from(read_varint(raw)?)
                .map_err(|_| ProtoError::Message("length overflows usize".to_string()))?;
            skip_fixed(raw, len)?;
        }
        5 => skip_fixed(raw, 4)?,
        _ => return Err(ProtoError::Message(format!("unsupported wire type {wire}"))),
    }
    Ok(())
}

fn skip_fixed(raw: &mut &[u8], len: usize) -> Result<(), ProtoError> {
    if raw.len() < len {
        return Err(ProtoError::Message(
            "unexpected EOF while skipping field".to_string(),
        ));
    }
    *raw = &raw[len..];
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("{0}")]
    Message(String),
    #[error(
        "protoc not found in PATH. Install protoc from https://github.com/protocolbuffers/protobuf/releases"
    )]
    ProtocNotFound,
    #[error("protoc failed: {0}")]
    Protoc(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        MethodDescriptorProto, ServiceDescriptorProto,
        field_descriptor_proto::{Label, Type},
    };
    use std::path::Path;

    fn stream_descriptor_set() -> Vec<u8> {
        let fds = FileDescriptorSet {
            file: vec![FileDescriptorProto {
                name: Some("stream.proto".to_string()),
                package: Some("streampkg".to_string()),
                syntax: Some("proto3".to_string()),
                message_type: vec![
                    DescriptorProto {
                        name: Some("StreamRequest".to_string()),
                        field: vec![FieldDescriptorProto {
                            name: Some("value".to_string()),
                            number: Some(1),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::String as i32),
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                    DescriptorProto {
                        name: Some("StreamResponse".to_string()),
                        field: vec![FieldDescriptorProto {
                            name: Some("count".to_string()),
                            number: Some(1),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::Int64 as i32),
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                ],
                service: vec![ServiceDescriptorProto {
                    name: Some("StreamService".to_string()),
                    method: vec![MethodDescriptorProto {
                        name: Some("ClientStream".to_string()),
                        input_type: Some(".streampkg.StreamRequest".to_string()),
                        output_type: Some(".streampkg.StreamResponse".to_string()),
                        client_streaming: Some(true),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        fds.encode_to_vec()
    }

    fn test_descriptor_set() -> Vec<u8> {
        let fds = FileDescriptorSet {
            file: vec![FileDescriptorProto {
                name: Some("test.proto".to_string()),
                package: Some("testpkg".to_string()),
                syntax: Some("proto3".to_string()),
                message_type: vec![
                    DescriptorProto {
                        name: Some("TestMessage".to_string()),
                        field: vec![
                            FieldDescriptorProto {
                                name: Some("id".to_string()),
                                number: Some(1),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::Int64 as i32),
                                ..Default::default()
                            },
                            FieldDescriptorProto {
                                name: Some("name".to_string()),
                                number: Some(2),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::String as i32),
                                ..Default::default()
                            },
                        ],
                        ..Default::default()
                    },
                    DescriptorProto {
                        name: Some("NestedOuter".to_string()),
                        nested_type: vec![DescriptorProto {
                            name: Some("NestedInner".to_string()),
                            field: vec![FieldDescriptorProto {
                                name: Some("value".to_string()),
                                number: Some(1),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::String as i32),
                                ..Default::default()
                            }],
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                ],
                service: vec![ServiceDescriptorProto {
                    name: Some("TestService".to_string()),
                    method: vec![
                        MethodDescriptorProto {
                            name: Some("GetTest".to_string()),
                            input_type: Some(".testpkg.TestMessage".to_string()),
                            output_type: Some(".testpkg.TestMessage".to_string()),
                            ..Default::default()
                        },
                        MethodDescriptorProto {
                            name: Some("CreateTest".to_string()),
                            input_type: Some(".testpkg.TestMessage".to_string()),
                            output_type: Some(".testpkg.TestMessage".to_string()),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        fds.encode_to_vec()
    }

    fn nested_descriptor_set() -> Vec<u8> {
        let fds = FileDescriptorSet {
            file: vec![FileDescriptorProto {
                name: Some("nested.proto".to_string()),
                package: Some("nested".to_string()),
                syntax: Some("proto3".to_string()),
                message_type: vec![
                    DescriptorProto {
                        name: Some("Inner".to_string()),
                        field: vec![FieldDescriptorProto {
                            name: Some("value".to_string()),
                            number: Some(1),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::String as i32),
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                    DescriptorProto {
                        name: Some("Outer".to_string()),
                        field: vec![
                            FieldDescriptorProto {
                                name: Some("inner".to_string()),
                                number: Some(1),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::Message as i32),
                                type_name: Some(".nested.Inner".to_string()),
                                ..Default::default()
                            },
                            FieldDescriptorProto {
                                name: Some("count".to_string()),
                                number: Some(2),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::Int32 as i32),
                                ..Default::default()
                            },
                        ],
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
        };
        fds.encode_to_vec()
    }

    fn protoc_available() -> bool {
        std::process::Command::new("protoc")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    fn write_file(path: &Path, contents: &str) {
        std::fs::write(path, contents).unwrap();
    }

    fn test_message_descriptor() -> MessageDescriptor {
        Schema::from_descriptor_set(&test_descriptor_set())
            .unwrap()
            .find_message("testpkg.TestMessage")
            .unwrap()
    }

    fn snake_case_descriptor() -> MessageDescriptor {
        let fds = FileDescriptorSet {
            file: vec![FileDescriptorProto {
                name: Some("snake.proto".to_string()),
                package: Some("snakepkg".to_string()),
                syntax: Some("proto3".to_string()),
                message_type: vec![DescriptorProto {
                    name: Some("SnakeMessage".to_string()),
                    field: vec![FieldDescriptorProto {
                        name: Some("snake_case_name".to_string()),
                        number: Some(1),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::String as i32),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        Schema::from_descriptor_set(&fds.encode_to_vec())
            .unwrap()
            .find_message("snakepkg.SnakeMessage")
            .unwrap()
    }

    fn build_test_protobuf(id: i64, name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        if id != 0 {
            append_key(&mut out, 1, 0);
            append_varint(&mut out, id as u64);
        }
        if !name.is_empty() {
            append_key(&mut out, 2, 2);
            append_len_bytes(&mut out, name.as_bytes());
        }
        out
    }

    fn build_name_only_protobuf(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        append_key(&mut out, 2, 2);
        append_len_bytes(&mut out, name.as_bytes());
        out
    }

    fn append_key(out: &mut Vec<u8>, field: u64, wire: u8) {
        append_varint(out, (field << 3) | u64::from(wire));
    }

    fn append_len_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
        append_varint(out, bytes.len() as u64);
        out.extend_from_slice(bytes);
    }

    fn append_varint(out: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            out.push((value as u8 & 0x7f) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }

    fn json_map(bytes: &[u8]) -> serde_json::Map<String, serde_json::Value> {
        serde_json::from_slice::<serde_json::Value>(bytes)
            .unwrap()
            .as_object()
            .unwrap()
            .clone()
    }

    fn assert_json_id(map: &serde_json::Map<String, serde_json::Value>, want: &str, context: &str) {
        match map.get("id") {
            Some(serde_json::Value::String(value)) => assert_eq!(value, want, "{context}"),
            Some(serde_json::Value::Number(value)) => {
                assert_eq!(value.to_string(), want, "{context}")
            }
            other => panic!("{context}: unexpected id value {other:?}"),
        }
    }

    #[test]
    fn load_descriptor_set_finds_services_and_methods() {
        let schema = Schema::from_descriptor_set(&stream_descriptor_set()).unwrap();

        assert_eq!(schema.services(), ["streampkg.StreamService"]);
        let method = schema
            .find_method("streampkg.StreamService/ClientStream")
            .unwrap();
        assert!(method.is_client_streaming());
        assert_eq!(method.input().full_name(), "streampkg.StreamRequest");
        assert_eq!(method.output().full_name(), "streampkg.StreamResponse");
    }

    #[test]
    fn stream_json_to_grpc_frames_converts_multiple_messages() {
        let schema = Schema::from_descriptor_set(&stream_descriptor_set()).unwrap();
        let method = schema
            .find_method("streampkg.StreamService/ClientStream")
            .unwrap();

        let framed =
            stream_json_to_grpc_frames(br#"{"value":"one"}{"value":"two"}"#, &method.input())
                .unwrap();
        let frames = framing::read_frames(&framed).unwrap();

        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].data, b"\x0a\x03one");
        assert_eq!(frames[1].data, b"\x0a\x03two");
    }

    #[test]
    fn unary_json_to_protobuf_ignores_unknown_fields_like_go() {
        let schema = Schema::from_descriptor_set(&stream_descriptor_set()).unwrap();
        let method = schema
            .find_method("streampkg.StreamService/ClientStream")
            .unwrap();

        let encoded =
            json_to_protobuf(br#"{"value":"one","unknown":true}"#, &method.input()).unwrap();

        assert_eq!(encoded, b"\x0a\x03one");
    }

    #[test]
    fn format_grpc_stream_with_descriptor_outputs_proto_json() {
        let schema = Schema::from_descriptor_set(&stream_descriptor_set()).unwrap();
        let method = schema
            .find_method("streampkg.StreamService/ClientStream")
            .unwrap();
        let body = framing::frame(b"\x08\x03", false).unwrap();

        let out = format_grpc_stream_with_descriptor(&body, &method.output()).unwrap();

        assert!(out.contains("\"count\": \"3\""));
    }

    #[test]
    fn describe_symbol_renders_service_method_and_message_like_go() {
        let schema = Schema::from_descriptor_set(&stream_descriptor_set()).unwrap();

        let service = describe_symbol(&schema, "streampkg.StreamService").unwrap();
        assert!(service.contains("service streampkg.StreamService"));
        assert!(service.contains("rpc: client-stream"));
        assert!(service.contains("request: streampkg.StreamRequest"));

        let method = describe_symbol(&schema, "streampkg.StreamService/ClientStream").unwrap();
        assert!(method.contains("method streampkg.StreamService/ClientStream"));
        assert!(method.contains("response: streampkg.StreamResponse"));

        let message = describe_symbol(&schema, "streampkg.StreamRequest").unwrap();
        assert!(message.contains("message streampkg.StreamRequest"));
        assert!(message.contains("1  value  optional  string"));
    }

    #[test]
    fn test_load_descriptor_set_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.pb");
        std::fs::write(&path, test_descriptor_set()).unwrap();

        let schema = Schema::load_descriptor_set_file(path.to_str().unwrap()).unwrap();

        assert!(schema.find_message("testpkg.TestMessage").is_some());
    }

    #[test]
    fn test_load_descriptor_set_file_not_found() {
        let err = Schema::load_descriptor_set_file("/nonexistent/path/to/file.pb").unwrap_err();

        assert!(
            err.to_string()
                .contains("failed to read descriptor set file")
        );
    }

    #[test]
    fn test_load_descriptor_set_file_invalid_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invalid.pb");
        std::fs::write(&path, b"not a valid protobuf").unwrap();

        let err = Schema::load_descriptor_set_file(path.to_str().unwrap()).unwrap_err();

        assert!(
            err.to_string()
                .contains("failed to create file descriptors")
        );
    }

    #[test]
    fn test_load_descriptor_set_bytes() {
        let schema = Schema::from_descriptor_set(&test_descriptor_set()).unwrap();

        assert!(schema.find_message("testpkg.TestMessage").is_some());
    }

    #[test]
    fn test_load_descriptor_set_bytes_empty() {
        let empty = FileDescriptorSet { file: vec![] }.encode_to_vec();
        let schema = Schema::from_descriptor_set(&empty).unwrap();

        assert!(schema.messages().is_empty());
        assert!(schema.services().is_empty());
    }

    #[test]
    fn test_load_descriptor_set_bytes_invalid() {
        let err = Schema::from_descriptor_set(b"not valid protobuf").unwrap_err();

        assert!(
            err.to_string()
                .contains("failed to create file descriptors")
        );
    }

    #[test]
    fn test_new_schema_equivalent_empty_descriptor_pool() {
        let empty = FileDescriptorSet { file: vec![] }.encode_to_vec();
        let schema = Schema::from_descriptor_set(&empty).unwrap();

        assert!(schema.messages().is_empty());
        assert!(schema.services().is_empty());
    }

    #[test]
    fn test_load_from_descriptor_set() {
        let schema = Schema::from_descriptor_set(&test_descriptor_set()).unwrap();

        assert!(schema.messages().len() >= 2);
        assert_eq!(schema.services(), ["testpkg.TestService"]);
    }

    #[test]
    fn test_find_message() {
        let schema = Schema::from_descriptor_set(&test_descriptor_set()).unwrap();
        let cases = [
            ("testpkg.TestMessage", true),
            (".testpkg.TestMessage", true),
            ("testpkg.NestedOuter.NestedInner", true),
            ("testpkg.NonExistent", false),
            ("wrongpkg.TestMessage", false),
        ];

        for (name, found) in cases {
            assert_eq!(
                schema.find_message(name).is_some(),
                found,
                "message lookup {name}"
            );
        }
    }

    #[test]
    fn test_find_service() {
        let schema = Schema::from_descriptor_set(&test_descriptor_set()).unwrap();
        let cases = [
            ("testpkg.TestService", true),
            (".testpkg.TestService", true),
            ("testpkg.NonExistent", false),
        ];

        for (name, found) in cases {
            assert_eq!(
                schema.find_service(name).is_some(),
                found,
                "service lookup {name}"
            );
        }
    }

    #[test]
    fn test_find_method() {
        let schema = Schema::from_descriptor_set(&test_descriptor_set()).unwrap();
        let cases = [
            ("testpkg.TestService/GetTest", true),
            ("testpkg.TestService.GetTest", true),
            ("testpkg.TestService/CreateTest", true),
            ("testpkg.NonExistent/GetTest", false),
            ("testpkg.TestService/NonExistent", false),
            ("InvalidMethodName", false),
        ];

        for (name, found) in cases {
            assert_eq!(
                schema.find_method(name).is_ok(),
                found,
                "method lookup {name}"
            );
        }
    }

    #[test]
    fn test_list_messages() {
        let schema = Schema::from_descriptor_set(&test_descriptor_set()).unwrap();
        let messages = schema.messages();

        assert!(messages.len() >= 3, "messages: {messages:?}");
        assert!(messages.contains(&"testpkg.TestMessage".to_string()));
        assert!(messages.contains(&"testpkg.NestedOuter".to_string()));
        assert!(messages.contains(&"testpkg.NestedOuter.NestedInner".to_string()));
    }

    #[test]
    fn test_list_services() {
        let schema = Schema::from_descriptor_set(&test_descriptor_set()).unwrap();

        assert_eq!(schema.services(), ["testpkg.TestService"]);
    }

    #[test]
    fn test_load_from_descriptor_set_error() {
        let empty = FileDescriptorSet { file: vec![] }.encode_to_vec();
        let schema = Schema::from_descriptor_set(&empty).unwrap();

        assert!(schema.messages().is_empty());
        assert!(schema.services().is_empty());
    }

    #[test]
    fn test_json_to_protobuf() {
        let desc = test_message_descriptor();

        assert!(
            !json_to_protobuf(br#"{"id": 123, "name": "test"}"#, &desc)
                .unwrap()
                .is_empty()
        );
        assert!(json_to_protobuf(br#"{}"#, &desc).unwrap().is_empty());
        assert!(
            !json_to_protobuf(br#"{"id": 456}"#, &desc)
                .unwrap()
                .is_empty()
        );
        assert!(
            !json_to_protobuf(br#"{"name": "only name"}"#, &desc)
                .unwrap()
                .is_empty()
        );
        assert!(json_to_protobuf(br#"{"id": 1, "unknownField": "ignored"}"#, &desc).is_ok());
        assert!(json_to_protobuf(br#"{invalid"#, &desc).is_err());
        assert!(json_to_protobuf(br#"{"id": "not a number"}"#, &desc).is_err());
    }

    #[test]
    fn test_protobuf_to_json() {
        let desc = test_message_descriptor();
        let cases = [
            (
                "simple message",
                build_test_protobuf(123, "test"),
                "123",
                "test",
            ),
            ("empty message", Vec::new(), "", ""),
            ("id only", build_test_protobuf(999, ""), "999", ""),
            ("name only", build_name_only_protobuf("hello"), "", "hello"),
        ];

        for (name, proto_input, want_id, want_name) in cases {
            let json = protobuf_to_json(&proto_input, &desc).unwrap();
            let result = json_map(&json);
            if !want_id.is_empty() {
                assert_json_id(&result, want_id, name);
            }
            if !want_name.is_empty() {
                assert_eq!(
                    result.get("name").and_then(|value| value.as_str()),
                    Some(want_name)
                );
            }
        }
    }

    #[test]
    fn test_protobuf_to_json_compact() {
        let desc = test_message_descriptor();
        let json = protobuf_to_json_compact(&build_test_protobuf(123, "test"), &desc).unwrap();

        assert!(!json.contains(&b'\n'));
        let result = json_map(&json);
        assert_json_id(&result, "123", "compact");
        assert_eq!(
            result.get("name").and_then(|value| value.as_str()),
            Some("test")
        );
    }

    #[test]
    fn protobuf_to_json_uses_proto_field_names_like_go() {
        let desc = snake_case_descriptor();
        let mut proto = Vec::new();
        append_key(&mut proto, 1, 2);
        append_len_bytes(&mut proto, b"kept");

        let json = protobuf_to_json(&proto, &desc).unwrap();
        let result = json_map(&json);

        assert_eq!(
            result
                .get("snake_case_name")
                .and_then(|value| value.as_str()),
            Some("kept")
        );
        assert!(!result.contains_key("snakeCaseName"));
    }

    #[test]
    fn test_json_to_protobuf_round_trip() {
        let desc = test_message_descriptor();
        let cases = [
            (
                "full message",
                br#"{"id": 42, "name": "roundtrip"}"#.as_slice(),
                "42",
                "roundtrip",
            ),
            (
                "zero values",
                br#"{"id": 0, "name": ""}"#.as_slice(),
                "",
                "",
            ),
            (
                "large id",
                br#"{"id": 9223372036854775807, "name": "max int64"}"#.as_slice(),
                "9223372036854775807",
                "max int64",
            ),
        ];

        for (name, json_input, want_id, want_name) in cases {
            let proto_data = json_to_protobuf(json_input, &desc).unwrap();
            let json = protobuf_to_json(&proto_data, &desc).unwrap();
            let result = json_map(&json);
            if !want_id.is_empty() {
                assert_json_id(&result, want_id, name);
            }
            if !want_name.is_empty() {
                assert_eq!(
                    result.get("name").and_then(|value| value.as_str()),
                    Some(want_name)
                );
            }
        }
    }

    #[test]
    fn test_json_to_protobuf_with_nested_message() {
        let schema = Schema::from_descriptor_set(&nested_descriptor_set()).unwrap();
        let desc = schema.find_message("nested.Outer").unwrap();

        let proto_data = json_to_protobuf(
            br#"{"inner": {"value": "nested value"}, "count": 5}"#,
            &desc,
        )
        .unwrap();
        let json = protobuf_to_json(&proto_data, &desc).unwrap();
        let result = json_map(&json);

        let inner = result
            .get("inner")
            .and_then(|value| value.as_object())
            .unwrap();
        assert_eq!(
            inner.get("value").and_then(|value| value.as_str()),
            Some("nested value")
        );
        assert_eq!(
            result.get("count").and_then(|value| value.as_i64()),
            Some(5)
        );
    }

    #[test]
    fn test_compile_protos_success() {
        if !protoc_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let proto_file = dir.path().join("test.proto");
        write_file(
            &proto_file,
            r#"
syntax = "proto3";
package testcompile;

message TestRequest {
  int64 id = 1;
  string name = 2;
}

message TestResponse {
  bool success = 1;
  string message = 2;
}

service TestService {
  rpc GetTest(TestRequest) returns (TestResponse);
}
"#,
        );

        let schema = compile_protos(&[proto_file.display().to_string()], &[]).unwrap();

        assert!(schema.find_message("testcompile.TestRequest").is_some());
        assert!(schema.find_message("testcompile.TestResponse").is_some());
        assert!(schema.find_service("testcompile.TestService").is_some());
        assert!(
            schema
                .find_method("testcompile.TestService/GetTest")
                .is_ok()
        );
    }

    #[test]
    fn test_compile_protos_with_imports() {
        if !protoc_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let common_dir = dir.path().join("common");
        let service_dir = dir.path().join("service");
        std::fs::create_dir_all(&common_dir).unwrap();
        std::fs::create_dir_all(&service_dir).unwrap();
        let common_proto = common_dir.join("common.proto");
        let service_proto = service_dir.join("service.proto");
        write_file(
            &common_proto,
            r#"
syntax = "proto3";
package common;

message Timestamp {
  int64 seconds = 1;
  int32 nanos = 2;
}
"#,
        );
        write_file(
            &service_proto,
            r#"
syntax = "proto3";
package myservice;

import "common/common.proto";

message Event {
  string id = 1;
  common.Timestamp timestamp = 2;
}
"#,
        );

        let schema = compile_protos(
            &[service_proto.display().to_string()],
            &[dir.path().display().to_string()],
        )
        .unwrap();

        assert!(schema.find_message("myservice.Event").is_some());
        assert!(schema.find_message("common.Timestamp").is_some());
    }

    #[test]
    fn test_compile_protos_file_not_found() {
        if !protoc_available() {
            return;
        }

        let err =
            compile_protos(&["/nonexistent/path/to/file.proto".to_string()], &[]).unwrap_err();

        assert!(matches!(err, ProtoError::Protoc(_)));
        assert!(err.to_string().starts_with("protoc failed: "));
    }

    #[test]
    fn test_compile_protos_invalid_syntax() {
        if !protoc_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let proto_file = dir.path().join("invalid.proto");
        write_file(
            &proto_file,
            r#"
this is not valid proto syntax!!!
message {
  broken = 1;
}
"#,
        );

        let err = compile_protos(&[proto_file.display().to_string()], &[]).unwrap_err();

        match err {
            ProtoError::Protoc(message) => assert!(!message.is_empty()),
            other => panic!("expected Protoc error, got {other:?}"),
        }
    }

    #[test]
    fn test_compile_protos_multiple_files() {
        if !protoc_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first.proto");
        let second = dir.path().join("second.proto");
        write_file(
            &first,
            r#"
syntax = "proto3";
package first;

message FirstMessage {
  string value = 1;
}
"#,
        );
        write_file(
            &second,
            r#"
syntax = "proto3";
package second;

message SecondMessage {
  int32 count = 1;
}
"#,
        );

        let schema = compile_protos(
            &[first.display().to_string(), second.display().to_string()],
            &[],
        )
        .unwrap();

        assert!(schema.find_message("first.FirstMessage").is_some());
        assert!(schema.find_message("second.SecondMessage").is_some());
    }

    #[test]
    fn test_protoc_not_found_error() {
        let message = ProtoError::ProtocNotFound.to_string();
        assert!(message.contains("protoc not found in PATH"));
        assert!(message.len() >= 10);
    }

    #[test]
    fn test_protoc_error() {
        let message = ProtoError::Protoc("test error message".to_string()).to_string();
        assert_eq!(message, "protoc failed: test error message");
    }
}
