use prost_reflect::{Cardinality, FieldDescriptor, Kind, MethodDescriptor, ServiceDescriptor};

use crate::error::FetchError;
use crate::proto::schema::{Schema, load_local_schema, normalize_symbol_name};

pub fn execute_local_discovery(cli: &crate::cli::Cli) -> Result<i32, FetchError> {
    let Some(schema) = load_local_schema(cli)? else {
        return Err("gRPC discovery requires --proto-file or --proto-desc".into());
    };

    if cli.grpc_list {
        crate::core::write_stdout(service_list_output(schema.services()))?;
        return Ok(0);
    }

    if let Some(symbol) = cli.grpc_describe.as_deref() {
        let symbol = normalize_symbol_name(symbol);
        crate::core::write_stdout(describe_symbol(&schema, symbol)?)?;
        return Ok(0);
    }

    Err("gRPC discovery requires --grpc-list or --grpc-describe".into())
}

pub fn describe_symbol(schema: &Schema, symbol: &str) -> Result<String, FetchError> {
    let symbol = normalize_symbol_name(symbol);
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

fn service_list_output(services: Vec<String>) -> String {
    let mut output = String::new();
    for service in services {
        output.push_str(&service);
        output.push('\n');
    }
    output
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

fn render_message_description(message: &prost_reflect::MessageDescriptor) -> String {
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
