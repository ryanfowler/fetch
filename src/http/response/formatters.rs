use super::*;

use super::stdout::{StdoutBody, response_header_content_type, response_header_content_type_label};
use super::stream::{MAX_BUFFERED_RESPONSE_BYTES, StdoutStreamFormatter, StreamedOutput};

pub(super) fn should_stream_formatted_sse_stdout(
    cli: &Cli,
    headers: &HeaderMap,
    stdout_is_terminal: bool,
) -> bool {
    response_header_content_type(headers) == ContentType::Sse
        && core::format_enabled(cli.format.as_deref(), stdout_is_terminal)
}

pub(super) fn should_stream_formatted_ndjson_stdout(
    cli: &Cli,
    headers: &HeaderMap,
    stdout_is_terminal: bool,
) -> bool {
    response_header_content_type(headers) == ContentType::Ndjson
        && core::format_enabled(cli.format.as_deref(), stdout_is_terminal)
}

pub(super) fn should_stream_formatted_grpc_stdout(
    cli: &Cli,
    headers: &HeaderMap,
    stdout_is_terminal: bool,
) -> bool {
    response_header_content_type(headers) == ContentType::Grpc
        && core::format_enabled(cli.format.as_deref(), stdout_is_terminal)
}

pub(in crate::http) fn should_retry_sse_without_compression(
    response: &Response,
    compression: CompressionMode,
) -> bool {
    compression == CompressionMode::Auto
        && response_header_content_type(response.headers()) == ContentType::Sse
        && content_encoding_decoders(response.headers(), compression).is_some_and(|decoders| {
            decoders
                .iter()
                .any(|encoding| encoding.as_str() != "aws-chunked")
        })
}

pub(in crate::http) fn should_retry_sse_without_compression_for_method(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD)
}

pub(super) async fn stream_response_to_formatted_sse_stdout(
    response: Response,
    response_headers: HeaderMap,
    compression: CompressionMode,
    copy: bool,
    use_color: bool,
) -> Result<StreamedOutput, FetchError> {
    super::stream::stream_formatted_response_to_stdout(
        response,
        response_headers,
        compression,
        copy,
        FormattedSseStream::new(use_color),
    )
    .await
}

pub(super) async fn stream_response_to_formatted_ndjson_stdout(
    response: Response,
    response_headers: HeaderMap,
    compression: CompressionMode,
    copy: bool,
    use_color: bool,
) -> Result<StreamedOutput, FetchError> {
    super::stream::stream_formatted_response_to_stdout(
        response,
        response_headers,
        compression,
        copy,
        FormattedNdjsonStream::new(use_color),
    )
    .await
}

pub(super) async fn stream_response_to_formatted_grpc_stdout(
    response: Response,
    response_headers: HeaderMap,
    compression: CompressionMode,
    copy: bool,
    grpc_response_desc: Option<prost_reflect::MessageDescriptor>,
    use_color: bool,
) -> Result<StreamedOutput, FetchError> {
    let formatter = FormattedGrpcStream::new(&response_headers, grpc_response_desc, use_color);
    super::stream::stream_formatted_response_to_stdout(
        response,
        response_headers,
        compression,
        copy,
        formatter,
    )
    .await
}

pub(super) fn formatted_ndjson_record(
    record: &[u8],
    use_color: bool,
    terminated: bool,
) -> Option<Vec<u8>> {
    if record.iter().all(u8::is_ascii_whitespace) {
        return None;
    }
    let mut formatted = core::Printer::new(use_color);
    match json::format_json_line_to(record, &mut formatted) {
        Ok(()) => Some(formatted.into_bytes()),
        Err(_) => {
            let mut output = record.to_vec();
            if terminated {
                output.push(b'\n');
            }
            Some(output)
        }
    }
}

pub(super) struct FormattedSseStream {
    formatter: sse::EventStreamFormatter,
    pending: Vec<u8>,
    use_color: bool,
}

impl FormattedSseStream {
    fn new(use_color: bool) -> Self {
        Self::with_pending_limit(use_color, MAX_BUFFERED_RESPONSE_BYTES)
    }

    pub(super) fn with_pending_limit(use_color: bool, max_pending_bytes: usize) -> Self {
        Self {
            formatter: sse::EventStreamFormatter::with_pending_limit(max_pending_bytes),
            pending: Vec::new(),
            use_color,
        }
    }

    fn ensure_pending_utf8_len_within_limit(&self) -> Result<(), FetchError> {
        if let Some(max) = self.formatter.max_pending_bytes()
            && self.pending.len() > max
        {
            return Err(FetchError::Message(
                sse::EventStreamError::PendingBufferTooLarge {
                    kind: sse::PendingBufferKind::Utf8,
                    max_bytes: max,
                }
                .to_string(),
            ));
        }
        Ok(())
    }
}

impl StdoutStreamFormatter for FormattedSseStream {
    fn push_chunk(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, FetchError> {
        self.pending.extend_from_slice(chunk);
        let formatted =
            push_sse_stream_bytes(&mut self.pending, &mut self.formatter, self.use_color)
                .map_err(|err| FetchError::Message(err.to_string()))?;
        self.ensure_pending_utf8_len_within_limit()?;
        Ok(vec![formatted.into_bytes()])
    }

    fn finish(&mut self) -> Result<Vec<Vec<u8>>, FetchError> {
        let formatted =
            finish_sse_stream_formatter(&mut self.pending, &mut self.formatter, self.use_color)
                .map_err(|err| FetchError::Message(err.to_string()))?;
        Ok(vec![formatted.into_bytes()])
    }
}

pub(super) struct FormattedNdjsonStream {
    pending: Vec<u8>,
    use_color: bool,
    max_record_bytes: usize,
}

impl FormattedNdjsonStream {
    fn new(use_color: bool) -> Self {
        Self::with_record_limit(use_color, MAX_BUFFERED_RESPONSE_BYTES)
    }

    pub(super) fn with_record_limit(use_color: bool, max_record_bytes: usize) -> Self {
        Self {
            pending: Vec::new(),
            use_color,
            max_record_bytes,
        }
    }

    fn ensure_record_len_within_limit(&self, len: usize) -> Result<(), FetchError> {
        if len > self.max_record_bytes {
            return Err(FetchError::Message(format!(
                "NDJSON record exceeds {} bytes and cannot be formatted as a stream",
                self.max_record_bytes
            )));
        }
        Ok(())
    }
}

impl StdoutStreamFormatter for FormattedNdjsonStream {
    fn push_chunk(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, FetchError> {
        self.pending.extend_from_slice(chunk);
        let mut outputs = Vec::new();
        while let Some(newline) = self.pending.iter().position(|byte| *byte == b'\n') {
            self.ensure_record_len_within_limit(newline)?;
            let mut record = self.pending.drain(..=newline).collect::<Vec<_>>();
            record.pop();
            if let Some(output) = formatted_ndjson_record(&record, self.use_color, true) {
                outputs.push(output);
            }
        }
        self.ensure_record_len_within_limit(self.pending.len())?;
        Ok(outputs)
    }

    fn finish(&mut self) -> Result<Vec<Vec<u8>>, FetchError> {
        if self.pending.is_empty() {
            return Ok(Vec::new());
        }
        self.ensure_record_len_within_limit(self.pending.len())?;
        let record = std::mem::take(&mut self.pending);
        Ok(formatted_ndjson_record(&record, self.use_color, false)
            .into_iter()
            .collect())
    }
}

struct FormattedGrpcStream {
    decoder: crate::grpc::framing::FrameDecoder,
    grpc_message_encoding: grpc_encoding::MessageEncoding,
    grpc_response_desc: Option<prost_reflect::MessageDescriptor>,
    use_color: bool,
    frame_index: usize,
    descriptor_wrote_any: bool,
    descriptor_output_ends_with_newline: bool,
}

impl FormattedGrpcStream {
    fn new(
        response_headers: &HeaderMap,
        grpc_response_desc: Option<prost_reflect::MessageDescriptor>,
        use_color: bool,
    ) -> Self {
        Self {
            decoder: crate::grpc::framing::FrameDecoder::new(),
            grpc_message_encoding: grpc_encoding::MessageEncoding::from_headers(response_headers),
            grpc_response_desc,
            use_color,
            frame_index: 0,
            descriptor_wrote_any: false,
            descriptor_output_ends_with_newline: true,
        }
    }

    fn format_frame(&mut self, frame: &crate::grpc::framing::Frame) -> Result<Vec<u8>, FetchError> {
        if let Some(desc) = self.grpc_response_desc.as_ref() {
            let formatted = format_grpc_frame_with_descriptor_json(
                frame,
                desc,
                &self.grpc_message_encoding,
                self.use_color,
            )?;
            let mut output = Vec::new();
            if self.descriptor_wrote_any && !self.descriptor_output_ends_with_newline {
                output.push(b'\n');
            }
            self.descriptor_output_ends_with_newline = formatted.ends_with(b"\n");
            output.extend_from_slice(&formatted);
            self.descriptor_wrote_any = true;
            return Ok(output);
        }

        let formatted = grpc_format::format_grpc_frame(frame, &self.grpc_message_encoding)
            .map_err(|err| FetchError::Message(err.to_string()))?;
        let mut output = Vec::new();
        if self.frame_index > 0 {
            output.push(b'\n');
        }
        output.extend_from_slice(formatted.as_bytes());
        self.frame_index += 1;
        Ok(output)
    }
}

fn format_grpc_frame_with_descriptor_json(
    frame: &crate::grpc::framing::Frame,
    desc: &prost_reflect::MessageDescriptor,
    message_encoding: &grpc_encoding::MessageEncoding,
    use_color: bool,
) -> Result<Vec<u8>, FetchError> {
    let formatted = proto::format_grpc_frame_with_descriptor(frame, desc, message_encoding)
        .map_err(|err| FetchError::Message(err.to_string()))?;
    Ok(format_printer_bytes(use_color, |out| {
        json::format_json_to(formatted.as_bytes(), out)
    })
    .unwrap_or_else(|_| formatted.into_bytes()))
}

fn format_grpc_stream_with_descriptor_json(
    bytes: &[u8],
    desc: &prost_reflect::MessageDescriptor,
    message_encoding: &grpc_encoding::MessageEncoding,
    use_color: bool,
) -> Result<Vec<u8>, FetchError> {
    let frames = crate::grpc::framing::read_frames(bytes)
        .map_err(|err| FetchError::Message(format!("failed to read gRPC stream: {err}")))?;
    let mut out = Vec::new();
    let mut wrote_any = false;
    let mut output_ends_with_newline = true;
    for frame in &frames {
        let formatted =
            format_grpc_frame_with_descriptor_json(frame, desc, message_encoding, use_color)?;
        if wrote_any && !output_ends_with_newline {
            out.push(b'\n');
        }
        output_ends_with_newline = formatted.ends_with(b"\n");
        out.extend_from_slice(&formatted);
        wrote_any = true;
    }
    Ok(out)
}

impl StdoutStreamFormatter for FormattedGrpcStream {
    fn push_chunk(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, FetchError> {
        let frames = self
            .decoder
            .push(chunk)
            .map_err(|err| FetchError::Message(format!("failed to read gRPC stream: {err}")))?;
        frames
            .iter()
            .map(|frame| self.format_frame(frame))
            .collect::<Result<Vec<_>, _>>()
    }

    fn finish(&mut self) -> Result<Vec<Vec<u8>>, FetchError> {
        self.decoder
            .finish()
            .map_err(|err| FetchError::Message(format!("failed to read gRPC stream: {err}")))?;
        Ok(Vec::new())
    }
}

pub(super) fn push_sse_stream_bytes(
    pending: &mut Vec<u8>,
    formatter: &mut sse::EventStreamFormatter,
    use_color: bool,
) -> Result<String, sse::EventStreamError> {
    let mut out = core::Printer::new(use_color);
    loop {
        match std::str::from_utf8(pending) {
            Ok(input) => {
                formatter.push_str(input, &mut out)?;
                pending.clear();
                return Ok(out
                    .into_string()
                    .expect("event stream formatter output is valid UTF-8"));
            }
            Err(err) if err.error_len().is_none() => {
                let valid_up_to = err.valid_up_to();
                if valid_up_to == 0 {
                    return Ok(out
                        .into_string()
                        .expect("event stream formatter output is valid UTF-8"));
                }
                {
                    let input = std::str::from_utf8(&pending[..valid_up_to])?;
                    formatter.push_str(input, &mut out)?;
                }
                pending.drain(..valid_up_to);
            }
            Err(err) => return Err(err.into()),
        }
    }
}

pub(super) fn finish_sse_stream_formatter(
    pending: &mut Vec<u8>,
    formatter: &mut sse::EventStreamFormatter,
    use_color: bool,
) -> Result<String, sse::EventStreamError> {
    let mut out = core::Printer::new(use_color);
    let chunk = push_sse_stream_bytes(pending, formatter, use_color)?;
    out.push_str(&chunk);
    formatter.finish(&mut out)?;
    Ok(out
        .into_string()
        .expect("event stream formatter output is valid UTF-8"))
}

pub(super) fn format_stdout_bytes(
    cli: &Cli,
    headers: &HeaderMap,
    bytes: &[u8],
    grpc_response_desc: Option<prost_reflect::MessageDescriptor>,
) -> Result<StdoutBody, FetchError> {
    let stdout_is_terminal = core::stdio().stdout_is_terminal();
    let terminal_cols = if stdout_is_terminal {
        core::terminal_cols()
    } else {
        0
    };
    format_stdout_bytes_with_terminal(
        cli,
        headers,
        bytes,
        grpc_response_desc,
        stdout_is_terminal,
        terminal_cols,
    )
}

pub(super) fn format_stdout_bytes_with_terminal(
    cli: &Cli,
    headers: &HeaderMap,
    bytes: &[u8],
    grpc_response_desc: Option<prost_reflect::MessageDescriptor>,
    stdout_is_terminal: bool,
    terminal_cols: usize,
) -> Result<StdoutBody, FetchError> {
    let content_type = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    let (mut content_type, charset) = content_type::get_content_type(content_type);
    if content_type == ContentType::Unknown {
        content_type = content_type::sniff_content_type(bytes);
    }
    if !core::format_enabled(cli.format.as_deref(), stdout_is_terminal) {
        return Ok(StdoutBody {
            bytes: bytes.to_vec(),
            content_type,
            content_type_label: response_header_content_type_label(headers),
        });
    }

    let use_color = core::color_enabled(cli.color.as_deref(), stdout_is_terminal);
    let bytes = transcode_format_bytes(bytes, &charset, content_type);
    let bytes = match content_type {
        ContentType::Json => {
            Ok(
                format_printer_bytes(use_color, |out| json::format_json_to(&bytes, out))
                    .unwrap_or_else(|_| bytes.to_vec()),
            )
        }
        ContentType::Ndjson => {
            Ok(
                format_printer_bytes(use_color, |out| json::format_ndjson_to(&bytes, out))
                    .unwrap_or_else(|_| bytes.to_vec()),
            )
        }
        ContentType::Csv => Ok(format_printer_bytes(use_color, |out| {
            csv::format_csv_to_with_terminal_cols(&bytes, out, terminal_cols)
        })
        .unwrap_or_else(|_| bytes.to_vec())),
        ContentType::Xml => {
            Ok(
                format_printer_bytes(use_color, |out| xml::format_xml_to(&bytes, out))
                    .unwrap_or_else(|_| bytes.to_vec()),
            )
        }
        ContentType::Yaml => {
            Ok(
                format_printer_bytes(use_color, |out| yaml::format_yaml_to(&bytes, out))
                    .unwrap_or_else(|_| bytes.to_vec()),
            )
        }
        ContentType::Css => {
            Ok(
                format_printer_bytes(use_color, |out| css::format_css_to(&bytes, out))
                    .unwrap_or_else(|_| bytes.to_vec()),
            )
        }
        ContentType::Html => {
            Ok(
                format_printer_bytes(use_color, |out| html::format_html_to(&bytes, out))
                    .unwrap_or_else(|_| bytes.to_vec()),
            )
        }
        ContentType::Markdown => {
            Ok(
                format_printer_bytes(use_color, |out| markdown::format_markdown_to(&bytes, out))
                    .unwrap_or_else(|_| bytes.to_vec()),
            )
        }
        ContentType::MsgPack => {
            Ok(
                format_printer_bytes(use_color, |out| msgpack::format_msgpack_to(&bytes, out))
                    .unwrap_or_else(|_| bytes.to_vec()),
            )
        }
        ContentType::Protobuf => {
            if let Some(desc) = grpc_response_desc {
                if let Ok(json_bytes) = proto::protobuf_to_json(&bytes, &desc) {
                    Ok(format_printer_bytes(use_color, |out| {
                        json::format_json_to(&json_bytes, out)
                    })
                    .unwrap_or(json_bytes))
                } else {
                    Ok(bytes.to_vec())
                }
            } else {
                Ok(protobuf::format_protobuf(&bytes)
                    .map(|formatted| formatted.into_bytes())
                    .unwrap_or_else(|_| bytes.to_vec()))
            }
        }
        ContentType::Image => {
            if cli.image.as_deref() == Some("off") {
                Ok(bytes.to_vec())
            } else {
                let decode_mode = if cli.image.as_deref() == Some("external") {
                    crate::image::DecodeMode::External
                } else {
                    crate::image::DecodeMode::BuiltIn
                };
                crate::image::render(&bytes, decode_mode)
                    .map_err(|err| FetchError::Message(err.to_string()))
            }
        }
        ContentType::Grpc => {
            let grpc_message_encoding = grpc_encoding::MessageEncoding::from_headers(headers);
            if let Some(desc) = grpc_response_desc {
                format_grpc_stream_with_descriptor_json(
                    &bytes,
                    &desc,
                    &grpc_message_encoding,
                    use_color,
                )
            } else {
                grpc_format::format_grpc_stream(&bytes, &grpc_message_encoding)
                    .map(|formatted| formatted.into_bytes())
                    .map_err(|err| FetchError::Message(err.to_string()))
            }
        }
        ContentType::Sse => {
            format_printer_bytes(use_color, |out| sse::format_event_stream_to(&bytes, out))
                .map_err(|err| FetchError::Message(err.to_string()))
        }
        _ => Ok(bytes.to_vec()),
    }?;
    Ok(StdoutBody {
        bytes,
        content_type,
        content_type_label: response_header_content_type_label(headers),
    })
}

fn format_printer_bytes<E>(
    use_color: bool,
    write: impl FnOnce(&mut core::Printer) -> Result<(), E>,
) -> Result<Vec<u8>, E> {
    let mut out = core::Printer::new(use_color);
    write(&mut out)?;
    Ok(out.into_bytes())
}

pub(super) fn transcode_format_bytes(
    bytes: &[u8],
    charset: &str,
    content_type: ContentType,
) -> Vec<u8> {
    if matches!(
        content_type,
        ContentType::Image | ContentType::MsgPack | ContentType::Protobuf | ContentType::Grpc
    ) {
        return bytes.to_vec();
    }
    transcode_bytes(bytes, charset)
}

fn charset_decoder(charset: &str) -> Option<&'static encoding_rs::Encoding> {
    let charset = charset.trim();
    if charset.is_empty() {
        return None;
    }
    if matches!(
        charset.to_ascii_lowercase().as_str(),
        "utf-8" | "utf8" | "us-ascii" | "ascii"
    ) {
        return None;
    }
    encoding_rs::Encoding::for_label(charset.as_bytes())
}

pub(super) fn transcode_bytes(bytes: &[u8], charset: &str) -> Vec<u8> {
    let Some(encoding) = charset_decoder(charset) else {
        return bytes.to_vec();
    };
    let (decoded, _, had_errors) = encoding.decode(bytes);
    if had_errors {
        return bytes.to_vec();
    }
    decoded.into_owned().into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    use clap::Parser;
    use prost::Message;
    use prost_reflect::{DynamicMessage, Value as ReflectValue};
    use prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        MethodDescriptorProto, ServiceDescriptorProto,
        field_descriptor_proto::{Label, Type},
    };

    fn test_response_descriptor() -> prost_reflect::MessageDescriptor {
        let fds = FileDescriptorSet {
            file: vec![FileDescriptorProto {
                name: Some("response.proto".to_string()),
                package: Some("testpkg".to_string()),
                syntax: Some("proto3".to_string()),
                message_type: vec![
                    DescriptorProto {
                        name: Some("TestRequest".to_string()),
                        ..Default::default()
                    },
                    DescriptorProto {
                        name: Some("TestResponse".to_string()),
                        field: vec![
                            FieldDescriptorProto {
                                name: Some("response_text".to_string()),
                                json_name: Some("responseText".to_string()),
                                number: Some(1),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::String as i32),
                                ..Default::default()
                            },
                            FieldDescriptorProto {
                                name: Some("count".to_string()),
                                json_name: Some("count".to_string()),
                                number: Some(2),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::Int64 as i32),
                                ..Default::default()
                            },
                        ],
                        ..Default::default()
                    },
                ],
                service: vec![ServiceDescriptorProto {
                    name: Some("TestService".to_string()),
                    method: vec![MethodDescriptorProto {
                        name: Some("Get".to_string()),
                        input_type: Some(".testpkg.TestRequest".to_string()),
                        output_type: Some(".testpkg.TestResponse".to_string()),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        let schema = proto::Schema::from_descriptor_set(&fds.encode_to_vec()).unwrap();
        schema
            .find_method("testpkg.TestService/Get")
            .unwrap()
            .output()
    }

    fn test_response_body(text: &str, count: i64) -> Vec<u8> {
        let desc = test_response_descriptor();
        let mut msg = DynamicMessage::new(desc.clone());
        msg.set_field(
            &desc.get_field_by_name("response_text").unwrap(),
            ReflectValue::String(text.to_string()),
        );
        msg.set_field(
            &desc.get_field_by_name("count").unwrap(),
            ReflectValue::I64(count),
        );
        msg.encode_to_vec()
    }

    #[test]
    fn image_off_returns_raw_image_bytes() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("image/png"));
        let cli = Cli::try_parse_from([
            "fetch",
            "--format",
            "on",
            "--image",
            "off",
            "https://example.com",
        ])
        .unwrap();

        let out = format_stdout_bytes(&cli, &headers, b"not decoded", None).unwrap();
        assert_eq!(out.bytes, b"not decoded");
        assert_eq!(out.content_type, ContentType::Image);
    }

    #[test]
    fn formatted_sse_uses_dedicated_streaming_path() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));

        let cli = Cli::try_parse_from(["fetch", "https://example.com"]).unwrap();
        assert!(!should_stream_formatted_sse_stdout(&cli, &headers, false));
        assert!(should_stream_formatted_sse_stdout(&cli, &headers, true));

        let cli = Cli::try_parse_from(["fetch", "--format", "on", "https://example.com"]).unwrap();
        assert!(should_stream_formatted_sse_stdout(&cli, &headers, false));

        let cli = Cli::try_parse_from(["fetch", "--format", "off", "https://example.com"]).unwrap();
        assert!(!should_stream_formatted_sse_stdout(&cli, &headers, true));
    }

    #[test]
    fn compressed_sse_retry_is_limited_to_safe_methods() {
        assert!(should_retry_sse_without_compression_for_method(
            &Method::GET
        ));
        assert!(should_retry_sse_without_compression_for_method(
            &Method::HEAD
        ));
        assert!(!should_retry_sse_without_compression_for_method(
            &Method::POST
        ));
        assert!(!should_retry_sse_without_compression_for_method(
            &Method::PUT
        ));
        assert!(!should_retry_sse_without_compression_for_method(
            &Method::DELETE
        ));
    }

    #[test]
    fn formatted_sse_errors_on_oversized_unterminated_event() {
        let mut formatter = FormattedSseStream::with_pending_limit(false, 8);

        let err = formatter.push_chunk(b"data: 123").unwrap_err();

        assert_eq!(
            err.to_string(),
            "SSE line exceeds 8 bytes and cannot be formatted as a stream"
        );
    }

    #[test]
    fn formatted_sse_pending_limit_resets_after_dispatch() {
        let mut formatter = FormattedSseStream::with_pending_limit(false, 8);
        let mut got = Vec::new();

        for output in formatter.push_chunk(b"data: ab\ndata: cd\n\n").unwrap() {
            got.extend(output);
        }
        for output in formatter.push_chunk(b"data: ef\ndata: gh\n\n").unwrap() {
            got.extend(output);
        }
        for output in formatter.finish().unwrap() {
            got.extend(output);
        }

        assert_eq!(
            String::from_utf8(got).unwrap(),
            "event: message\ndata: ab\ndata: cd\n\nevent: message\ndata: ef\ndata: gh\n\n"
        );
    }

    #[test]
    fn formatted_ndjson_uses_dedicated_streaming_path() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-ndjson"),
        );

        let cli = Cli::try_parse_from(["fetch", "https://example.com"]).unwrap();
        assert!(!should_stream_formatted_ndjson_stdout(
            &cli, &headers, false
        ));
        assert!(should_stream_formatted_ndjson_stdout(&cli, &headers, true));

        let cli = Cli::try_parse_from(["fetch", "--format", "on", "https://example.com"]).unwrap();
        assert!(should_stream_formatted_ndjson_stdout(&cli, &headers, false));

        let cli = Cli::try_parse_from(["fetch", "--format", "off", "https://example.com"]).unwrap();
        assert!(!should_stream_formatted_ndjson_stdout(&cli, &headers, true));
    }

    #[test]
    fn formatted_ndjson_errors_on_oversized_unterminated_record() {
        let mut formatter = FormattedNdjsonStream::with_record_limit(false, 8);

        let err = formatter.push_chunk(b"123456789").unwrap_err();

        assert_eq!(
            err.to_string(),
            "NDJSON record exceeds 8 bytes and cannot be formatted as a stream"
        );
    }

    #[test]
    fn charset_decoder_matches_go_noop_and_known_charset_policy() {
        for charset in [
            "", "utf-8", "UTF-8", "utf8", "us-ascii", "ascii", "US-ASCII",
        ] {
            assert!(
                charset_decoder(charset).is_none(),
                "{charset} should not need transcoding"
            );
        }
        for charset in [
            "iso-8859-1",
            "ISO-8859-1",
            "windows-1252",
            "shift_jis",
            "euc-kr",
        ] {
            assert!(
                charset_decoder(charset).is_some(),
                "{charset} should have a decoder"
            );
        }
        assert!(charset_decoder("not-a-real-charset").is_none());
    }

    #[test]
    fn transcode_bytes_matches_go_charset_cases() {
        let cases = [
            (
                "latin1 cafe",
                &[0x63, 0x61, 0x66, 0xe9][..],
                "iso-8859-1",
                "caf\u{e9}",
            ),
            (
                "windows-1252 curly quotes",
                &[0x93, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x94][..],
                "windows-1252",
                "\u{201c}hello\u{201d}",
            ),
            ("empty charset returns unchanged", b"hello", "", "hello"),
            (
                "utf-8 charset returns unchanged",
                b"hello",
                "utf-8",
                "hello",
            ),
            (
                "unknown charset returns unchanged",
                b"hello",
                "not-a-real-charset",
                "hello",
            ),
        ];

        for (name, input, charset, want) in cases {
            let got = transcode_bytes(input, charset);
            assert_eq!(String::from_utf8(got).unwrap(), want, "{name}");
        }
    }

    #[test]
    fn formatted_stdout_transcodes_charset_before_formatting_like_go() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=iso-8859-1"),
        );
        let cli = Cli::try_parse_from([
            "fetch",
            "--format",
            "on",
            "--color",
            "off",
            "https://example.com",
        ])
        .unwrap();

        let out = format_stdout_bytes_with_terminal(
            &cli,
            &headers,
            b"{\"word\":\"caf\xe9\"}",
            None,
            false,
            0,
        )
        .unwrap();

        assert_eq!(
            String::from_utf8(out.bytes).unwrap(),
            "{\n  \"word\": \"caf\u{e9}\"\n}\n"
        );
    }

    #[test]
    fn formatted_stdout_does_not_transcode_binary_formats_like_go() {
        let raw = [0x0a, 0x01, 0xe9];
        for content_type in [
            ContentType::Image,
            ContentType::MsgPack,
            ContentType::Protobuf,
            ContentType::Grpc,
        ] {
            assert_eq!(
                transcode_format_bytes(&raw, "windows-1252", content_type),
                raw
            );
        }
    }

    #[test]
    fn formatted_stdout_uses_go_color_auto_target_policy() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let cli = Cli::try_parse_from(["fetch", "--format", "on", "https://example.com"]).unwrap();

        let out =
            format_stdout_bytes_with_terminal(&cli, &headers, br#"{"ok":"yes"}"#, None, false, 0)
                .unwrap();
        assert!(!String::from_utf8(out.bytes).unwrap().contains("\x1b["));

        let out =
            format_stdout_bytes_with_terminal(&cli, &headers, br#"{"ok":"yes"}"#, None, true, 80)
                .unwrap();
        assert!(String::from_utf8(out.bytes).unwrap().contains("\x1b["));

        let cli = Cli::try_parse_from([
            "fetch",
            "--format",
            "on",
            "--color",
            "off",
            "https://example.com",
        ])
        .unwrap();
        let out =
            format_stdout_bytes_with_terminal(&cli, &headers, br#"{"ok":"yes"}"#, None, true, 80)
                .unwrap();
        assert!(!String::from_utf8(out.bytes).unwrap().contains("\x1b["));

        let cli = Cli::try_parse_from([
            "fetch",
            "--format",
            "on",
            "--color",
            "on",
            "https://example.com",
        ])
        .unwrap();
        let out =
            format_stdout_bytes_with_terminal(&cli, &headers, br#"{"ok":"yes"}"#, None, false, 0)
                .unwrap();
        assert!(String::from_utf8(out.bytes).unwrap().contains("\x1b["));
    }

    #[test]
    fn formatted_stdout_auto_follows_stdout_terminal_like_go() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        for args in [
            ["fetch", "https://example.com"].as_slice(),
            ["fetch", "--format", "auto", "https://example.com"].as_slice(),
        ] {
            let cli = Cli::try_parse_from(args).unwrap();
            let out = format_stdout_bytes_with_terminal(
                &cli,
                &headers,
                br#"{"ok":"yes"}"#,
                None,
                false,
                0,
            )
            .unwrap();
            assert_eq!(String::from_utf8(out.bytes).unwrap(), r#"{"ok":"yes"}"#);

            let out = format_stdout_bytes_with_terminal(
                &cli,
                &headers,
                br#"{"ok":"yes"}"#,
                None,
                true,
                80,
            )
            .unwrap();
            let out = String::from_utf8(out.bytes).unwrap();
            assert!(out.starts_with("{\n  \""));
            assert!(out.contains("\x1b[34m\x1b[1mok\x1b[0m"));
            assert!(out.contains("\x1b[32myes\x1b[0m"));
        }

        let cli = Cli::try_parse_from(["fetch", "--format", "off", "https://example.com"]).unwrap();
        let out =
            format_stdout_bytes_with_terminal(&cli, &headers, br#"{"ok":"yes"}"#, None, true, 80)
                .unwrap();
        assert_eq!(String::from_utf8(out.bytes).unwrap(), r#"{"ok":"yes"}"#);
    }

    #[test]
    fn formatted_stdout_passes_terminal_width_to_csv_like_go() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/csv"));
        let cli = Cli::try_parse_from([
            "fetch",
            "--format",
            "on",
            "--color",
            "off",
            "https://example.com",
        ])
        .unwrap();

        let out = format_stdout_bytes_with_terminal(
            &cli,
            &headers,
            b"name,age,city\nAlice,30,NYC\nBob,25,LA",
            None,
            true,
            5,
        )
        .unwrap();
        let out = String::from_utf8(out.bytes).unwrap();

        assert!(out.contains("--- Row 1 ---"));
        assert!(out.contains("name: Alice"));
    }

    #[test]
    fn protobuf_response_uses_grpc_descriptor_for_unframed_body_like_go() {
        let desc = test_response_descriptor();
        let mut msg = DynamicMessage::new(desc.clone());
        msg.set_field(
            &desc.get_field_by_name("response_text").unwrap(),
            ReflectValue::String("hello".to_string()),
        );
        msg.set_field(
            &desc.get_field_by_name("count").unwrap(),
            ReflectValue::I64(7),
        );
        let body = msg.encode_to_vec();

        let json_bytes = proto::protobuf_to_json(&body, &desc).unwrap();
        let out = json::format_json(&json_bytes, false).unwrap();
        let text = String::from_utf8(out).unwrap();
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();

        assert_eq!(json["response_text"], "hello");
        assert_eq!(json["count"], "7");
        assert!(!text.contains("1:"));
    }

    #[test]
    fn grpc_descriptor_response_uses_json_color_policy() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/grpc+proto"),
        );
        let cli = Cli::try_parse_from([
            "fetch",
            "--grpc",
            "--format",
            "on",
            "--color",
            "on",
            "https://example.com/testpkg.TestService/Get",
        ])
        .unwrap();
        let body = crate::grpc::framing::frame(&test_response_body("hello", 7), false).unwrap();

        let out = format_stdout_bytes_with_terminal(
            &cli,
            &headers,
            &body,
            Some(test_response_descriptor()),
            false,
            0,
        )
        .unwrap();
        let out = String::from_utf8(out.bytes).unwrap();

        assert!(out.contains("\x1b[34m\x1b[1mresponse_text\x1b[0m"));
        assert!(out.contains("\x1b[32mhello\x1b[0m"));
        assert!(!out.contains("1:"));
    }

    #[test]
    fn streaming_grpc_descriptor_response_uses_json_color_policy() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/grpc+proto"),
        );
        let mut formatter =
            FormattedGrpcStream::new(&headers, Some(test_response_descriptor()), true);
        let body = crate::grpc::framing::frame(&test_response_body("hello", 7), false).unwrap();

        let chunks = formatter.push_chunk(&body).unwrap();
        let out = String::from_utf8(chunks.into_iter().flatten().collect()).unwrap();

        assert!(out.contains("\x1b[34m\x1b[1mresponse_text\x1b[0m"));
        assert!(out.contains("\x1b[32mhello\x1b[0m"));
        assert!(!out.contains("1:"));
    }

    #[test]
    fn protobuf_descriptor_decode_failure_falls_back_to_raw_bytes_like_go() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/protobuf"),
        );
        let cli = Cli::try_parse_from([
            "fetch",
            "--grpc",
            "--format",
            "on",
            "https://example.com/testpkg.TestService/Get",
        ])
        .unwrap();

        let raw = b"\x0a\xff";
        let out =
            format_stdout_bytes(&cli, &headers, raw, Some(test_response_descriptor())).unwrap();

        assert_eq!(out.bytes, raw);
    }
}
