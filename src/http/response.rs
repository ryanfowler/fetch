use super::*;

const MAX_BUFFERED_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_DISCARDED_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_DRAIN_DURATION: Duration = Duration::from_millis(250);
const BINARY_RESPONSE_WARNING: &str =
    "the response body appears to be binary\n\nTo output to the terminal anyway, use '--output -'";
type ResponseTrailers = Arc<Mutex<HeaderMap>>;

pub(super) async fn finish_response(
    cli: &Cli,
    response: Response,
    compression: CompressionMode,
    timing: Option<AttemptTiming>,
    grpc_method: Option<&prost_reflect::MethodDescriptor>,
) -> Result<i32, FetchError> {
    let status = response.status();
    print_response_metadata(cli, &response);
    let response_headers = response.headers().clone();
    let response_url = response.url().clone();
    let response_content_length = response
        .content_length()
        .and_then(|len| i64::try_from(len).ok());
    let output_progress_total =
        output_progress_total_bytes(compression, &response_headers, response_content_length);
    let method_is_head = cli.method().eq_ignore_ascii_case("HEAD");
    let response_timing = timing.and_then(AttemptTiming::response_timing);
    let stdio = core::stdio();
    if cli.discard {
        let body_start = Instant::now();
        let streamed =
            stream_response_to_discard(response, response_headers.clone(), compression).await?;
        let body_duration =
            body_duration_from_len(method_is_head, streamed.bytes_written, body_start);
        print_timing(cli, response_timing, body_duration);
        let code = exit_code(status.as_u16(), cli.ignore_status);
        return Ok(check_grpc_status(
            cli,
            &response_headers,
            &streamed.trailers,
            code,
        ));
    }

    let output_path = output::resolve_output_path(
        cli.output.as_deref(),
        cli.remote_name,
        cli.remote_header_name,
        &response_url,
        &response_headers,
    )
    .map_err(|err| FetchError::Message(err.to_string()))?;
    if let Some(path) = output_path {
        let progress = if cli.silent {
            output::WriteProgress::disabled()
        } else {
            output::WriteProgress::stdio(cli.color.as_deref(), output_progress_total)
        };
        let body_start = Instant::now();
        let streamed = stream_response_to_output(
            response,
            response_headers.clone(),
            compression,
            path,
            cli.clobber,
            progress,
            cli.copy,
        )
        .await?;
        handle_optional_clipboard_outcome(cli, streamed.clipboard);
        let body_duration = if method_is_head || streamed.bytes_written == 0 {
            None
        } else {
            Some(body_start.elapsed())
        };
        print_timing(cli, response_timing, body_duration);

        let code = exit_code(status.as_u16(), cli.ignore_status);
        Ok(check_grpc_status(
            cli,
            &response_headers,
            &streamed.trailers,
            code,
        ))
    } else {
        let body_start = Instant::now();
        let stdout_is_terminal = stdio.stdout_is_terminal();
        if should_stream_formatted_sse_stdout(cli, &response_headers, stdout_is_terminal) {
            let use_color = stdio.stdout_color(cli.color.as_deref());
            let streamed = stream_response_to_formatted_sse_stdout(
                response,
                response_headers.clone(),
                compression,
                cli.copy,
                use_color,
            )
            .await?;
            handle_optional_clipboard_outcome(cli, streamed.clipboard);
            let body_duration =
                body_duration_from_len(method_is_head, streamed.bytes_written, body_start);
            print_timing(cli, response_timing, body_duration);

            let code = exit_code(status.as_u16(), cli.ignore_status);
            return Ok(check_grpc_status(
                cli,
                &response_headers,
                &streamed.trailers,
                code,
            ));
        }
        if should_stream_formatted_ndjson_stdout(cli, &response_headers, stdout_is_terminal) {
            let use_color = stdio.stdout_color(cli.color.as_deref());
            let streamed = stream_response_to_formatted_ndjson_stdout(
                response,
                response_headers.clone(),
                compression,
                cli.copy,
                use_color,
            )
            .await?;
            handle_optional_clipboard_outcome(cli, streamed.clipboard);
            let body_duration =
                body_duration_from_len(method_is_head, streamed.bytes_written, body_start);
            print_timing(cli, response_timing, body_duration);

            let code = exit_code(status.as_u16(), cli.ignore_status);
            return Ok(check_grpc_status(
                cli,
                &response_headers,
                &streamed.trailers,
                code,
            ));
        }
        if should_stream_formatted_grpc_stdout(cli, &response_headers, stdout_is_terminal) {
            let streamed = stream_response_to_formatted_grpc_stdout(
                response,
                response_headers.clone(),
                compression,
                cli.copy,
                grpc_method.map(|method| method.output()),
            )
            .await?;
            handle_optional_clipboard_outcome(cli, streamed.clipboard);
            let body_duration =
                body_duration_from_len(method_is_head, streamed.bytes_written, body_start);
            print_timing(cli, response_timing, body_duration);

            let code = exit_code(status.as_u16(), cli.ignore_status);
            return Ok(check_grpc_status(
                cli,
                &response_headers,
                &streamed.trailers,
                code,
            ));
        }
        if let Some(target) = stdout_stream_target(cli, &response_headers, stdout_is_terminal) {
            let streamed = stream_response_to_stdout(
                cli,
                response,
                response_headers.clone(),
                compression,
                cli.copy,
                target,
                stdout_is_terminal,
            )
            .await?;
            handle_optional_clipboard_outcome(cli, streamed.clipboard);
            let body_duration =
                body_duration_from_len(method_is_head, streamed.bytes_written, body_start);
            print_timing(cli, response_timing, body_duration);

            let code = exit_code(status.as_u16(), cli.ignore_status);
            return Ok(check_grpc_status(
                cli,
                &response_headers,
                &streamed.trailers,
                code,
            ));
        }

        let (bytes, trailers) =
            read_decoded_response_body_limited(response, response_headers.clone(), compression)
                .await?;
        let body_duration = body_duration(method_is_head, bytes.as_ref(), body_start);
        if cli.copy {
            handle_clipboard_outcome(cli, clipboard::copy_bytes(&bytes));
        }
        let stdout_body = format_stdout_bytes(
            cli,
            &response_headers,
            &bytes,
            grpc_method.map(|method| method.output()),
        )?;
        write_stdout_bytes(cli, &stdout_body)?;
        print_timing(cli, response_timing, body_duration);

        let code = exit_code(status.as_u16(), cli.ignore_status);
        Ok(check_grpc_status(cli, &response_headers, &trailers, code))
    }
}

pub(super) struct StdoutBody {
    bytes: Vec<u8>,
    content_type: ContentType,
}

pub(super) fn write_stdout_bytes(cli: &Cli, body: &StdoutBody) -> Result<(), FetchError> {
    let stdout_is_terminal = core::stdio().stdout_is_terminal();
    if should_warn_for_terminal_binary_stdout(cli, &body.bytes, stdout_is_terminal) {
        write_warning(cli, BINARY_RESPONSE_WARNING);
        return Ok(());
    }

    if should_page_stdout(cli, &body.bytes, body.content_type, stdout_is_terminal) {
        return write_stdout_bytes_with_pager(&body.bytes);
    }

    core::write_stdout(&body.bytes)?;
    Ok(())
}

pub(super) fn should_page_stdout(
    cli: &Cli,
    bytes: &[u8],
    content_type: ContentType,
    stdout_is_terminal: bool,
) -> bool {
    let pager_allowed = !bytes.is_empty() && content_type != ContentType::Image;
    pager_allowed
        && match crate::cli::PagerMode::from_cli(cli) {
            crate::cli::PagerMode::Auto => stdout_is_terminal,
            crate::cli::PagerMode::On => true,
            crate::cli::PagerMode::Off => false,
        }
}

pub(super) fn write_stdout_bytes_with_pager(bytes: &[u8]) -> Result<(), FetchError> {
    let mut child = match std::process::Command::new("less")
        .arg("-FIRX")
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(child) => child,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            core::write_stdout(bytes)?;
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };

    if let Some(mut stdin) = child.stdin.take() {
        match stdin.write_all(bytes) {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::BrokenPipe => {}
            Err(err) => return Err(err.into()),
        }
    }

    let status = child.wait()?;
    if !status.success() {
        return Err(FetchError::Runtime(format!("pager exited with {status}")));
    }

    Ok(())
}

#[derive(Clone, Copy)]
pub(super) enum StdoutStreamTarget {
    Direct,
    Pager,
}

pub(super) fn stdout_stream_target(
    cli: &Cli,
    headers: &HeaderMap,
    stdout_is_terminal: bool,
) -> Option<StdoutStreamTarget> {
    if core::format_enabled(cli.format.as_deref(), stdout_is_terminal) {
        return None;
    }

    let is_image = response_header_content_type(headers) == ContentType::Image;
    match crate::cli::PagerMode::from_cli(cli) {
        crate::cli::PagerMode::Auto if stdout_is_terminal && !is_image => {
            Some(StdoutStreamTarget::Pager)
        }
        crate::cli::PagerMode::On if !is_image => Some(StdoutStreamTarget::Pager),
        crate::cli::PagerMode::Auto | crate::cli::PagerMode::Off | crate::cli::PagerMode::On => {
            Some(StdoutStreamTarget::Direct)
        }
    }
}

pub(super) fn response_header_content_type(headers: &HeaderMap) -> ContentType {
    let content_type = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    content_type::get_content_type(content_type).0
}

pub(super) fn terminal_binary_stdout_guard_enabled(cli: &Cli, stdout_is_terminal: bool) -> bool {
    stdout_is_terminal && cli.output.as_deref() != Some("-")
}

pub(super) fn should_warn_for_terminal_binary_stdout(
    cli: &Cli,
    bytes: &[u8],
    stdout_is_terminal: bool,
) -> bool {
    terminal_binary_stdout_guard_enabled(cli, stdout_is_terminal) && !is_printable(bytes)
}

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

pub(super) fn should_retry_sse_without_compression(
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

pub(super) async fn read_decoded_response_body_limited(
    response: Response,
    response_headers: HeaderMap,
    compression: CompressionMode,
) -> Result<(Vec<u8>, HeaderMap), FetchError> {
    let (reader, trailers) = async_response_reader(response);
    let mut reader = decoded_async_response_reader(reader, compression, &response_headers)?;
    let mut bytes = Vec::new();
    let mut buf = vec![0; 16 * 1024];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            let trailers = captured_trailers(&trailers);
            return Ok((bytes, trailers));
        }
        if bytes.len().saturating_add(n) > MAX_BUFFERED_RESPONSE_BYTES {
            return Err(FetchError::Message(format!(
                "response body exceeds {} bytes and cannot be buffered; use '--format off' or write to a file to stream it",
                MAX_BUFFERED_RESPONSE_BYTES
            )));
        }
        bytes.extend_from_slice(&buf[..n]);
    }
}

pub(super) async fn drain_response_body_bounded(mut response: Response) {
    drain_response_body_bounded_mut(&mut response).await;
}

pub(super) async fn drain_response_body_bounded_mut(response: &mut Response) {
    let mut discarded = 0usize;
    let drain_deadline = tokio::time::Instant::now() + MAX_RESPONSE_DRAIN_DURATION;
    while discarded < MAX_DISCARDED_RESPONSE_BYTES {
        if tokio::time::Instant::now() >= drain_deadline {
            break;
        }
        match tokio::time::timeout_at(drain_deadline, response.chunk()).await {
            Ok(Ok(Some(chunk))) => {
                discarded = discarded.saturating_add(chunk.len());
            }
            Ok(Ok(None)) | Ok(Err(_)) | Err(_) => break,
        }
    }
}

pub(super) struct StreamedOutput {
    trailers: HeaderMap,
    bytes_written: i64,
    clipboard: Option<clipboard::CopyOutcome>,
}

pub(super) trait StdoutStreamFormatter {
    fn push_chunk(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, FetchError>;

    fn finish(&mut self) -> Result<Vec<Vec<u8>>, FetchError>;
}

pub(super) fn captured_trailers(trailers: &ResponseTrailers) -> HeaderMap {
    trailers
        .lock()
        .map(|trailers| trailers.clone())
        .unwrap_or_default()
}

pub(super) async fn stream_response_to_discard(
    response: Response,
    response_headers: HeaderMap,
    compression: CompressionMode,
) -> Result<StreamedOutput, FetchError> {
    let (reader, trailers) = async_response_reader(response);
    let mut reader = decoded_async_response_reader(reader, compression, &response_headers)?;
    let mut sink = tokio::io::sink();
    let bytes_written = copy_async_reader_to_writer(&mut reader, &mut sink, None).await?;
    let trailers = captured_trailers(&trailers);
    Ok(StreamedOutput {
        trailers,
        bytes_written,
        clipboard: None,
    })
}

pub(super) async fn stream_response_to_stdout(
    cli: &Cli,
    response: Response,
    response_headers: HeaderMap,
    compression: CompressionMode,
    copy: bool,
    target: StdoutStreamTarget,
    stdout_is_terminal: bool,
) -> Result<StreamedOutput, FetchError> {
    let (reader, trailers) = async_response_reader(response);
    let mut reader = decoded_async_response_reader(reader, compression, &response_headers)?;
    let mut capture = copy.then(clipboard::Capture::default);
    let bytes_written = if terminal_binary_stdout_guard_enabled(cli, stdout_is_terminal) {
        stream_response_to_stdout_with_binary_check(cli, &mut reader, target, capture.as_mut())
            .await?
    } else {
        copy_async_reader_to_stdout_target(&mut reader, target, &[], capture.as_mut()).await?
    };
    let clipboard = capture.map(clipboard::Capture::copy);
    let trailers = captured_trailers(&trailers);
    Ok(StreamedOutput {
        trailers,
        bytes_written,
        clipboard,
    })
}

pub(super) async fn stream_response_to_formatted_sse_stdout(
    response: Response,
    response_headers: HeaderMap,
    compression: CompressionMode,
    copy: bool,
    use_color: bool,
) -> Result<StreamedOutput, FetchError> {
    stream_formatted_response_to_stdout(
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
    stream_formatted_response_to_stdout(
        response,
        response_headers,
        compression,
        copy,
        FormattedNdjsonStream::new(use_color),
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

pub(super) async fn stream_response_to_formatted_grpc_stdout(
    response: Response,
    response_headers: HeaderMap,
    compression: CompressionMode,
    copy: bool,
    grpc_response_desc: Option<prost_reflect::MessageDescriptor>,
) -> Result<StreamedOutput, FetchError> {
    let formatter = FormattedGrpcStream::new(&response_headers, grpc_response_desc);
    stream_formatted_response_to_stdout(response, response_headers, compression, copy, formatter)
        .await
}

pub(super) async fn stream_formatted_response_to_stdout<F>(
    response: Response,
    response_headers: HeaderMap,
    compression: CompressionMode,
    copy: bool,
    mut formatter: F,
) -> Result<StreamedOutput, FetchError>
where
    F: StdoutStreamFormatter,
{
    let (reader, trailers) = async_response_reader(response);
    let mut reader = decoded_async_response_reader(reader, compression, &response_headers)?;
    let mut stdout = tokio::io::stdout();
    let mut capture = copy.then(clipboard::Capture::default);
    let mut buf = vec![0; 16 * 1024];
    let mut bytes_read = 0i64;

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            if write_formatted_stream_outputs(&mut stdout, formatter.finish()?, false).await?
                == core::StdoutWriteStatus::Closed
            {
                let clipboard = capture.map(clipboard::Capture::copy);
                let trailers = captured_trailers(&trailers);
                return Ok(StreamedOutput {
                    trailers,
                    bytes_written: bytes_read,
                    clipboard,
                });
            }
            if flush_stdout(&mut stdout).await? == core::StdoutWriteStatus::Closed {
                let clipboard = capture.map(clipboard::Capture::copy);
                let trailers = captured_trailers(&trailers);
                return Ok(StreamedOutput {
                    trailers,
                    bytes_written: bytes_read,
                    clipboard,
                });
            }
            let clipboard = capture.map(clipboard::Capture::copy);
            let trailers = captured_trailers(&trailers);
            return Ok(StreamedOutput {
                trailers,
                bytes_written: bytes_read,
                clipboard,
            });
        }

        if let Some(capture) = capture.as_mut() {
            capture.push(&buf[..n]);
        }
        bytes_read = bytes_read.saturating_add(i64::try_from(n).unwrap_or(i64::MAX));
        if write_formatted_stream_outputs(&mut stdout, formatter.push_chunk(&buf[..n])?, true)
            .await?
            == core::StdoutWriteStatus::Closed
        {
            let clipboard = capture.map(clipboard::Capture::copy);
            let trailers = captured_trailers(&trailers);
            return Ok(StreamedOutput {
                trailers,
                bytes_written: bytes_read,
                clipboard,
            });
        }
    }
}

pub(super) async fn write_formatted_stream_outputs(
    stdout: &mut tokio::io::Stdout,
    outputs: Vec<Vec<u8>>,
    flush_after_each: bool,
) -> Result<core::StdoutWriteStatus, FetchError> {
    for output in outputs {
        if output.is_empty() {
            continue;
        }
        if core::stdout_write_status(stdout.write_all(&output).await)?
            == core::StdoutWriteStatus::Closed
        {
            return Ok(core::StdoutWriteStatus::Closed);
        }
        if flush_after_each && flush_stdout(stdout).await? == core::StdoutWriteStatus::Closed {
            return Ok(core::StdoutWriteStatus::Closed);
        }
    }
    Ok(core::StdoutWriteStatus::Open)
}

async fn flush_stdout(
    stdout: &mut tokio::io::Stdout,
) -> Result<core::StdoutWriteStatus, FetchError> {
    Ok(core::stdout_write_status(stdout.flush().await)?)
}

pub(super) struct FormattedSseStream {
    formatter: sse::EventStreamFormatter,
    pending: Vec<u8>,
    use_color: bool,
}

impl FormattedSseStream {
    fn new(use_color: bool) -> Self {
        Self {
            formatter: sse::EventStreamFormatter::new(),
            pending: Vec::new(),
            use_color,
        }
    }
}

impl StdoutStreamFormatter for FormattedSseStream {
    fn push_chunk(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, FetchError> {
        self.pending.extend_from_slice(chunk);
        let formatted =
            push_sse_stream_bytes(&mut self.pending, &mut self.formatter, self.use_color)
                .map_err(invalid_sse_utf8_error)?;
        Ok(vec![formatted.into_bytes()])
    }

    fn finish(&mut self) -> Result<Vec<Vec<u8>>, FetchError> {
        let formatted =
            finish_sse_stream_formatter(&mut self.pending, &mut self.formatter, self.use_color)
                .map_err(invalid_sse_utf8_error)?;
        Ok(vec![formatted.into_bytes()])
    }
}

pub(super) fn invalid_sse_utf8_error(err: std::str::Utf8Error) -> FetchError {
    FetchError::Message(format!("invalid UTF-8 in event stream: {err}"))
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

    fn with_record_limit(use_color: bool, max_record_bytes: usize) -> Self {
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

pub(super) struct FormattedGrpcStream {
    decoder: crate::grpc::framing::FrameDecoder,
    grpc_message_encoding: grpc_encoding::MessageEncoding,
    grpc_response_desc: Option<prost_reflect::MessageDescriptor>,
    frame_index: usize,
    descriptor_wrote_any: bool,
    descriptor_output_ends_with_newline: bool,
}

impl FormattedGrpcStream {
    fn new(
        response_headers: &HeaderMap,
        grpc_response_desc: Option<prost_reflect::MessageDescriptor>,
    ) -> Self {
        Self {
            decoder: crate::grpc::framing::FrameDecoder::new(),
            grpc_message_encoding: grpc_encoding::MessageEncoding::from_headers(response_headers),
            grpc_response_desc,
            frame_index: 0,
            descriptor_wrote_any: false,
            descriptor_output_ends_with_newline: true,
        }
    }

    fn format_frame(&mut self, frame: &crate::grpc::framing::Frame) -> Result<Vec<u8>, FetchError> {
        if let Some(desc) = self.grpc_response_desc.as_ref() {
            let formatted =
                proto::format_grpc_frame_with_descriptor(frame, desc, &self.grpc_message_encoding)
                    .map_err(|err| FetchError::Message(err.to_string()))?;
            let mut output = Vec::new();
            if self.descriptor_wrote_any && !self.descriptor_output_ends_with_newline {
                output.push(b'\n');
            }
            output.extend_from_slice(formatted.as_bytes());
            self.descriptor_output_ends_with_newline = formatted.ends_with('\n');
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
) -> Result<String, std::str::Utf8Error> {
    let mut out = core::Printer::new(use_color);
    loop {
        match std::str::from_utf8(pending) {
            Ok(input) => {
                formatter.push_str(input, &mut out);
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
                let input = std::str::from_utf8(&pending[..valid_up_to])?.to_string();
                formatter.push_str(&input, &mut out);
                pending.drain(..valid_up_to);
            }
            Err(err) => return Err(err),
        }
    }
}

pub(super) fn finish_sse_stream_formatter(
    pending: &mut Vec<u8>,
    formatter: &mut sse::EventStreamFormatter,
    use_color: bool,
) -> Result<String, std::str::Utf8Error> {
    let mut out = core::Printer::new(use_color);
    let chunk = push_sse_stream_bytes(pending, formatter, use_color)?;
    out.push_str(&chunk);
    formatter.finish(&mut out);
    Ok(out
        .into_string()
        .expect("event stream formatter output is valid UTF-8"))
}

pub(super) async fn stream_response_to_output(
    response: Response,
    response_headers: HeaderMap,
    compression: CompressionMode,
    path: String,
    clobber: bool,
    progress: output::WriteProgress,
    copy: bool,
) -> Result<StreamedOutput, FetchError> {
    let (reader, trailers) = async_response_reader(response);
    let mut reader = decoded_async_response_reader(reader, compression, &response_headers)?;
    let mut capture = copy.then(clipboard::Capture::default);
    let bytes_written = if let Some(capture) = capture.as_mut() {
        let mut reader = AsyncClipboardTeeReader { reader, capture };
        output::write_output_async_reader(&path, &mut reader, clobber, progress)
            .await
            .map_err(|err| FetchError::Message(err.to_string()))?
    } else {
        output::write_output_async_reader(&path, &mut reader, clobber, progress)
            .await
            .map_err(|err| FetchError::Message(err.to_string()))?
    };
    let clipboard = capture.map(clipboard::Capture::copy);
    let trailers = captured_trailers(&trailers);
    Ok(StreamedOutput {
        trailers,
        bytes_written,
        clipboard,
    })
}

pub(super) struct AsyncClipboardTeeReader<'a> {
    reader: AsyncReadBox,
    capture: &'a mut clipboard::Capture,
}

impl AsyncRead for AsyncClipboardTeeReader<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let filled_before = buf.filled().len();
        match self.reader.as_mut().poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let filled = buf.filled();
                self.capture.push(&filled[filled_before..]);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

pub(super) fn async_response_reader(response: Response) -> (AsyncReadBox, ResponseTrailers) {
    let (body, deadline) = response.into_body_with_deadline();
    let trailers = Arc::new(Mutex::new(HeaderMap::new()));
    let stream_trailers = trailers.clone();
    let stream = stream::try_unfold((body, deadline), move |(mut body, deadline)| {
        let stream_trailers = stream_trailers.clone();
        async move {
            loop {
                let Some(frame) = transport::read_body_frame(&mut body, deadline.as_ref())
                    .await
                    .map_err(|err| {
                        std::io::Error::other(transport_response_body_error_message(&err))
                    })?
                else {
                    return Ok::<
                        Option<(Bytes, (Body, Option<transport::BodyDeadline>))>,
                        std::io::Error,
                    >(None);
                };
                match frame.into_data() {
                    Ok(data) => {
                        if data.is_empty() {
                            continue;
                        }
                        return Ok(Some((data, (body, deadline))));
                    }
                    Err(frame) => {
                        if let Ok(trailers) = frame.into_trailers()
                            && let Ok(mut stored) = stream_trailers.lock()
                        {
                            *stored = trailers;
                        }
                    }
                }
            }
        }
    });
    (Box::pin(StreamReader::new(stream)), trailers)
}

pub(super) async fn stream_response_to_stdout_with_binary_check(
    cli: &Cli,
    reader: &mut AsyncReadBox,
    target: StdoutStreamTarget,
    mut capture: Option<&mut clipboard::Capture>,
) -> Result<i64, FetchError> {
    let mut first_chunk = vec![0; 16 * 1024];
    let n = reader.read(&mut first_chunk).await?;
    if n == 0 {
        return Ok(0);
    }

    let first_chunk = &first_chunk[..n];
    if !is_printable(first_chunk) {
        write_warning(cli, BINARY_RESPONSE_WARNING);
        if let Some(capture) = capture.as_mut() {
            capture.push(first_chunk);
        }
        let mut sink = tokio::io::sink();
        let drained = copy_async_reader_to_writer(reader, &mut sink, capture).await?;
        return Ok(i64::try_from(n).unwrap_or(i64::MAX).saturating_add(drained));
    }

    copy_async_reader_to_stdout_target(reader, target, first_chunk, capture).await
}

pub(super) async fn copy_async_reader_to_stdout_target(
    reader: &mut AsyncReadBox,
    target: StdoutStreamTarget,
    prefix: &[u8],
    capture: Option<&mut clipboard::Capture>,
) -> Result<i64, FetchError> {
    match target {
        StdoutStreamTarget::Direct => {
            let mut stdout = tokio::io::stdout();
            Ok(
                copy_async_reader_to_stdout_with_prefix(reader, &mut stdout, prefix, capture)
                    .await?,
            )
        }
        StdoutStreamTarget::Pager => stream_async_reader_to_pager(reader, prefix, capture).await,
    }
}

pub(super) async fn copy_async_reader_to_writer<W>(
    reader: &mut AsyncReadBox,
    writer: &mut W,
    mut capture: Option<&mut clipboard::Capture>,
) -> std::io::Result<i64>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0; 64 * 1024];
    let mut written = 0i64;
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            writer.flush().await?;
            return Ok(written);
        }
        if let Some(capture) = capture.as_mut() {
            capture.push(&buf[..n]);
        }
        writer.write_all(&buf[..n]).await?;
        written = written.saturating_add(i64::try_from(n).unwrap_or(i64::MAX));
    }
}

pub(super) async fn copy_async_reader_to_stdout<W>(
    reader: &mut AsyncReadBox,
    writer: &mut W,
    mut capture: Option<&mut clipboard::Capture>,
) -> std::io::Result<i64>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0; 64 * 1024];
    let mut written = 0i64;
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return match core::stdout_write_status(writer.flush().await)? {
                core::StdoutWriteStatus::Open => Ok(written),
                core::StdoutWriteStatus::Closed => Ok(written),
            };
        }
        match core::stdout_write_status(writer.write_all(&buf[..n]).await)? {
            core::StdoutWriteStatus::Open => {
                if let Some(capture) = capture.as_mut() {
                    capture.push(&buf[..n]);
                }
                written = written.saturating_add(i64::try_from(n).unwrap_or(i64::MAX));
            }
            core::StdoutWriteStatus::Closed => return Ok(written),
        }
    }
}

pub(super) async fn copy_async_reader_to_writer_with_prefix<W>(
    reader: &mut AsyncReadBox,
    writer: &mut W,
    prefix: &[u8],
    mut capture: Option<&mut clipboard::Capture>,
) -> std::io::Result<i64>
where
    W: AsyncWrite + Unpin,
{
    let mut written = 0i64;
    if !prefix.is_empty() {
        if let Some(capture) = capture.as_mut() {
            capture.push(prefix);
        }
        writer.write_all(prefix).await?;
        written = i64::try_from(prefix.len()).unwrap_or(i64::MAX);
    }
    Ok(written.saturating_add(copy_async_reader_to_writer(reader, writer, capture).await?))
}

pub(super) async fn copy_async_reader_to_stdout_with_prefix<W>(
    reader: &mut AsyncReadBox,
    writer: &mut W,
    prefix: &[u8],
    mut capture: Option<&mut clipboard::Capture>,
) -> std::io::Result<i64>
where
    W: AsyncWrite + Unpin,
{
    let mut written = 0i64;
    if !prefix.is_empty() {
        match core::stdout_write_status(writer.write_all(prefix).await)? {
            core::StdoutWriteStatus::Open => {
                if let Some(capture) = capture.as_mut() {
                    capture.push(prefix);
                }
                written = i64::try_from(prefix.len()).unwrap_or(i64::MAX);
            }
            core::StdoutWriteStatus::Closed => return Ok(0),
        }
    }
    Ok(written.saturating_add(copy_async_reader_to_stdout(reader, writer, capture).await?))
}

pub(super) async fn stream_async_reader_to_pager(
    reader: &mut AsyncReadBox,
    prefix: &[u8],
    capture: Option<&mut clipboard::Capture>,
) -> Result<i64, FetchError> {
    let mut child = match tokio::process::Command::new("less")
        .arg("-FIRX")
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(child) => child,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            let mut stdout = tokio::io::stdout();
            return Ok(copy_async_reader_to_stdout_with_prefix(
                reader,
                &mut stdout,
                prefix,
                capture,
            )
            .await?);
        }
        Err(err) => return Err(err.into()),
    };

    let mut bytes_written = 0;
    if let Some(mut stdin) = child.stdin.take() {
        match copy_async_reader_to_writer_with_prefix(reader, &mut stdin, prefix, capture).await {
            Ok(n) => bytes_written = n,
            Err(err) if err.kind() == ErrorKind::BrokenPipe => {}
            Err(err) => return Err(err.into()),
        }
    }

    let status = child.wait().await?;
    if !status.success() {
        return Err(FetchError::Runtime(format!("pager exited with {status}")));
    }

    Ok(bytes_written)
}

pub(super) fn handle_optional_clipboard_outcome(
    cli: &Cli,
    outcome: Option<clipboard::CopyOutcome>,
) {
    if let Some(outcome) = outcome {
        handle_clipboard_outcome(cli, outcome);
    }
}

pub(super) fn handle_clipboard_outcome(cli: &Cli, outcome: clipboard::CopyOutcome) {
    match outcome {
        clipboard::CopyOutcome::Copied { .. } => {}
        other => write_warning(cli, &other.to_string()),
    }
}

pub(super) fn body_duration(
    method_is_head: bool,
    bytes: &[u8],
    start: Instant,
) -> Option<Duration> {
    body_duration_from_len(
        method_is_head,
        i64::try_from(bytes.len()).unwrap_or(i64::MAX),
        start,
    )
}

pub(super) fn body_duration_from_len(
    method_is_head: bool,
    len: i64,
    start: Instant,
) -> Option<Duration> {
    if method_is_head || len == 0 {
        None
    } else {
        Some(start.elapsed())
    }
}

pub(super) fn print_timing(cli: &Cli, timing: Option<ResponseTiming>, body: Option<Duration>) {
    if !cli.timing || cli.silent {
        return;
    }
    let Some(mut timing) = timing else {
        return;
    };
    timing.body = body;
    let mut printer = core::stdio().stderr_printer(cli.color.as_deref());
    timing::render_waterfall_to(timing, &mut printer);
    let _ = printer.flush_to(&mut std::io::stderr());
}

pub(super) fn response_body_exceeds_discard_bound(response: &Response) -> bool {
    response
        .content_length()
        .is_some_and(|len| len > MAX_DISCARDED_RESPONSE_BYTES as u64)
}

pub(super) fn check_grpc_status(
    cli: &Cli,
    headers: &HeaderMap,
    trailers: &HeaderMap,
    exit_code: i32,
) -> i32 {
    if !cli.grpc {
        return exit_code;
    }
    let Some(status) = grpc_status::from_headers_or_trailers(headers, trailers) else {
        return exit_code;
    };
    if status.ok() {
        return exit_code;
    }
    if !cli.silent {
        write_error_with_color(status, cli.color.as_deref());
    }
    if exit_code == 0 { 1 } else { exit_code }
}

pub(super) fn print_response_metadata(cli: &Cli, response: &Response) {
    if cli.silent {
        return;
    }

    let status = response.status();
    let mut printer = core::Printer::stderr(cli.color.as_deref());
    if cli.verbose >= 2 {
        printer.write_response_prefix();
    }
    printer.write_styled(version_label(response.version()), &[core::Sequence::Dim]);
    printer.push_str(" ");
    let status_color = color_for_status(status.as_u16());
    printer.write_styled(
        &status.as_u16().to_string(),
        &[status_color, core::Sequence::Bold],
    );
    let reason = status.canonical_reason().unwrap_or("");
    if !reason.is_empty() {
        printer.push_str(" ");
        printer.write_styled(reason, &[status_color]);
    }
    printer.push_str("\n");

    if cli.verbose > 0 {
        let mut lines = header_lines(response.headers());
        if cli.sort_headers {
            sort_header_lines(&mut lines);
        }
        for (name, value) in lines {
            if cli.verbose >= 2 {
                printer.write_response_prefix();
            }
            printer.write_styled(&name, &[core::Sequence::Bold, core::Sequence::Cyan]);
            printer.push_str(": ");
            printer.push_str(&value);
            printer.push_str("\n");
        }
    }
    if cli.verbose >= 2 {
        printer.write_response_prefix();
    }
    printer.push_str("\n");
    flush_stderr(printer);
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
                proto::format_grpc_stream_with_descriptor(&bytes, &desc, &grpc_message_encoding)
                    .map(|formatted| formatted.into_bytes())
                    .map_err(|err| FetchError::Message(err.to_string()))
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
    })
}

pub(super) fn format_printer_bytes<E>(
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

pub(super) fn charset_decoder(charset: &str) -> Option<&'static encoding_rs::Encoding> {
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

pub(super) fn exit_code(status: u16, ignore_status: bool) -> i32 {
    if ignore_status || (200..400).contains(&status) {
        0
    } else if (400..500).contains(&status) {
        4
    } else if (500..600).contains(&status) {
        5
    } else {
        6
    }
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

    #[derive(Default)]
    struct RecordingAsyncWriter {
        bytes: Vec<u8>,
        flushes: usize,
    }

    impl AsyncWrite for RecordingAsyncWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.bytes.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

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

    #[test]
    fn terminal_binary_stdout_guard_requires_terminal_and_allows_forced_stdout() {
        let cli = Cli::try_parse_from(["fetch", "https://example.com"]).unwrap();
        assert!(should_warn_for_terminal_binary_stdout(
            &cli,
            b"abc\0def",
            true
        ));
        assert!(!should_warn_for_terminal_binary_stdout(
            &cli,
            b"abc\0def",
            false
        ));
        assert!(!should_warn_for_terminal_binary_stdout(
            &cli,
            b"plain text",
            true
        ));

        let forced = Cli::try_parse_from(["fetch", "-o", "-", "https://example.com"]).unwrap();
        assert!(!should_warn_for_terminal_binary_stdout(
            &forced,
            b"abc\0def",
            true
        ));
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
    fn pager_auto_uses_stdout_terminal_and_skips_images() {
        let cli = Cli::try_parse_from(["fetch", "https://example.com"]).unwrap();
        assert!(!should_page_stdout(
            &cli,
            b"\x1b_Gq=2,f=100,a=T,t=d,s=1,v=1,m=0;AAAA\x1b\\\n",
            ContentType::Image,
            true,
        ));
        assert!(should_page_stdout(
            &cli,
            b"{\"ok\":true}\n",
            ContentType::Json,
            true,
        ));
        assert!(!should_page_stdout(
            &cli,
            b"{\"ok\":true}\n",
            ContentType::Json,
            false,
        ));
    }

    #[test]
    fn pager_on_forces_pager_for_non_terminal_stdout() {
        let cli = Cli::try_parse_from(["fetch", "--pager", "on", "https://example.com"]).unwrap();
        assert!(should_page_stdout(
            &cli,
            b"{\"ok\":true}\n",
            ContentType::Json,
            false,
        ));
    }

    #[test]
    fn pager_off_disables_pager_for_terminal_stdout() {
        let cli = Cli::try_parse_from(["fetch", "--pager", "off", "https://example.com"]).unwrap();
        assert!(!should_page_stdout(
            &cli,
            b"{\"ok\":true}\n",
            ContentType::Json,
            true,
        ));
    }

    #[test]
    fn stdout_streaming_follows_format_and_pager_modes() {
        let headers = HeaderMap::new();
        let cli = Cli::try_parse_from(["fetch", "https://example.com"]).unwrap();
        assert!(matches!(
            stdout_stream_target(&cli, &headers, false),
            Some(StdoutStreamTarget::Direct)
        ));
        assert!(stdout_stream_target(&cli, &headers, true).is_none());

        let cli = Cli::try_parse_from(["fetch", "--format", "off", "https://example.com"]).unwrap();
        assert!(matches!(
            stdout_stream_target(&cli, &headers, false),
            Some(StdoutStreamTarget::Direct)
        ));
        assert!(matches!(
            stdout_stream_target(&cli, &headers, true),
            Some(StdoutStreamTarget::Pager)
        ));

        let cli = Cli::try_parse_from([
            "fetch",
            "--format",
            "off",
            "--pager",
            "off",
            "https://example.com",
        ])
        .unwrap();
        assert!(matches!(
            stdout_stream_target(&cli, &headers, true),
            Some(StdoutStreamTarget::Direct)
        ));

        let cli = Cli::try_parse_from([
            "fetch",
            "--format",
            "off",
            "--pager",
            "on",
            "https://example.com",
        ])
        .unwrap();
        assert!(matches!(
            stdout_stream_target(&cli, &headers, false),
            Some(StdoutStreamTarget::Pager)
        ));

        let cli = Cli::try_parse_from(["fetch", "--format", "on", "https://example.com"]).unwrap();
        assert!(stdout_stream_target(&cli, &headers, false).is_none());

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("image/png"));
        let cli = Cli::try_parse_from(["fetch", "--format", "off", "https://example.com"]).unwrap();
        assert!(matches!(
            stdout_stream_target(&cli, &headers, true),
            Some(StdoutStreamTarget::Direct)
        ));
    }

    #[tokio::test]
    async fn async_copy_flushes_once_after_streaming_body() {
        let input = vec![b'a'; (64 * 1024) + 17];
        let mut reader: AsyncReadBox = Box::pin(std::io::Cursor::new(input.clone()));
        let mut writer = RecordingAsyncWriter::default();

        let written = copy_async_reader_to_writer(&mut reader, &mut writer, None)
            .await
            .unwrap();

        assert_eq!(written, i64::try_from(input.len()).unwrap());
        assert_eq!(writer.bytes, input);
        assert_eq!(writer.flushes, 1);
    }

    #[tokio::test]
    async fn async_copy_with_prefix_flushes_once_after_streaming_body() {
        let prefix = b"first chunk";
        let body = vec![b'b'; (64 * 1024) + 17];
        let mut reader: AsyncReadBox = Box::pin(std::io::Cursor::new(body.clone()));
        let mut writer = RecordingAsyncWriter::default();

        let written =
            copy_async_reader_to_writer_with_prefix(&mut reader, &mut writer, prefix, None)
                .await
                .unwrap();

        let mut expected = prefix.to_vec();
        expected.extend_from_slice(&body);
        assert_eq!(written, i64::try_from(expected.len()).unwrap());
        assert_eq!(writer.bytes, expected);
        assert_eq!(writer.flushes, 1);
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
                "café",
            ),
            (
                "windows-1252 curly quotes",
                &[0x93, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x94][..],
                "windows-1252",
                "“hello”",
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
            "{\n  \"word\": \"café\"\n}\n"
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

    #[test]
    fn exit_code_maps_status_classes() {
        assert_eq!(exit_code(200, false), 0);
        assert_eq!(exit_code(302, false), 0);
        assert_eq!(exit_code(404, false), 4);
        assert_eq!(exit_code(503, false), 5);
        assert_eq!(exit_code(999, false), 6);
        assert_eq!(exit_code(404, true), 0);
    }
}
