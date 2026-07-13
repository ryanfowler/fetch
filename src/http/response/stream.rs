use super::*;

use super::stdout::{
    StdoutStreamTarget, binary_response_warning, response_header_content_type_label,
    terminal_binary_stdout_guard_enabled,
};

pub(super) const MAX_BUFFERED_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_DISCARDED_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_DRAIN_DURATION: Duration = Duration::from_millis(250);

type ResponseTrailers = Arc<Mutex<HeaderMap>>;

pub(super) async fn read_decoded_response_body_limited(
    response: Response,
    response_headers: HeaderMap,
    compression: CompressionMode,
) -> Result<(Vec<u8>, HeaderMap), FetchError> {
    read_decoded_response_body_with_limit_message(
        response,
        response_headers,
        compression,
        "cannot be buffered; use '--format off' or write to a file to stream it",
    )
    .await
}

pub(super) async fn read_decoded_article_body_limited(
    response: Response,
    response_headers: HeaderMap,
    compression: CompressionMode,
) -> Result<(Vec<u8>, HeaderMap), FetchError> {
    read_decoded_response_body_with_limit_message(
        response,
        response_headers,
        compression,
        "cannot be extracted as an article",
    )
    .await
}

async fn read_decoded_response_body_with_limit_message(
    response: Response,
    response_headers: HeaderMap,
    compression: CompressionMode,
    limit_message: &str,
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
                "response body exceeds {} bytes and {limit_message}",
                MAX_BUFFERED_RESPONSE_BYTES
            )));
        }
        bytes.extend_from_slice(&buf[..n]);
    }
}

pub(in crate::http) async fn drain_response_body_bounded(mut response: Response) {
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

pub(in crate::http) fn response_body_exceeds_discard_bound(response: &Response) -> bool {
    response
        .content_length()
        .is_some_and(|len| len > MAX_DISCARDED_RESPONSE_BYTES as u64)
}

pub(super) struct StreamedOutput {
    pub(super) trailers: HeaderMap,
    pub(super) bytes_written: i64,
    pub(super) clipboard: Option<clipboard::CopyOutcome>,
}

pub(super) trait StdoutStreamFormatter {
    fn push_chunk(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, FetchError>;

    fn finish(&mut self) -> Result<Vec<Vec<u8>>, FetchError>;
}

fn captured_trailers(trailers: &ResponseTrailers) -> HeaderMap {
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
        stream_response_to_stdout_with_binary_check(
            cli,
            &response_headers,
            &mut reader,
            target,
            capture.as_mut(),
        )
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

async fn write_formatted_stream_outputs(
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

struct AsyncClipboardTeeReader<'a> {
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

fn async_response_reader(response: Response) -> (AsyncReadBox, ResponseTrailers) {
    let (body, deadline) = response.into_body_with_deadline();
    let trailers = Arc::new(Mutex::new(HeaderMap::new()));
    let stream_trailers = trailers.clone();
    let stream = futures_util::stream::try_unfold((body, deadline), move |(mut body, deadline)| {
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

async fn stream_response_to_stdout_with_binary_check(
    cli: &Cli,
    response_headers: &HeaderMap,
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
        write_warning(
            cli,
            &binary_response_warning(&response_header_content_type_label(response_headers)),
        );
        if let Some(capture) = capture.as_mut() {
            capture.push(first_chunk);
        }
        let mut sink = tokio::io::sink();
        let drained = copy_async_reader_to_writer(reader, &mut sink, capture).await?;
        return Ok(i64::try_from(n).unwrap_or(i64::MAX).saturating_add(drained));
    }

    // Write first chunk and continue checking subsequent chunks against binary data.
    match target {
        StdoutStreamTarget::Direct => {
            let mut stdout = tokio::io::stdout();
            copy_checked_async_reader_to_stdout(
                reader,
                &mut stdout,
                first_chunk,
                capture,
                cli,
                response_headers,
            )
            .await
        }
        StdoutStreamTarget::Pager => {
            stream_checked_async_reader_to_pager(
                reader,
                first_chunk,
                capture,
                cli,
                response_headers,
            )
            .await
        }
    }
}

/// Like [`copy_async_reader_to_sink`] but checks every chunk with
/// [`is_printable`] before writing.  If any chunk appears binary the
/// function drains the remainder and sets `triggered` so the caller can
/// emit a warning.
///
/// To avoid false positives when a multi-byte UTF-8 character is split
/// across transport read boundaries, trailing incomplete UTF-8 bytes
/// from one chunk are prepended to the next chunk before classification.
async fn copy_checked_async_reader_to_writer<W>(
    reader: &mut AsyncReadBox,
    writer: &mut W,
    prefix: &[u8],
    mut capture: Option<&mut clipboard::Capture>,
    broken_pipe: SinkBrokenPipePolicy,
    triggered: &mut bool,
) -> std::io::Result<i64>
where
    W: AsyncWrite + Unpin,
{
    *triggered = false;
    let mut written = 0i64;

    // Carries incomplete trailing bytes from a previous chunk so that
    // split multi-byte characters are classified on the combined bytes.
    let mut carry: Vec<u8> = Vec::with_capacity(4);
    if !prefix.is_empty() {
        if !is_printable(prefix) {
            *triggered = true;
            if let Some(capture) = capture.as_mut() {
                capture.push(prefix);
            }
            written = written.saturating_add(i64::try_from(prefix.len()).unwrap_or(i64::MAX));
            let mut sink = tokio::io::sink();
            let drained = copy_async_reader_to_writer(reader, &mut sink, capture).await?;
            return Ok(written.saturating_add(drained));
        }

        let (complete, tail) = split_incomplete_trailing_utf8(prefix);
        if !complete.is_empty()
            && write_stream_chunk(writer, complete, &mut capture, &mut written, broken_pipe).await?
                == SinkWriteStatus::Closed
        {
            return Ok(written);
        }
        carry.extend_from_slice(tail);
    }

    let mut combined: Vec<u8> = Vec::new();
    let mut buf = vec![0; 64 * 1024];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            if !carry.is_empty() {
                // Flush an orphaned incomplete suffix. Writing it now
                // preserves the original bytes; the classifier already
                // approved the preceding chunk with this suffix present.
                if write_stream_chunk(writer, &carry, &mut capture, &mut written, broken_pipe)
                    .await?
                    == SinkWriteStatus::Closed
                {
                    return Ok(written);
                }
                carry.clear();
            }
            let _ = stream_sink_status(writer.flush().await, broken_pipe)?;
            return Ok(written);
        }

        // Build a combined slice for classification: any trailing
        // bytes from the previous chunk + the new data.
        combined.clear();
        combined.extend_from_slice(&carry);
        combined.extend_from_slice(&buf[..n]);

        if !is_printable(&combined) {
            *triggered = true;
            if let Some(capture) = capture.as_mut() {
                capture.push(&combined);
            }
            written = written.saturating_add(i64::try_from(combined.len()).unwrap_or(i64::MAX));
            carry.clear();
            let mut sink = tokio::io::sink();
            let drained = copy_async_reader_to_writer(reader, &mut sink, capture).await?;
            return Ok(written.saturating_add(drained));
        }

        // Classification passed.  Keep any trailing incomplete UTF-8
        // for the next chunk and write the complete portion now.
        let (complete, tail) = split_incomplete_trailing_utf8(&combined);
        if !complete.is_empty()
            && write_stream_chunk(writer, complete, &mut capture, &mut written, broken_pipe).await?
                == SinkWriteStatus::Closed
        {
            return Ok(written);
        }
        carry.clear();
        carry.extend_from_slice(tail);
    }
}

/// Splits `bytes` into a complete prefix and an incomplete trailing
/// portion (at most 3 bytes).  The incomplete portion is the longest
/// suffix that by itself forms an invalid, truncated UTF-8 sequence.
fn split_incomplete_trailing_utf8(bytes: &[u8]) -> (&[u8], &[u8]) {
    let len = bytes.len();
    // Check from shortest to longest tail so we find the smallest
    // incomplete suffix.
    for tail_len in 1..=4.min(len) {
        let split = len - tail_len;
        if let Err(e) = std::str::from_utf8(&bytes[split..])
            && e.error_len().is_none()
        {
            return (&bytes[..split], &bytes[split..]);
        }
    }
    (bytes, &[])
}

/// Like [`copy_checked_async_reader_to_writer`] specialised for stdout:
/// emits the binary warning to stderr when the guard triggers.
async fn copy_checked_async_reader_to_stdout(
    reader: &mut AsyncReadBox,
    stdout: &mut tokio::io::Stdout,
    prefix: &[u8],
    capture: Option<&mut clipboard::Capture>,
    cli: &Cli,
    response_headers: &HeaderMap,
) -> Result<i64, FetchError> {
    let mut triggered = false;
    let written = copy_checked_async_reader_to_writer(
        reader,
        stdout,
        prefix,
        capture,
        SinkBrokenPipePolicy::TreatAsClosed,
        &mut triggered,
    )
    .await?;
    if triggered {
        write_warning(
            cli,
            &binary_response_warning(&response_header_content_type_label(response_headers)),
        );
    }
    Ok(written)
}

async fn copy_async_reader_to_stdout_target(
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
    capture: Option<&mut clipboard::Capture>,
) -> std::io::Result<i64>
where
    W: AsyncWrite + Unpin,
{
    copy_async_reader_to_sink(
        reader,
        writer,
        &[],
        capture,
        SinkBrokenPipePolicy::Propagate,
    )
    .await
}

async fn copy_async_reader_to_stdout_with_prefix<W>(
    reader: &mut AsyncReadBox,
    writer: &mut W,
    prefix: &[u8],
    capture: Option<&mut clipboard::Capture>,
) -> std::io::Result<i64>
where
    W: AsyncWrite + Unpin,
{
    copy_async_reader_to_sink(
        reader,
        writer,
        prefix,
        capture,
        SinkBrokenPipePolicy::TreatAsClosed,
    )
    .await
}

#[derive(Clone, Copy)]
enum SinkBrokenPipePolicy {
    Propagate,
    TreatAsClosed,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SinkWriteStatus {
    Open,
    Closed,
}

async fn copy_async_reader_to_sink<W>(
    reader: &mut AsyncReadBox,
    writer: &mut W,
    prefix: &[u8],
    mut capture: Option<&mut clipboard::Capture>,
    broken_pipe: SinkBrokenPipePolicy,
) -> std::io::Result<i64>
where
    W: AsyncWrite + Unpin,
{
    let mut written = 0i64;
    if write_stream_chunk(writer, prefix, &mut capture, &mut written, broken_pipe).await?
        == SinkWriteStatus::Closed
    {
        return Ok(written);
    }

    let mut buf = vec![0; 64 * 1024];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            let _ = stream_sink_status(writer.flush().await, broken_pipe)?;
            return Ok(written);
        }
        if write_stream_chunk(writer, &buf[..n], &mut capture, &mut written, broken_pipe).await?
            == SinkWriteStatus::Closed
        {
            return Ok(written);
        }
    }
}

async fn write_stream_chunk<W>(
    writer: &mut W,
    bytes: &[u8],
    capture: &mut Option<&mut clipboard::Capture>,
    written: &mut i64,
    broken_pipe: SinkBrokenPipePolicy,
) -> std::io::Result<SinkWriteStatus>
where
    W: AsyncWrite + Unpin,
{
    if bytes.is_empty() {
        return Ok(SinkWriteStatus::Open);
    }
    match stream_sink_status(writer.write_all(bytes).await, broken_pipe)? {
        SinkWriteStatus::Open => {
            if let Some(capture) = capture.as_deref_mut() {
                capture.push(bytes);
            }
            *written = (*written).saturating_add(i64::try_from(bytes.len()).unwrap_or(i64::MAX));
            Ok(SinkWriteStatus::Open)
        }
        SinkWriteStatus::Closed => Ok(SinkWriteStatus::Closed),
    }
}

fn stream_sink_status(
    result: std::io::Result<()>,
    broken_pipe: SinkBrokenPipePolicy,
) -> std::io::Result<SinkWriteStatus> {
    match result {
        Ok(()) => Ok(SinkWriteStatus::Open),
        Err(err)
            if matches!(broken_pipe, SinkBrokenPipePolicy::TreatAsClosed)
                && core::is_broken_pipe(&err) =>
        {
            Ok(SinkWriteStatus::Closed)
        }
        Err(err) => Err(err),
    }
}

async fn stream_async_reader_to_pager(
    reader: &mut AsyncReadBox,
    prefix: &[u8],
    capture: Option<&mut clipboard::Capture>,
) -> Result<i64, FetchError> {
    let pager = output::pager::command();
    let mut child = match tokio::process::Command::new(&pager.program)
        .args(&pager.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(child) => child,
        Err(err) if pager.is_fallback && err.kind() == ErrorKind::NotFound => {
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
        bytes_written = copy_async_reader_to_sink(
            reader,
            &mut stdin,
            prefix,
            capture,
            SinkBrokenPipePolicy::TreatAsClosed,
        )
        .await?;
    }

    let status = child.wait().await?;
    if !status.success() {
        return Err(FetchError::Runtime(format!("pager exited with {status}")));
    }

    Ok(bytes_written)
}

/// Like [`stream_async_reader_to_pager`] but checks each chunk for
/// binary data before writing.  If binary is detected mid-stream the
/// function drains the remainder, emits a warning, and returns.
async fn stream_checked_async_reader_to_pager(
    reader: &mut AsyncReadBox,
    prefix: &[u8],
    capture: Option<&mut clipboard::Capture>,
    cli: &Cli,
    response_headers: &HeaderMap,
) -> Result<i64, FetchError> {
    let pager = output::pager::command();
    let mut child = match tokio::process::Command::new(&pager.program)
        .args(&pager.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(child) => child,
        Err(err) if pager.is_fallback && err.kind() == ErrorKind::NotFound => {
            let mut stdout = tokio::io::stdout();
            let mut triggered = false;
            let written = copy_checked_async_reader_to_writer(
                reader,
                &mut stdout,
                prefix,
                capture,
                SinkBrokenPipePolicy::TreatAsClosed,
                &mut triggered,
            )
            .await?;
            if triggered {
                write_warning(
                    cli,
                    &binary_response_warning(&response_header_content_type_label(response_headers)),
                );
            }
            return Ok(written);
        }
        Err(err) => return Err(err.into()),
    };

    let mut bytes_written = 0i64;
    let mut triggered = false;
    if let Some(mut stdin) = child.stdin.take() {
        bytes_written = copy_checked_async_reader_to_writer(
            reader,
            &mut stdin,
            prefix,
            capture,
            SinkBrokenPipePolicy::TreatAsClosed,
            &mut triggered,
        )
        .await?;
    }

    let status = child.wait().await?;
    if !status.success() {
        return Err(FetchError::Runtime(format!("pager exited with {status}")));
    }

    if triggered {
        write_warning(
            cli,
            &binary_response_warning(&response_header_content_type_label(response_headers)),
        );
    }

    Ok(bytes_written)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    struct BrokenPipeAfterFirstWrite {
        bytes: Vec<u8>,
    }

    impl AsyncWrite for BrokenPipeAfterFirstWrite {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.bytes.is_empty() {
                self.bytes.extend_from_slice(buf);
                Poll::Ready(Ok(buf.len()))
            } else {
                Poll::Ready(Err(std::io::Error::new(
                    ErrorKind::BrokenPipe,
                    "sink closed",
                )))
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
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

        let written = copy_async_reader_to_sink(
            &mut reader,
            &mut writer,
            prefix,
            None,
            SinkBrokenPipePolicy::Propagate,
        )
        .await
        .unwrap();

        let mut expected = prefix.to_vec();
        expected.extend_from_slice(&body);
        assert_eq!(written, i64::try_from(expected.len()).unwrap());
        assert_eq!(writer.bytes, expected);
        assert_eq!(writer.flushes, 1);
    }

    #[tokio::test]
    async fn async_copy_treats_broken_pipe_as_closed_when_requested() {
        let input = vec![b'a'; (64 * 1024) + 17];
        let mut reader: AsyncReadBox = Box::pin(std::io::Cursor::new(input));
        let mut writer = BrokenPipeAfterFirstWrite { bytes: Vec::new() };

        let written = copy_async_reader_to_sink(
            &mut reader,
            &mut writer,
            &[],
            None,
            SinkBrokenPipePolicy::TreatAsClosed,
        )
        .await
        .unwrap();

        assert_eq!(written, 64 * 1024);
        assert_eq!(writer.bytes, vec![b'a'; 64 * 1024]);
    }

    /// When a body is entirely printable the checked copy forwards every byte.
    #[tokio::test]
    async fn checked_copy_forwards_printable_body() {
        let body: Vec<u8> = (b'a'..=b'z').cycle().take(20 * 1024).collect();
        let mut reader: AsyncReadBox = Box::pin(std::io::Cursor::new(body.clone()));
        let mut writer = RecordingAsyncWriter::default();
        let mut triggered = false;

        let written = copy_checked_async_reader_to_writer(
            &mut reader,
            &mut writer,
            &[],
            None,
            SinkBrokenPipePolicy::Propagate,
            &mut triggered,
        )
        .await
        .unwrap();

        assert!(!triggered, "guard should not trigger on printable body");
        assert_eq!(written, i64::try_from(body.len()).unwrap());
        assert_eq!(writer.bytes, body);
        assert_eq!(writer.flushes, 1);
    }

    /// When a prefix is printable but a later chunk contains binary data
    /// the checked copy must forward the prefix, consume the rest, and
    /// signal that the guard triggered.
    #[tokio::test]
    async fn checked_copy_triggers_on_binary_after_printable_prefix() {
        // The read buffer is 64 KiB; use a body larger than one buffer
        // so the first read is all-printable and the second contains
        // the binary tail.
        let prefix_len = 65 * 1024;
        let mut body = vec![b'A'; prefix_len];
        body.extend_from_slice(b"\0MORE");

        let mut reader: AsyncReadBox = Box::pin(std::io::Cursor::new(body.clone()));
        let mut writer = RecordingAsyncWriter::default();
        let mut triggered = false;

        let written = copy_checked_async_reader_to_writer(
            &mut reader,
            &mut writer,
            &[],
            None,
            SinkBrokenPipePolicy::Propagate,
            &mut triggered,
        )
        .await
        .unwrap();

        assert!(
            triggered,
            "guard must trigger when binary chunk appears mid-stream"
        );
        // The first 64 KiB were forwarded before the binary tail was
        // encountered in the second read.
        assert_eq!(writer.bytes.len(), 64 * 1024);
        assert!(writer.bytes.iter().all(|&b| b == b'A'));
        // The total byte count includes everything (forwarded + consumed).
        assert_eq!(written, i64::try_from(body.len()).unwrap());
    }

    #[test]
    fn trailing_utf8_detects_split_multibyte_characters() {
        // Complete sequences return no tail.
        assert_eq!(
            split_incomplete_trailing_utf8(b"hello"),
            (&b"hello"[..], &b""[..])
        );
        // 2-byte: é = C3 A9
        assert_eq!(
            split_incomplete_trailing_utf8(b"abc\xC3\xA9"),
            (&b"abc\xC3\xA9"[..], &b""[..])
        );
        // Truncated 2-byte: only start byte remains.
        let (complete, tail) = split_incomplete_trailing_utf8(b"abc\xC3");
        assert_eq!(complete, b"abc");
        assert_eq!(tail, b"\xC3");
        // Truncated 3-byte: start + one continuation.
        // ☃ (U+2603) = E2 98 83
        let (complete, tail) = split_incomplete_trailing_utf8(b"ab\xE2\x98");
        assert_eq!(complete, b"ab");
        assert_eq!(tail, b"\xE2\x98");
        // Truncated 4-byte: start + two continuation.
        // 😀 (U+1F600) = F0 9F 98 80
        let (complete, tail) = split_incomplete_trailing_utf8(b"a\xF0\x9F\x98");
        assert_eq!(complete, b"a");
        assert_eq!(tail, b"\xF0\x9F\x98");
        // Orphaned continuation bytes (no start byte in slice) are
        // not marked as incomplete because we can't know the expected
        // length — the start byte was in a previous chunk.
        assert_eq!(
            split_incomplete_trailing_utf8(b"\x98\x80"),
            (&b"\x98\x80"[..], &b""[..])
        );
    }

    /// If binary data follows an incomplete UTF-8 tail, the carried
    /// byte is consumed and counted even though it is not written.
    #[tokio::test]
    async fn checked_copy_counts_carried_bytes_when_binary_triggers() {
        let prefix = b"ok\xC3";
        let suffix = b"\0rest";
        let mut reader: AsyncReadBox = Box::pin(std::io::Cursor::new(suffix));
        let mut writer = RecordingAsyncWriter::default();
        let mut triggered = false;

        let written = copy_checked_async_reader_to_writer(
            &mut reader,
            &mut writer,
            prefix,
            None,
            SinkBrokenPipePolicy::Propagate,
            &mut triggered,
        )
        .await
        .unwrap();

        assert!(triggered, "guard must trigger on binary data after carry");
        assert_eq!(written, i64::try_from(prefix.len() + suffix.len()).unwrap());
        assert_eq!(writer.bytes, b"ok");
    }

    /// Valid UTF-8 text split between the initial prefix and the first
    /// reader chunk must not trigger the binary guard.
    #[tokio::test]
    async fn checked_copy_handles_split_utf8_after_prefix() {
        let prefix = b"caf\xC3";
        let suffix = b"\xA9 au lait";
        let mut reader: AsyncReadBox = Box::pin(std::io::Cursor::new(suffix));
        let mut writer = RecordingAsyncWriter::default();
        let mut triggered = false;

        let written = copy_checked_async_reader_to_writer(
            &mut reader,
            &mut writer,
            prefix,
            None,
            SinkBrokenPipePolicy::Propagate,
            &mut triggered,
        )
        .await
        .unwrap();

        assert!(!triggered, "guard must not trigger on valid split UTF-8");
        assert_eq!(written, i64::try_from(prefix.len() + suffix.len()).unwrap());
        assert_eq!(writer.bytes, b"caf\xC3\xA9 au lait");
    }

    /// Valid UTF-8 text split across read boundaries must not trigger
    /// the binary guard.
    #[tokio::test]
    async fn checked_copy_handles_split_utf8_across_reads() {
        // "café" repeated so that the multi-byte 'é' (C3 A9) is split
        // across reads: the first 4-byte read ends with C3, and the
        // next read starts with A9.
        let body: Vec<u8> = b"caf\xC3\xA9".repeat(16 * 1024);
        // Wrap in a reader that returns at most 4 bytes at a time,
        // guaranteeing that C3 and A9 land in different chunks.
        let reader = ChunkedReader {
            inner: std::io::Cursor::new(body.clone()),
            chunk_size: 4,
        };
        let mut reader: AsyncReadBox = Box::pin(reader);
        let mut writer = RecordingAsyncWriter::default();
        let mut triggered = false;

        let written = copy_checked_async_reader_to_writer(
            &mut reader,
            &mut writer,
            &[],
            None,
            SinkBrokenPipePolicy::Propagate,
            &mut triggered,
        )
        .await
        .unwrap();

        assert!(!triggered, "guard must not trigger on valid split UTF-8");
        assert_eq!(written, i64::try_from(body.len()).unwrap());
        assert_eq!(writer.bytes, body);
    }

    /// Test helper that wraps a [`std::io::Read`] and limits each
    /// [`AsyncRead::poll_read`] call to at most `chunk_size` bytes.
    struct ChunkedReader<R> {
        inner: R,
        chunk_size: usize,
    }

    impl<R: std::io::Read + Unpin> AsyncRead for ChunkedReader<R> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let limit = self.chunk_size.min(buf.remaining());
            if limit == 0 {
                return Poll::Ready(Ok(()));
            }
            let mut tmp = vec![0u8; limit];
            match self.inner.read(&mut tmp) {
                Ok(0) => Poll::Ready(Ok(())),
                Ok(n) => {
                    buf.put_slice(&tmp[..n]);
                    Poll::Ready(Ok(()))
                }
                Err(e) => Poll::Ready(Err(e)),
            }
        }
    }
}
