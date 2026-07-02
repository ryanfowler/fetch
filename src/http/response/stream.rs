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

    copy_async_reader_to_stdout_target(reader, target, first_chunk, capture).await
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
}
