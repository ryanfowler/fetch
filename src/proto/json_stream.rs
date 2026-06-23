use bytes::Bytes;
use prost_reflect::MessageDescriptor;
use std::io::Read;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::grpc::framing;
use crate::proto::ProtoError;
use crate::proto::convert::json_value_to_grpc_frame;

const MAX_GRPC_JSON_PENDING_BYTES: usize = framing::MAX_MESSAGE_SIZE;

pub fn stream_json_to_grpc_frames(
    json_stream: &[u8],
    desc: &MessageDescriptor,
) -> Result<Vec<u8>, ProtoError> {
    let mut out = Vec::new();
    let stream = serde_json::Deserializer::from_slice(json_stream).into_iter::<serde_json::Value>();
    for value in stream {
        let value = value
            .map_err(|err| ProtoError::Message(format!("failed to decode JSON message: {err}")))?;
        out.extend_from_slice(&json_value_to_grpc_frame(value, desc)?);
    }
    Ok(out)
}

pub(crate) fn json_reader_to_grpc_frame_stream<R>(
    reader: R,
    desc: MessageDescriptor,
) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    json_reader_to_grpc_frame_stream_with_limit(reader, desc, MAX_GRPC_JSON_PENDING_BYTES)
}

pub(crate) fn json_reader_to_grpc_frame_stream_with_limit<R>(
    reader: R,
    desc: MessageDescriptor,
    max_pending_json_bytes: usize,
) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    struct State<R> {
        reader: R,
        desc: MessageDescriptor,
        pending: Vec<u8>,
        eof: bool,
        max_pending_json_bytes: usize,
    }

    futures_util::stream::try_unfold(
        State {
            reader,
            desc,
            pending: Vec::new(),
            eof: false,
            max_pending_json_bytes,
        },
        |mut state| async move {
            loop {
                discard_leading_json_whitespace(&mut state.pending);
                validate_grpc_json_pending_len(state.pending.len(), state.max_pending_json_bytes)
                    .map_err(std::io::Error::other)?;
                match parse_next_json_value(&state.pending, state.eof) {
                    Ok(JsonParse::Message { value, consumed }) => {
                        state.pending.drain(..consumed);
                        let frame = json_value_to_grpc_frame(value, &state.desc)
                            .map_err(std::io::Error::other)?;
                        return Ok(Some((Bytes::from(frame), state)));
                    }
                    Ok(JsonParse::NeedMore) => {}
                    Ok(JsonParse::Done) => return Ok(None),
                    Err(err) => return Err(std::io::Error::other(err)),
                }

                if state.eof {
                    return Ok(None);
                }

                let mut buf = [0_u8; 16 * 1024];
                let n = state.reader.read(&mut buf).await?;
                if n == 0 {
                    state.eof = true;
                } else {
                    state.pending.extend_from_slice(&buf[..n]);
                }
            }
        },
    )
}

pub(crate) fn stdin_json_to_grpc_frame_stream(
    desc: MessageDescriptor,
) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> {
    const READ_BUF_LEN: usize = 16 * 1024;

    let (tx, rx) = tokio::sync::mpsc::channel(1);
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut stdin_read = StdinReadState::new(&stdin);
        let mut reader = stdin.lock();
        let mut pending = Vec::new();
        let mut eof = false;
        let mut buf = [0_u8; READ_BUF_LEN];

        loop {
            discard_leading_json_whitespace(&mut pending);
            if let Err(err) =
                validate_grpc_json_pending_len(pending.len(), MAX_GRPC_JSON_PENDING_BYTES)
            {
                let _ = tx.blocking_send(Err(std::io::Error::other(err)));
                break;
            }
            match parse_next_json_value(&pending, eof) {
                Ok(JsonParse::Message { value, consumed }) => {
                    pending.drain(..consumed);
                    let item = json_value_to_grpc_frame(value, &desc)
                        .map(Bytes::from)
                        .map_err(std::io::Error::other);
                    if tx.blocking_send(item).is_err() {
                        break;
                    }
                }
                Ok(JsonParse::NeedMore) => {}
                Ok(JsonParse::Done) => break,
                Err(err) => {
                    let _ = tx.blocking_send(Err(std::io::Error::other(err)));
                    break;
                }
            }

            if eof {
                break;
            }

            match stdin_read.read_chunk(&mut reader, &mut buf) {
                Ok(0) => eof = true,
                Ok(n) => pending.extend_from_slice(&buf[..n]),
                Err(err) => {
                    let _ = tx.blocking_send(Err(err));
                    break;
                }
            }
        }
    });

    futures_util::stream::unfold(rx, |mut rx| async {
        rx.recv().await.map(|item| (item, rx))
    })
}

fn discard_leading_json_whitespace(pending: &mut Vec<u8>) {
    match pending.iter().position(|byte| !byte.is_ascii_whitespace()) {
        Some(0) => {}
        Some(first_non_whitespace) => {
            pending.drain(..first_non_whitespace);
        }
        None => pending.clear(),
    }
}

fn validate_grpc_json_pending_len(len: usize, max: usize) -> Result<(), ProtoError> {
    if len > max {
        return Err(ProtoError::Message(format!(
            "gRPC JSON message exceeds {max} bytes before a complete JSON value"
        )));
    }
    Ok(())
}

#[cfg(not(windows))]
struct StdinReadState;

#[cfg(not(windows))]
impl StdinReadState {
    fn new(_stdin: &std::io::Stdin) -> Self {
        Self
    }

    fn read_chunk<R: Read>(&mut self, reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
        reader.read(buf)
    }
}

#[cfg(windows)]
struct StdinReadState {
    handle: windows_sys::Win32::Foundation::HANDLE,
    is_pipe: bool,
}

#[cfg(windows)]
impl StdinReadState {
    fn new(stdin: &std::io::Stdin) -> Self {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType};

        let handle = stdin.as_raw_handle();
        // SAFETY: the handle is borrowed from stdio and remains valid while
        // stdin is alive; GetFileType does not retain it.
        let is_pipe = unsafe { GetFileType(handle) } == FILE_TYPE_PIPE;
        Self { handle, is_pipe }
    }

    fn read_chunk<R: Read>(&mut self, reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.is_pipe {
            return reader.read(buf);
        }

        loop {
            match self.pipe_bytes_available()? {
                PipeReadiness::Available(0) => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                PipeReadiness::Available(n) => {
                    let len = n.min(buf.len());
                    return reader.read(&mut buf[..len]);
                }
                PipeReadiness::Eof => return Ok(0),
            }
        }
    }

    fn pipe_bytes_available(&self) -> std::io::Result<PipeReadiness> {
        use windows_sys::Win32::Foundation::{ERROR_BROKEN_PIPE, ERROR_HANDLE_EOF, GetLastError};
        use windows_sys::Win32::System::Pipes::PeekNamedPipe;

        let mut available = 0_u32;
        // SAFETY: the handle is a stdin pipe handle. All optional output
        // pointers are either null or valid for the duration of the call.
        let ok = unsafe {
            PeekNamedPipe(
                self.handle,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        };
        if ok != 0 {
            return Ok(PipeReadiness::Available(available as usize));
        }

        // SAFETY: GetLastError reads the thread-local error from the failed
        // PeekNamedPipe call above.
        match unsafe { GetLastError() } {
            ERROR_BROKEN_PIPE | ERROR_HANDLE_EOF => Ok(PipeReadiness::Eof),
            _ => Err(std::io::Error::last_os_error()),
        }
    }
}

#[cfg(windows)]
enum PipeReadiness {
    Available(usize),
    Eof,
}

enum JsonParse {
    Message {
        value: serde_json::Value,
        consumed: usize,
    },
    NeedMore,
    Done,
}

fn parse_next_json_value(buf: &[u8], eof: bool) -> Result<JsonParse, ProtoError> {
    if buf.is_empty() {
        return Ok(if eof {
            JsonParse::Done
        } else {
            JsonParse::NeedMore
        });
    }
    if buf.iter().all(u8::is_ascii_whitespace) {
        return Ok(if eof {
            JsonParse::Done
        } else {
            JsonParse::NeedMore
        });
    }

    let mut stream = serde_json::Deserializer::from_slice(buf).into_iter::<serde_json::Value>();
    match stream.next() {
        Some(Ok(value)) => Ok(JsonParse::Message {
            value,
            consumed: stream.byte_offset(),
        }),
        Some(Err(err)) if err.is_eof() && !eof => Ok(JsonParse::NeedMore),
        Some(Err(err)) => Err(ProtoError::Message(format!(
            "failed to decode JSON message: {err}"
        ))),
        None => Ok(if eof {
            JsonParse::Done
        } else {
            JsonParse::NeedMore
        }),
    }
}
