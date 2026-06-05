use std::collections::HashSet;
use std::error::Error as StdError;
use std::future::Future;
use std::io::{self, BufRead, Read, Write};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(test)]
use base64::Engine;
use futures_util::{Sink, SinkExt, StreamExt};
use http::header::{ACCEPT, AUTHORIZATION, COOKIE, HeaderMap, HeaderValue, SET_COOKIE, USER_AGENT};
#[cfg(test)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::error::CapacityError;
use tokio_tungstenite::tungstenite::http::{
    HeaderMap as WsHeaderMap, HeaderName as WsHeaderName, HeaderValue as WsHeaderValue,
    Version as WsVersion,
};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{Connector, client_async_tls_with_config};
use url::Url;

use crate::auth::aws_sigv4;
use crate::cli::Cli;
use crate::core;
use crate::duration::{TimeoutBudget, duration_from_seconds};
use crate::error::{
    FetchError, write_warning_with_color, write_warnings_with_separator_with_color,
};
use crate::format::json;
use crate::net::DialStream;

pub mod interactive;

const STDIN_MESSAGE_CHANNEL_CAPACITY: usize = 16;
const STDIN_BINARY_CHUNK_SIZE: usize = 16 * 1024;
const STDIN_TEXT_MESSAGE_MAX_BYTES: usize = 16 * 1024 * 1024;
const WEBSOCKET_MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const WEBSOCKET_MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const BINARY_MESSAGE_WARNING: &str = "the WebSocket message appears to be binary\n\nRedirect stdout to a file or pipe to output binary WebSocket messages";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MessageOutput {
    Continue,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WebSocketMessageMode {
    Auto,
    Text,
    Binary,
}

pub fn is_websocket_url(raw: &str) -> bool {
    let raw = raw.to_ascii_lowercase();
    raw.starts_with("ws://") || raw.starts_with("wss://")
}

pub async fn execute(cli: &Cli) -> Result<i32, FetchError> {
    let mut url = websocket_url(cli.url.as_deref().expect("URL checked by app"))?;
    crate::http::apply_query(&mut url, &cli.query);
    let session = crate::http::load_session(cli)?;

    let method = effective_method(cli);
    let mut warnings = Vec::new();
    if !cli.method().eq_ignore_ascii_case("GET") {
        warnings.push(format!(
            "WebSocket requires GET; ignoring method {}",
            cli.method()
        ));
    }
    if cli.timing {
        warnings.push("--timing is not supported for WebSocket connections".to_string());
    }
    write_warnings(cli, &warnings);
    let interactive = should_use_interactive(cli)?;

    let request = build_handshake_request(cli, &url, session.as_ref())?;
    let connector = websocket_connector(cli, &url)?;
    if cli.dry_run {
        print_request_metadata(cli, method, &url, Some(request.headers()));
        return Ok(0);
    }
    let initial_message = websocket_initial_message(cli)?;
    if cli.verbose >= 2 && !cli.silent {
        print_request_metadata(cli, method, &url, Some(request.headers()));
    }

    let request_start = Instant::now();
    let request_timeout = websocket_request_timeout(cli)?;
    let request_budget = TimeoutBudget::started_at(request_timeout, request_start);
    let connect_timeout = websocket_connect_timeout(cli, request_timeout, request_start)?;
    let connect = async { connect_websocket(cli, &url, request, connector, connect_timeout).await };
    let (stream, response) = request_budget.run(connect).await?;
    store_handshake_cookies(session.as_ref(), &url, response.headers());
    crate::http::save_session(cli, session.as_ref());

    print_response_metadata(cli, &response);

    if interactive
        && let Some(size) = core::terminal_size()
        && interactive::InteractiveMode::is_screen_tall_enough(size.rows)
    {
        let stdio = core::stdio();
        interactive::run_terminal(
            stream,
            initial_message.as_deref(),
            should_format_for_interactive(cli),
            stdio.stdout_color(cli.color.as_deref()),
            size.rows,
            size.cols,
        )
        .await?;
        return Ok(0);
    }

    let (mut sender, mut receiver) = stream.split();
    let send_messages =
        send_noninteractive_messages(&mut sender, initial_message, message_mode(cli));
    let receive_messages = read_messages(cli, &mut receiver);
    tokio::pin!(send_messages);
    tokio::pin!(receive_messages);
    tokio::select! {
        send_result = &mut send_messages => {
            send_result?;
            receive_messages.await?;
        }
        receive_result = &mut receive_messages => {
            receive_result?;
        }
    }
    Ok(0)
}

fn websocket_url(raw: &str) -> Result<Url, FetchError> {
    let url = Url::parse(raw)?;
    match url.scheme() {
        "ws" | "wss" => Ok(url),
        scheme => Err(format!("unsupported url scheme: {scheme}").into()),
    }
}

fn effective_method(_cli: &Cli) -> &'static str {
    "GET"
}

fn websocket_connector(cli: &Cli, url: &Url) -> Result<Option<Connector>, FetchError> {
    if url.scheme() != "wss" {
        return Ok(None);
    }

    crate::tls::validate_client_auth_for_tls(cli.cert.as_deref(), cli.key.as_deref())?;
    let min_tls = cli.min_tls.as_deref().or(cli.tls.as_deref()).map(|value| {
        if cli.min_tls.is_some() {
            ("min-tls", value)
        } else {
            ("tls", value)
        }
    });
    let config = crate::tls::rustls_client_config(
        &cli.ca_cert,
        cli.cert.as_deref(),
        cli.key.as_deref(),
        cli.insecure,
        min_tls,
        cli.max_tls.as_deref(),
    )?;
    Ok(Some(Connector::Rustls(Arc::new(config))))
}

async fn connect_websocket(
    cli: &Cli,
    url: &Url,
    request: tokio_tungstenite::tungstenite::http::Request<()>,
    connector: Option<Connector>,
    timeout: TimeoutBudget,
) -> Result<
    (
        tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<DialStream>>,
        tokio_tungstenite::tungstenite::handshake::client::Response,
    ),
    FetchError,
> {
    let stream = dial_websocket(cli, url, timeout)
        .await
        .map_err(websocket_network_error)?;
    timeout_ws(
        timeout,
        client_async_tls_with_config(request, stream, Some(websocket_config()), connector),
    )
    .await
}

fn websocket_config() -> WebSocketConfig {
    // Keep inbound message allocation policy owned by fetch instead of inheriting
    // dependency defaults. The limit matches non-interactive text stdin messages.
    WebSocketConfig::default()
        .max_frame_size(Some(WEBSOCKET_MAX_FRAME_BYTES))
        .max_message_size(Some(WEBSOCKET_MAX_MESSAGE_BYTES))
}

async fn dial_websocket(
    cli: &Cli,
    url: &Url,
    timeout: TimeoutBudget,
) -> Result<DialStream, FetchError> {
    crate::net::dial_url(
        url,
        cli.proxy.as_deref(),
        cli.dns_server.as_deref(),
        timeout,
    )
    .await
}

fn websocket_request_timeout(cli: &Cli) -> Result<Option<Duration>, FetchError> {
    cli.timeout
        .map(|seconds| duration_from_seconds("timeout", seconds))
        .transpose()
}

fn websocket_connect_timeout(
    cli: &Cli,
    request_timeout: Option<Duration>,
    request_start: Instant,
) -> Result<TimeoutBudget, FetchError> {
    let connect_timeout = cli
        .connect_timeout
        .map(|seconds| duration_from_seconds("connect-timeout", seconds))
        .transpose()?;
    TimeoutBudget::for_connect(connect_timeout, request_timeout, request_start)
}

async fn timeout_ws<T>(
    timeout: TimeoutBudget,
    future: impl Future<Output = Result<T, WsError>>,
) -> Result<T, FetchError> {
    let Some(remaining) = timeout.remaining()? else {
        return future.await.map_err(websocket_error);
    };
    tokio::time::timeout(remaining, future)
        .await
        .map_err(|_| timeout.timeout_error())?
        .map_err(websocket_error)
}

fn websocket_network_error(err: FetchError) -> FetchError {
    match err {
        FetchError::Io(err) => FetchError::Runtime(err.to_string()),
        FetchError::Transport(err) => FetchError::Runtime(err.to_string()),
        err => err,
    }
}

fn write_warnings(cli: &Cli, warnings: &[String]) {
    if cli.silent || warnings.is_empty() {
        return;
    }
    write_warnings_with_separator_with_color(
        warnings.iter().map(String::as_str),
        cli.color.as_deref(),
    );
}

fn should_use_interactive(cli: &Cli) -> Result<bool, FetchError> {
    interactive_for_mode(cli.ws_interactive.as_deref(), core::stdio().all_terminal())
}

fn message_mode(cli: &Cli) -> WebSocketMessageMode {
    match cli.ws_message_mode.as_deref().unwrap_or("auto") {
        "text" => WebSocketMessageMode::Text,
        "binary" => WebSocketMessageMode::Binary,
        _ => WebSocketMessageMode::Auto,
    }
}

fn interactive_for_mode(mode: Option<&str>, all_terms: bool) -> Result<bool, FetchError> {
    match mode {
        Some("on") if !all_terms => {
            Err("--ws-interactive on requires stdin, stdout, and stderr to be terminals".into())
        }
        Some("on") => Ok(true),
        Some("off") => Ok(false),
        _ => Ok(all_terms),
    }
}

fn websocket_initial_message(cli: &Cli) -> Result<Option<Vec<u8>>, FetchError> {
    let limit_error =
        format!("WebSocket initial message exceeds maximum of {WEBSOCKET_MAX_MESSAGE_BYTES} bytes");
    Ok(crate::http::request_body_into_bytes_limited(
        crate::http::request_body(cli)?,
        WEBSOCKET_MAX_MESSAGE_BYTES,
        &limit_error,
    )?
    .map(|(bytes, _content_type)| bytes))
}

async fn send_noninteractive_messages<S>(
    sink: &mut S,
    initial_message: Option<Vec<u8>>,
    mode: WebSocketMessageMode,
) -> Result<(), FetchError>
where
    S: Sink<Message, Error = WsError> + Unpin,
{
    if let Some(message) = initial_message {
        sink.send(outgoing_message(message, mode)?)
            .await
            .map_err(websocket_error)?;
    }
    if core::stdio().stdin_is_terminal() {
        return Ok(());
    }

    let mut stdin_messages = spawn_stdin_message_reader(mode);
    while let Some(message) = stdin_messages.recv().await {
        sink.send(outgoing_message(message?, mode)?)
            .await
            .map_err(websocket_error)?;
    }
    let _ = sink.close().await;
    Ok(())
}

fn outgoing_message(bytes: Vec<u8>, mode: WebSocketMessageMode) -> Result<Message, FetchError> {
    match mode {
        WebSocketMessageMode::Auto => match String::from_utf8(bytes) {
            Ok(text) => Ok(Message::Text(text.into())),
            Err(err) => Ok(Message::Binary(err.into_bytes().into())),
        },
        WebSocketMessageMode::Text => String::from_utf8(bytes)
            .map(|text| Message::Text(text.into()))
            .map_err(|err| {
                FetchError::Message(format!(
                    "WebSocket text message is not valid UTF-8: {}",
                    err.utf8_error()
                ))
            }),
        WebSocketMessageMode::Binary => Ok(Message::Binary(bytes.into())),
    }
}

fn spawn_stdin_message_reader(
    mode: WebSocketMessageMode,
) -> mpsc::Receiver<Result<Vec<u8>, io::Error>> {
    let (tx, rx) = mpsc::channel(STDIN_MESSAGE_CHANNEL_CAPACITY);
    thread::spawn(move || {
        let stdin = io::stdin();
        let mut reader = io::BufReader::new(stdin.lock());
        if mode == WebSocketMessageMode::Binary {
            read_stdin_binary_chunks(&mut reader, tx);
        } else {
            read_stdin_lines_as_bytes(&mut reader, tx);
        }
    });
    rx
}

fn read_stdin_lines_as_bytes(
    reader: &mut impl BufRead,
    tx: mpsc::Sender<Result<Vec<u8>, io::Error>>,
) {
    read_stdin_lines_as_bytes_with_limit(reader, tx, STDIN_TEXT_MESSAGE_MAX_BYTES);
}

fn read_stdin_lines_as_bytes_with_limit(
    reader: &mut impl BufRead,
    tx: mpsc::Sender<Result<Vec<u8>, io::Error>>,
    max_message_bytes: usize,
) {
    loop {
        let mut line = Vec::new();
        let read_limit = max_message_bytes.saturating_add(2) as u64;
        match reader
            .by_ref()
            .take(read_limit)
            .read_until(b'\n', &mut line)
        {
            Ok(0) => break,
            Ok(_) => {
                strip_line_ending(&mut line);
                if line.len() > max_message_bytes {
                    let _ =
                        tx.blocking_send(Err(websocket_text_stdin_limit_error(max_message_bytes)));
                    break;
                }
                if tx.blocking_send(Ok(line)).is_err() {
                    break;
                }
            }
            Err(err) => {
                let _ = tx.blocking_send(Err(err));
                break;
            }
        }
    }
}

fn websocket_text_stdin_limit_error(max_message_bytes: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "WebSocket stdin text message exceeds maximum of {max_message_bytes} bytes before a newline; use --ws-message-mode binary for raw streams"
        ),
    )
}

fn read_stdin_binary_chunks(reader: &mut impl Read, tx: mpsc::Sender<Result<Vec<u8>, io::Error>>) {
    let mut buf = vec![0; STDIN_BINARY_CHUNK_SIZE];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if tx.blocking_send(Ok(buf[..n].to_vec())).is_err() {
                    break;
                }
            }
            Err(err) => {
                let _ = tx.blocking_send(Err(err));
                break;
            }
        }
    }
}

fn strip_line_ending(line: &mut Vec<u8>) {
    if line.ends_with(b"\n") {
        line.pop();
    }
    if line.ends_with(b"\r") {
        line.pop();
    }
}

fn build_handshake_request(
    cli: &Cli,
    url: &Url,
    session: Option<&crate::session::Session>,
) -> Result<tokio_tungstenite::tungstenite::http::Request<()>, FetchError> {
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(websocket_error)?;
    let headers = handshake_headers(cli, url, session)?;
    let mut replaced_headers = HashSet::new();
    for (name, value) in &headers {
        let name = WsHeaderName::from_bytes(name.as_str().as_bytes()).map_err(|err| {
            FetchError::Message(format!("invalid header name '{}': {err}", name.as_str()))
        })?;
        let value = WsHeaderValue::from_bytes(value.as_bytes()).map_err(|err| {
            FetchError::Message(format!(
                "invalid header value for '{}': {err}",
                name.as_str()
            ))
        })?;
        if replaced_headers.insert(name.clone()) {
            request.headers_mut().remove(&name);
        }
        request.headers_mut().append(name, value);
    }
    Ok(request)
}

fn handshake_headers(
    cli: &Cli,
    url: &Url,
    session: Option<&crate::session::Session>,
) -> Result<HeaderMap, FetchError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        ACCEPT,
        HeaderValue::from_static(core::DEFAULT_ACCEPT_HEADER),
    );
    headers.insert(
        USER_AGENT,
        HeaderValue::from_str(&core::user_agent()).expect("valid user agent"),
    );
    crate::http::apply_headers(&mut headers, &cli.headers)?;
    apply_session_cookies(session, url, &mut headers)?;

    if let Some(auth) = crate::http::basic_header(cli.basic.as_deref())? {
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&auth)
                .map_err(|err| FetchError::Message(format!("invalid basic auth header: {err}")))?,
        );
    }
    if let Some(token) = cli.bearer.as_deref() {
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|err| FetchError::Message(format!("invalid bearer auth header: {err}")))?,
        );
    }
    if let Some(value) = cli.aws_sigv4.as_deref() {
        let config =
            aws_sigv4::parse_config(value).map_err(|err| FetchError::Message(err.to_string()))?;
        let sign_url = websocket_signing_url(url)?;
        aws_sigv4::sign(
            "GET",
            &sign_url,
            &mut headers,
            None,
            &config,
            time::OffsetDateTime::now_utc(),
            false,
        )
        .map_err(|err| FetchError::Message(err.to_string()))?;
    }
    Ok(headers)
}

fn apply_session_cookies(
    session: Option<&crate::session::Session>,
    url: &Url,
    headers: &mut HeaderMap,
) -> Result<(), FetchError> {
    if headers.contains_key(COOKIE) {
        return Ok(());
    }
    let Some(session) = session else {
        return Ok(());
    };
    let cookie_url = websocket_cookie_url(url)?;
    if let Some(cookies) = session.cookie_provider().cookies(&cookie_url) {
        headers.insert(COOKIE, cookies);
    }
    Ok(())
}

fn store_handshake_cookies(
    session: Option<&crate::session::Session>,
    url: &Url,
    headers: &WsHeaderMap,
) {
    let Some(session) = session else {
        return;
    };
    let Ok(cookie_url) = websocket_cookie_url(url) else {
        return;
    };
    session
        .cookie_provider()
        .set_cookies(&mut headers.get_all(SET_COOKIE).iter(), &cookie_url);
}

fn websocket_cookie_url(url: &Url) -> Result<Url, FetchError> {
    let mut cookie_url = url.clone();
    let scheme = match cookie_url.scheme() {
        "ws" => "http",
        "wss" => "https",
        other => return Err(format!("unsupported url scheme: {other}").into()),
    };
    cookie_url
        .set_scheme(scheme)
        .map_err(|_| FetchError::Message(format!("unsupported url scheme: {}", url.scheme())))?;
    Ok(cookie_url)
}

fn websocket_signing_url(url: &Url) -> Result<Url, FetchError> {
    let mut signed = url.clone();
    let scheme = match signed.scheme() {
        "ws" => "http",
        "wss" => "https",
        other => return Err(format!("unsupported url scheme: {other}").into()),
    };
    signed
        .set_scheme(scheme)
        .map_err(|_| FetchError::Message(format!("unsupported url scheme: {}", url.scheme())))?;
    Ok(signed)
}

fn print_request_metadata(cli: &Cli, method: &str, url: &Url, headers: Option<&WsHeaderMap>) {
    if cli.silent {
        return;
    }
    let debug = cli.verbose >= 2 || cli.dry_run;
    let mut printer = core::Printer::stderr(cli.color.as_deref());
    if debug {
        printer.write_request_prefix();
    }
    printer.write_styled(method, &[core::Sequence::Bold, core::Sequence::Yellow]);
    printer.push_str(" ");
    printer.write_styled(
        &crate::http::request_target(url),
        &[core::Sequence::Bold, core::Sequence::Cyan],
    );
    printer.push_str(" ");
    printer.write_styled("HTTP/1.1", &[core::Sequence::Dim]);
    printer.push_str("\n");
    if let Some(headers) = headers {
        let mut lines = header_lines(headers);
        if cli.sort_headers {
            sort_header_lines(&mut lines);
        }
        for (name, value) in lines {
            if debug {
                printer.write_request_prefix();
            }
            printer.write_styled(&name, &[core::Sequence::Bold, core::Sequence::Blue]);
            printer.push_str(": ");
            printer.push_str(&value);
            printer.push_str("\n");
        }
    }
    if debug {
        printer.write_request_prefix();
        printer.push_str("\n");
    }
    flush_stderr(printer);
}

fn print_response_metadata(
    cli: &Cli,
    response: &tokio_tungstenite::tungstenite::handshake::client::Response,
) {
    if cli.verbose == 0 || cli.silent {
        return;
    }

    let status = response.status();
    let mut printer = core::Printer::stderr(cli.color.as_deref());
    if cli.verbose >= 2 {
        printer.write_response_prefix();
    }
    printer.write_styled(ws_version_label(response.version()), &[core::Sequence::Dim]);
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
    if cli.verbose >= 2 {
        printer.write_response_prefix();
    }
    printer.push_str("\n");
    flush_stderr(printer);
}

fn header_lines(headers: &WsHeaderMap) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (name, value) in headers {
        if let Ok(value) = value.to_str() {
            out.push((name.as_str().to_ascii_lowercase(), value.to_string()));
        }
    }
    out
}

fn sort_header_lines(lines: &mut [(String, String)]) {
    lines.sort_by(
        |(left, _), (right, _)| match (left.starts_with(':'), right.starts_with(':')) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => left.cmp(right),
        },
    );
}

fn ws_version_label(version: WsVersion) -> &'static str {
    match version {
        WsVersion::HTTP_09 => "HTTP/0.9",
        WsVersion::HTTP_10 => "HTTP/1.0",
        WsVersion::HTTP_11 => "HTTP/1.1",
        WsVersion::HTTP_2 => "HTTP/2.0",
        WsVersion::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/?",
    }
}

fn color_for_status(code: u16) -> core::Sequence {
    match code {
        200..=299 => core::Sequence::Green,
        300..=399 => core::Sequence::Yellow,
        _ => core::Sequence::Red,
    }
}

fn flush_stderr(mut printer: core::Printer) {
    let mut stderr = std::io::stderr();
    let _ = printer.flush_to(&mut stderr);
}

async fn read_messages<S>(cli: &Cli, stream: &mut S) -> Result<(), FetchError>
where
    S: futures_util::Stream<Item = Result<Message, WsError>> + Unpin,
{
    let stdout_is_terminal = core::stdio().stdout_is_terminal();
    while let Some(message) = stream.next().await {
        match message.map_err(websocket_error)? {
            Message::Text(text) => {
                if write_text_message(cli, text.as_str().as_bytes(), stdout_is_terminal)?
                    == MessageOutput::Closed
                {
                    return Ok(());
                }
            }
            Message::Binary(bytes) => {
                if write_binary_message(cli, &bytes, stdout_is_terminal)? == MessageOutput::Closed {
                    return Ok(());
                }
            }
            Message::Close(_) => return Ok(()),
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
        }
    }
    Ok(())
}

fn write_text_message(
    cli: &Cli,
    bytes: &[u8],
    stdout_is_terminal: bool,
) -> Result<MessageOutput, FetchError> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    if should_format(cli, stdout_is_terminal) {
        let mut formatted = core::Printer::new(use_color(cli, stdout_is_terminal));
        if json::format_json_line_to(bytes, &mut formatted).is_ok() {
            return write_stdout_message(&mut stdout, &formatted.into_bytes(), false);
        }
    }
    write_stdout_message(&mut stdout, bytes, true)
}

fn write_binary_message(
    cli: &Cli,
    bytes: &[u8],
    stdout_is_terminal: bool,
) -> Result<MessageOutput, FetchError> {
    if should_warn_for_terminal_binary_message(bytes, stdout_is_terminal) {
        write_binary_terminal_warning(cli);
        return Ok(MessageOutput::Continue);
    }

    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    write_stdout_message(&mut stdout, bytes, false)
}

fn should_warn_for_terminal_binary_message(bytes: &[u8], stdout_is_terminal: bool) -> bool {
    stdout_is_terminal && !core::bytes_appear_printable(bytes)
}

fn write_stdout_message(
    stdout: &mut impl Write,
    bytes: &[u8],
    append_newline: bool,
) -> Result<MessageOutput, FetchError> {
    let result = stdout.write_all(bytes).and_then(|()| {
        if append_newline {
            stdout.write_all(b"\n")?;
        }
        stdout.flush()
    });

    match core::stdout_write_status(result)? {
        core::StdoutWriteStatus::Open => Ok(MessageOutput::Continue),
        core::StdoutWriteStatus::Closed => Ok(MessageOutput::Closed),
    }
}

fn should_format(cli: &Cli, stdout_is_terminal: bool) -> bool {
    core::format_enabled(cli.format.as_deref(), stdout_is_terminal)
}

fn should_format_for_interactive(cli: &Cli) -> bool {
    !matches!(cli.format.as_deref(), Some("off"))
}

fn use_color(cli: &Cli, stdout_is_terminal: bool) -> bool {
    core::color_enabled(cli.color.as_deref(), stdout_is_terminal)
}

fn write_binary_terminal_warning(cli: &Cli) {
    if cli.silent {
        return;
    }
    write_warning_with_color(BINARY_MESSAGE_WARNING, cli.color.as_deref());
}

fn websocket_error(err: WsError) -> FetchError {
    let message = err.to_string();
    if websocket_certificate_validation_error(&err, &message) {
        return FetchError::CertificateValidation(message);
    }
    if let Some(start) = message.find("request timed out after ") {
        return FetchError::Runtime(message[start..].to_string());
    }
    match err {
        WsError::Capacity(CapacityError::MessageTooLong { size, max_size }) => {
            FetchError::Runtime(format!(
                "WebSocket message exceeds maximum of {max_size} bytes (received {size} bytes)"
            ))
        }
        WsError::Url(_) | WsError::HttpFormat(_) => FetchError::Message(message),
        _ => FetchError::Runtime(message),
    }
}

fn websocket_certificate_validation_error(err: &WsError, message: &str) -> bool {
    if crate::http::is_certificate_validation_message(message) {
        return true;
    }

    let mut source = err.source();
    while let Some(err) = source {
        if crate::http::is_certificate_validation_message(&err.to_string()) {
            return true;
        }
        source = err.source();
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn detects_websocket_urls() {
        assert!(is_websocket_url("ws://example.com"));
        assert!(is_websocket_url("wss://example.com"));
        assert!(is_websocket_url("WS://example.com"));
        assert!(!is_websocket_url("https://example.com"));
    }

    #[test]
    fn websocket_url_rejects_non_websocket_schemes() {
        let err = websocket_url("https://example.com").unwrap_err();

        assert!(err.to_string().contains("unsupported url scheme"));
    }

    #[test]
    fn websocket_config_sets_fetch_receive_limits() {
        let config = websocket_config();

        assert_eq!(config.max_frame_size, Some(WEBSOCKET_MAX_FRAME_BYTES));
        assert_eq!(config.max_message_size, Some(WEBSOCKET_MAX_MESSAGE_BYTES));
    }

    #[test]
    fn websocket_capacity_error_reports_fetch_limit() {
        let err = websocket_error(WsError::Capacity(CapacityError::MessageTooLong {
            size: WEBSOCKET_MAX_MESSAGE_BYTES + 1,
            max_size: WEBSOCKET_MAX_MESSAGE_BYTES,
        }));

        assert_eq!(
            err.to_string(),
            "WebSocket message exceeds maximum of 16777216 bytes (received 16777217 bytes)"
        );
    }

    #[test]
    fn websocket_signing_url_rewrites_ws_schemes_for_sigv4() {
        let ws = websocket_signing_url(&Url::parse("ws://example.com/socket").unwrap()).unwrap();
        let wss = websocket_signing_url(&Url::parse("wss://example.com/socket").unwrap()).unwrap();

        assert_eq!(ws.as_str(), "http://example.com/socket");
        assert_eq!(wss.as_str(), "https://example.com/socket");
    }

    #[test]
    fn websocket_headers_include_bearer_auth() {
        let cli = Cli::try_parse_from(["fetch", "--bearer", "token", "ws://example.com"]).unwrap();
        let headers =
            handshake_headers(&cli, &Url::parse("ws://example.com").unwrap(), None).unwrap();

        assert_eq!(
            headers.get(ACCEPT).and_then(|value| value.to_str().ok()),
            Some(core::DEFAULT_ACCEPT_HEADER)
        );
        assert_eq!(
            headers
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer token")
        );
    }

    #[test]
    fn websocket_request_preserves_duplicate_cli_headers_and_replaces_defaults() {
        let cli = Cli::try_parse_from([
            "fetch",
            "-H",
            "X-Test: one",
            "-H",
            "X-Test: two",
            "-H",
            "Host: vhost.example",
            "ws://example.com/socket",
        ])
        .unwrap();
        let request =
            build_handshake_request(&cli, &Url::parse("ws://example.com/socket").unwrap(), None)
                .unwrap();

        let values = request
            .headers()
            .get_all("x-test")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(values, ["one", "two"]);

        let hosts = request
            .headers()
            .get_all("host")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(hosts, ["vhost.example"]);
    }

    #[test]
    fn proxy_basic_auth_treats_missing_password_as_empty() {
        let proxy_url = Url::parse("http://user@proxy.example:8080").unwrap();

        assert_eq!(
            crate::net::proxy_basic_auth(&proxy_url).unwrap(),
            Some("Basic dXNlcjo=".to_string())
        );
    }

    #[test]
    fn proxy_basic_auth_preserves_explicit_empty_password() {
        let proxy_url = Url::parse("http://user:@proxy.example:8080").unwrap();

        assert_eq!(
            crate::net::proxy_basic_auth(&proxy_url).unwrap(),
            Some("Basic dXNlcjo=".to_string())
        );
    }

    #[tokio::test]
    async fn socks5_proxy_username_only_auth_sends_empty_password() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_url =
            Url::parse(&format!("socks5://user@{}", listener.local_addr().unwrap())).unwrap();
        let server = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut greeting = [0_u8; 2];
            conn.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x02]);

            let mut methods = vec![0_u8; greeting[1] as usize];
            conn.read_exact(&mut methods).await.unwrap();
            assert_eq!(methods, vec![0x00, 0x02]);
            conn.write_all(&[0x05, 0x02]).await.unwrap();

            let mut auth = vec![0_u8; 2];
            conn.read_exact(&mut auth).await.unwrap();
            let username_len = auth[1] as usize;
            auth.resize(2 + username_len + 1, 0);
            conn.read_exact(&mut auth[2..]).await.unwrap();
            let password_len = *auth.last().unwrap() as usize;
            let password_start = auth.len();
            auth.resize(password_start + password_len, 0);
            if password_len > 0 {
                conn.read_exact(&mut auth[password_start..]).await.unwrap();
            }
            conn.write_all(&[0x01, 0x00]).await.unwrap();

            let mut request = [0_u8; 10];
            conn.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80]);
            conn.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            auth
        });

        let target = Url::parse("ws://127.0.0.1/socket").unwrap();
        let stream = crate::net::dial_socks5_proxy(
            &proxy_url,
            &target,
            None,
            TimeoutBudget::new(Some(Duration::from_secs(5))),
        )
        .await
        .unwrap();
        drop(stream);

        assert_eq!(
            server.await.unwrap(),
            vec![0x01, 0x04, b'u', b's', b'e', b'r', 0x00]
        );
    }

    #[test]
    fn proxy_basic_auth_percent_decodes_credentials() {
        let proxy_url = Url::parse("http://us%20er:p%40ss%3Aword@proxy.example:8080").unwrap();
        let expected = base64::engine::general_purpose::STANDARD.encode("us er:p@ss:word");

        assert_eq!(
            crate::net::proxy_basic_auth(&proxy_url).unwrap(),
            Some(format!("Basic {expected}"))
        );
    }

    #[test]
    fn proxy_basic_auth_skips_proxy_without_credentials() {
        let proxy_url = Url::parse("http://proxy.example:8080").unwrap();

        assert_eq!(crate::net::proxy_basic_auth(&proxy_url).unwrap(), None);
    }

    #[test]
    fn websocket_request_uses_effective_get_method_for_dry_run() {
        let cli = Cli::try_parse_from(["fetch", "-X", "POST", "ws://example.com"]).unwrap();

        assert_eq!(effective_method(&cli), "GET");
    }

    #[test]
    fn websocket_interactive_mode_selection_matches_go() {
        assert!(interactive_for_mode(None, true).unwrap());
        assert!(!interactive_for_mode(None, false).unwrap());
        assert!(interactive_for_mode(Some("auto"), true).unwrap());
        assert!(!interactive_for_mode(Some("auto"), false).unwrap());
        assert!(interactive_for_mode(Some("on"), true).unwrap());
        assert!(!interactive_for_mode(Some("off"), true).unwrap());

        let err = interactive_for_mode(Some("on"), false).unwrap_err();
        assert_eq!(
            err.to_string(),
            "--ws-interactive on requires stdin, stdout, and stderr to be terminals"
        );
    }

    #[test]
    fn websocket_json_color_matches_core_auto_policy() {
        let default_cli = Cli::try_parse_from(["fetch", "ws://example.com"]).unwrap();
        assert!(use_color(&default_cli, true));
        assert!(!use_color(&default_cli, false));

        let on_cli = Cli::try_parse_from(["fetch", "--color", "on", "ws://example.com"]).unwrap();
        assert!(use_color(&on_cli, false));

        let off_cli = Cli::try_parse_from(["fetch", "--color", "off", "ws://example.com"]).unwrap();
        assert!(!use_color(&off_cli, true));
    }

    #[test]
    fn websocket_message_mode_controls_outgoing_frame_type() {
        let auto_text = outgoing_message(b"hello".to_vec(), WebSocketMessageMode::Auto).unwrap();
        assert!(matches!(auto_text, Message::Text(_)));

        let auto_binary =
            outgoing_message(vec![0xff, 0, 0xfe], WebSocketMessageMode::Auto).unwrap();
        assert!(matches!(auto_binary, Message::Binary(_)));

        let forced_binary =
            outgoing_message(b"hello".to_vec(), WebSocketMessageMode::Binary).unwrap();
        assert!(matches!(forced_binary, Message::Binary(_)));

        let err = outgoing_message(vec![0xff], WebSocketMessageMode::Text).unwrap_err();
        assert!(err.to_string().contains("not valid UTF-8"));
    }

    #[test]
    fn websocket_initial_message_rejects_oversized_file_before_reading() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large.bin");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(WEBSOCKET_MAX_MESSAGE_BYTES as u64 + 1)
            .unwrap();
        let body = format!("@{}", path.display());
        let cli = Cli::try_parse_from(["fetch", "-d", &body, "ws://example.com"]).unwrap();

        let err = websocket_initial_message(&cli).unwrap_err();

        assert_eq!(
            err.to_string(),
            format!(
                "WebSocket initial message exceeds maximum of {WEBSOCKET_MAX_MESSAGE_BYTES} bytes"
            )
        );
    }

    #[test]
    fn websocket_text_stdin_reader_rejects_line_over_limit_without_newline() {
        let (tx, mut rx) = mpsc::channel(1);
        let mut reader = io::Cursor::new(b"abcdef".as_slice());

        read_stdin_lines_as_bytes_with_limit(&mut reader, tx, 5);

        let err = rx.blocking_recv().unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds maximum of 5 bytes"));
        assert!(err.to_string().contains("--ws-message-mode binary"));
        assert!(rx.blocking_recv().is_none());
    }

    #[test]
    fn websocket_text_stdin_reader_allows_limit_sized_crlf_line() {
        let (tx, mut rx) = mpsc::channel(2);
        let mut reader = io::Cursor::new(b"abcde\r\nx".as_slice());

        read_stdin_lines_as_bytes_with_limit(&mut reader, tx, 5);

        assert_eq!(rx.blocking_recv().unwrap().unwrap(), b"abcde");
        assert_eq!(rx.blocking_recv().unwrap().unwrap(), b"x");
        assert!(rx.blocking_recv().is_none());
    }

    #[test]
    fn websocket_binary_stdin_reader_streams_chunks() {
        let input = vec![b'a'; STDIN_BINARY_CHUNK_SIZE * 2 + 7];
        let (tx, mut rx) = mpsc::channel(4);
        let mut reader = io::Cursor::new(input.as_slice());

        read_stdin_binary_chunks(&mut reader, tx);

        assert_eq!(
            rx.blocking_recv().unwrap().unwrap().len(),
            STDIN_BINARY_CHUNK_SIZE
        );
        assert_eq!(
            rx.blocking_recv().unwrap().unwrap().len(),
            STDIN_BINARY_CHUNK_SIZE
        );
        assert_eq!(rx.blocking_recv().unwrap().unwrap().len(), 7);
        assert!(rx.blocking_recv().is_none());
    }

    #[test]
    fn websocket_binary_terminal_guard_matches_printable_policy() {
        assert!(should_warn_for_terminal_binary_message(b"abc\0def", true));
        assert!(!should_warn_for_terminal_binary_message(b"abc\0def", false));
        assert!(!should_warn_for_terminal_binary_message(
            b"plain text",
            true
        ));
    }

    #[test]
    fn websocket_stdout_message_treats_broken_pipe_as_closed() {
        struct BrokenPipeWriter;

        impl std::io::Write for BrokenPipeWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "stdout closed",
                ))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut writer = BrokenPipeWriter;
        let output = write_stdout_message(&mut writer, b"hello", true).unwrap();

        assert_eq!(output, MessageOutput::Closed);
    }

    #[test]
    fn websocket_connect_timeout_uses_connect_timeout_when_shorter() {
        let cli = Cli::try_parse_from([
            "fetch",
            "--connect-timeout",
            "0.25",
            "--timeout",
            "5",
            "ws://example.com",
        ])
        .unwrap();
        let request_timeout = websocket_request_timeout(&cli).unwrap();
        let budget = websocket_connect_timeout(&cli, request_timeout, Instant::now()).unwrap();
        let remaining = budget.remaining().unwrap().unwrap();

        assert!(remaining <= Duration::from_millis(250));
        assert!(remaining > Duration::from_millis(200));
    }

    #[test]
    fn websocket_connect_timeout_is_bounded_by_remaining_request_timeout() {
        let cli = Cli::try_parse_from([
            "fetch",
            "--connect-timeout",
            "5",
            "--timeout",
            "0.25",
            "ws://example.com",
        ])
        .unwrap();
        let request_timeout = websocket_request_timeout(&cli).unwrap();
        let request_start = Instant::now() - Duration::from_millis(100);
        let budget = websocket_connect_timeout(&cli, request_timeout, request_start).unwrap();
        let remaining = budget.remaining().unwrap().unwrap();

        assert!(remaining <= Duration::from_millis(150));
        assert!(remaining > Duration::from_millis(100));
    }

    #[test]
    fn websocket_connect_timeout_falls_back_to_request_timeout() {
        let cli = Cli::try_parse_from(["fetch", "--timeout", "0.25", "ws://example.com"]).unwrap();
        let request_timeout = websocket_request_timeout(&cli).unwrap();
        let budget = websocket_connect_timeout(&cli, request_timeout, Instant::now()).unwrap();
        let remaining = budget.remaining().unwrap().unwrap();

        assert!(remaining <= Duration::from_millis(250));
        assert!(remaining > Duration::from_millis(200));
    }
}
