use std::io::{self, IsTerminal, Read};

use futures_util::{SinkExt, StreamExt};
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue, USER_AGENT};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{
    HeaderName as WsHeaderName, HeaderValue as WsHeaderValue,
};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use url::Url;

use crate::auth::aws_sigv4;
use crate::cli::Cli;
use crate::core;
use crate::error::{FetchError, write_warning_with_color};
use crate::format::json;

pub mod interactive;

pub fn is_websocket_url(raw: &str) -> bool {
    let raw = raw.to_ascii_lowercase();
    raw.starts_with("ws://") || raw.starts_with("wss://")
}

pub async fn execute(cli: &Cli) -> Result<i32, FetchError> {
    let mut url = websocket_url(cli.url.as_deref().expect("URL checked by app"))?;
    crate::http::apply_query(&mut url, &cli.query);

    let method = effective_method(cli);
    if !cli.method().eq_ignore_ascii_case("GET") {
        write_warning(
            cli,
            &format!("WebSocket requires GET; ignoring method {}", cli.method()),
        );
    }
    if cli.timing {
        write_warning(cli, "--timing is not supported for WebSocket connections");
    }
    let interactive = should_use_interactive(cli)?;

    let initial_message = websocket_initial_message(cli)?;
    if cli.dry_run {
        print_request_metadata(cli, method, &url, None);
        return Ok(0);
    }
    let stdin_messages = if interactive {
        Vec::new()
    } else {
        read_stdin_messages()?
    };

    let request = build_handshake_request(cli, &url)?;
    if cli.verbose >= 2 && !cli.silent {
        print_request_metadata(cli, method, &url, Some(request.headers()));
    }

    let connect = connect_async(request);
    let (mut stream, response) = if let Some(seconds) = cli.timeout {
        let timeout = crate::http::duration_from_seconds("timeout", seconds)?;
        tokio::time::timeout(timeout, connect)
            .await
            .map_err(|_| {
                FetchError::Message(format!(
                    "request timed out after {}",
                    crate::timing::format_timing_duration(timeout)
                ))
            })?
            .map_err(websocket_error)?
    } else {
        connect.await.map_err(websocket_error)?
    };

    if cli.verbose > 0 && !cli.silent {
        let status = response.status();
        eprintln!(
            "HTTP/1.1 {} {}",
            status.as_u16(),
            status.canonical_reason().unwrap_or("")
        );
    }

    if interactive
        && let Some(size) = core::terminal_size()
        && interactive::InteractiveMode::is_screen_tall_enough(size.rows)
    {
        interactive::run_terminal(
            stream,
            initial_message.as_deref(),
            should_format_for_interactive(cli),
            size.rows,
            size.cols,
        )
        .await?;
        return Ok(0);
    }

    if let Some(message) = initial_message {
        stream
            .send(Message::Text(
                String::from_utf8_lossy(&message).into_owned().into(),
            ))
            .await
            .map_err(websocket_error)?;
    }
    for message in stdin_messages {
        stream
            .send(Message::Text(message.into()))
            .await
            .map_err(websocket_error)?;
    }

    read_messages(cli, &mut stream).await?;
    let _ = stream.close(None).await;
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

fn write_warning(cli: &Cli, message: &str) {
    if cli.silent {
        return;
    }
    write_warning_with_color(message, cli.color.as_deref());
}

fn should_use_interactive(cli: &Cli) -> Result<bool, FetchError> {
    let all_terms =
        io::stdin().is_terminal() && io::stdout().is_terminal() && io::stderr().is_terminal();
    interactive_for_mode(cli.ws_interactive.as_deref(), all_terms)
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
    Ok(crate::http::request_body(cli)?.map(|(bytes, _content_type)| bytes))
}

fn read_stdin_messages() -> Result<Vec<String>, FetchError> {
    let mut stdin = io::stdin();
    if stdin.is_terminal() {
        return Ok(Vec::new());
    }

    let mut input = String::new();
    stdin.read_to_string(&mut input)?;
    Ok(input
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

fn build_handshake_request(
    cli: &Cli,
    url: &Url,
) -> Result<tokio_tungstenite::tungstenite::http::Request<()>, FetchError> {
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(websocket_error)?;
    let headers = handshake_headers(cli, url)?;
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
        request.headers_mut().insert(name, value);
    }
    Ok(request)
}

fn handshake_headers(cli: &Cli, url: &Url) -> Result<HeaderMap, FetchError> {
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

fn print_request_metadata(
    cli: &Cli,
    method: &str,
    url: &Url,
    headers: Option<&tokio_tungstenite::tungstenite::http::HeaderMap>,
) {
    if cli.silent {
        return;
    }
    eprintln!("> {method} {} HTTP/1.1", crate::http::request_target(url));
    if let Some(headers) = headers {
        for (name, value) in headers {
            if let Ok(value) = value.to_str() {
                eprintln!("> {}: {value}", name.as_str().to_ascii_lowercase());
            }
        }
    }
    if cli.verbose >= 2 || cli.dry_run {
        eprintln!("> ");
    }
}

async fn read_messages<S>(cli: &Cli, stream: &mut S) -> Result<(), FetchError>
where
    S: futures_util::Stream<Item = Result<Message, WsError>> + Unpin,
{
    while let Some(message) = stream.next().await {
        match message.map_err(websocket_error)? {
            Message::Text(text) => write_text_message(cli, text.as_str().as_bytes())?,
            Message::Binary(bytes) => write_binary_indicator(cli, bytes.len()),
            Message::Close(_) => return Ok(()),
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
        }
    }
    Ok(())
}

fn write_text_message(cli: &Cli, bytes: &[u8]) -> Result<(), FetchError> {
    if should_format(cli)
        && let Ok(formatted) = json::format_json_line(bytes, use_color(cli))
    {
        print!("{}", String::from_utf8_lossy(&formatted));
        return Ok(());
    }
    println!("{}", String::from_utf8_lossy(bytes));
    Ok(())
}

fn should_format(cli: &Cli) -> bool {
    match cli.format.as_deref() {
        Some("off") => false,
        Some("on") => true,
        _ => io::stdout().is_terminal(),
    }
}

fn should_format_for_interactive(cli: &Cli) -> bool {
    !matches!(cli.format.as_deref(), Some("off"))
}

fn use_color(cli: &Cli) -> bool {
    cli.color.as_deref() == Some("on")
}

fn write_binary_indicator(cli: &Cli, len: usize) {
    if cli.silent {
        return;
    }
    eprintln!("[binary {len} bytes]");
}

fn websocket_error(err: WsError) -> FetchError {
    FetchError::Message(err.to_string())
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
    fn websocket_signing_url_rewrites_ws_schemes_for_sigv4() {
        let ws = websocket_signing_url(&Url::parse("ws://example.com/socket").unwrap()).unwrap();
        let wss = websocket_signing_url(&Url::parse("wss://example.com/socket").unwrap()).unwrap();

        assert_eq!(ws.as_str(), "http://example.com/socket");
        assert_eq!(wss.as_str(), "https://example.com/socket");
    }

    #[test]
    fn websocket_headers_include_bearer_auth() {
        let cli = Cli::try_parse_from(["fetch", "--bearer", "token", "ws://example.com"]).unwrap();
        let headers = handshake_headers(&cli, &Url::parse("ws://example.com").unwrap()).unwrap();

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
}
