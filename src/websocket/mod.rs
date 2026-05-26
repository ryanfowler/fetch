use std::io::{self, IsTerminal, Read};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue, USER_AGENT};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{
    HeaderName as WsHeaderName, HeaderValue as WsHeaderValue,
};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{Connector, client_async_tls_with_config};
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
    let request = build_handshake_request(cli, &url)?;
    let connector = websocket_connector(cli, &url)?;
    if cli.dry_run {
        print_request_metadata(cli, method, &url, Some(request.headers()));
        return Ok(0);
    }
    let stdin_messages = if interactive {
        Vec::new()
    } else {
        read_stdin_messages()?
    };

    if cli.verbose >= 2 && !cli.silent {
        print_request_metadata(cli, method, &url, Some(request.headers()));
    }

    let connect = connect_websocket(cli, &url, request, connector);
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
            use_color(cli, io::stdout().is_terminal()),
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

fn websocket_connector(cli: &Cli, url: &Url) -> Result<Option<Connector>, FetchError> {
    if url.scheme() != "wss" {
        return Ok(None);
    }

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

trait AsyncIo: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> AsyncIo for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

type DialStream = Pin<Box<dyn AsyncIo>>;

async fn connect_websocket(
    cli: &Cli,
    url: &Url,
    request: tokio_tungstenite::tungstenite::http::Request<()>,
    connector: Option<Connector>,
) -> Result<
    (
        tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<DialStream>>,
        tokio_tungstenite::tungstenite::handshake::client::Response,
    ),
    WsError,
> {
    let stream = dial_websocket(cli, url).await.map_err(websocket_io_error)?;
    client_async_tls_with_config(request, stream, None, connector).await
}

async fn dial_websocket(cli: &Cli, url: &Url) -> Result<DialStream, FetchError> {
    if let Some(proxy) = cli.proxy.as_deref() {
        return dial_proxy(proxy, url, websocket_timeout(cli)?).await;
    }
    let stream = connect_tcp(url, cli.dns_server.as_deref(), websocket_timeout(cli)?).await?;
    Ok(Box::pin(stream))
}

async fn connect_tcp(
    url: &Url,
    dns_server: Option<&str>,
    timeout: Option<Duration>,
) -> Result<TcpStream, FetchError> {
    let host = url
        .host_str()
        .ok_or_else(|| FetchError::Message("URL host is required".to_string()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| FetchError::Message("URL port is required".to_string()))?;

    if host.parse::<IpAddr>().is_ok() || dns_server.is_none() {
        return TcpStream::connect((host, port))
            .await
            .map_err(FetchError::from);
    }

    let mut addrs = resolve_websocket_host(host, dns_server, timeout).await?;
    for addr in &mut addrs {
        addr.set_port(port);
    }
    connect_first(addrs).await
}

async fn resolve_websocket_host(
    host: &str,
    dns_server: Option<&str>,
    timeout: Option<Duration>,
) -> Result<Vec<SocketAddr>, FetchError> {
    let Some(dns_server) = dns_server else {
        return tokio::net::lookup_host((host, 0))
            .await
            .map(|addrs| addrs.collect())
            .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")));
    };

    let addrs = if dns_server.starts_with("http://") || dns_server.starts_with("https://") {
        let server_url = Url::parse(dns_server).map_err(|err| {
            FetchError::Message(format!("invalid dns-server '{dns_server}': {err}"))
        })?;
        crate::dns::doh::lookup_doh(&server_url, host, timeout)
            .await
            .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))?
    } else {
        let server_addr = crate::dns::resolver::normalize_udp_dns_server(dns_server)
            .map_err(|err| FetchError::Message(err.to_string()))?;
        crate::dns::resolver::lookup_udp(&server_addr, host, timeout)
            .await
            .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))?
    };
    Ok(addrs
        .into_iter()
        .map(|addr| SocketAddr::new(addr, 0))
        .collect())
}

async fn connect_first(addrs: Vec<SocketAddr>) -> Result<TcpStream, FetchError> {
    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err
        .map(FetchError::from)
        .unwrap_or_else(|| FetchError::Runtime("lookup returned no addresses".to_string())))
}

async fn dial_proxy(
    proxy: &str,
    target: &Url,
    timeout: Option<Duration>,
) -> Result<DialStream, FetchError> {
    let proxy_url = parse_proxy_url(proxy)?;
    match proxy_url.scheme() {
        "http" | "https" => dial_http_proxy(proxy, &proxy_url, target, timeout).await,
        "socks5" | "socks5h" => dial_socks5_proxy(&proxy_url, target, timeout).await,
        scheme => Err(FetchError::Message(format!(
            "invalid proxy '{proxy}': unsupported proxy scheme '{scheme}'"
        ))),
    }
}

fn parse_proxy_url(proxy: &str) -> Result<Url, FetchError> {
    Url::parse(proxy)
        .or_else(|err| {
            if matches!(err, url::ParseError::RelativeUrlWithoutBase) {
                Url::parse(&format!("http://{proxy}"))
            } else {
                Err(err)
            }
        })
        .map_err(|err| FetchError::Message(format!("invalid proxy '{proxy}': {err}")))
}

async fn dial_http_proxy(
    raw_proxy: &str,
    proxy_url: &Url,
    target: &Url,
    timeout: Option<Duration>,
) -> Result<DialStream, FetchError> {
    let stream = connect_proxy_tcp(proxy_url, timeout).await?;
    let mut stream: DialStream = if proxy_url.scheme() == "https" {
        let host = proxy_url.host_str().ok_or_else(|| {
            FetchError::Message(format!("invalid proxy '{raw_proxy}': missing host"))
        })?;
        let server_name =
            rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|_| {
                FetchError::Message(format!("invalid proxy '{raw_proxy}': invalid host"))
            })?;
        let config = crate::tls::rustls_client_config(&[], None, None, false, None, None)?;
        let stream = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(server_name, stream)
            .await?;
        Box::pin(stream)
    } else {
        Box::pin(stream)
    };

    let authority = url_authority(target)?;
    let mut request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: {}\r\n",
        core::user_agent()
    );
    if let Some(auth) = proxy_basic_auth(proxy_url)? {
        request.push_str("Proxy-Authorization: ");
        request.push_str(&auth);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;

    let mut raw = Vec::new();
    let mut buf = [0_u8; 1];
    while !raw.ends_with(b"\r\n\r\n") {
        if raw.len() >= 16 * 1024 {
            return Err(FetchError::Runtime(
                "proxy CONNECT response was too large".to_string(),
            ));
        }
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(FetchError::Runtime(
                "proxy closed connection during CONNECT".to_string(),
            ));
        }
        raw.extend_from_slice(&buf[..n]);
    }
    let response = String::from_utf8_lossy(&raw);
    let status = response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(0);
    if !(200..300).contains(&status) {
        return Err(FetchError::Runtime(format!(
            "proxy CONNECT failed with status {status}"
        )));
    }
    Ok(stream)
}

async fn connect_proxy_tcp(
    proxy_url: &Url,
    timeout: Option<Duration>,
) -> Result<TcpStream, FetchError> {
    let host = proxy_url
        .host_str()
        .ok_or_else(|| FetchError::Message("proxy host is required".to_string()))?;
    let port = proxy_url.port_or_known_default().unwrap_or_else(|| {
        if matches!(proxy_url.scheme(), "socks5" | "socks5h") {
            1080
        } else if proxy_url.scheme() == "https" {
            443
        } else {
            80
        }
    });
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))?
        .collect();
    let connect = connect_first(addrs);
    if let Some(timeout) = timeout {
        tokio::time::timeout(timeout, connect).await.map_err(|_| {
            FetchError::Runtime(format!(
                "request timed out after {}",
                crate::http::format_go_duration(timeout)
            ))
        })?
    } else {
        connect.await
    }
}

fn proxy_basic_auth(proxy_url: &Url) -> Result<Option<String>, FetchError> {
    let Some(password) = proxy_url.password() else {
        return Ok(None);
    };
    let username = percent_encoding::percent_decode_str(proxy_url.username())
        .decode_utf8()
        .map_err(|err| FetchError::Message(format!("invalid proxy username: {err}")))?;
    let password = percent_encoding::percent_decode_str(password)
        .decode_utf8()
        .map_err(|err| FetchError::Message(format!("invalid proxy password: {err}")))?;
    let raw = format!("{username}:{password}");
    Ok(Some(format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(raw)
    )))
}

async fn dial_socks5_proxy(
    proxy_url: &Url,
    target: &Url,
    timeout: Option<Duration>,
) -> Result<DialStream, FetchError> {
    let mut stream = connect_proxy_tcp(proxy_url, timeout).await?;
    let username = percent_encoding::percent_decode_str(proxy_url.username())
        .decode_utf8()
        .map_err(|err| FetchError::Message(format!("invalid proxy username: {err}")))?;
    let password = proxy_url
        .password()
        .map(|password| percent_encoding::percent_decode_str(password).decode_utf8())
        .transpose()
        .map_err(|err| FetchError::Message(format!("invalid proxy password: {err}")))?;

    if let Some(password) = password.as_deref() {
        if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
            return Err(FetchError::Message(
                "SOCKS5 proxy credentials are too long".to_string(),
            ));
        }
        stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
    }

    let mut method = [0_u8; 2];
    stream.read_exact(&mut method).await?;
    if method[0] != 0x05 {
        return Err(FetchError::Runtime(
            "SOCKS5 proxy returned an invalid greeting".to_string(),
        ));
    }
    match method[1] {
        0x00 => {}
        0x02 => {
            let password = password.as_deref().ok_or_else(|| {
                FetchError::Runtime("SOCKS5 proxy requires authentication".to_string())
            })?;
            let mut auth = Vec::with_capacity(3 + username.len() + password.len());
            auth.push(0x01);
            auth.push(username.len() as u8);
            auth.extend_from_slice(username.as_bytes());
            auth.push(password.len() as u8);
            auth.extend_from_slice(password.as_bytes());
            stream.write_all(&auth).await?;
            let mut response = [0_u8; 2];
            stream.read_exact(&mut response).await?;
            if response != [0x01, 0x00] {
                return Err(FetchError::Runtime(
                    "SOCKS5 proxy authentication failed".to_string(),
                ));
            }
        }
        0xff => {
            return Err(FetchError::Runtime(
                "SOCKS5 proxy rejected authentication methods".to_string(),
            ));
        }
        _ => {
            return Err(FetchError::Runtime(
                "SOCKS5 proxy selected an unsupported authentication method".to_string(),
            ));
        }
    }

    let mut request = vec![0x05, 0x01, 0x00];
    write_socks5_target(&mut request, proxy_url.scheme() == "socks5h", target).await?;
    stream.write_all(&request).await?;

    let mut response = [0_u8; 4];
    stream.read_exact(&mut response).await?;
    if response[0] != 0x05 || response[1] != 0x00 {
        return Err(FetchError::Runtime(format!(
            "SOCKS5 proxy CONNECT failed with status {}",
            response[1]
        )));
    }
    read_socks5_bound_addr(&mut stream, response[3]).await?;
    Ok(Box::pin(stream))
}

async fn write_socks5_target(
    request: &mut Vec<u8>,
    remote_dns: bool,
    target: &Url,
) -> Result<(), FetchError> {
    let host = target
        .host_str()
        .ok_or_else(|| FetchError::Message("URL host is required".to_string()))?;
    let port = target
        .port_or_known_default()
        .ok_or_else(|| FetchError::Message("URL port is required".to_string()))?;

    if remote_dns {
        if host.len() > u8::MAX as usize {
            return Err(FetchError::Message(
                "SOCKS5 target hostname is too long".to_string(),
            ));
        }
        request.push(0x03);
        request.push(host.len() as u8);
        request.extend_from_slice(host.as_bytes());
    } else if let Ok(ip) = host.parse::<IpAddr>() {
        write_socks5_ip(request, ip);
    } else {
        let addr = tokio::net::lookup_host((host, port))
            .await
            .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))?
            .next()
            .ok_or_else(|| FetchError::Runtime(format!("lookup {host}: no addresses")))?;
        write_socks5_ip(request, addr.ip());
    }
    request.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

fn write_socks5_ip(request: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(ip) => {
            request.push(0x01);
            request.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            request.push(0x04);
            request.extend_from_slice(&ip.octets());
        }
    }
}

async fn read_socks5_bound_addr(stream: &mut TcpStream, atyp: u8) -> Result<(), FetchError> {
    match atyp {
        0x01 => {
            let mut raw = [0_u8; 6];
            stream.read_exact(&mut raw).await?;
        }
        0x03 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len).await?;
            let mut raw = vec![0_u8; len[0] as usize + 2];
            stream.read_exact(&mut raw).await?;
        }
        0x04 => {
            let mut raw = [0_u8; 18];
            stream.read_exact(&mut raw).await?;
        }
        _ => {
            return Err(FetchError::Runtime(
                "SOCKS5 proxy returned an invalid address type".to_string(),
            ));
        }
    }
    Ok(())
}

fn url_authority(url: &Url) -> Result<String, FetchError> {
    let host = url
        .host_str()
        .ok_or_else(|| FetchError::Message("URL host is required".to_string()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| FetchError::Message("URL port is required".to_string()))?;
    Ok(if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    })
}

fn websocket_timeout(cli: &Cli) -> Result<Option<Duration>, FetchError> {
    cli.timeout
        .map(|seconds| crate::http::duration_from_seconds("timeout", seconds))
        .transpose()
}

fn websocket_io_error(err: FetchError) -> WsError {
    WsError::Io(io::Error::other(err.to_string()))
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
    Ok(
        crate::http::request_body_into_bytes(crate::http::request_body(cli)?)?
            .map(|(bytes, _content_type)| bytes),
    )
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
    let stdout_is_terminal = io::stdout().is_terminal();
    while let Some(message) = stream.next().await {
        match message.map_err(websocket_error)? {
            Message::Text(text) => {
                write_text_message(cli, text.as_str().as_bytes(), stdout_is_terminal)?
            }
            Message::Binary(bytes) => write_binary_indicator(cli, bytes.len()),
            Message::Close(_) => return Ok(()),
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
        }
    }
    Ok(())
}

fn write_text_message(cli: &Cli, bytes: &[u8], stdout_is_terminal: bool) -> Result<(), FetchError> {
    if should_format(cli, stdout_is_terminal)
        && let Ok(formatted) = json::format_json_line(bytes, use_color(cli, stdout_is_terminal))
    {
        print!("{}", String::from_utf8_lossy(&formatted));
        return Ok(());
    }
    println!("{}", String::from_utf8_lossy(bytes));
    Ok(())
}

fn should_format(cli: &Cli, stdout_is_terminal: bool) -> bool {
    match cli.format.as_deref() {
        Some("off") => false,
        Some("on") => true,
        _ => stdout_is_terminal,
    }
}

fn should_format_for_interactive(cli: &Cli) -> bool {
    !matches!(cli.format.as_deref(), Some("off"))
}

fn use_color(cli: &Cli, stdout_is_terminal: bool) -> bool {
    core::color_enabled(cli.color.as_deref(), stdout_is_terminal)
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
}
