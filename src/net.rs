use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::task::JoinHandle;
use url::{Host, Url};

use crate::core;
use crate::duration::TimeoutBudget;
use crate::error::FetchError;

pub(crate) trait AsyncIo: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> AsyncIo for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub(crate) type DialStream = Pin<Box<dyn AsyncIo>>;

const HAPPY_EYEBALLS_FALLBACK_DELAY: Duration = Duration::from_millis(300);
const TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(15);
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const TCP_KEEPALIVE_RETRIES: u32 = 3;
#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
const TCP_USER_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) async fn dial_url(
    url: &Url,
    proxy: Option<&str>,
    dns_server: Option<&str>,
    timeout: TimeoutBudget,
) -> Result<DialStream, FetchError> {
    if let Some(proxy) = proxy {
        return dial_proxy(proxy, url, dns_server, timeout).await;
    }
    let stream = connect_tcp(url, dns_server, timeout).await?;
    Ok(Box::pin(stream))
}

pub(crate) async fn connect_tcp(
    url: &Url,
    dns_server: Option<&str>,
    timeout: TimeoutBudget,
) -> Result<TcpStream, FetchError> {
    let host = url
        .host_str()
        .ok_or_else(|| FetchError::Message("URL host is required".to_string()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| FetchError::Message("URL port is required".to_string()))?;

    if let Ok(ip) = host.parse::<IpAddr>() {
        return timeout_fetch(timeout, connect_addr(SocketAddr::new(ip, port))).await;
    }

    let mut addrs = timeout_fetch(timeout, resolve_host(host, dns_server, timeout)).await?;
    for addr in &mut addrs {
        addr.set_port(port);
    }
    timeout_fetch(timeout, connect_first(addrs, timeout)).await
}

pub(crate) async fn resolve_host(
    host: &str,
    dns_server: Option<&str>,
    timeout: TimeoutBudget,
) -> Result<Vec<SocketAddr>, FetchError> {
    let Some(dns_server) = dns_server else {
        return tokio::net::lookup_host((host, 0))
            .await
            .map(|addrs| addrs.collect())
            .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")));
    };

    let addrs = crate::dns::custom::lookup_ips(dns_server, host, timeout.remaining()?).await?;
    Ok(addrs
        .into_iter()
        .map(|addr| SocketAddr::new(addr, 0))
        .collect())
}

pub(crate) async fn connect_first(
    addrs: Vec<SocketAddr>,
    timeout: TimeoutBudget,
) -> Result<TcpStream, FetchError> {
    let (preferred, fallback) = split_addrs_by_first_family(addrs)?;

    if fallback.is_empty() {
        return connect_sequence(preferred, timeout).await;
    }

    connect_happy_eyeballs(preferred, fallback, timeout).await
}

pub(crate) fn split_addrs_by_first_family(
    addrs: Vec<SocketAddr>,
) -> Result<(Vec<SocketAddr>, Vec<SocketAddr>), FetchError> {
    let Some(first) = addrs.first() else {
        return Err(FetchError::Runtime(
            "lookup returned no addresses".to_string(),
        ));
    };
    let first_is_ipv4 = first.is_ipv4();
    Ok(addrs
        .into_iter()
        .partition(|addr| addr.is_ipv4() == first_is_ipv4))
}

async fn connect_happy_eyeballs(
    preferred: Vec<SocketAddr>,
    fallback: Vec<SocketAddr>,
    timeout: TimeoutBudget,
) -> Result<TcpStream, FetchError> {
    let mut preferred = ConnectTask::new(preferred, timeout);
    let mut fallback_addrs = Some(fallback);
    let mut fallback_task: Option<ConnectTask> = None;
    let mut preferred_err = None;
    let mut fallback_err = None;
    let delay = tokio::time::sleep(HAPPY_EYEBALLS_FALLBACK_DELAY);
    tokio::pin!(delay);

    loop {
        if preferred_err.is_some() && fallback_err.is_some() {
            return Err(fallback_err
                .take()
                .or(preferred_err)
                .expect("at least one error exists"));
        }

        if preferred_err.is_some() {
            if fallback_task.is_none() && fallback_err.is_none() {
                fallback_task = Some(ConnectTask::new(
                    fallback_addrs.take().expect("fallback addresses exist"),
                    timeout,
                ));
            }
            if let Some(task) = fallback_task.as_mut() {
                match task.await {
                    Ok(stream) => return Ok(stream),
                    Err(err) => {
                        fallback_err = Some(err);
                        fallback_task = None;
                    }
                }
            }
            continue;
        }

        if fallback_err.is_some() {
            match (&mut preferred).await {
                Ok(stream) => return Ok(stream),
                Err(err) => preferred_err = Some(err),
            }
            continue;
        }

        if fallback_task.is_none() {
            tokio::select! {
                result = &mut preferred => match result {
                    Ok(stream) => return Ok(stream),
                    Err(err) => {
                        preferred_err = Some(err);
                        fallback_task = Some(ConnectTask::new(
                            fallback_addrs.take().expect("fallback addresses exist"),
                            timeout,
                        ));
                    }
                },
                _ = &mut delay => {
                    fallback_task = Some(ConnectTask::new(
                        fallback_addrs.take().expect("fallback addresses exist"),
                        timeout,
                    ));
                }
            }
        } else {
            let fallback_future = fallback_task.as_mut().expect("fallback task exists");
            tokio::select! {
                result = &mut preferred => match result {
                    Ok(stream) => return Ok(stream),
                    Err(err) => preferred_err = Some(err),
                },
                result = fallback_future => match result {
                    Ok(stream) => return Ok(stream),
                    Err(err) => {
                        fallback_err = Some(err);
                        fallback_task = None;
                    }
                },
            }
        }
    }
}

struct ConnectTask {
    handle: JoinHandle<Result<TcpStream, FetchError>>,
}

impl ConnectTask {
    fn new(addrs: Vec<SocketAddr>, timeout: TimeoutBudget) -> Self {
        Self {
            handle: tokio::spawn(connect_sequence(addrs, timeout)),
        }
    }
}

impl Future for ConnectTask {
    type Output = Result<TcpStream, FetchError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.handle).poll(cx).map(|result| {
            result.unwrap_or_else(|err| {
                Err(FetchError::Runtime(format!("connect task failed: {err}")))
            })
        })
    }
}

impl Drop for ConnectTask {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn connect_sequence(
    addrs: Vec<SocketAddr>,
    timeout: TimeoutBudget,
) -> Result<TcpStream, FetchError> {
    let per_address_timeout = per_address_timeout(addrs.len(), timeout);
    let mut last_err = None;
    for addr in addrs {
        match connect_addr_with_timeout(addr, per_address_timeout).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| FetchError::Runtime("lookup returned no addresses".to_string())))
}

async fn connect_addr_with_timeout(
    addr: SocketAddr,
    timeout: Option<Duration>,
) -> Result<TcpStream, FetchError> {
    let Some(timeout) = timeout else {
        return connect_addr(addr).await;
    };
    match tokio::time::timeout(timeout, connect_addr(addr)).await {
        Ok(result) => result,
        Err(_) => Err(FetchError::Runtime(format!("connect {addr}: timed out"))),
    }
}

fn per_address_timeout(addrs_len: usize, timeout: TimeoutBudget) -> Option<Duration> {
    let addrs_len = u32::try_from(addrs_len).ok()?;
    if addrs_len == 0 {
        return None;
    }
    timeout
        .timeout()
        .and_then(|timeout| timeout.checked_div(addrs_len))
}

async fn connect_addr(addr: SocketAddr) -> Result<TcpStream, FetchError> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }?;
    socket.set_nodelay(true)?;
    let _ = socket.set_keepalive(true);
    let stream = socket.connect(addr).await?;
    configure_tcp_stream(&stream);
    Ok(stream)
}

fn configure_tcp_stream(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let socket = socket2::SockRef::from(stream);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE_IDLE)
        .with_interval(TCP_KEEPALIVE_INTERVAL)
        .with_retries(TCP_KEEPALIVE_RETRIES);
    let _ = socket.set_tcp_keepalive(&keepalive);
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    let _ = socket.set_tcp_user_timeout(Some(TCP_USER_TIMEOUT));
}

pub(crate) fn http_host_header_value(url: &Url) -> Result<String, FetchError> {
    let host = match url.host() {
        Some(Host::Domain(host)) => host.to_string(),
        Some(Host::Ipv4(host)) => host.to_string(),
        Some(Host::Ipv6(host)) => format!("[{host}]"),
        None => return Err(FetchError::Message("URL host is required".to_string())),
    };
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

pub(crate) async fn dial_proxy(
    proxy: &str,
    target: &Url,
    dns_server: Option<&str>,
    timeout: TimeoutBudget,
) -> Result<DialStream, FetchError> {
    let proxy_url = parse_proxy_url(proxy)?;
    match proxy_url.scheme() {
        "http" | "https" => {
            dial_http_proxy_tunnel(proxy, &proxy_url, target, timeout, None, None).await
        }
        "socks5" | "socks5h" => dial_socks5_proxy(&proxy_url, target, dns_server, timeout).await,
        scheme => Err(FetchError::Message(format!(
            "invalid proxy '{proxy}': unsupported proxy scheme '{scheme}'"
        ))),
    }
}

pub(crate) fn parse_proxy_url(proxy: &str) -> Result<Url, FetchError> {
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

pub(crate) async fn dial_http_proxy_tunnel(
    raw_proxy: &str,
    proxy_url: &Url,
    target: &Url,
    timeout: TimeoutBudget,
    tls_config: Option<rustls::ClientConfig>,
    proxy_authorization: Option<String>,
) -> Result<DialStream, FetchError> {
    let mut stream = match tls_config {
        Some(config) => {
            dial_http_proxy_stream_with_tls(raw_proxy, proxy_url, timeout, Some(config)).await?
        }
        None => dial_http_proxy_stream(raw_proxy, proxy_url, timeout).await?,
    };

    let authority = url_authority(target)?;
    let mut request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: {}\r\n",
        core::user_agent()
    );
    let proxy_authorization = match proxy_authorization {
        Some(auth) => Some(auth),
        None => proxy_basic_auth(proxy_url)?,
    };
    if let Some(auth) = proxy_authorization {
        request.push_str("Proxy-Authorization: ");
        request.push_str(&auth);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    timeout_fetch(timeout, async {
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
        Ok(())
    })
    .await?;
    Ok(stream)
}

pub(crate) async fn dial_http_proxy_stream(
    raw_proxy: &str,
    proxy_url: &Url,
    timeout: TimeoutBudget,
) -> Result<DialStream, FetchError> {
    dial_http_proxy_stream_with_tls(raw_proxy, proxy_url, timeout, None).await
}

pub(crate) async fn dial_http_proxy_stream_with_tls(
    raw_proxy: &str,
    proxy_url: &Url,
    timeout: TimeoutBudget,
    tls_config: Option<rustls::ClientConfig>,
) -> Result<DialStream, FetchError> {
    let stream = connect_proxy_tcp(proxy_url, timeout).await?;
    if proxy_url.scheme() == "https" {
        let host = proxy_url.host_str().ok_or_else(|| {
            FetchError::Message(format!("invalid proxy '{raw_proxy}': missing host"))
        })?;
        let server_name =
            rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|_| {
                FetchError::Message(format!("invalid proxy '{raw_proxy}': invalid host"))
            })?;
        let mut config = match tls_config {
            Some(config) => config,
            None => crate::tls::rustls_platform_client_config()?,
        };
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let stream = timeout_fetch(timeout, async {
            tokio_rustls::TlsConnector::from(Arc::new(config))
                .connect(server_name, stream)
                .await
                .map_err(FetchError::from)
        })
        .await?;
        Ok(Box::pin(stream))
    } else {
        Ok(Box::pin(stream))
    }
}

pub(crate) async fn connect_proxy_tcp(
    proxy_url: &Url,
    timeout: TimeoutBudget,
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
    timeout_fetch(timeout, async {
        let addrs = tokio::net::lookup_host((host, port))
            .await
            .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))?
            .collect();
        connect_first(addrs, timeout).await
    })
    .await
}

pub(crate) fn proxy_basic_auth(proxy_url: &Url) -> Result<Option<String>, FetchError> {
    if proxy_url.username().is_empty() && proxy_url.password().is_none() {
        return Ok(None);
    }
    let username = percent_encoding::percent_decode_str(proxy_url.username())
        .decode_utf8()
        .map_err(|err| FetchError::Message(format!("invalid proxy username: {err}")))?;
    let password = proxy_url.password().unwrap_or("");
    let password = percent_encoding::percent_decode_str(password)
        .decode_utf8()
        .map_err(|err| FetchError::Message(format!("invalid proxy password: {err}")))?;
    let raw = format!("{username}:{password}");
    Ok(Some(format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(raw)
    )))
}

pub(crate) async fn dial_socks5_proxy(
    proxy_url: &Url,
    target: &Url,
    dns_server: Option<&str>,
    timeout: TimeoutBudget,
) -> Result<DialStream, FetchError> {
    let stream = connect_socks5_proxy(proxy_url, timeout).await?;
    let mut request = vec![0x05, 0x01, 0x00];
    timeout_fetch(
        timeout,
        write_socks5_target(
            &mut request,
            proxy_url.scheme() == "socks5h",
            target,
            dns_server,
            timeout,
        ),
    )
    .await?;
    send_socks5_connect(stream, request, timeout).await
}

pub(crate) async fn dial_socks5_proxy_to_addr(
    proxy_url: &Url,
    target_addr: SocketAddr,
    timeout: TimeoutBudget,
) -> Result<DialStream, FetchError> {
    let stream = connect_socks5_proxy(proxy_url, timeout).await?;
    let mut request = vec![0x05, 0x01, 0x00];
    write_socks5_ip(&mut request, target_addr.ip());
    request.extend_from_slice(&target_addr.port().to_be_bytes());
    send_socks5_connect(stream, request, timeout).await
}

async fn connect_socks5_proxy(
    proxy_url: &Url,
    timeout: TimeoutBudget,
) -> Result<TcpStream, FetchError> {
    let mut stream = connect_proxy_tcp(proxy_url, timeout).await?;
    let username = percent_encoding::percent_decode_str(proxy_url.username())
        .decode_utf8()
        .map_err(|err| FetchError::Message(format!("invalid proxy username: {err}")))?;
    let password = proxy_url
        .password()
        .map(|password| percent_encoding::percent_decode_str(password).decode_utf8())
        .transpose()
        .map_err(|err| FetchError::Message(format!("invalid proxy password: {err}")))?;
    let has_credentials = !username.is_empty() || password.is_some();
    let password = password.unwrap_or(std::borrow::Cow::Borrowed(""));

    if has_credentials {
        if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
            return Err(FetchError::Message(
                "SOCKS5 proxy credentials are too long".to_string(),
            ));
        }
        timeout_fetch(timeout, async {
            stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
            Ok(())
        })
        .await?;
    } else {
        timeout_fetch(timeout, async {
            stream.write_all(&[0x05, 0x01, 0x00]).await?;
            Ok(())
        })
        .await?;
    }

    let mut method = [0_u8; 2];
    timeout_fetch(timeout, async {
        stream.read_exact(&mut method).await?;
        Ok(())
    })
    .await?;
    if method[0] != 0x05 {
        return Err(FetchError::Runtime(
            "SOCKS5 proxy returned an invalid greeting".to_string(),
        ));
    }
    match method[1] {
        0x00 => {}
        0x02 => {
            if !has_credentials {
                return Err(FetchError::Runtime(
                    "SOCKS5 proxy requires authentication".to_string(),
                ));
            }
            let mut auth = Vec::with_capacity(3 + username.len() + password.len());
            auth.push(0x01);
            auth.push(username.len() as u8);
            auth.extend_from_slice(username.as_bytes());
            auth.push(password.len() as u8);
            auth.extend_from_slice(password.as_bytes());
            timeout_fetch(timeout, async {
                stream.write_all(&auth).await?;
                Ok(())
            })
            .await?;
            let mut response = [0_u8; 2];
            timeout_fetch(timeout, async {
                stream.read_exact(&mut response).await?;
                Ok(())
            })
            .await?;
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

    Ok(stream)
}

async fn send_socks5_connect(
    mut stream: TcpStream,
    request: Vec<u8>,
    timeout: TimeoutBudget,
) -> Result<DialStream, FetchError> {
    timeout_fetch(timeout, async {
        stream.write_all(&request).await?;
        Ok(())
    })
    .await?;

    let mut response = [0_u8; 4];
    timeout_fetch(timeout, async {
        stream.read_exact(&mut response).await?;
        Ok(())
    })
    .await?;
    if response[0] != 0x05 || response[1] != 0x00 {
        return Err(FetchError::Runtime(format!(
            "SOCKS5 proxy CONNECT failed with status {}",
            response[1]
        )));
    }
    timeout_fetch(timeout, read_socks5_bound_addr(&mut stream, response[3])).await?;
    Ok(Box::pin(stream))
}

async fn write_socks5_target(
    request: &mut Vec<u8>,
    remote_dns: bool,
    target: &Url,
    dns_server: Option<&str>,
    timeout: TimeoutBudget,
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
        let addr = resolve_host(host, dns_server, timeout)
            .await?
            .into_iter()
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

pub(crate) fn url_authority(url: &Url) -> Result<String, FetchError> {
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

async fn timeout_fetch<T>(
    timeout: TimeoutBudget,
    future: impl Future<Output = Result<T, FetchError>>,
) -> Result<T, FetchError> {
    timeout.run(future).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_header_value_brackets_ipv6_literals() {
        let url = Url::parse("http://[::1]/").unwrap();
        assert_eq!(http_host_header_value(&url).unwrap(), "[::1]");

        let url = Url::parse("http://[::1]:3000/path").unwrap();
        assert_eq!(http_host_header_value(&url).unwrap(), "[::1]:3000");
    }

    #[test]
    fn host_header_value_keeps_domain_and_ipv4_authorities() {
        let url = Url::parse("https://example.com/path").unwrap();
        assert_eq!(http_host_header_value(&url).unwrap(), "example.com");

        let url = Url::parse("http://127.0.0.1:3000/path").unwrap();
        assert_eq!(http_host_header_value(&url).unwrap(), "127.0.0.1:3000");
    }

    #[test]
    fn per_address_timeout_splits_connect_timeout_across_addresses() {
        let timeout = TimeoutBudget::new(Some(Duration::from_secs(9)));
        assert_eq!(
            per_address_timeout(3, timeout),
            Some(Duration::from_secs(3))
        );
        assert_eq!(per_address_timeout(0, timeout), None);
        assert_eq!(per_address_timeout(3, TimeoutBudget::new(None)), None);
    }

    #[test]
    fn split_addrs_by_first_family_preserves_resolver_family_preference() {
        let addrs = vec![
            SocketAddr::new("::1".parse().unwrap(), 443),
            SocketAddr::new("127.0.0.1".parse().unwrap(), 443),
            SocketAddr::new("::2".parse().unwrap(), 443),
            SocketAddr::new("127.0.0.2".parse().unwrap(), 443),
        ];

        let (preferred, fallback) = split_addrs_by_first_family(addrs).unwrap();

        assert_eq!(
            preferred,
            [
                SocketAddr::new("::1".parse().unwrap(), 443),
                SocketAddr::new("::2".parse().unwrap(), 443)
            ]
        );
        assert_eq!(
            fallback,
            [
                SocketAddr::new("127.0.0.1".parse().unwrap(), 443),
                SocketAddr::new("127.0.0.2".parse().unwrap(), 443)
            ]
        );
    }
}
