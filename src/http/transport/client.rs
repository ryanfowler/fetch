use std::collections::HashMap;
use std::convert::Infallible;
use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use http::header::{
    AUTHORIZATION, COOKIE, HOST, HeaderMap, HeaderValue, PROXY_AUTHORIZATION, SET_COOKIE,
};
use http::{Method, Request, Uri, Version};
use http_body_util::{BodyExt, Empty};
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::pki_types::ServerName;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;
use tower_service::Service;
use url::Url;

use super::body::{Body, BodyDeadline, PeerAddr, Response};
use super::h3::{AutoHttp3Config, H3PooledClient};
use super::proxy::{Proxy, dial_stream_for_config, proxy_for_config};
use super::{Error, ErrorKind};
use crate::cli::HttpVersion;
use crate::duration::{TimeoutBudget, request_timeout_message};
use crate::error::FetchError;
use crate::http::http3_cache::Http3Cache;
use crate::timing::{DnsTiming, TransportTiming};

#[derive(Clone)]
pub struct Client {
    pub(super) config: Arc<ClientConfig>,
    pooled: HyperClient<TransportConnector, Body>,
    pub(super) h3_pool: Arc<Mutex<HashMap<String, H3PooledClient>>>,
}

pub(super) struct AutoTcpConnection {
    stream: PooledStream,
    negotiated_h2: bool,
    remote_addr: Option<SocketAddr>,
    pub(super) timing: TransportTiming,
}

#[derive(Clone)]
pub(super) struct ClientConfig {
    pub(super) mode: Option<HttpVersion>,
    pub(super) unix_socket: Option<String>,
    pub(super) dns_overrides: HashMap<String, Vec<SocketAddr>>,
    pub(super) proxies: Vec<Proxy>,
    pub(super) tls_config: Option<rustls::ClientConfig>,
    pub(super) request_timeout: Option<Duration>,
    pub(super) request_timeout_message: Option<String>,
    pub(super) connect_timeout: Option<Duration>,
    pub(super) session: Option<Arc<crate::session::PersistentCookieStore>>,
    pub(super) connection_timing: Option<crate::http::client::ConnectionTiming>,
    pub(super) dns_resolution: Option<crate::http::client::DnsResolutionHandle>,
    pub(super) dns_server: Option<String>,
    pub(super) local_address: Option<IpAddr>,
    pub(super) auto_http3: Option<AutoHttp3Config>,
    pub(super) auto_http3_discovery: bool,
    pub(super) http3_cache: Option<Arc<Http3Cache>>,
    pub(super) learn_alt_svc: bool,
}

pub(crate) struct ClientBuilder {
    pub(super) config: ClientConfig,
}

impl fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientBuilder")
    }
}

impl Client {
    pub(crate) fn builder() -> ClientBuilder {
        ClientBuilder {
            config: ClientConfig {
                mode: None,
                unix_socket: None,
                dns_overrides: HashMap::new(),
                proxies: Vec::new(),
                tls_config: None,
                request_timeout: None,
                request_timeout_message: None,
                connect_timeout: None,
                session: None,
                connection_timing: None,
                dns_resolution: None,
                dns_server: None,
                local_address: None,
                auto_http3: None,
                auto_http3_discovery: false,
                http3_cache: None,
                learn_alt_svc: false,
            },
        }
    }

    pub(crate) fn request(&self, method: Method, mut url: Url) -> RequestBuilder {
        let mut headers = HeaderMap::new();
        if let Some((username, password)) = extract_url_basic_auth(&mut url) {
            headers.insert(
                AUTHORIZATION,
                basic_auth_header_value(&username, password.as_deref()),
            );
        }
        RequestBuilder {
            client: self.clone(),
            method,
            url,
            headers,
            body: None,
            version: None,
            timeout: self.config.request_timeout,
            timeout_message: self.config.request_timeout_message.clone(),
        }
    }

    pub(crate) fn post(&self, url: Url) -> RequestBuilder {
        self.request(Method::POST, url)
    }

    async fn execute(&self, request: RequestBuilder) -> Result<Response, Error> {
        let version = request
            .version
            .or_else(|| self.config.mode.map(version_for_cli));
        let timeout = TimeoutBudget::new(request.timeout);
        let body_deadline = request.timeout.map(|timeout| {
            BodyDeadline::with_message(
                timeout,
                request
                    .timeout_message
                    .unwrap_or_else(|| request_timeout_message(timeout)),
            )
        });
        timeout
            .run(self.send(
                request.method,
                request.url,
                request.headers,
                request.body,
                version,
                body_deadline,
            ))
            .await
            .map_err(|err| Error::from_fetch(ErrorKind::Request, err))?
    }

    async fn send(
        &self,
        method: Method,
        url: Url,
        mut headers: HeaderMap,
        body: Option<Body>,
        version: Option<Version>,
        body_deadline: Option<BodyDeadline>,
    ) -> Result<Result<Response, Error>, FetchError> {
        self.apply_session_cookies(&url, &mut headers);
        self.apply_proxy_authorization(&url, &mut headers)?;
        apply_host_header(&url, &mut headers)?;
        let response = match version {
            None if (self.config.auto_http3.is_some()
                || self.config.auto_http3_discovery
                || self.config.http3_cache.is_some())
                && url.scheme() == "https" =>
            {
                self.send_auto_http3(method, url.clone(), headers, body, body_deadline)
                    .await
            }
            None | Some(Version::HTTP_11 | Version::HTTP_10 | Version::HTTP_2) => {
                self.send_pooled(method, url.clone(), headers, body, version, body_deadline)
                    .await
            }
            Some(Version::HTTP_3) => {
                self.send_http3(method, url.clone(), headers, body, body_deadline)
                    .await
            }
            Some(version) => Err(Error::request(format!(
                "unsupported HTTP version: {version:?}"
            ))),
        };
        if let Ok(response) = &response {
            self.store_http3_alt_svc(&url, response.headers());
            self.store_response_cookies(&url, response.headers());
        }
        Ok(response)
    }

    fn apply_session_cookies(&self, url: &Url, headers: &mut HeaderMap) {
        if headers.contains_key(COOKIE) {
            return;
        }
        let Some(session) = &self.config.session else {
            return;
        };
        if let Some(cookies) = session.cookies(url) {
            headers.insert(COOKIE, cookies);
        }
    }

    fn store_response_cookies(&self, url: &Url, headers: &HeaderMap) {
        let Some(session) = &self.config.session else {
            return;
        };
        session.set_cookies(&mut headers.get_all(SET_COOKIE).iter(), url);
    }

    fn store_http3_alt_svc(&self, url: &Url, headers: &HeaderMap) {
        if !self.config.learn_alt_svc {
            return;
        }
        let Some(cache) = &self.config.http3_cache else {
            return;
        };
        cache.store_alt_svc(url, self.config.dns_server.as_deref(), headers);
    }

    pub(super) fn apply_proxy_authorization(
        &self,
        url: &Url,
        headers: &mut HeaderMap,
    ) -> Result<(), FetchError> {
        if url.scheme() != "http" || headers.contains_key(PROXY_AUTHORIZATION) {
            return Ok(());
        }
        let Some(proxy) = proxy_for_config(&self.config, url) else {
            return Ok(());
        };
        if !proxy.is_http_proxy() {
            return Ok(());
        }
        let Some(auth) = proxy.basic_auth()? else {
            return Ok(());
        };
        headers.insert(
            PROXY_AUTHORIZATION,
            HeaderValue::from_str(&auth).map_err(|err| {
                FetchError::Message(format!("invalid proxy authorization: {err}"))
            })?,
        );
        Ok(())
    }

    async fn send_pooled(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Option<Body>,
        version: Option<Version>,
        body_deadline: Option<BodyDeadline>,
    ) -> Result<Response, Error> {
        let body = body.unwrap_or_else(|| Body::from(Bytes::new()));
        let request_version = version.unwrap_or(Version::HTTP_11);
        let request = build_request(method, absolute_uri(&url)?, request_version, headers, body)
            .map_err(Error::request)?;
        let response = self
            .pooled
            .request(request)
            .await
            .map_err(map_pooled_client_error)?;
        Ok(Response::from_hyper(url, response, body_deadline))
    }

    pub(super) async fn send_tcp_one_shot(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Option<Body>,
        body_deadline: Option<BodyDeadline>,
        connection: AutoTcpConnection,
    ) -> Result<Response, Error> {
        let body = body.unwrap_or_else(|| Body::from(Bytes::new()));
        let version = if connection.negotiated_h2 {
            Version::HTTP_2
        } else {
            Version::HTTP_11
        };
        let uri = if connection.negotiated_h2 {
            absolute_uri(&url)?
        } else {
            origin_form_uri(&url)?
        };
        let remote_addr = connection.remote_addr;
        let request = build_request(method, uri, version, headers, body).map_err(Error::request)?;
        let io = TokioIo::new(connection.stream);
        let response = if connection.negotiated_h2 {
            let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .timer(TokioTimer::new())
                .handshake(io)
                .await
                .map_err(|err| {
                    Error::with_source(ErrorKind::Connect, format!("http2 handshake: {err}"), err)
                })?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            sender
                .send_request(request)
                .await
                .map_err(|err| Error::with_source(ErrorKind::Request, err.to_string(), err))?
        } else {
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(io)
                .await
                .map_err(|err| {
                    Error::with_source(ErrorKind::Connect, format!("http1 handshake: {err}"), err)
                })?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            sender
                .send_request(request)
                .await
                .map_err(|err| Error::with_source(ErrorKind::Request, err.to_string(), err))?
        };
        Ok(Response::from_hyper_with_remote(
            url,
            response,
            body_deadline,
            remote_addr,
        ))
    }

    pub(super) async fn connect_auto_tcp_tls(
        &self,
        url: &Url,
        timeout: TimeoutBudget,
    ) -> Result<AutoTcpConnection, Error> {
        let trace = connect_direct_tcp_config(&self.config, url, timeout)
            .await
            .map_err(|err| Error::from_fetch(ErrorKind::Connect, err))?;
        record_dns_trace(&self.config, url, &trace);
        let remote_addr = trace.stream.peer_addr().ok();
        let tcp = trace.tcp_duration;
        let tls_start = std::time::Instant::now();
        let (stream, negotiated_h2) = tls_stream_for_config(
            &self.config,
            url,
            Box::pin(trace.stream) as crate::net::DialStream,
            &alpn_for_config(&self.config),
            timeout,
        )
        .await?;
        Ok(AutoTcpConnection {
            stream: PooledStream {
                inner: stream,
                negotiated_h2,
                proxied: false,
                remote_addr,
            },
            negotiated_h2,
            remote_addr,
            timing: TransportTiming {
                tcp: Some(tcp),
                tls: Some(tls_start.elapsed()),
                quic: None,
            },
        })
    }
}

impl ClientBuilder {
    pub(crate) fn build(self) -> Result<Client, Error> {
        let config = Arc::new(self.config);
        let connector = TransportConnector {
            config: config.clone(),
        };
        let mut builder = HyperClient::builder(TokioExecutor::new());
        builder.pool_timer(TokioTimer::new());
        if matches!(config.mode, Some(HttpVersion::Http2)) {
            builder.http2_only(true);
        }
        Ok(Client {
            config,
            pooled: builder.build(connector),
            h3_pool: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub(crate) fn use_rustls_tls(self) -> Self {
        self
    }

    pub(crate) fn no_brotli(self) -> Self {
        self
    }

    pub(crate) fn no_gzip(self) -> Self {
        self
    }

    pub(crate) fn no_zstd(self) -> Self {
        self
    }

    pub(crate) fn http1_only(mut self) -> Self {
        self.config.mode = Some(HttpVersion::Http1);
        self
    }

    pub(crate) fn http2_prior_knowledge(mut self) -> Self {
        self.config.mode = Some(HttpVersion::Http2);
        self
    }

    pub(crate) fn http3_prior_knowledge(mut self) -> Self {
        self.config.mode = Some(HttpVersion::Http3);
        self
    }

    #[cfg(unix)]
    pub(crate) fn unix_socket(mut self, path: &str) -> Self {
        self.config.unix_socket = Some(path.to_string());
        self
    }

    pub(crate) fn local_address(mut self, addr: IpAddr) -> Self {
        self.config.local_address = Some(addr);
        self
    }

    pub(crate) fn auto_http3(mut self, config: AutoHttp3Config) -> Self {
        self.config.auto_http3 = Some(config);
        self
    }

    pub(crate) fn auto_http3_discovery(mut self) -> Self {
        self.config.auto_http3_discovery = true;
        self
    }

    pub(crate) fn http3_cache(mut self, cache: Arc<Http3Cache>, learn_alt_svc: bool) -> Self {
        self.config.http3_cache = Some(cache);
        self.config.learn_alt_svc = learn_alt_svc;
        self
    }

    pub(crate) fn dns_server(mut self, server: String) -> Self {
        self.config.dns_server = Some(server);
        self
    }

    pub(crate) fn dns_resolution(
        mut self,
        resolution: crate::http::client::DnsResolutionHandle,
    ) -> Self {
        self.config.dns_resolution = Some(resolution);
        self
    }

    pub(crate) fn resolve_to_addrs(mut self, host: &str, addrs: &[SocketAddr]) -> Self {
        self.config
            .dns_overrides
            .insert(host.to_string(), addrs.to_vec());
        self
    }

    pub(crate) fn tls_config(mut self, config: rustls::ClientConfig) -> Self {
        self.config.tls_config = Some(config);
        self
    }

    pub(crate) fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.config.connect_timeout = Some(timeout);
        self
    }

    pub(crate) fn timeout_with_message(
        mut self,
        timeout: Duration,
        timeout_message: impl Into<String>,
    ) -> Self {
        self.config.request_timeout = Some(timeout);
        self.config.request_timeout_message = Some(timeout_message.into());
        self
    }

    pub(crate) fn cookie_provider(
        mut self,
        session: Arc<crate::session::PersistentCookieStore>,
    ) -> Self {
        self.config.session = Some(session);
        self
    }

    pub(crate) fn proxy(mut self, proxy: Proxy) -> Self {
        self.config.proxies.push(proxy);
        self
    }

    pub(crate) fn connection_timing(
        mut self,
        timing: crate::http::client::ConnectionTiming,
    ) -> Self {
        self.config.connection_timing = Some(timing);
        self
    }

    pub(crate) fn redirect(self, _policy: redirect::Policy) -> Self {
        self
    }
}

#[derive(Clone)]
struct TransportConnector {
    config: Arc<ClientConfig>,
}

impl Service<Uri> for TransportConnector {
    type Response = TokioIo<PooledStream>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let config = self.config.clone();
        Box::pin(async move { connect_pooled(config, uri).await })
    }
}

async fn connect_pooled(
    config: Arc<ClientConfig>,
    uri: Uri,
) -> Result<TokioIo<PooledStream>, Error> {
    let url = Url::parse(&uri.to_string())
        .map_err(|err| Error::request(format!("invalid request URI: {err}")))?;
    let proxy = proxy_for_config(&config, &url);
    let timeout = TimeoutBudget::new(config.connect_timeout);
    let tcp_start = std::time::Instant::now();
    let (mut stream, proxied, uses_tcp, remote_addr, tcp_duration) =
        dial_stream_for_config(&config, &url, proxy.as_ref(), timeout).await?;
    let mut timing = TransportTiming {
        tcp: uses_tcp.then_some(tcp_duration.unwrap_or_else(|| tcp_start.elapsed())),
        tls: None,
        quic: None,
    };
    let mut negotiated_h2 = false;

    if url.scheme() == "https" {
        let tls_start = std::time::Instant::now();
        let (tls, h2) =
            tls_stream_for_config(&config, &url, stream, &alpn_for_config(&config), timeout)
                .await?;
        timing.tls = Some(tls_start.elapsed());
        stream = tls;
        negotiated_h2 = h2;
    }

    if let Some(connection_timing) = &config.connection_timing {
        connection_timing.set(timing);
    }

    Ok(TokioIo::new(PooledStream {
        inner: stream,
        negotiated_h2,
        proxied,
        remote_addr,
    }))
}

pub(super) async fn connect_direct_tcp_config(
    config: &ClientConfig,
    url: &Url,
    timeout: TimeoutBudget,
) -> Result<crate::net::TcpConnectTrace, FetchError> {
    let host = url
        .host_str()
        .ok_or_else(|| FetchError::Message("URL host is required".to_string()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| FetchError::Message("URL port is required".to_string()))?;
    if let Some(addrs) = config.dns_overrides.get(host) {
        let mut addrs = addrs.clone();
        for addr in &mut addrs {
            addr.set_port(port);
        }
        let tcp_start = std::time::Instant::now();
        let stream = timeout
            .run(crate::net::connect_first(addrs.clone(), timeout))
            .await?;
        return Ok(crate::net::TcpConnectTrace {
            stream,
            resolved_addrs: addrs,
            dns_duration: None,
            tcp_duration: tcp_start.elapsed(),
        });
    }
    crate::net::connect_tcp_traced(url, config.dns_server.as_deref(), timeout).await
}

pub(super) fn record_dns_trace(
    config: &ClientConfig,
    url: &Url,
    trace: &crate::net::TcpConnectTrace,
) {
    let Some(duration) = trace.dns_duration else {
        return;
    };
    record_dns_addrs_trace(config, url, &trace.resolved_addrs, duration);
}

pub(super) fn record_dns_addrs_trace(
    config: &ClientConfig,
    url: &Url,
    addrs: &[SocketAddr],
    duration: Duration,
) {
    let Some(resolution) = &config.dns_resolution else {
        return;
    };
    let Some(host) = url.host_str() else {
        return;
    };
    resolution.set(crate::http::client::DnsResolution {
        socket_addrs: addrs.to_vec(),
        timing: Some(DnsTiming {
            host: host.to_string(),
            addrs: dns_timing_addrs(addrs.iter().map(|addr| addr.ip())),
            duration,
        }),
    });
}

fn dns_timing_addrs(addrs: impl IntoIterator<Item = IpAddr>) -> Vec<IpAddr> {
    let mut unique = Vec::new();
    for addr in addrs {
        if !unique.contains(&addr) {
            unique.push(addr);
        }
    }
    unique
}

pub(super) fn alpn_for_config(config: &ClientConfig) -> Vec<Vec<u8>> {
    match config.mode {
        Some(HttpVersion::Http1) => vec![b"http/1.1".to_vec()],
        Some(HttpVersion::Http2) => vec![b"h2".to_vec()],
        Some(HttpVersion::Http3) => vec![b"h3".to_vec()],
        None => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    }
}

pub(super) async fn tls_stream_for_config(
    config: &ClientConfig,
    url: &Url,
    stream: crate::net::DialStream,
    alpn: &[Vec<u8>],
    timeout: TimeoutBudget,
) -> Result<(crate::net::DialStream, bool), Error> {
    let host = url
        .host_str()
        .ok_or_else(|| Error::request("URL host is required"))?;
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| Error::request(format!("invalid server name '{host}'")))?;
    let mut tls_config = config.tls_config.clone().unwrap_or_else(default_tls_config);
    tls_config.alpn_protocols = alpn.to_vec();
    let stream = timeout
        .run(async {
            TlsConnector::from(Arc::new(tls_config))
                .connect(server_name, stream)
                .await
                .map_err(|err| FetchError::Runtime(format!("tls: {err}")))
        })
        .await
        .map_err(|err| Error::from_fetch(ErrorKind::Connect, err))?;
    let negotiated_h2 = {
        let (_, conn) = stream.get_ref();
        matches!(conn.alpn_protocol(), Some(b"h2"))
    };
    Ok((Box::pin(stream), negotiated_h2))
}

fn map_pooled_client_error(err: hyper_util::client::legacy::Error) -> Error {
    let kind = if err.is_connect() {
        ErrorKind::Connect
    } else {
        ErrorKind::Request
    };
    let message = err
        .source()
        .map(ToString::to_string)
        .unwrap_or_else(|| err.to_string());
    Error::with_source(kind, message, err)
}

struct PooledStream {
    inner: crate::net::DialStream,
    negotiated_h2: bool,
    proxied: bool,
    remote_addr: Option<SocketAddr>,
}

impl Connection for PooledStream {
    fn connected(&self) -> Connected {
        let mut connected = Connected::new().proxy(self.proxied);
        if let Some(remote_addr) = self.remote_addr {
            connected = connected.extra(PeerAddr(remote_addr));
        }
        if self.negotiated_h2 {
            connected.negotiated_h2()
        } else {
            connected
        }
    }
}

impl tokio::io::AsyncRead for PooledStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.inner.as_mut().poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for PooledStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.inner.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.inner.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.inner.as_mut().poll_shutdown(cx)
    }
}

pub(crate) mod redirect {
    #[derive(Clone, Copy)]
    pub(crate) struct Policy;

    impl Policy {
        pub(crate) fn none() -> Self {
            Self
        }
    }
}

pub(crate) struct RequestBuilder {
    client: Client,
    method: Method,
    url: Url,
    headers: HeaderMap,
    body: Option<Body>,
    version: Option<Version>,
    timeout: Option<Duration>,
    timeout_message: Option<String>,
}

impl RequestBuilder {
    pub(crate) fn headers(mut self, headers: HeaderMap) -> Self {
        replace_headers(&mut self.headers, headers);
        self
    }

    pub(crate) fn body(mut self, body: impl Into<Body>) -> Self {
        self.body = Some(body.into());
        self
    }

    pub(crate) fn version(mut self, version: Version) -> Self {
        self.version = Some(version);
        self
    }

    pub(crate) fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self.timeout_message
            .get_or_insert_with(|| request_timeout_message(timeout));
        self
    }

    pub(crate) fn timeout_with_message(
        mut self,
        timeout: Duration,
        timeout_message: impl Into<String>,
    ) -> Self {
        self.timeout = Some(timeout);
        self.timeout_message = Some(timeout_message.into());
        self
    }

    pub(crate) async fn send(self) -> Result<Response, Error> {
        self.client.clone().execute(self).await
    }
}

fn version_for_cli(version: HttpVersion) -> Version {
    match version {
        HttpVersion::Http1 => Version::HTTP_11,
        HttpVersion::Http2 => Version::HTTP_2,
        HttpVersion::Http3 => Version::HTTP_3,
    }
}

pub(crate) fn extract_url_basic_auth(url: &mut Url) -> Option<(String, Option<String>)> {
    let username = url.username().to_string();
    let password = url.password().map(str::to_string);
    if username.is_empty() && password.is_none() {
        return None;
    }

    url.set_username("").ok()?;
    url.set_password(None).ok()?;

    let username = percent_encoding::percent_decode_str(&username)
        .decode_utf8()
        .ok()?
        .into_owned();
    let password = match password.as_deref() {
        Some(password) => Some(
            percent_encoding::percent_decode_str(password)
                .decode_utf8()
                .ok()?
                .into_owned(),
        ),
        None => None,
    };

    Some((username, password))
}

pub(crate) fn basic_auth_header_value(username: &str, password: Option<&str>) -> HeaderValue {
    let raw = format!("{}:{}", username, password.unwrap_or_default());
    let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
    let mut value =
        HeaderValue::from_str(&format!("Basic {encoded}")).expect("base64 is a valid header value");
    value.set_sensitive(true);
    value
}

pub(super) fn replace_headers(target: &mut HeaderMap, headers: HeaderMap) {
    let mut last_name = None;
    for (name, value) in headers {
        match name {
            Some(name) => {
                last_name = Some(name.clone());
                target.insert(name, value);
            }
            None => {
                if let Some(name) = &last_name {
                    target.append(name.clone(), value);
                }
            }
        }
    }
}

pub(super) fn build_request<B>(
    method: Method,
    uri: Uri,
    version: Version,
    headers: HeaderMap,
    body: B,
) -> Result<Request<B>, String> {
    let mut builder = Request::builder().method(method).uri(uri).version(version);
    *builder
        .headers_mut()
        .expect("request builder has no error before headers") = headers;
    builder.body(body).map_err(|err| err.to_string())
}

pub(super) fn empty_request_body()
-> impl http_body::Body<Data = Bytes, Error = Error> + Send + 'static {
    Empty::<Bytes>::new().map_err(|err: Infallible| match err {})
}

pub(super) fn default_tls_config() -> rustls::ClientConfig {
    crate::tls::rustls_platform_client_config().expect("default rustls client config is valid")
}

pub(super) fn absolute_uri(url: &Url) -> Result<Uri, Error> {
    url.as_str()
        .parse::<Uri>()
        .map_err(|err| Error::request(format!("invalid request URI: {err}")))
}

pub(super) fn origin_form_uri(url: &Url) -> Result<Uri, Error> {
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    let mut out = path.to_string();
    if let Some(query) = url.query() {
        out.push('?');
        out.push_str(query);
    }
    out.parse::<Uri>()
        .map_err(|err| Error::request(format!("invalid request URI: {err}")))
}

fn apply_host_header(url: &Url, headers: &mut HeaderMap) -> Result<(), FetchError> {
    if headers.contains_key(HOST) {
        return Ok(());
    }
    let value = crate::net::http_host_header_value(url)?;
    headers.insert(
        HOST,
        HeaderValue::from_str(&value)
            .map_err(|err| FetchError::Message(format!("invalid host header: {err}")))?,
    );
    Ok(())
}
