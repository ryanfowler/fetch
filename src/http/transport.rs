use std::collections::HashMap;
use std::convert::Infallible;
use std::error::Error as StdError;
use std::fmt;
use std::future::{self, Future};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine;
use bytes::{Buf, Bytes};
use futures_util::{Stream, TryStreamExt};
use http::header::{
    AUTHORIZATION, CONTENT_LENGTH, COOKIE, HOST, HeaderMap, HeaderValue, PROXY_AUTHORIZATION,
    SET_COOKIE,
};
use http::{Method, Request, Uri, Version};
use http_body::Frame;
use http_body_util::{BodyExt, Empty, Full, StreamBody, combinators::UnsyncBoxBody};
use hyper::body::Incoming;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::client::proxy::matcher;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_util::io::ReaderStream;
use tower_service::Service;
use url::Url;

use crate::cli::HttpVersion;
use crate::duration::{TimeoutBudget, request_timeout_message};
use crate::error::FetchError;
use crate::timing::TransportTiming;

const HTTP3_HAPPY_EYEBALLS_FALLBACK_DELAY: Duration = Duration::from_millis(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorKind {
    Request,
    Connect,
    Timeout,
    Body,
}

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    message: String,
    source: Option<Box<dyn StdError + Send + Sync>>,
}

impl Error {
    fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            source: None,
        }
    }

    fn with_source(
        kind: ErrorKind,
        message: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    fn request(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Request, message)
    }

    fn connect(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Connect, message)
    }

    fn timeout(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Timeout, message)
    }

    fn body(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Body, message)
    }

    fn body_source(source: impl StdError + Send + Sync + 'static) -> Self {
        let message = source.to_string();
        Self::with_source(ErrorKind::Body, message, source)
    }

    fn from_fetch(kind: ErrorKind, err: FetchError) -> Self {
        let message = err.to_string();
        let kind = if message.starts_with("request timed out after ") {
            ErrorKind::Timeout
        } else {
            kind
        };
        Self::new(kind, message)
    }

    pub(crate) fn is_timeout(&self) -> bool {
        self.kind == ErrorKind::Timeout
    }

    pub(crate) fn is_connect(&self) -> bool {
        self.kind == ErrorKind::Connect
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct BodyDeadline {
    deadline: tokio::time::Instant,
    timeout_message: String,
}

impl BodyDeadline {
    #[cfg(test)]
    pub(crate) fn new(request_timeout: Duration) -> Self {
        Self::with_message(request_timeout, request_timeout_message(request_timeout))
    }

    fn with_message(timeout: Duration, timeout_message: String) -> Self {
        Self {
            deadline: tokio::time::Instant::now() + timeout,
            timeout_message,
        }
    }

    fn timeout_error(&self) -> Error {
        Error::timeout(self.timeout_message.clone())
    }
}

pub struct Body {
    inner: UnsyncBoxBody<Bytes, Error>,
}

impl Body {
    pub(crate) fn wrap_stream<S, E>(stream: S) -> Self
    where
        S: Stream<Item = Result<Bytes, E>> + Send + 'static,
        E: fmt::Display + Send + Sync + 'static,
    {
        let stream = stream
            .map_ok(Frame::data)
            .map_err(|err| Error::body(err.to_string()));
        Self::boxed(StreamBody::new(stream))
    }

    fn boxed<B>(body: B) -> Self
    where
        B: http_body::Body<Data = Bytes, Error = Error> + Send + 'static,
    {
        Self {
            inner: BodyExt::boxed_unsync(body),
        }
    }

    fn map_incoming(body: Incoming) -> Self {
        Self::boxed(body.map_err(Error::body_source))
    }
}

impl From<Bytes> for Body {
    fn from(bytes: Bytes) -> Self {
        Self::boxed(Full::new(bytes).map_err(|err| match err {}))
    }
}

impl From<Vec<u8>> for Body {
    fn from(bytes: Vec<u8>) -> Self {
        Self::from(Bytes::from(bytes))
    }
}

impl From<String> for Body {
    fn from(value: String) -> Self {
        Self::from(Bytes::from(value))
    }
}

impl From<&'static str> for Body {
    fn from(value: &'static str) -> Self {
        Self::from(Bytes::from_static(value.as_bytes()))
    }
}

impl From<tokio::fs::File> for Body {
    fn from(file: tokio::fs::File) -> Self {
        Self::wrap_stream(ReaderStream::new(file))
    }
}

impl http_body::Body for Body {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

#[derive(Clone)]
pub struct Client {
    config: Arc<ClientConfig>,
    pooled: HyperClient<TransportConnector, Body>,
    h3_pool: Arc<Mutex<HashMap<String, H3PooledClient>>>,
}

type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

#[derive(Clone)]
struct H3PooledClient {
    origin: String,
    sender: H3SendRequest,
    remote_addr: SocketAddr,
}

#[derive(Clone)]
struct ClientConfig {
    mode: Option<HttpVersion>,
    unix_socket: Option<String>,
    dns_overrides: HashMap<String, Vec<SocketAddr>>,
    proxies: Vec<Proxy>,
    tls_config: Option<rustls::ClientConfig>,
    request_timeout: Option<Duration>,
    request_timeout_message: Option<String>,
    connect_timeout: Option<Duration>,
    session: Option<Arc<crate::session::PersistentCookieStore>>,
    connection_timing: Option<crate::http::client::ConnectionTiming>,
    local_address: Option<IpAddr>,
}

pub(crate) struct ClientBuilder {
    config: ClientConfig,
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
                local_address: None,
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

    fn apply_proxy_authorization(
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

    async fn send_http3(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Option<Body>,
        body_deadline: Option<BodyDeadline>,
    ) -> Result<Response, Error> {
        if url.scheme() != "https" {
            return Err(Error::request(format!(
                "http3: unsupported protocol scheme: {}",
                url.scheme()
            )));
        }
        let (req, body) = match body {
            Some(body) => {
                let request =
                    build_request(method, absolute_uri(&url)?, Version::HTTP_3, headers, body)
                        .map_err(Error::request)?;
                let (parts, body) = request.into_parts();
                (Request::from_parts(parts, ()), Some(body))
            }
            None => {
                let request = build_request(
                    method,
                    absolute_uri(&url)?,
                    Version::HTTP_3,
                    headers,
                    empty_request_body(),
                )
                .map_err(Error::request)?;
                let (parts, _) = request.into_parts();
                (Request::from_parts(parts, ()), None)
            }
        };
        let pooled = self.http3_client(&url).await?;
        let mut sender = pooled.sender.clone();
        let stream = match sender.send_request(req).await {
            Ok(stream) => stream,
            Err(err) => {
                self.remove_http3_client(&pooled.origin).await;
                return Err(Error::with_source(
                    ErrorKind::Request,
                    format!("http3 request: {err}"),
                    err,
                ));
            }
        };
        let (mut send, mut recv) = stream.split();
        let upload_deadline = body_deadline.clone();
        let send_task = H3UploadTask::new(tokio::spawn(async move {
            match body {
                Some(body) => send_h3_body(&mut send, body, upload_deadline).await,
                None => send
                    .finish()
                    .await
                    .map_err(|err| Error::body(format!("http3 request body: {err}"))),
            }
        }));
        let response = recv.recv_response().await.map_err(|err| {
            Error::with_source(ErrorKind::Request, format!("http3 response: {err}"), err)
        })?;
        let upload_task = if send_task.is_finished() {
            send_task.await?;
            None
        } else {
            Some(send_task)
        };
        Ok(Response::from_h3(
            url,
            response,
            recv,
            sender,
            upload_task,
            body_deadline,
            pooled.remote_addr,
        ))
    }

    async fn http3_client(&self, url: &Url) -> Result<H3PooledClient, Error> {
        let origin = http3_origin(url)?;
        if let Some(client) = self.h3_pool.lock().await.get(&origin).cloned() {
            return Ok(client);
        }

        let client = self.connect_http3_client(url, origin.clone()).await?;
        let mut pool = self.h3_pool.lock().await;
        Ok(pool.entry(origin).or_insert_with(|| client.clone()).clone())
    }

    async fn remove_http3_client(&self, origin: &str) {
        self.h3_pool.lock().await.remove(origin);
    }

    async fn connect_http3_client(
        &self,
        url: &Url,
        origin: String,
    ) -> Result<H3PooledClient, Error> {
        let host = url
            .host_str()
            .ok_or_else(|| Error::request("URL host is required"))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| Error::request("URL port is required"))?;
        let timeout = TimeoutBudget::new(self.config.connect_timeout);
        let mut addrs = if let Some(addrs) = self.config.dns_overrides.get(host) {
            let mut addrs = addrs.clone();
            for addr in &mut addrs {
                addr.set_port(port);
            }
            addrs
        } else {
            crate::net::resolve_host(host, None, timeout)
                .await
                .map_err(|err| Error::from_fetch(ErrorKind::Connect, err))?
                .into_iter()
                .map(|mut addr| {
                    addr.set_port(port);
                    addr
                })
                .collect()
        };
        let (mut endpoint, family_filter) = http3_client_endpoint(self.config.local_address)?;
        if let Some(local_ip) = family_filter {
            addrs.retain(|addr| addr.ip().is_ipv4() == local_ip.is_ipv4());
        }
        let mut tls = self
            .config
            .tls_config
            .clone()
            .unwrap_or_else(default_tls_config);
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let client_config = QuicClientConfig::try_from(tls)
            .map(|config| quinn::ClientConfig::new(Arc::new(config)))
            .map_err(|err| Error::request(format!("invalid QUIC TLS configuration: {err}")))?;
        endpoint.set_default_client_config(client_config);
        let start = std::time::Instant::now();
        let connection = connect_http3(endpoint, addrs, host.to_string(), timeout)
            .await
            .map_err(|err| Error::from_fetch(ErrorKind::Connect, err))?;
        let remote_addr = connection.remote_address();
        if let Some(timing) = &self.config.connection_timing {
            timing.set(TransportTiming {
                tcp: None,
                tls: None,
                quic: Some(start.elapsed()),
            });
        }
        let h3_connection = h3_quinn::Connection::new(connection);
        let (mut driver, sender) = h3::client::new(h3_connection)
            .await
            .map_err(|err| Error::connect(format!("http3 handshake: {err}")))?;
        tokio::spawn(async move {
            let _ = future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        Ok(H3PooledClient {
            origin,
            sender,
            remote_addr,
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
    let (mut stream, proxied, uses_tcp, remote_addr) =
        dial_stream_for_config(&config, &url, proxy.as_ref(), timeout).await?;
    let mut timing = TransportTiming {
        tcp: uses_tcp.then(|| tcp_start.elapsed()),
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

async fn dial_stream_for_config(
    config: &ClientConfig,
    url: &Url,
    proxy: Option<&Proxy>,
    timeout: TimeoutBudget,
) -> Result<(crate::net::DialStream, bool, bool, Option<SocketAddr>), Error> {
    match proxy {
        Some(proxy) if proxy.is_http_proxy() && url.scheme() == "http" => {
            let proxy_url = crate::net::parse_proxy_url(&proxy.url)
                .map_err(|err| Error::from_fetch(ErrorKind::Connect, err))?;
            let stream =
                crate::net::dial_http_proxy_stream_with_tls(&proxy.url, &proxy_url, timeout, None)
                    .await
                    .map_err(|err| Error::from_fetch(ErrorKind::Connect, err))?;
            Ok((stream, true, true, None))
        }
        Some(proxy) if proxy.is_http_proxy() => {
            let proxy_url = crate::net::parse_proxy_url(&proxy.url)
                .map_err(|err| Error::from_fetch(ErrorKind::Connect, err))?;
            let proxy_authorization = proxy
                .basic_auth()
                .map_err(|err| Error::from_fetch(ErrorKind::Connect, err))?;
            let stream = crate::net::dial_http_proxy_tunnel(
                &proxy.url,
                &proxy_url,
                url,
                timeout,
                None,
                proxy_authorization,
            )
            .await
            .map_err(|err| Error::from_fetch(ErrorKind::Connect, err))?;
            Ok((stream, false, true, None))
        }
        Some(proxy)
            if proxy.scheme().is_ok_and(|scheme| scheme == "socks5")
                && target_override_addrs(config, url).is_some() =>
        {
            let proxy_url = crate::net::parse_proxy_url(&proxy.url)
                .map_err(|err| Error::from_fetch(ErrorKind::Connect, err))?;
            let addrs = target_override_addrs(config, url).expect("checked above");
            dial_socks5_proxy_to_addrs(&proxy_url, addrs, timeout)
                .await
                .map(|stream| (stream, false, true, None))
                .map_err(|err| Error::from_fetch(ErrorKind::Connect, err))
        }
        Some(proxy) => crate::net::dial_proxy(&proxy.url, url, None, timeout)
            .await
            .map(|stream| (stream, false, true, None))
            .map_err(|err| Error::from_fetch(ErrorKind::Connect, err)),
        None if config.unix_socket.is_some() => {
            #[cfg(unix)]
            {
                let path = config.unix_socket.as_deref().expect("unix socket checked");
                UnixStream::connect(path)
                    .await
                    .map(|stream| {
                        (
                            Box::pin(stream) as crate::net::DialStream,
                            false,
                            false,
                            None,
                        )
                    })
                    .map_err(|err| Error::with_source(ErrorKind::Connect, err.to_string(), err))
            }
            #[cfg(not(unix))]
            {
                Err(Error::connect("--unix is not supported on this platform"))
            }
        }
        None => {
            let stream = connect_direct_tcp_config(config, url, timeout)
                .await
                .map_err(|err| Error::from_fetch(ErrorKind::Connect, err))?;
            let remote_addr = stream.peer_addr().ok();
            Ok((
                Box::pin(stream) as crate::net::DialStream,
                false,
                true,
                remote_addr,
            ))
        }
    }
}

async fn connect_direct_tcp_config(
    config: &ClientConfig,
    url: &Url,
    timeout: TimeoutBudget,
) -> Result<TcpStream, FetchError> {
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
        return timeout.run(crate::net::connect_first(addrs, timeout)).await;
    }
    crate::net::connect_tcp(url, None, timeout).await
}

fn proxy_for_config(config: &ClientConfig, url: &Url) -> Option<Proxy> {
    config
        .proxies
        .iter()
        .find_map(|proxy| proxy.selected_for(url))
}

fn target_override_addrs(config: &ClientConfig, url: &Url) -> Option<Vec<SocketAddr>> {
    let host = url.host_str()?;
    let port = url.port_or_known_default()?;
    let mut addrs = config.dns_overrides.get(host)?.clone();
    for addr in &mut addrs {
        addr.set_port(port);
    }
    (!addrs.is_empty()).then_some(addrs)
}

async fn dial_socks5_proxy_to_addrs(
    proxy_url: &Url,
    addrs: Vec<SocketAddr>,
    timeout: TimeoutBudget,
) -> Result<crate::net::DialStream, FetchError> {
    let mut last_err = None;
    for addr in addrs {
        match crate::net::dial_socks5_proxy_to_addr(proxy_url, addr, timeout).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| FetchError::Runtime("lookup returned no addresses".to_string())))
}

fn alpn_for_config(config: &ClientConfig) -> Vec<Vec<u8>> {
    match config.mode {
        Some(HttpVersion::Http1) => vec![b"http/1.1".to_vec()],
        Some(HttpVersion::Http2) => vec![b"h2".to_vec()],
        Some(HttpVersion::Http3) => vec![b"h3".to_vec()],
        None => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    }
}

async fn tls_stream_for_config(
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

fn http3_origin(url: &Url) -> Result<String, Error> {
    let host = url
        .host_str()
        .ok_or_else(|| Error::request("URL host is required"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| Error::request("URL port is required"))?;
    Ok(format!("{}://{}:{}", url.scheme(), host, port))
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

#[derive(Clone, Copy, Debug)]
struct PeerAddr(SocketAddr);

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

#[derive(Clone)]
pub(crate) struct Proxy {
    url: String,
    kind: ProxyKind,
    no_proxy: Option<NoProxy>,
    basic_auth: Option<HeaderValue>,
}

#[derive(Clone)]
enum ProxyKind {
    All,
    Http,
    Https,
    System(Arc<matcher::Matcher>),
}

impl Proxy {
    pub(crate) fn all(proxy: &str) -> Result<Self, Error> {
        parse_proxy(proxy)?;
        Ok(Self {
            url: proxy.to_string(),
            kind: ProxyKind::All,
            no_proxy: None,
            basic_auth: None,
        })
    }

    pub(crate) fn http(proxy: &str) -> Result<Self, Error> {
        parse_proxy(proxy)?;
        Ok(Self {
            url: proxy.to_string(),
            kind: ProxyKind::Http,
            no_proxy: None,
            basic_auth: None,
        })
    }

    pub(crate) fn https(proxy: &str) -> Result<Self, Error> {
        parse_proxy(proxy)?;
        Ok(Self {
            url: proxy.to_string(),
            kind: ProxyKind::Https,
            no_proxy: None,
            basic_auth: None,
        })
    }

    pub(crate) fn system() -> Self {
        Self {
            url: String::new(),
            kind: ProxyKind::System(Arc::new(matcher::Matcher::from_system())),
            no_proxy: None,
            basic_auth: None,
        }
    }

    pub(crate) fn no_proxy(mut self, no_proxy: NoProxy) -> Self {
        self.no_proxy = Some(no_proxy);
        self
    }

    pub(crate) fn selected_for_url(&self, url: &Url) -> Option<Self> {
        self.selected_for(url)
    }

    pub(crate) fn uses_local_target_dns(&self) -> bool {
        self.scheme().is_ok_and(|scheme| scheme == "socks5")
    }

    fn applies_to(&self, url: &Url) -> bool {
        if self.no_proxy.as_ref().is_some_and(|no_proxy| {
            crate::http::client::no_proxy_matches_url(url, no_proxy.0.as_deref())
        }) {
            return false;
        }
        match &self.kind {
            ProxyKind::All => true,
            ProxyKind::Http => url.scheme() == "http",
            ProxyKind::Https => url.scheme() == "https",
            ProxyKind::System(_) => self.system_selected_for(url).is_some(),
        }
    }

    fn selected_for(&self, url: &Url) -> Option<Self> {
        match &self.kind {
            ProxyKind::System(_) => self.system_selected_for(url),
            _ => self.applies_to(url).then(|| self.clone()),
        }
    }

    fn system_selected_for(&self, url: &Url) -> Option<Self> {
        let ProxyKind::System(matcher) = &self.kind else {
            return None;
        };
        let uri = url.as_str().parse::<Uri>().ok()?;
        let intercepted = matcher.intercept(&uri)?;
        let proxy_url = intercepted.uri().to_string();
        let mut proxy = Self::all(&proxy_url).ok()?;
        proxy.basic_auth = intercepted.basic_auth().cloned();
        Some(proxy)
    }

    fn is_http_proxy(&self) -> bool {
        crate::net::parse_proxy_url(&self.url)
            .map(|url| matches!(url.scheme(), "http" | "https"))
            .unwrap_or(false)
    }

    fn scheme(&self) -> Result<String, FetchError> {
        crate::net::parse_proxy_url(&self.url).map(|url| url.scheme().to_string())
    }

    fn basic_auth(&self) -> Result<Option<String>, FetchError> {
        if let Some(auth) = &self.basic_auth {
            return auth
                .to_str()
                .map(|value| Some(value.to_string()))
                .map_err(|err| FetchError::Message(format!("invalid proxy authorization: {err}")));
        }
        let url = crate::net::parse_proxy_url(&self.url)?;
        crate::net::proxy_basic_auth(&url)
    }
}

fn parse_proxy(proxy: &str) -> Result<(), Error> {
    crate::net::parse_proxy_url(proxy)
        .map(|_| ())
        .map_err(|err| Error::from_fetch(ErrorKind::Request, err))
}

#[derive(Clone)]
pub(crate) struct NoProxy(Option<String>);

impl NoProxy {
    pub(crate) fn from_env() -> Self {
        Self(
            std::env::var("NO_PROXY")
                .or_else(|_| std::env::var("no_proxy"))
                .ok(),
        )
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

pub(crate) struct Response {
    url: Url,
    status: http::StatusCode,
    version: Version,
    headers: HeaderMap,
    body: Body,
    body_deadline: Option<BodyDeadline>,
    remote_addr: Option<SocketAddr>,
}

impl Response {
    fn from_hyper(
        url: Url,
        response: http::Response<Incoming>,
        body_deadline: Option<BodyDeadline>,
    ) -> Self {
        let (parts, body) = response.into_parts();
        let remote_addr = parts.extensions.get::<PeerAddr>().map(|addr| addr.0);
        Self {
            url,
            status: parts.status,
            version: parts.version,
            headers: parts.headers,
            body: Body::map_incoming(body),
            body_deadline,
            remote_addr,
        }
    }

    fn from_h3<S, O>(
        url: Url,
        response: http::Response<()>,
        stream: h3::client::RequestStream<S, Bytes>,
        sender: h3::client::SendRequest<O, Bytes>,
        upload_task: Option<H3UploadTask>,
        body_deadline: Option<BodyDeadline>,
        remote_addr: SocketAddr,
    ) -> Self
    where
        S: h3::quic::RecvStream + Send + Unpin + 'static,
        O: h3::quic::OpenStreams<Bytes> + Send + Unpin + 'static,
    {
        let (parts, _) = response.into_parts();
        Self {
            url,
            status: parts.status,
            version: Version::HTTP_3,
            headers: parts.headers,
            body: Body::boxed(H3Body {
                stream,
                _sender: sender,
                upload_task,
                state: H3BodyState::Data,
            }),
            body_deadline,
            remote_addr: Some(remote_addr),
        }
    }

    pub(crate) fn status(&self) -> http::StatusCode {
        self.status
    }

    pub(crate) fn version(&self) -> Version {
        self.version
    }

    pub(crate) fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub(crate) fn url(&self) -> &Url {
        &self.url
    }

    pub(crate) fn content_length(&self) -> Option<u64> {
        self.headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok())
    }

    pub(crate) fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }

    pub(crate) async fn chunk(&mut self) -> Result<Option<Bytes>, Error> {
        loop {
            let Some(frame) = read_body_frame(&mut self.body, self.body_deadline.as_ref()).await?
            else {
                return Ok(None);
            };
            if let Ok(data) = frame.into_data()
                && !data.is_empty()
            {
                return Ok(Some(data));
            }
        }
    }

    pub(crate) fn into_body_with_deadline(self) -> (Body, Option<BodyDeadline>) {
        (self.body, self.body_deadline)
    }
}

impl From<Response> for http::Response<Body> {
    fn from(response: Response) -> Self {
        let mut builder = http::Response::builder()
            .status(response.status)
            .version(response.version);
        *builder
            .headers_mut()
            .expect("response builder has no error before headers") = response.headers;
        builder
            .body(response.body)
            .expect("response parts are valid")
    }
}

pub(crate) async fn read_body_frame(
    body: &mut Body,
    deadline: Option<&BodyDeadline>,
) -> Result<Option<Frame<Bytes>>, Error> {
    let frame = match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline.deadline, body.frame())
            .await
            .map_err(|_| deadline.timeout_error())?,
        None => body.frame().await,
    };
    match frame {
        Some(Ok(frame)) => Ok(Some(frame)),
        Some(Err(err)) => Err(err),
        None => Ok(None),
    }
}

struct H3UploadTask {
    handle: JoinHandle<Result<(), Error>>,
}

impl H3UploadTask {
    fn new(handle: JoinHandle<Result<(), Error>>) -> Self {
        Self { handle }
    }

    fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }
}

impl Future for H3UploadTask {
    type Output = Result<(), Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.handle).poll(cx).map(|result| {
            result.unwrap_or_else(|err| Err(Error::body(format!("http3 request body task: {err}"))))
        })
    }
}

impl Drop for H3UploadTask {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

struct H3Body<S, O>
where
    O: h3::quic::OpenStreams<Bytes>,
{
    stream: h3::client::RequestStream<S, Bytes>,
    _sender: h3::client::SendRequest<O, Bytes>,
    upload_task: Option<H3UploadTask>,
    state: H3BodyState,
}

enum H3BodyState {
    Data,
    Trailers,
    Done,
}

impl<S, O> http_body::Body for H3Body<S, O>
where
    S: h3::quic::RecvStream + Unpin,
    O: h3::quic::OpenStreams<Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        loop {
            if let Some(upload_task) = &mut self.upload_task {
                match Pin::new(upload_task).poll(cx) {
                    Poll::Ready(Ok(())) => self.upload_task = None,
                    Poll::Ready(Err(err)) => {
                        self.upload_task = None;
                        return Poll::Ready(Some(Err(err)));
                    }
                    Poll::Pending => {}
                }
            }
            match self.state {
                H3BodyState::Data => match futures_util::ready!(self.stream.poll_recv_data(cx)) {
                    Ok(Some(mut data)) => {
                        return Poll::Ready(Some(Ok(Frame::data(
                            data.copy_to_bytes(data.remaining()),
                        ))));
                    }
                    Ok(None) => {
                        self.state = H3BodyState::Trailers;
                    }
                    Err(err) => {
                        return Poll::Ready(Some(Err(Error::with_source(
                            ErrorKind::Body,
                            format!("http3 body: {err}"),
                            err,
                        ))));
                    }
                },
                H3BodyState::Trailers => {
                    match futures_util::ready!(self.stream.poll_recv_trailers(cx)) {
                        Ok(Some(trailers)) => {
                            self.state = H3BodyState::Done;
                            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
                        }
                        Ok(None) => {
                            self.state = H3BodyState::Done;
                            return Poll::Ready(None);
                        }
                        Err(err) => {
                            return Poll::Ready(Some(Err(Error::with_source(
                                ErrorKind::Body,
                                format!("http3 trailers: {err}"),
                                err,
                            ))));
                        }
                    }
                }
                H3BodyState::Done => return Poll::Ready(None),
            }
        }
    }
}

async fn send_h3_body<S>(
    send: &mut h3::client::RequestStream<S, Bytes>,
    mut body: Body,
    deadline: Option<BodyDeadline>,
) -> Result<(), Error>
where
    S: h3::quic::SendStream<Bytes> + Unpin,
{
    while let Some(frame) = read_body_frame(&mut body, deadline.as_ref()).await? {
        if let Ok(data) = frame.into_data()
            && !data.is_empty()
        {
            send.send_data(data).await.map_err(|err| {
                Error::with_source(ErrorKind::Body, format!("http3 request body: {err}"), err)
            })?;
        }
    }
    send.finish().await.map_err(|err| {
        Error::with_source(ErrorKind::Body, format!("http3 request body: {err}"), err)
    })
}

fn version_for_cli(version: HttpVersion) -> Version {
    match version {
        HttpVersion::Http1 => Version::HTTP_11,
        HttpVersion::Http2 => Version::HTTP_2,
        HttpVersion::Http3 => Version::HTTP_3,
    }
}

fn extract_url_basic_auth(url: &mut Url) -> Option<(String, Option<String>)> {
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

fn basic_auth_header_value(username: &str, password: Option<&str>) -> HeaderValue {
    let raw = format!("{}:{}", username, password.unwrap_or_default());
    let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
    let mut value =
        HeaderValue::from_str(&format!("Basic {encoded}")).expect("base64 is a valid header value");
    value.set_sensitive(true);
    value
}

fn replace_headers(target: &mut HeaderMap, headers: HeaderMap) {
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

fn http3_client_endpoint(
    local_address: Option<IpAddr>,
) -> Result<(quinn::Endpoint, Option<IpAddr>), Error> {
    let local_addr = http3_endpoint_local_addr(local_address);
    match quinn::Endpoint::client(local_addr) {
        Ok(endpoint) => Ok((endpoint, local_address)),
        Err(err) if local_address.is_none() => {
            let fallback_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            quinn::Endpoint::client(fallback_addr)
                .map(|endpoint| (endpoint, Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED))))
                .map_err(|fallback_err| {
                    Error::connect(format!(
                        "failed to bind HTTP/3 client endpoint to {local_addr}: {err}; \
                         IPv4 fallback {fallback_addr} also failed: {fallback_err}"
                    ))
                })
        }
        Err(err) => Err(Error::with_source(ErrorKind::Connect, err.to_string(), err)),
    }
}

fn http3_endpoint_local_addr(local_address: Option<IpAddr>) -> SocketAddr {
    SocketAddr::new(
        local_address.unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
        0,
    )
}

async fn connect_http3(
    endpoint: quinn::Endpoint,
    addrs: Vec<SocketAddr>,
    host: String,
    timeout: TimeoutBudget,
) -> Result<quinn::Connection, FetchError> {
    let (preferred, fallback) = crate::net::split_addrs_by_first_family(addrs)?;
    if fallback.is_empty() {
        connect_http3_sequence(endpoint, preferred, host, timeout).await
    } else {
        connect_http3_happy_eyeballs(endpoint, preferred, fallback, host, timeout).await
    }
}

async fn connect_http3_happy_eyeballs(
    endpoint: quinn::Endpoint,
    preferred: Vec<SocketAddr>,
    fallback: Vec<SocketAddr>,
    host: String,
    timeout: TimeoutBudget,
) -> Result<quinn::Connection, FetchError> {
    let preferred = connect_http3_sequence(endpoint.clone(), preferred, host.clone(), timeout);
    tokio::pin!(preferred);
    let delay = tokio::time::sleep(HTTP3_HAPPY_EYEBALLS_FALLBACK_DELAY);
    tokio::pin!(delay);

    tokio::select! {
        result = &mut preferred => {
            return match result {
                Ok(connection) => Ok(connection),
                Err(_) => match connect_http3_sequence(endpoint, fallback, host, timeout).await {
                    Ok(connection) => Ok(connection),
                    Err(fallback_err) => Err(fallback_err),
                },
            };
        }
        _ = &mut delay => {}
    }

    let fallback = connect_http3_sequence(endpoint, fallback, host, timeout);
    tokio::pin!(fallback);
    let mut preferred_done = false;
    let mut fallback_done = false;
    let mut preferred_err = None;
    let mut fallback_err = None;

    loop {
        if preferred_done && fallback_done {
            return Err(fallback_err
                .take()
                .or(preferred_err)
                .expect("at least one HTTP/3 connect error exists"));
        }

        tokio::select! {
            result = &mut preferred, if !preferred_done => match result {
                Ok(connection) => return Ok(connection),
                Err(err) => {
                    preferred_err = Some(err);
                    preferred_done = true;
                }
            },
            result = &mut fallback, if !fallback_done => match result {
                Ok(connection) => return Ok(connection),
                Err(err) => {
                    fallback_err = Some(err);
                    fallback_done = true;
                }
            },
        }
    }
}

async fn connect_http3_sequence(
    endpoint: quinn::Endpoint,
    addrs: Vec<SocketAddr>,
    host: String,
    timeout: TimeoutBudget,
) -> Result<quinn::Connection, FetchError> {
    let mut last_err = None;
    for addr in addrs {
        let connecting = match endpoint.connect(addr, &host) {
            Ok(connecting) => connecting,
            Err(err) => {
                last_err = Some(FetchError::Runtime(format!("http3 connect {addr}: {err}")));
                continue;
            }
        };
        match timeout
            .run(async {
                connecting
                    .await
                    .map_err(|err| FetchError::Runtime(format!("http3 connect {addr}: {err}")))
            })
            .await
        {
            Ok(connection) => return Ok(connection),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| FetchError::Runtime("lookup returned no addresses".to_string())))
}

fn build_request<B>(
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

fn empty_request_body() -> impl http_body::Body<Data = Bytes, Error = Error> + Send + 'static {
    Empty::<Bytes>::new().map_err(|err: Infallible| match err {})
}

fn default_tls_config() -> rustls::ClientConfig {
    crate::tls::rustls_platform_client_config().expect("default rustls client config is valid")
}

fn absolute_uri(url: &Url) -> Result<Uri, Error> {
    url.as_str()
        .parse::<Uri>()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn replace_headers_preserves_duplicate_values() {
        let mut source = HeaderMap::new();
        source.append("x-repeat", HeaderValue::from_static("one"));
        source.append("x-repeat", HeaderValue::from_static("two"));
        let mut target = HeaderMap::new();

        replace_headers(&mut target, source);

        let values = target
            .get_all("x-repeat")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(values, ["one", "two"]);
    }

    #[test]
    fn replace_headers_replaces_existing_first_value() {
        let mut source = HeaderMap::new();
        source.append("authorization", HeaderValue::from_static("Bearer new"));
        let mut target = HeaderMap::new();
        target.append("authorization", HeaderValue::from_static("Bearer old"));
        target.append(
            "authorization",
            HeaderValue::from_static("Bearer duplicate"),
        );

        replace_headers(&mut target, source);

        let values = target
            .get_all("authorization")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(values, ["Bearer new"]);
    }

    #[test]
    fn extract_url_basic_auth_decodes_and_strips_authority() {
        let mut url = Url::parse("https://user:open%20sesame@example.com/path").unwrap();

        let auth = extract_url_basic_auth(&mut url).unwrap();

        assert_eq!(auth, ("user".to_string(), Some("open sesame".to_string())));
        assert_eq!(url.as_str(), "https://example.com/path");
    }

    #[test]
    fn http3_client_endpoint_defaults_to_dual_stack_bind() {
        let default_addr = http3_endpoint_local_addr(None);
        assert_eq!(default_addr.ip(), IpAddr::V6(Ipv6Addr::UNSPECIFIED));

        let explicit = http3_endpoint_local_addr(Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert_eq!(explicit.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[tokio::test]
    async fn client_reuses_http1_connections() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let url = Url::parse(&format!("http://{peer_addr}")).unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let server = {
            let accepted = accepted.clone();
            let requests = requests.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        break;
                    };
                    accepted.fetch_add(1, Ordering::SeqCst);
                    let requests = requests.clone();
                    tokio::spawn(async move {
                        while read_http1_headers(&mut stream).await.is_some() {
                            requests.fetch_add(1, Ordering::SeqCst);
                            stream
                                .write_all(
                                    b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: keep-alive\r\n\r\nok",
                                )
                                .await
                                .unwrap();
                        }
                    });
                }
            })
        };

        let client = Client::builder().build().unwrap();
        for path in ["/one", "/two"] {
            let mut response = client
                .request(Method::GET, url.join(path).unwrap())
                .send()
                .await
                .unwrap();
            assert_eq!(response.remote_addr(), Some(peer_addr));
            while response.chunk().await.unwrap().is_some() {}
        }

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while requests.load(Ordering::SeqCst) < 2 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test]
    async fn client_reuses_http2_connections() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let url = Url::parse(&format!("http://{peer_addr}")).unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let server = {
            let accepted = accepted.clone();
            let requests = requests.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    accepted.fetch_add(1, Ordering::SeqCst);
                    let requests = requests.clone();
                    tokio::spawn(async move {
                        let mut connection = h2::server::handshake(stream).await.unwrap();
                        while let Some(result) = connection.accept().await {
                            let (request, mut respond) = result.unwrap();
                            requests.fetch_add(1, Ordering::SeqCst);
                            tokio::spawn(async move {
                                let mut body = request.into_body();
                                while let Some(chunk) = body.data().await {
                                    chunk.unwrap();
                                }
                                let response = http::Response::builder()
                                    .status(http::StatusCode::OK)
                                    .body(())
                                    .unwrap();
                                let mut stream = respond.send_response(response, false).unwrap();
                                stream.send_data(Bytes::from_static(b"ok"), true).unwrap();
                            });
                        }
                    });
                }
            })
        };

        let client = Client::builder().http2_prior_knowledge().build().unwrap();
        for path in ["/one", "/two"] {
            let mut response = client
                .request(Method::GET, url.join(path).unwrap())
                .send()
                .await
                .unwrap();
            assert_eq!(response.remote_addr(), Some(peer_addr));
            while response.chunk().await.unwrap().is_some() {}
        }

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while requests.load(Ordering::SeqCst) < 2 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test]
    async fn h3_upload_task_aborts_when_dropped() {
        struct NotifyOnDrop(Option<tokio::sync::oneshot::Sender<()>>);

        impl Drop for NotifyOnDrop {
            fn drop(&mut self) {
                if let Some(tx) = self.0.take() {
                    let _ = tx.send(());
                }
            }
        }

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        let task = H3UploadTask::new(tokio::spawn(async move {
            let _notify = NotifyOnDrop(Some(dropped_tx));
            let _ = started_tx.send(());
            std::future::pending::<Result<(), Error>>().await
        }));

        started_rx.await.unwrap();
        drop(task);

        tokio::time::timeout(std::time::Duration::from_secs(1), dropped_rx)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn proxy_selection_prefers_scheme_specific_proxy_before_all_proxy() {
        let config = Client::builder()
            .proxy(Proxy::http("http://http-proxy.example:8080").unwrap())
            .proxy(Proxy::all("http://all-proxy.example:8080").unwrap())
            .config;
        let url = Url::parse("http://example.com/").unwrap();

        let proxy = proxy_for_config(&config, &url).unwrap();

        assert_eq!(proxy.url, "http://http-proxy.example:8080");
    }

    #[test]
    fn plain_http_proxy_auth_is_added_to_request_headers() {
        let client = Client::builder()
            .proxy(Proxy::all("http://user:pass@proxy.example:8080").unwrap())
            .build()
            .unwrap();
        let url = Url::parse("http://example.com/").unwrap();
        let mut headers = HeaderMap::new();

        client
            .apply_proxy_authorization(&url, &mut headers)
            .unwrap();

        assert_eq!(
            headers
                .get(PROXY_AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            Some("Basic dXNlcjpwYXNz")
        );
    }

    async fn read_http1_headers(stream: &mut tokio::net::TcpStream) -> Option<Vec<u8>> {
        let mut raw = Vec::new();
        let mut buf = [0_u8; 1024];
        loop {
            let n = stream.read(&mut buf).await.ok()?;
            if n == 0 {
                return None;
            }
            raw.extend_from_slice(&buf[..n]);
            if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                return Some(raw);
            }
        }
    }
}
