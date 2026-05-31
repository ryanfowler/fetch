#![allow(dead_code)]

use std::sync::Arc;

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, HOST, HeaderMap, HeaderValue};
use http::{Method, Request, StatusCode, Uri, Version};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;
use url::Url;

use crate::duration::TimeoutBudget;
use crate::error::FetchError;

#[derive(Debug)]
pub(crate) struct BufferedResponse {
    pub(crate) status: StatusCode,
    pub(crate) version: Version,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Bytes,
}

pub(crate) struct StreamingResponse {
    pub(crate) status: StatusCode,
    pub(crate) version: Version,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Incoming,
}

#[derive(Clone)]
pub(crate) enum SharedHttpClient {
    Http1(SharedHttp1Client),
    Http2(SharedHttp2Client),
}

impl SharedHttpClient {
    pub(crate) async fn send_buffered(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<BufferedResponse, FetchError> {
        match self {
            Self::Http1(client) => client.send_buffered(method, url, headers, body).await,
            Self::Http2(client) => client.send_buffered(method, url, headers, body).await,
        }
    }

    pub(crate) async fn send_buffered_with_limit(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Bytes,
        max_body_bytes: usize,
        limit_error: &'static str,
    ) -> Result<BufferedResponse, FetchError> {
        match self {
            Self::Http1(client) => {
                client
                    .send_buffered_with_limit(
                        method,
                        url,
                        headers,
                        body,
                        max_body_bytes,
                        limit_error,
                    )
                    .await
            }
            Self::Http2(client) => {
                client
                    .send_buffered_with_limit(
                        method,
                        url,
                        headers,
                        body,
                        max_body_bytes,
                        limit_error,
                    )
                    .await
            }
        }
    }
}

#[derive(Clone)]
pub(crate) struct SharedHttp1Client {
    sender: Arc<Mutex<http1::SendRequest<Full<Bytes>>>>,
}

impl SharedHttp1Client {
    pub(crate) async fn send_buffered(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<BufferedResponse, FetchError> {
        let mut sender = self.sender.lock().await;
        send_buffered_http1_with_sender(&mut sender, method, url, headers, body, None).await
    }

    pub(crate) async fn send_buffered_with_limit(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Bytes,
        max_body_bytes: usize,
        limit_error: &'static str,
    ) -> Result<BufferedResponse, FetchError> {
        let mut sender = self.sender.lock().await;
        send_buffered_http1_with_sender(
            &mut sender,
            method,
            url,
            headers,
            body,
            Some((max_body_bytes, limit_error)),
        )
        .await
    }

    pub(crate) async fn try_send_buffered(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<Option<BufferedResponse>, FetchError> {
        let Ok(mut sender) = self.sender.try_lock() else {
            return Ok(None);
        };
        send_buffered_http1_with_sender(&mut sender, method, url, headers, body, None)
            .await
            .map(Some)
    }

    pub(crate) async fn try_send_buffered_with_limit(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Bytes,
        max_body_bytes: usize,
        limit_error: &'static str,
    ) -> Result<Option<BufferedResponse>, FetchError> {
        let Ok(mut sender) = self.sender.try_lock() else {
            return Ok(None);
        };
        send_buffered_http1_with_sender(
            &mut sender,
            method,
            url,
            headers,
            body,
            Some((max_body_bytes, limit_error)),
        )
        .await
        .map(Some)
    }
}

async fn send_buffered_http1_with_sender(
    sender: &mut http1::SendRequest<Full<Bytes>>,
    method: Method,
    url: Url,
    mut headers: HeaderMap,
    body: Bytes,
    body_limit: Option<(usize, &'static str)>,
) -> Result<BufferedResponse, FetchError> {
    ensure_http1_url(&url)?;
    apply_host_header(&url, &mut headers)?;
    if !body.is_empty() && !headers.contains_key(CONTENT_LENGTH) {
        headers.insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&body.len().to_string())
                .expect("content length is a valid header value"),
        );
    }
    let request = build_request(method, &url, headers, body)?;
    sender
        .ready()
        .await
        .map_err(|err| FetchError::Runtime(format!("http1 ready: {err}")))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|err| FetchError::Runtime(format!("http1 request: {err}")))?;
    streaming_response(response)
        .into_buffered_with_limit(body_limit)
        .await
}

#[derive(Clone)]
pub(crate) struct SharedHttp2Client {
    sender: http2::SendRequest<Full<Bytes>>,
}

impl SharedHttp2Client {
    pub(crate) async fn send_buffered(
        &self,
        method: Method,
        url: Url,
        mut headers: HeaderMap,
        body: Bytes,
    ) -> Result<BufferedResponse, FetchError> {
        ensure_http1_url(&url)?;
        apply_host_header(&url, &mut headers)?;
        if !body.is_empty() && !headers.contains_key(CONTENT_LENGTH) {
            headers.insert(
                CONTENT_LENGTH,
                HeaderValue::from_str(&body.len().to_string())
                    .expect("content length is a valid header value"),
            );
        }
        let request =
            build_request_with_uri(method, absolute_uri(&url)?, Version::HTTP_2, headers, body)?;
        let mut sender = self.sender.clone();
        sender
            .ready()
            .await
            .map_err(|err| FetchError::Runtime(format!("http2 ready: {err}")))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|err| FetchError::Runtime(format!("http2 request: {err}")))?;
        streaming_response(response).into_buffered().await
    }

    pub(crate) async fn send_buffered_with_limit(
        &self,
        method: Method,
        url: Url,
        mut headers: HeaderMap,
        body: Bytes,
        max_body_bytes: usize,
        limit_error: &'static str,
    ) -> Result<BufferedResponse, FetchError> {
        ensure_http1_url(&url)?;
        apply_host_header(&url, &mut headers)?;
        if !body.is_empty() && !headers.contains_key(CONTENT_LENGTH) {
            headers.insert(
                CONTENT_LENGTH,
                HeaderValue::from_str(&body.len().to_string())
                    .expect("content length is a valid header value"),
            );
        }
        let request =
            build_request_with_uri(method, absolute_uri(&url)?, Version::HTTP_2, headers, body)?;
        let mut sender = self.sender.clone();
        sender
            .ready()
            .await
            .map_err(|err| FetchError::Runtime(format!("http2 ready: {err}")))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|err| FetchError::Runtime(format!("http2 request: {err}")))?;
        streaming_response(response)
            .into_buffered_with_limit(Some((max_body_bytes, limit_error)))
            .await
    }
}

pub(crate) async fn connect_shared_http2(
    url: &Url,
    dns_server: Option<&str>,
    timeout: TimeoutBudget,
    tls_config: Option<rustls::ClientConfig>,
) -> Result<Option<SharedHttp2Client>, FetchError> {
    if url.scheme() != "https" {
        return Ok(None);
    }
    match connect_shared_http(url, dns_server, timeout, tls_config).await? {
        SharedHttpClient::Http2(client) => Ok(Some(client)),
        SharedHttpClient::Http1(_) => Ok(None),
    }
}

pub(crate) async fn connect_shared_http(
    url: &Url,
    dns_server: Option<&str>,
    timeout: TimeoutBudget,
    tls_config: Option<rustls::ClientConfig>,
) -> Result<SharedHttpClient, FetchError> {
    ensure_http1_url(url)?;

    let stream = crate::net::connect_tcp(url, dns_server, timeout).await?;

    if url.scheme() == "https" {
        let host = url
            .host_str()
            .ok_or_else(|| FetchError::Message("URL host is required".to_string()))?;
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| FetchError::Message(format!("invalid server name '{host}'")))?;
        let mut config = tls_config.unwrap_or_else(default_tls_config);
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let stream = timeout
            .run(async {
                TlsConnector::from(Arc::new(config))
                    .connect(server_name, stream)
                    .await
                    .map_err(|err| FetchError::Runtime(format!("tls: {err}")))
            })
            .await?;
        let negotiated = {
            let (_, conn) = stream.get_ref();
            conn.alpn_protocol().map(|protocol| protocol.to_vec())
        };
        match negotiated.as_deref() {
            Some(b"h2") => return shared_http2(TokioIo::new(stream)).await,
            Some(b"http/1.1") | None => return shared_http1(TokioIo::new(stream)).await,
            Some(protocol) => {
                return Err(FetchError::Runtime(format!(
                    "unsupported ALPN protocol: {}",
                    String::from_utf8_lossy(protocol)
                )));
            }
        }
    }

    shared_http1(TokioIo::new(stream)).await
}

pub(crate) async fn send_buffered_http1(
    method: Method,
    url: Url,
    headers: HeaderMap,
    body: Bytes,
    dns_server: Option<&str>,
    timeout: TimeoutBudget,
    tls_config: Option<rustls::ClientConfig>,
) -> Result<BufferedResponse, FetchError> {
    send_http1(method, url, headers, body, dns_server, timeout, tls_config)
        .await?
        .into_buffered()
        .await
}

pub(crate) async fn send_http1(
    method: Method,
    url: Url,
    mut headers: HeaderMap,
    body: Bytes,
    dns_server: Option<&str>,
    timeout: TimeoutBudget,
    tls_config: Option<rustls::ClientConfig>,
) -> Result<StreamingResponse, FetchError> {
    ensure_http1_url(&url)?;
    apply_host_header(&url, &mut headers)?;
    if !body.is_empty() && !headers.contains_key(CONTENT_LENGTH) {
        headers.insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&body.len().to_string())
                .expect("content length is a valid header value"),
        );
    }

    let stream = crate::net::connect_tcp(&url, dns_server, timeout).await?;
    let request = build_request(method, &url, headers, body)?;
    let response = if url.scheme() == "https" {
        let host = url
            .host_str()
            .ok_or_else(|| FetchError::Message("URL host is required".to_string()))?;
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| FetchError::Message(format!("invalid server name '{host}'")))?;
        let mut config = tls_config.unwrap_or_else(default_tls_config);
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let stream = timeout
            .run(async {
                TlsConnector::from(Arc::new(config))
                    .connect(server_name, stream)
                    .await
                    .map_err(|err| FetchError::Runtime(format!("tls: {err}")))
            })
            .await?;
        send_hyper_http1(TokioIo::new(stream), request).await?
    } else {
        send_hyper_http1(TokioIo::new(stream), request).await?
    };
    Ok(streaming_response(response))
}

pub(crate) async fn send_buffered_http2(
    method: Method,
    url: Url,
    mut headers: HeaderMap,
    body: Bytes,
    dns_server: Option<&str>,
    timeout: TimeoutBudget,
    tls_config: Option<rustls::ClientConfig>,
) -> Result<BufferedResponse, FetchError> {
    ensure_http1_url(&url)?;
    apply_host_header(&url, &mut headers)?;
    if !body.is_empty() && !headers.contains_key(CONTENT_LENGTH) {
        headers.insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&body.len().to_string())
                .expect("content length is a valid header value"),
        );
    }

    let stream = crate::net::connect_tcp(&url, dns_server, timeout).await?;
    let request =
        build_request_with_uri(method, absolute_uri(&url)?, Version::HTTP_2, headers, body)?;
    let response = if url.scheme() == "https" {
        let host = url
            .host_str()
            .ok_or_else(|| FetchError::Message("URL host is required".to_string()))?;
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| FetchError::Message(format!("invalid server name '{host}'")))?;
        let mut config = tls_config.unwrap_or_else(default_tls_config);
        config.alpn_protocols = vec![b"h2".to_vec()];
        let stream = timeout
            .run(async {
                TlsConnector::from(Arc::new(config))
                    .connect(server_name, stream)
                    .await
                    .map_err(|err| FetchError::Runtime(format!("tls: {err}")))
            })
            .await?;
        send_hyper_http2(TokioIo::new(stream), request).await?
    } else {
        send_hyper_http2(TokioIo::new(stream), request).await?
    };
    streaming_response(response).into_buffered().await
}

fn ensure_http1_url(url: &Url) -> Result<(), FetchError> {
    match url.scheme() {
        "http" | "https" => Ok(()),
        scheme => Err(FetchError::Message(format!(
            "unsupported url scheme: {scheme}"
        ))),
    }
}

fn default_tls_config() -> rustls::ClientConfig {
    crate::tls::rustls_platform_client_config().expect("default rustls client config is valid")
}

fn build_request(
    method: Method,
    url: &Url,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Request<Full<Bytes>>, FetchError> {
    build_request_with_uri(
        method,
        origin_form_uri(url)?,
        Version::HTTP_11,
        headers,
        body,
    )
}

fn build_request_with_uri(
    method: Method,
    uri: Uri,
    version: Version,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Request<Full<Bytes>>, FetchError> {
    let mut builder = Request::builder().method(method).uri(uri).version(version);
    *builder
        .headers_mut()
        .expect("request builder has no error before headers") = headers;
    builder
        .body(Full::new(body))
        .map_err(|err| FetchError::Message(err.to_string()))
}

fn absolute_uri(url: &Url) -> Result<Uri, FetchError> {
    url.as_str()
        .parse::<Uri>()
        .map_err(|err| FetchError::Message(format!("invalid request URI: {err}")))
}

fn origin_form_uri(url: &Url) -> Result<Uri, FetchError> {
    let mut target = if url.path().is_empty() {
        "/".to_string()
    } else {
        url.path().to_string()
    };
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }
    target
        .parse::<Uri>()
        .map_err(|err| FetchError::Message(format!("invalid request target: {err}")))
}

fn apply_host_header(url: &Url, headers: &mut HeaderMap) -> Result<(), FetchError> {
    if headers.contains_key(HOST) {
        return Ok(());
    }
    let host = crate::net::http_host_header_value(url)?;
    headers.insert(
        HOST,
        HeaderValue::from_str(&host)
            .map_err(|err| FetchError::Message(format!("invalid host header: {err}")))?,
    );
    Ok(())
}

async fn send_hyper_http1<T>(
    stream: TokioIo<T>,
    request: Request<Full<Bytes>>,
) -> Result<http::Response<Incoming>, FetchError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let (mut sender, connection) = http1::handshake(stream)
        .await
        .map_err(|err| FetchError::Runtime(format!("http1 handshake: {err}")))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender
        .send_request(request)
        .await
        .map_err(|err| FetchError::Runtime(format!("http1 request: {err}")))
}

async fn send_hyper_http2<T>(
    stream: TokioIo<T>,
    request: Request<Full<Bytes>>,
) -> Result<http::Response<Incoming>, FetchError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let (mut sender, connection) = http2::handshake(TokioExecutor::new(), stream)
        .await
        .map_err(|err| FetchError::Runtime(format!("http2 handshake: {err}")))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender
        .ready()
        .await
        .map_err(|err| FetchError::Runtime(format!("http2 ready: {err}")))?;
    sender
        .send_request(request)
        .await
        .map_err(|err| FetchError::Runtime(format!("http2 request: {err}")))
}

async fn shared_http1<T>(stream: TokioIo<T>) -> Result<SharedHttpClient, FetchError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let (sender, connection) = http1::handshake(stream)
        .await
        .map_err(|err| FetchError::Runtime(format!("http1 handshake: {err}")))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(SharedHttpClient::Http1(SharedHttp1Client {
        sender: Arc::new(Mutex::new(sender)),
    }))
}

async fn shared_http2<T>(stream: TokioIo<T>) -> Result<SharedHttpClient, FetchError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let (sender, connection) = http2::handshake(TokioExecutor::new(), stream)
        .await
        .map_err(|err| FetchError::Runtime(format!("http2 handshake: {err}")))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(SharedHttpClient::Http2(SharedHttp2Client { sender }))
}

fn streaming_response(response: http::Response<Incoming>) -> StreamingResponse {
    let (parts, body) = response.into_parts();
    StreamingResponse {
        status: parts.status,
        version: parts.version,
        headers: parts.headers,
        body,
    }
}

impl StreamingResponse {
    pub(crate) async fn into_buffered(self) -> Result<BufferedResponse, FetchError> {
        self.into_buffered_with_limit(None).await
    }

    async fn into_buffered_with_limit(
        self,
        body_limit: Option<(usize, &'static str)>,
    ) -> Result<BufferedResponse, FetchError> {
        let body = if let Some((max_body_bytes, limit_error)) = body_limit {
            Limited::new(self.body, max_body_bytes)
                .collect()
                .await
                .map_err(|err| {
                    if err.downcast_ref::<LengthLimitError>().is_some() {
                        FetchError::Message(limit_error.to_string())
                    } else {
                        FetchError::Runtime(format!("response body error: {err}"))
                    }
                })?
                .to_bytes()
        } else {
            self.body
                .collect()
                .await
                .map_err(|err| FetchError::Runtime(format!("response body error: {err}")))?
                .to_bytes()
        };
        Ok(BufferedResponse {
            status: self.status,
            version: self.version,
            headers: self.headers,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn sends_plain_http1_request() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!(
            "http://{}/path?x=1",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut raw = Vec::new();
            let mut buf = [0_u8; 1024];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                raw.extend_from_slice(&buf[..n]);
                if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            String::from_utf8(raw).unwrap()
        });

        let response = send_buffered_http1(
            Method::GET,
            url,
            HeaderMap::new(),
            Bytes::new(),
            None,
            TimeoutBudget::new(Some(std::time::Duration::from_secs(5))),
            None,
        )
        .await
        .unwrap();

        let request = server.await.unwrap();
        assert!(request.starts_with("GET /path?x=1 HTTP/1.1\r\n"));
        assert_eq!(response.status, StatusCode::CREATED);
        assert_eq!(response.body, Bytes::from_static(b"ok"));
    }

    #[tokio::test]
    async fn sends_plain_http2_request() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}/h2?x=1", listener.local_addr().unwrap())).unwrap();
        let (uri_tx, uri_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(stream).await.unwrap();
            if let Some(result) = connection.accept().await {
                let (request, respond) = result.unwrap();
                tokio::spawn(async move {
                    handle_h2_request(request, respond, uri_tx).await;
                });
            }
            while connection.accept().await.is_some() {}
        });

        let response = send_buffered_http2(
            Method::GET,
            url.clone(),
            HeaderMap::new(),
            Bytes::new(),
            None,
            TimeoutBudget::new(Some(std::time::Duration::from_secs(5))),
            None,
        )
        .await
        .unwrap();

        let request_uri = uri_rx.await.unwrap();
        assert_eq!(request_uri, url.as_str());
        assert_eq!(response.status, StatusCode::ACCEPTED);
        assert_eq!(response.body, Bytes::from_static(b"h2"));
        server.await.unwrap();
    }

    async fn handle_h2_request(
        request: http::Request<h2::RecvStream>,
        mut respond: h2::server::SendResponse<Bytes>,
        uri_tx: tokio::sync::oneshot::Sender<String>,
    ) {
        let uri = request.uri().to_string();
        let mut body = request.into_body();
        while let Some(chunk) = body.data().await {
            chunk.unwrap();
        }
        let _ = uri_tx.send(uri);
        let response = http::Response::builder()
            .status(StatusCode::ACCEPTED)
            .body(())
            .unwrap();
        let mut stream = respond.send_response(response, false).unwrap();
        stream.send_data(Bytes::from_static(b"h2"), true).unwrap();
    }
}
