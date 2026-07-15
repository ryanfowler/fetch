use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes};
use futures_util::{Stream, TryStreamExt};
use http::Version;
use http::header::{CONTENT_LENGTH, HeaderMap};
use http_body::Frame;
use http_body_util::{BodyExt, Full, StreamBody, combinators::UnsyncBoxBody};
use hyper::body::Incoming;
use tokio::task::JoinHandle;
use tokio_util::io::ReaderStream;
use url::Url;

use super::{Error, ErrorKind};
#[cfg(test)]
use crate::duration::request_timeout_message;

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

    pub(super) fn with_message(timeout: Duration, timeout_message: String) -> Self {
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

    pub(super) fn boxed<B>(body: B) -> Self
    where
        B: http_body::Body<Data = Bytes, Error = Error> + Send + 'static,
    {
        Self {
            inner: BodyExt::boxed_unsync(body),
        }
    }

    pub(super) fn map_incoming(body: Incoming) -> Self {
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

#[derive(Clone, Copy, Debug)]
pub(super) struct PeerAddr(pub(super) SocketAddr);

pub(crate) struct Response {
    url: Url,
    status: http::StatusCode,
    version: Version,
    headers: HeaderMap,
    body: Body,
    body_deadline: Option<BodyDeadline>,
    remote_addr: Option<SocketAddr>,
    _client_keepalive: Option<super::client::Client>,
}

impl Response {
    pub(super) fn from_hyper(
        url: Url,
        response: http::Response<Incoming>,
        body_deadline: Option<BodyDeadline>,
    ) -> Self {
        Self::from_hyper_with_remote(url, response, body_deadline, None)
    }

    pub(super) fn from_hyper_with_remote(
        url: Url,
        response: http::Response<Incoming>,
        body_deadline: Option<BodyDeadline>,
        fallback_remote_addr: Option<SocketAddr>,
    ) -> Self {
        let (parts, body) = response.into_parts();
        let remote_addr = parts
            .extensions
            .get::<PeerAddr>()
            .map(|addr| addr.0)
            .or(fallback_remote_addr);
        Self {
            url,
            status: parts.status,
            version: parts.version,
            headers: parts.headers,
            body: Body::map_incoming(body),
            body_deadline,
            remote_addr,
            _client_keepalive: None,
        }
    }

    pub(super) fn from_h3<S, O>(
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
            _client_keepalive: None,
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

    pub(in crate::http) fn keep_client_alive(&mut self, client: super::client::Client) {
        self._client_keepalive = Some(client);
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

pub(super) struct H3UploadTask {
    handle: JoinHandle<Result<(), Error>>,
}

impl H3UploadTask {
    pub(super) fn new(handle: JoinHandle<Result<(), Error>>) -> Self {
        Self { handle }
    }

    pub(super) fn is_finished(&self) -> bool {
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

pub(super) async fn send_h3_body<S>(
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
