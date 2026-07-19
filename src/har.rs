use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use base64::Engine;
use http::{HeaderMap, Method, Version};
use serde::Serialize;
use url::Url;

use crate::core;
use crate::error::FetchError;
use crate::output::PreparedOutput;
use crate::timing::ResponseTiming;

pub(crate) const CAPTURE_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Clone, Default)]
pub(crate) struct Capture(Arc<Mutex<CaptureState>>);

#[derive(Default)]
struct CaptureState {
    bytes: Vec<u8>,
    size: i64,
    truncated: bool,
    receive: Duration,
}

impl Capture {
    pub(crate) fn push(&self, bytes: &[u8]) {
        let Ok(mut state) = self.0.lock() else { return };
        state.size = state
            .size
            .saturating_add(i64::try_from(bytes.len()).unwrap_or(i64::MAX));
        let remaining = CAPTURE_LIMIT.saturating_sub(state.bytes.len());
        state
            .bytes
            .extend_from_slice(&bytes[..bytes.len().min(remaining)]);
        state.truncated |= bytes.len() > remaining;
    }

    pub(crate) fn add_receive_time(&self, started: Instant) {
        if let Ok(mut state) = self.0.lock() {
            state.receive = state.receive.saturating_add(started.elapsed());
        }
    }

    #[cfg(test)]
    pub(crate) fn receive_time(&self) -> Duration {
        self.0.lock().map(|state| state.receive).unwrap_or_default()
    }

    fn snapshot(&self) -> CaptureSnapshot {
        let state = self.0.lock().expect("HAR capture lock poisoned");
        CaptureSnapshot {
            bytes: state.bytes.clone(),
            size: state.size,
            truncated: state.truncated,
            receive: state.receive,
        }
    }
}

struct CaptureSnapshot {
    bytes: Vec<u8>,
    size: i64,
    truncated: bool,
    receive: Duration,
}

#[derive(Clone)]
pub(crate) struct Recorder(Arc<Mutex<RecorderState>>);

struct RecorderState {
    request: Option<RequestCapture>,
    response_body: Capture,
}

struct RequestCapture {
    method: Method,
    url: Url,
    headers: HeaderMap,
    body: Capture,
}

pub(crate) struct ResponseMeta {
    pub status: u16,
    pub status_text: String,
    pub headers: HeaderMap,
    pub version: Version,
    pub redirect_url: String,
    pub remote_ip: Option<String>,
    pub content_type: String,
    pub timing: Option<ResponseTiming>,
    pub started: SystemTime,
}

impl Recorder {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Mutex::new(RecorderState {
            request: None,
            response_body: Capture::default(),
        })))
    }

    pub(crate) fn observe_request(&self, method: Method, url: Url, headers: HeaderMap) -> Capture {
        let body = Capture::default();
        let mut state = self.0.lock().expect("HAR recorder lock poisoned");
        state.request = Some(RequestCapture {
            method,
            url,
            headers,
            body: body.clone(),
        });
        body
    }

    pub(crate) fn response_capture(&self) -> Capture {
        self.0
            .lock()
            .expect("HAR recorder lock poisoned")
            .response_body
            .clone()
    }

    pub(crate) fn serialize(&self, meta: ResponseMeta) -> Result<Vec<u8>, FetchError> {
        let state = self.0.lock().expect("HAR recorder lock poisoned");
        let request = state
            .request
            .as_ref()
            .ok_or_else(|| FetchError::Message("unable to capture final request for HAR".into()))?;
        let request_body = request.body.snapshot();
        let response_body = state.response_body.snapshot();
        let request_headers = header_entries(&request.headers);
        let response_headers = header_entries(&meta.headers);
        let query = request
            .url
            .query_pairs()
            .map(|(name, value)| NameValue {
                name: name.into_owned(),
                value: value.into_owned(),
            })
            .collect();
        let post_data = (request_body.size > 0).then(|| PostData {
            mime_type: content_type(&request.headers),
            text: body_text(&request_body),
            params: Vec::new(),
            comment: truncation_comment(&request_body),
        });
        let timing = meta.timing;
        let receive = duration_ms(response_body.receive);
        let dns = timing
            .and_then(|value| value.dns)
            .map(duration_ms)
            .unwrap_or(-1.0);
        let connect = timing
            .and_then(|value| value.tcp.or(value.quic))
            .map(duration_ms)
            .unwrap_or(-1.0);
        let ssl = timing
            .and_then(|value| value.tls)
            .map(duration_ms)
            .unwrap_or(-1.0);
        let wait = timing
            .map(|value| duration_ms(value.ttfb.saturating_sub(value.dns.unwrap_or_default())))
            .unwrap_or(-1.0);
        let total_time = [dns, connect, ssl, wait, receive]
            .into_iter()
            .filter(|value| *value >= 0.0)
            .sum();
        let doc = Har {
            log: Log {
                version: "1.2",
                creator: Creator {
                    name: "fetch",
                    version: core::version(),
                },
                entries: vec![Entry {
                    started_date_time: rfc3339(meta.started),
                    time: total_time,
                    request: HarRequest {
                        method: request.method.as_str(),
                        url: request.url.as_str(),
                        http_version: http_version(meta.version),
                        cookies: Vec::new(),
                        headers: request_headers,
                        query_string: query,
                        post_data,
                        headers_size: -1,
                        body_size: request_body.size,
                    },
                    response: HarResponse {
                        status: meta.status,
                        status_text: meta.status_text,
                        http_version: http_version(meta.version),
                        cookies: Vec::new(),
                        headers: response_headers,
                        content: Content {
                            size: response_body.size,
                            mime_type: meta.content_type,
                            text: body_text(&response_body),
                            encoding: body_encoding(&response_body),
                            comment: truncation_comment(&response_body),
                        },
                        redirect_url: meta.redirect_url,
                        headers_size: -1,
                        body_size: response_body.size,
                    },
                    cache: Empty {},
                    timings: Timings {
                        blocked: -1.0,
                        dns,
                        connect,
                        send: -1.0,
                        wait,
                        receive,
                        ssl,
                    },
                    server_ip_address: meta.remote_ip,
                    comment: "fetch records only the final HTTP exchange",
                }],
            },
        };
        serde_json::to_vec_pretty(&doc).map_err(|err| FetchError::Message(err.to_string()))
    }
}

pub(crate) struct Destination(PreparedOutput);

impl Destination {
    pub(crate) fn reserve(path: &str, clobber: bool) -> Result<Self, FetchError> {
        PreparedOutput::create(path, clobber)
            .map(Self)
            .map_err(|err| FetchError::Message(err.to_string()))
    }

    pub(crate) fn commit(self, bytes: &[u8]) -> Result<(), FetchError> {
        self.0
            .commit(bytes)
            .map_err(|err| FetchError::Message(err.to_string()))
    }
}

#[derive(Serialize)]
struct Har<'a> {
    log: Log<'a>,
}
#[derive(Serialize)]
struct Log<'a> {
    version: &'a str,
    creator: Creator<'a>,
    entries: Vec<Entry<'a>>,
}
#[derive(Serialize)]
struct Creator<'a> {
    name: &'a str,
    version: &'a str,
}
#[derive(Serialize)]
struct Entry<'a> {
    #[serde(rename = "startedDateTime")]
    started_date_time: String,
    time: f64,
    request: HarRequest<'a>,
    response: HarResponse,
    cache: Empty,
    timings: Timings,
    #[serde(rename = "serverIPAddress", skip_serializing_if = "Option::is_none")]
    server_ip_address: Option<String>,
    comment: &'a str,
}
#[derive(Serialize)]
struct HarRequest<'a> {
    method: &'a str,
    url: &'a str,
    #[serde(rename = "httpVersion")]
    http_version: &'static str,
    cookies: Vec<Empty>,
    headers: Vec<NameValue>,
    #[serde(rename = "queryString")]
    query_string: Vec<NameValue>,
    #[serde(rename = "postData", skip_serializing_if = "Option::is_none")]
    post_data: Option<PostData>,
    #[serde(rename = "headersSize")]
    headers_size: i64,
    #[serde(rename = "bodySize")]
    body_size: i64,
}
#[derive(Serialize)]
struct HarResponse {
    status: u16,
    #[serde(rename = "statusText")]
    status_text: String,
    #[serde(rename = "httpVersion")]
    http_version: &'static str,
    cookies: Vec<Empty>,
    headers: Vec<NameValue>,
    content: Content,
    #[serde(rename = "redirectURL")]
    redirect_url: String,
    #[serde(rename = "headersSize")]
    headers_size: i64,
    #[serde(rename = "bodySize")]
    body_size: i64,
}
#[derive(Serialize)]
struct PostData {
    #[serde(rename = "mimeType")]
    mime_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    params: Vec<Empty>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<&'static str>,
}
#[derive(Serialize)]
struct Content {
    size: i64,
    #[serde(rename = "mimeType")]
    mime_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    encoding: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<&'static str>,
}
#[derive(Serialize)]
struct NameValue {
    name: String,
    value: String,
}
#[derive(Serialize)]
struct Timings {
    blocked: f64,
    dns: f64,
    connect: f64,
    send: f64,
    wait: f64,
    receive: f64,
    ssl: f64,
}
#[derive(Serialize)]
struct Empty {}

fn header_entries(headers: &HeaderMap) -> Vec<NameValue> {
    headers
        .iter()
        .map(|(name, value)| NameValue {
            name: name.as_str().to_string(),
            value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
        })
        .collect()
}
fn content_type(headers: &HeaderMap) -> String {
    headers
        .get(http::header::CONTENT_TYPE)
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .unwrap_or_default()
}
fn body_text(body: &CaptureSnapshot) -> Option<String> {
    if body.truncated {
        None
    } else if let Ok(text) = std::str::from_utf8(&body.bytes) {
        Some(text.to_string())
    } else {
        Some(base64::engine::general_purpose::STANDARD.encode(&body.bytes))
    }
}
fn body_encoding(body: &CaptureSnapshot) -> Option<&'static str> {
    (!body.truncated && std::str::from_utf8(&body.bytes).is_err()).then_some("base64")
}
fn truncation_comment(body: &CaptureSnapshot) -> Option<&'static str> {
    body.truncated
        .then_some("Body omitted by fetch because it exceeds the 16 MiB HAR capture limit")
}
fn duration_ms(value: Duration) -> f64 {
    value.as_secs_f64() * 1000.0
}
fn http_version(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "HTTP",
    }
}
fn rfc3339(value: SystemTime) -> String {
    let dt = time::OffsetDateTime::from(value);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
        dt.millisecond()
    )
}
