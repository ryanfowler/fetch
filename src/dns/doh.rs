use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use bytes::Bytes;
use http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, USER_AGENT};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use serde::Deserialize;
use url::Url;

use crate::core;
use crate::dns::util::dns_query_id;
use crate::dns::wire;
use crate::duration::TimeoutBudget;
use crate::error::FetchError;
use crate::http::transport::{Client, Response};

const DNS_TYPE_A: u16 = wire::TYPE_A;
const DNS_TYPE_AAAA: u16 = wire::TYPE_AAAA;
const DNS_CLASS_IN: u16 = wire::CLASS_IN;
const DOH_RESPONSE_MAX_BYTES: usize = 1024 * 1024;
const DOH_RESPONSE_LIMIT_ERROR: &str = "DoH response exceeded maximum allowed size of 1 MiB";
const APPLICATION_DNS_MESSAGE: &str = "application/dns-message";
const APPLICATION_DNS_JSON: &str = "application/dns-json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsError(String);

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DnsError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    pub ip: IpAddr,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DohRecord {
    pub(crate) answer_type: u16,
    pub(crate) data: String,
    pub(crate) ttl: Option<u32>,
}

pub(crate) struct DohClient {
    budget: TimeoutBudget,
    client: Client,
}

pub async fn lookup_doh(
    server_url: &Url,
    host: &str,
    timeout: Option<Duration>,
) -> Result<Vec<IpAddr>, DnsError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    let client = client(timeout)?;
    let (a, aaaa) = tokio::join!(
        lookup_doh_type_with_client(&client, server_url, host, "A", DNS_TYPE_A),
        lookup_doh_type_with_client(&client, server_url, host, "AAAA", DNS_TYPE_AAAA)
    );

    let mut addrs = Vec::new();
    if let Ok(records) = &a {
        addrs.extend(records.iter().map(|record| record.ip));
    }
    if let Ok(records) = &aaaa {
        addrs.extend(records.iter().map(|record| record.ip));
    }

    if !addrs.is_empty() {
        return Ok(addrs);
    }
    a?;
    aaaa?;
    Err(DnsError("no such host".to_string()))
}

pub async fn lookup_doh_type(
    server_url: &Url,
    host: &str,
    dns_type: &str,
    answer_type: u16,
    timeout: Option<Duration>,
) -> Result<Vec<DnsRecord>, DnsError> {
    let client = client(timeout)?;
    lookup_doh_type_with_client(&client, server_url, host, dns_type, answer_type).await
}

pub(crate) fn client(timeout: Option<Duration>) -> Result<DohClient, DnsError> {
    client_with_budget(TimeoutBudget::new(timeout))
}

pub(crate) fn client_with_budget(budget: TimeoutBudget) -> Result<DohClient, DnsError> {
    let tls_config =
        crate::tls::rustls_platform_client_config().map_err(|err| DnsError(err.to_string()))?;
    let client = Client::builder()
        .tls_config(tls_config)
        .build()
        .map_err(|err| DnsError(err.to_string()))?;
    Ok(DohClient { budget, client })
}

async fn lookup_doh_type_with_client(
    client: &DohClient,
    server_url: &Url,
    host: &str,
    dns_type: &str,
    answer_type: u16,
) -> Result<Vec<DnsRecord>, DnsError> {
    let records = lookup_doh_records_with_client(client, server_url, host, dns_type).await?;
    ip_records(records, answer_type)
}

pub(crate) async fn lookup_doh_records_with_client(
    client: &DohClient,
    server_url: &Url,
    host: &str,
    dns_type: &str,
) -> Result<Vec<DohRecord>, DnsError> {
    if let Some(query_type) = dns_type_code(dns_type) {
        match lookup_doh_wire_records_with_client(client, server_url, host, query_type).await {
            Ok(records) => return Ok(records),
            Err(WireDohError::Fallback) => {}
            Err(WireDohError::Fatal(err)) => return Err(err),
        }
    }

    lookup_doh_json_records_with_client(client, server_url, host, dns_type).await
}

async fn lookup_doh_wire_records_with_client(
    client: &DohClient,
    server_url: &Url,
    host: &str,
    dns_type: u16,
) -> Result<Vec<DohRecord>, WireDohError> {
    let id = dns_query_id();
    let query = wire::build_query(id, host, dns_type)
        .map_err(|err| WireDohError::Fatal(DnsError(err.to_string())))?;

    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static(APPLICATION_DNS_MESSAGE));
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static(APPLICATION_DNS_MESSAGE),
    );
    headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&query.len().to_string()).expect("DNS query length is valid"),
    );
    headers.insert(
        USER_AGENT,
        HeaderValue::from_str(&core::user_agent()).expect("valid user agent"),
    );
    let response = client
        .post(server_url.clone(), headers, query)
        .await
        .map_err(WireDohError::Fatal)?;

    if !response.status().is_success() {
        let err = doh_status_error(&response);
        return if wire_status_may_support_json(response.status()) {
            Err(WireDohError::Fallback)
        } else {
            Err(WireDohError::Fatal(err))
        };
    }

    if has_json_content_type(&response) {
        return Err(WireDohError::Fallback);
    }

    match doh_records_from_wire_response(response.body(), id) {
        Ok(records) => Ok(records),
        Err(err) if is_dns_message_response(&response) || is_dns_wire_error(&err) => {
            Err(WireDohError::Fatal(err))
        }
        Err(_) => Err(WireDohError::Fallback),
    }
}

async fn lookup_doh_json_records_with_client(
    client: &DohClient,
    server_url: &Url,
    host: &str,
    dns_type: &str,
) -> Result<Vec<DohRecord>, DnsError> {
    let url = doh_query_url(server_url, host, dns_type);

    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static(APPLICATION_DNS_JSON));
    headers.insert(
        USER_AGENT,
        HeaderValue::from_str(&core::user_agent()).expect("valid user agent"),
    );
    let response = client.get(url, headers).await?;

    if !response.status().is_success() {
        return Err(doh_status_error(&response));
    }

    let body = serde_json::from_slice::<DohResponse>(response.body())
        .map_err(|err| DnsError(err.to_string()))?;

    if body.status != 0 {
        let name = rcode_name(body.status);
        if name.is_empty() {
            return Err(DnsError("no such host".to_string()));
        }
        return Err(DnsError(format!("no such host: {name}")));
    }

    Ok(body
        .answer
        .into_iter()
        .map(|answer| DohRecord {
            answer_type: answer.answer_type,
            data: answer.data,
            ttl: answer.ttl,
        })
        .collect())
}

impl DohClient {
    async fn get(&self, url: Url, headers: HeaderMap) -> Result<DohResponseBody, DnsError> {
        self.request(Method::GET, url, headers, None).await
    }

    async fn post(
        &self,
        url: Url,
        headers: HeaderMap,
        body: Vec<u8>,
    ) -> Result<DohResponseBody, DnsError> {
        self.request(Method::POST, url, headers, Some(body)).await
    }

    async fn request(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
    ) -> Result<DohResponseBody, DnsError> {
        self.budget
            .run(async {
                let mut request = self.client.request(method, url).headers(headers);
                if let Some(body) = body {
                    request = request.body(body);
                }
                let response = Box::pin(request.send()).await?;
                buffer_response_with_limit(
                    response,
                    DOH_RESPONSE_MAX_BYTES,
                    DOH_RESPONSE_LIMIT_ERROR,
                )
                .await
            })
            .await
            .map_err(|err| DnsError(err.to_string()))
    }
}

struct DohResponseBody {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl DohResponseBody {
    fn status(&self) -> StatusCode {
        self.status
    }

    fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    fn body(&self) -> &[u8] {
        &self.body
    }
}

async fn buffer_response_with_limit(
    mut response: Response,
    max_body_bytes: usize,
    limit_error: &'static str,
) -> Result<DohResponseBody, FetchError> {
    let status = response.status();
    let headers = response.headers().clone();
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        let Some(new_len) = body.len().checked_add(chunk.len()) else {
            return Err(FetchError::Message(limit_error.to_string()));
        };
        if new_len > max_body_bytes {
            return Err(FetchError::Message(limit_error.to_string()));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(DohResponseBody {
        status,
        headers,
        body: Bytes::from(body),
    })
}

fn ip_records(records: Vec<DohRecord>, answer_type: u16) -> Result<Vec<DnsRecord>, DnsError> {
    let records: Vec<DnsRecord> = records
        .into_iter()
        .filter(|answer| answer.answer_type == answer_type)
        .filter_map(|answer| {
            answer.data.parse::<IpAddr>().ok().map(|ip| DnsRecord {
                ip,
                ttl: answer.ttl,
            })
        })
        .collect();
    if records.is_empty() {
        return Err(DnsError("no such host".to_string()));
    }

    Ok(records)
}

fn doh_records_from_wire_response(
    raw: &[u8],
    expected_id: u16,
) -> Result<Vec<DohRecord>, DnsError> {
    let records =
        wire::parse_response(raw, expected_id).map_err(|err| DnsError(err.to_string()))?;
    let mut out = Vec::new();
    for record in records {
        if record.class != DNS_CLASS_IN {
            continue;
        }
        out.push(DohRecord {
            answer_type: record.typ,
            data: wire_record_data(raw, record)?,
            ttl: Some(record.ttl),
        });
    }
    Ok(out)
}

fn wire_record_data(packet: &[u8], record: wire::ResourceRecord<'_>) -> Result<String, DnsError> {
    let offset = record.data_offset;
    let len = record.data.len();
    let rdata = record.data;
    let value = match (record.typ, len) {
        (DNS_TYPE_A, 4) => IpAddr::from([rdata[0], rdata[1], rdata[2], rdata[3]]).to_string(),
        (DNS_TYPE_AAAA, 16) => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rdata);
            IpAddr::from(octets).to_string()
        }
        (wire::TYPE_CNAME | wire::TYPE_NS, _) => {
            wire::read_name(packet, offset)
                .map_err(|err| DnsError(err.to_string()))?
                .0
        }
        (wire::TYPE_TXT, _) => parse_txt_rdata(rdata),
        (wire::TYPE_MX, 3..) => {
            let pref = wire::read_u16(packet, offset).map_err(|err| DnsError(err.to_string()))?;
            let name = wire::read_name(packet, offset + 2)
                .map_err(|err| DnsError(err.to_string()))?
                .0;
            format!("{pref} {name}")
        }
        (wire::TYPE_SOA, _) => parse_soa_rdata(packet, offset)?,
        (wire::TYPE_SRV, 7..) => {
            let priority =
                wire::read_u16(packet, offset).map_err(|err| DnsError(err.to_string()))?;
            let weight =
                wire::read_u16(packet, offset + 2).map_err(|err| DnsError(err.to_string()))?;
            let port =
                wire::read_u16(packet, offset + 4).map_err(|err| DnsError(err.to_string()))?;
            let target = wire::read_name(packet, offset + 6)
                .map_err(|err| DnsError(err.to_string()))?
                .0;
            format!("{priority} {weight} {port} {target}")
        }
        _ => generic_rdata(rdata),
    };
    Ok(value)
}

fn parse_txt_rdata(raw: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut offset = 0;
    while offset < raw.len() {
        let len = usize::from(raw[offset]);
        offset += 1;
        if offset + len > raw.len() {
            parts.push(String::from_utf8_lossy(&raw[offset - 1..]).into_owned());
            break;
        }
        parts.push(String::from_utf8_lossy(&raw[offset..offset + len]).into_owned());
        offset += len;
    }
    parts.join(" ")
}

fn parse_soa_rdata(packet: &[u8], offset: usize) -> Result<String, DnsError> {
    let (ns, mut next) =
        wire::read_name(packet, offset).map_err(|err| DnsError(err.to_string()))?;
    let (mbox, next_after_mbox) =
        wire::read_name(packet, next).map_err(|err| DnsError(err.to_string()))?;
    next = next_after_mbox;
    let serial = wire::read_u32(packet, next).map_err(|err| DnsError(err.to_string()))?;
    let refresh = wire::read_u32(packet, next + 4).map_err(|err| DnsError(err.to_string()))?;
    let retry = wire::read_u32(packet, next + 8).map_err(|err| DnsError(err.to_string()))?;
    let expire = wire::read_u32(packet, next + 12).map_err(|err| DnsError(err.to_string()))?;
    let min_ttl = wire::read_u32(packet, next + 16).map_err(|err| DnsError(err.to_string()))?;
    Ok(format!(
        "{ns} {mbox} serial={serial} refresh={refresh} retry={retry} expire={expire} minttl={min_ttl}"
    ))
}

fn generic_rdata(raw: &[u8]) -> String {
    format!(r"\# {} {}", raw.len(), hex_encode(raw))
}

fn hex_encode(raw: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(raw.len() * 2);
    for byte in raw {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn doh_status_error(response: &DohResponseBody) -> DnsError {
    let status = response.status();
    if let Ok(err_response) = serde_json::from_slice::<DohErrorResponse>(response.body())
        && let Some(message) = err_response.error.filter(|message| !message.is_empty())
    {
        return DnsError(format!("{}: {message}", status.as_u16()));
    }
    DnsError(format!(
        "{}: {}",
        status.as_u16(),
        String::from_utf8_lossy(response.body())
    ))
}

fn is_dns_message_response(response: &DohResponseBody) -> bool {
    response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| media_type(value).eq_ignore_ascii_case(APPLICATION_DNS_MESSAGE))
}

fn has_json_content_type(response: &DohResponseBody) -> bool {
    response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            let media_type = media_type(value).to_ascii_lowercase();
            media_type.eq_ignore_ascii_case(APPLICATION_DNS_JSON)
                || media_type.eq_ignore_ascii_case("application/json")
                || media_type.ends_with("+json")
        })
}

fn media_type(content_type: &str) -> &str {
    content_type
        .split_once(';')
        .map_or(content_type, |(media_type, _)| media_type)
        .trim()
}

fn wire_status_may_support_json(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::BAD_REQUEST
            | StatusCode::NOT_FOUND
            | StatusCode::METHOD_NOT_ALLOWED
            | StatusCode::NOT_ACCEPTABLE
            | StatusCode::UNSUPPORTED_MEDIA_TYPE
            | StatusCode::NOT_IMPLEMENTED
    )
}

fn is_dns_wire_error(err: &DnsError) -> bool {
    err.0.starts_with("no such host") || err.0 == "DNS response was truncated"
}

fn dns_type_code(dns_type: &str) -> Option<u16> {
    match dns_type {
        "A" => Some(wire::TYPE_A),
        "AAAA" => Some(wire::TYPE_AAAA),
        "CNAME" => Some(wire::TYPE_CNAME),
        "TXT" => Some(wire::TYPE_TXT),
        "MX" => Some(wire::TYPE_MX),
        "NS" => Some(wire::TYPE_NS),
        "SOA" => Some(wire::TYPE_SOA),
        "SRV" => Some(wire::TYPE_SRV),
        "SVCB" => Some(wire::TYPE_SVCB),
        "HTTPS" => Some(wire::TYPE_HTTPS),
        "CAA" => Some(wire::TYPE_CAA),
        _ => dns_type
            .strip_prefix("TYPE")
            .and_then(|value| value.parse::<u16>().ok()),
    }
}

fn doh_query_url(server_url: &Url, host: &str, dns_type: &str) -> Url {
    let mut url = server_url.clone();
    let mut pairs: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(key, _)| key != "name" && key != "type")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    pairs.push(("name".to_string(), host.to_string()));
    pairs.push(("type".to_string(), dns_type.to_string()));
    url.query_pairs_mut().clear().extend_pairs(pairs);
    url
}

enum WireDohError {
    Fallback,
    Fatal(DnsError),
}

fn rcode_name(code: i32) -> &'static str {
    match code {
        0 => "NoError",
        1 => "FormErr",
        2 => "ServFail",
        3 => "NXDomain",
        4 => "NotImp",
        5 => "Refused",
        6 => "YXDomain",
        7 => "YXRRSet",
        8 => "NXRRSet",
        9 => "NotAuth",
        10 => "NotZone",
        11 => "DSOTYPENI",
        16 => "BADSIG",
        17 => "BADKEY",
        18 => "BADTIME",
        19 => "BADMODE",
        20 => "BADNAME",
        21 => "BADALG",
        22 => "BADTRUNC",
        23 => "BADCOOKIE",
        _ => "",
    }
}

#[derive(Debug, Deserialize)]
struct DohResponse {
    #[serde(rename = "Status")]
    status: i32,
    #[serde(rename = "Answer", default)]
    answer: Vec<DohAnswer>,
}

#[derive(Debug, Deserialize)]
struct DohAnswer {
    #[serde(rename = "type")]
    answer_type: u16,
    data: String,
    #[serde(rename = "TTL")]
    ttl: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct DohErrorResponse {
    error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn start_test_server<F>(handler: F) -> (Url, tokio::task::JoinHandle<()>)
    where
        F: Fn(http::Request<String>) -> http::Response<String> + Send + Sync + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = Arc::new(handler);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let handler = handler.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0; 4096];
                    let Ok(n) = stream
                        .readable()
                        .await
                        .and_then(|_| stream.try_read(&mut buf))
                    else {
                        return;
                    };
                    let request = String::from_utf8_lossy(&buf[..n]);
                    let first_line = request.lines().next().unwrap_or_default();
                    let method = first_line.split_whitespace().next().unwrap_or("GET");
                    let path = first_line.split_whitespace().nth(1).unwrap_or("/");
                    if method.eq_ignore_ascii_case("POST") {
                        let _ = stream
                            .write_all(
                                b"HTTP/1.1 415 Unsupported Media Type\r\ncontent-length: 0\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n",
                            )
                            .await;
                        return;
                    }
                    let req = http::Request::builder()
                        .method(method)
                        .uri(path)
                        .body(request.into_owned())
                        .unwrap();
                    let response = handler(req);
                    let (parts, body) = response.into_parts();
                    let status = parts.status.as_u16();
                    let reason = parts.status.canonical_reason().unwrap_or("");
                    let raw = format!(
                        "HTTP/1.1 {status} {reason}\r\ncontent-length: {}\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(raw.as_bytes()).await;
                });
            }
        });
        (
            Url::parse(&format!("http://{addr}/dns-query")).unwrap(),
            task,
        )
    }

    async fn start_delayed_test_server(delay: Duration) -> (Url, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0; 4096];
                    let Ok(n) = stream
                        .readable()
                        .await
                        .and_then(|_| stream.try_read(&mut buf))
                    else {
                        return;
                    };
                    let request = String::from_utf8_lossy(&buf[..n]);
                    let first_line = request.lines().next().unwrap_or_default();
                    let method = first_line.split_whitespace().next().unwrap_or("GET");
                    let path = first_line.split_whitespace().nth(1).unwrap_or("/");
                    if method.eq_ignore_ascii_case("POST") {
                        let _ = stream
                            .write_all(
                                b"HTTP/1.1 415 Unsupported Media Type\r\ncontent-length: 0\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n",
                            )
                            .await;
                        return;
                    }
                    let ty = path
                        .split_once('?')
                        .map(|(_, query)| query)
                        .unwrap_or_default()
                        .split('&')
                        .find_map(|part| part.strip_prefix("type="))
                        .unwrap_or_default();

                    tokio::time::sleep(delay).await;

                    let response = match ty {
                        "A" => http::Response::new(
                            r#"{"Status":0,"Answer":[{"type":1,"data":"127.0.0.1"}]}"#.to_string(),
                        ),
                        "AAAA" => http::Response::new(
                            r#"{"Status":0,"Answer":[{"type":28,"data":"::1"}]}"#.to_string(),
                        ),
                        _ => http::Response::builder()
                            .status(400)
                            .body(r#"{"error":"bad type"}"#.to_string())
                            .unwrap(),
                    };
                    let (parts, body) = response.into_parts();
                    let status = parts.status.as_u16();
                    let reason = parts.status.canonical_reason().unwrap_or("");
                    let raw = format!(
                        "HTTP/1.1 {status} {reason}\r\ncontent-length: {}\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(raw.as_bytes()).await;
                });
            }
        });
        (
            Url::parse(&format!("http://{addr}/dns-query")).unwrap(),
            task,
        )
    }

    async fn start_delayed_415_fallback_server(
        post_delay: Duration,
    ) -> (Url, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let Some(request) = read_wire_test_request(&mut stream).await else {
                    continue;
                };
                if request.method.eq_ignore_ascii_case("POST") {
                    tokio::time::sleep(post_delay).await;
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 415 Unsupported Media Type\r\ncontent-length: 0\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n",
                        )
                        .await;
                    continue;
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
        (
            Url::parse(&format!("http://{addr}/dns-query")).unwrap(),
            task,
        )
    }

    #[derive(Debug)]
    struct WireTestRequest {
        method: String,
        path: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    }

    impl WireTestRequest {
        fn header(&self, name: &str) -> String {
            self.headers
                .get(&name.to_ascii_lowercase())
                .cloned()
                .unwrap_or_default()
        }
    }

    async fn start_wire_test_server<F>(handler: F) -> (Url, tokio::task::JoinHandle<()>)
    where
        F: Fn(WireTestRequest) -> http::Response<Vec<u8>> + Send + Sync + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = Arc::new(handler);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let handler = handler.clone();
                tokio::spawn(async move {
                    let Some(request) = read_wire_test_request(&mut stream).await else {
                        return;
                    };
                    let response = handler(request);
                    let (parts, body) = response.into_parts();
                    let status = parts.status.as_u16();
                    let reason = parts.status.canonical_reason().unwrap_or("");
                    let mut raw = format!(
                        "HTTP/1.1 {status} {reason}\r\ncontent-length: {}\r\nconnection: close\r\n",
                        body.len()
                    )
                    .into_bytes();
                    for (name, value) in &parts.headers {
                        raw.extend_from_slice(name.as_str().as_bytes());
                        raw.extend_from_slice(b": ");
                        raw.extend_from_slice(value.as_bytes());
                        raw.extend_from_slice(b"\r\n");
                    }
                    raw.extend_from_slice(b"\r\n");
                    raw.extend_from_slice(&body);
                    let _ = stream.write_all(&raw).await;
                });
            }
        });
        (
            Url::parse(&format!("http://{addr}/dns-query")).unwrap(),
            task,
        )
    }

    async fn read_wire_test_request(stream: &mut tokio::net::TcpStream) -> Option<WireTestRequest> {
        let mut raw = Vec::new();
        let header_end = loop {
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).await.ok()?;
            if n == 0 {
                return None;
            }
            raw.extend_from_slice(&buf[..n]);
            if let Some(pos) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
                break pos + 4;
            }
        };

        let header_text = String::from_utf8_lossy(&raw[..header_end]);
        let mut lines = header_text.lines();
        let first_line = lines.next()?;
        let mut first = first_line.split_whitespace();
        let method = first.next()?.to_string();
        let path = first.next()?.to_string();
        let mut headers = HashMap::new();
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
            }
        }
        let content_length = headers
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        while raw.len() < header_end + content_length {
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).await.ok()?;
            if n == 0 {
                return None;
            }
            raw.extend_from_slice(&buf[..n]);
        }
        Some(WireTestRequest {
            method,
            path,
            headers,
            body: raw[header_end..header_end + content_length].to_vec(),
        })
    }

    fn test_dns_question(raw: &[u8]) -> Option<(String, u16, usize)> {
        if raw.len() < 12 {
            return None;
        }
        let mut offset = 12;
        let mut labels = Vec::new();
        loop {
            let len = *raw.get(offset)? as usize;
            offset += 1;
            if len == 0 {
                break;
            }
            if len & 0xc0 != 0 || offset + len > raw.len() {
                return None;
            }
            labels.push(String::from_utf8_lossy(&raw[offset..offset + len]).into_owned());
            offset += len;
        }
        if offset + 4 > raw.len() {
            return None;
        }
        let name = if labels.is_empty() {
            ".".to_string()
        } else {
            format!("{}.", labels.join("."))
        };
        let qtype = u16::from_be_bytes([raw[offset], raw[offset + 1]]);
        Some((name, qtype, offset + 4))
    }

    fn wire_response(query: &[u8], answers: Vec<(u16, u32, Vec<u8>)>) -> Vec<u8> {
        let (_, _, question_end) = test_dns_question(query).unwrap();
        let mut response = Vec::new();
        response.extend_from_slice(&query[0..2]);
        response.extend_from_slice(&0x8180u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&query[12..question_end]);
        for (typ, ttl, data) in answers {
            response.extend_from_slice(&[0xc0, 0x0c]);
            response.extend_from_slice(&typ.to_be_bytes());
            response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
            response.extend_from_slice(&ttl.to_be_bytes());
            response.extend_from_slice(&(data.len() as u16).to_be_bytes());
            response.extend_from_slice(&data);
        }
        response
    }

    #[tokio::test]
    async fn lookup_doh_uses_rfc8484_wire_format() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_for_handler = seen.clone();
        let (url, task) = start_wire_test_server(move |request| {
            if request.method != "POST" {
                return http::Response::builder()
                    .status(405)
                    .body(Vec::new())
                    .unwrap();
            }
            let (name, qtype, _) = test_dns_question(&request.body).unwrap();
            seen_for_handler.lock().unwrap().push((
                qtype,
                request.method.clone(),
                request.path.clone(),
                request.header("accept"),
                request.header("content-type"),
            ));
            let body = match qtype {
                DNS_TYPE_A => {
                    wire_response(&request.body, vec![(DNS_TYPE_A, 60, vec![127, 0, 0, 1])])
                }
                DNS_TYPE_AAAA => {
                    wire_response(&request.body, vec![(DNS_TYPE_AAAA, 60, vec![0; 16])])
                }
                _ => wire_response(&request.body, Vec::new()),
            };
            assert_eq!(name, "example.com.");
            http::Response::builder()
                .header(CONTENT_TYPE, APPLICATION_DNS_MESSAGE)
                .body(body)
                .unwrap()
        })
        .await;

        let addrs = lookup_doh(&url, "example.com", None).await.unwrap();

        assert_eq!(
            addrs.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["127.0.0.1", "::"]
        );
        let mut seen = seen.lock().unwrap().clone();
        seen.sort_by_key(|(qtype, _, _, _, _)| *qtype);
        assert_eq!(
            seen,
            [
                (
                    DNS_TYPE_A,
                    "POST".to_string(),
                    "/dns-query".to_string(),
                    APPLICATION_DNS_MESSAGE.to_string(),
                    APPLICATION_DNS_MESSAGE.to_string(),
                ),
                (
                    DNS_TYPE_AAAA,
                    "POST".to_string(),
                    "/dns-query".to_string(),
                    APPLICATION_DNS_MESSAGE.to_string(),
                    APPLICATION_DNS_MESSAGE.to_string(),
                ),
            ]
        );
        task.abort();
    }

    #[tokio::test]
    async fn lookup_doh_returns_a_and_aaaa() {
        let queries = Arc::new(Mutex::new(Vec::new()));
        let seen = queries.clone();
        let (url, task) = start_test_server(move |request| {
            let query = request.uri().query().unwrap_or_default().to_string();
            let params: Vec<_> = query.split('&').collect();
            let ty = params
                .iter()
                .find_map(|part| part.strip_prefix("type="))
                .unwrap_or_default()
                .to_string();
            seen.lock().unwrap().push(ty.clone());
            match ty.as_str() {
                "A" => http::Response::new(
                    r#"{"Status":0,"Answer":[{"type":5,"data":"alias.example"},{"type":1,"data":"127.0.0.1"}]}"#
                        .to_string(),
                ),
                "AAAA" => http::Response::new(
                    r#"{"Status":0,"Answer":[{"type":28,"data":"::1"}]}"#.to_string(),
                ),
                _ => http::Response::builder()
                    .status(400)
                    .body(r#"{"error":"bad type"}"#.to_string())
                    .unwrap(),
            }
        })
        .await;

        let addrs = lookup_doh(&url, "example.com", None).await.unwrap();

        assert_eq!(
            addrs.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["127.0.0.1", "::1"]
        );
        let mut queries = queries.lock().unwrap().clone();
        queries.sort();
        assert_eq!(queries, ["A", "AAAA"]);
        task.abort();
    }

    #[tokio::test]
    async fn lookup_doh_sends_http1_host_header() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_for_handler = seen.clone();
        let (url, task) = start_test_server(move |request| {
            seen_for_handler
                .lock()
                .unwrap()
                .push(request.body().clone());
            http::Response::new(
                r#"{"Status":0,"Answer":[{"type":1,"data":"127.0.0.1"}]}"#.to_string(),
            )
        })
        .await;

        let records = lookup_doh_type(&url, "example.com", "A", DNS_TYPE_A, None)
            .await
            .unwrap();

        assert_eq!(records.len(), 1);
        let expected_host = format!("{}:{}", url.host_str().unwrap(), url.port().unwrap());
        let requests = seen.lock().unwrap();
        assert!(
            requests.iter().any(|request| request
                .lines()
                .any(|line| line.eq_ignore_ascii_case(&format!("host: {expected_host}")))),
            "DoH HTTP/1.1 request did not include Host header:\n{}",
            requests.join("\n---\n")
        );
        task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn lookup_doh_queries_a_and_aaaa_concurrently() {
        let delay = Duration::from_millis(250);
        let (url, task) = start_delayed_test_server(delay).await;

        let _ = client(None).unwrap();
        let start = Instant::now();
        let addrs = lookup_doh(&url, "example.com", None).await.unwrap();
        let elapsed = start.elapsed();

        assert_eq!(
            addrs.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["127.0.0.1", "::1"]
        );
        assert!(
            elapsed < Duration::from_millis(400),
            "lookup took {elapsed:?}, expected parallel A/AAAA queries near {delay:?}"
        );
        task.abort();
    }

    #[tokio::test]
    async fn lookup_doh_timeout_budget_covers_415_json_fallback() {
        let timeout = Duration::from_millis(250);
        let (url, task) = start_delayed_415_fallback_server(Duration::from_millis(150)).await;

        let start = Instant::now();
        let err = lookup_doh_type(&url, "example.com", "A", DNS_TYPE_A, Some(timeout))
            .await
            .unwrap_err();
        let elapsed = start.elapsed();

        assert_eq!(err.to_string(), "request timed out after 250ms");
        assert!(
            elapsed < Duration::from_millis(350),
            "lookup took {elapsed:?}, expected timeout to cover POST and JSON fallback"
        );
        task.abort();
    }

    #[tokio::test]
    async fn lookup_doh_nxdomain_mentions_rcode() {
        let (url, task) =
            start_test_server(|_| http::Response::new(r#"{"Status":3}"#.to_string())).await;

        let err = lookup_doh(&url, "missing.example", None).await.unwrap_err();

        assert!(err.to_string().contains("NXDomain"));
        task.abort();
    }

    #[tokio::test]
    async fn lookup_doh_type_returns_ttl() {
        let (url, task) = start_test_server(|_| {
            http::Response::new(
                r#"{"Status":0,"Answer":[{"type":1,"data":"127.0.0.1","TTL":123}]}"#.to_string(),
            )
        })
        .await;

        let records = lookup_doh_type(&url, "example.com", "A", DNS_TYPE_A, None)
            .await
            .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].ip.to_string(), "127.0.0.1");
        assert_eq!(records[0].ttl, Some(123));
        task.abort();
    }

    #[tokio::test]
    async fn lookup_doh_rejects_oversized_response() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut raw = Vec::new();
            let mut buf = [0_u8; 1024];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    return;
                }
                raw.extend_from_slice(&buf[..n]);
                if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n")
                .await;
            let oversized = vec![b' '; DOH_RESPONSE_MAX_BYTES + 1];
            let _ = stream.write_all(&oversized).await;
        });
        let url = Url::parse(&format!("http://{addr}/dns-query")).unwrap();

        let err = lookup_doh_type(&url, "example.com", "A", DNS_TYPE_A, None)
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), DOH_RESPONSE_LIMIT_ERROR);
        task.await.unwrap();
    }

    #[test]
    fn doh_query_url_replaces_name_and_type_like_go_url_values_set() {
        let server_url =
            Url::parse("https://dns.example/query?cd=false&name=old.example&type=AAAA").unwrap();

        let url = doh_query_url(&server_url, "example.com", "A");

        assert_eq!(
            url.as_str(),
            "https://dns.example/query?cd=false&name=example.com&type=A"
        );
    }
}
