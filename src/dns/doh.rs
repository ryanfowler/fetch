use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use bytes::Bytes;
use http::header::{ACCEPT, AGE, CONTENT_LENGTH, CONTENT_TYPE, USER_AGENT};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use serde::Deserialize;
use url::Url;

use crate::core;
use crate::dns::util::{dns_transaction_budget, resolve_address_families};
use crate::dns::wire;
use crate::duration::TimeoutBudget;
use crate::error::FetchError;
use crate::http::transport::{Client, Response};

const DNS_TYPE_A: u16 = wire::TYPE_A;
const DNS_TYPE_AAAA: u16 = wire::TYPE_AAAA;
const DNS_CLASS_IN: u16 = wire::CLASS_IN;
const DNS_MESSAGE_MAX_BYTES: usize = u16::MAX as usize;
const DNS_MESSAGE_LIMIT_ERROR: &str =
    "DoH application/dns-message response exceeded maximum allowed size of 65,535 bytes";
const DOH_JSON_MAX_BYTES: usize = 1024 * 1024;
const DOH_JSON_LIMIT_ERROR: &str = "DoH JSON response exceeded maximum allowed size of 1 MiB";
const DOH_ERROR_MAX_BYTES: usize = 64 * 1024;
const DOH_ERROR_LIMIT_ERROR: &str = "DoH error response exceeded maximum allowed size of 64 KiB";
const DOH_ERROR_EXCERPT_MAX_BYTES: usize = 4 * 1024;
const DOH_ERROR_TRUNCATION_SUFFIX: &str = "... [truncated]";
const APPLICATION_DNS_MESSAGE: &str = "application/dns-message";
const APPLICATION_DNS_JSON: &str = "application/dns-json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsError {
    kind: crate::dns::error::DnsErrorKind,
    detail: Option<String>,
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.detail {
            Some(detail) => f.write_str(detail),
            None => self.kind.fmt(f),
        }
    }
}

impl std::error::Error for DnsError {}

impl DnsError {
    fn dns(kind: crate::dns::error::DnsErrorKind) -> Self {
        Self { kind, detail: None }
    }

    fn other(detail: impl Into<String>) -> Self {
        Self {
            kind: crate::dns::error::DnsErrorKind::Other,
            detail: Some(detail.into()),
        }
    }

    pub(crate) fn is_nxdomain(&self) -> bool {
        self.kind == crate::dns::error::DnsErrorKind::NxDomain
    }
}

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
    resolve_address_families(
        lookup_doh_type_with_client(&client, server_url, host, "A", DNS_TYPE_A),
        lookup_doh_type_with_client(&client, server_url, host, "AAAA", DNS_TYPE_AAAA),
        crate::net::HAPPY_EYEBALLS_RESOLUTION_DELAY,
        DnsError::dns(crate::dns::error::DnsErrorKind::NoData),
    )
    .await
    .map(|records| records.into_iter().map(|record| record.ip).collect())
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
    client_with_budget_and_tls_config(budget, None)
}

pub(crate) fn client_with_budget_and_tls_config(
    budget: TimeoutBudget,
    tls_config: Option<rustls::ClientConfig>,
) -> Result<DohClient, DnsError> {
    let budget = dns_transaction_budget(budget);
    let tls_config = match tls_config {
        Some(config) => config,
        None => crate::tls::rustls_platform_client_config()
            .map_err(|err| DnsError::other(err.to_string()))?,
    };
    let client = Client::builder()
        .tls_config(tls_config)
        .build()
        .map_err(|err| DnsError::other(err.to_string()))?;
    Ok(DohClient { budget, client })
}

pub(crate) async fn lookup_doh_type_with_client(
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
    // HTTP correlates DoH exchanges. RFC 8484 recommends ID 0 to improve
    // HTTP cache reuse and avoid carrying unnecessary entropy in the query.
    const DOH_QUERY_ID: u16 = 0;
    let query = wire::build_query(DOH_QUERY_ID, host, dns_type)
        .map_err(|err| WireDohError::Fatal(DnsError::other(err.to_string())))?;

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

    let age = doh_response_age(response.headers());
    match doh_records_from_wire_response(response.body(), DOH_QUERY_ID, host, dns_type) {
        Ok(mut records) => {
            subtract_age_from_ttls(&mut records, age);
            Ok(records)
        }
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

    let mut records = doh_records_from_json_response(response.body(), host)?;
    subtract_age_from_ttls(&mut records, doh_response_age(response.headers()));
    Ok(records)
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
        validate_doh_endpoint(&url)?;
        let wire_request = method == Method::POST;
        let operation = Box::pin(async {
            let mut request = self.client.request(method, url).headers(headers);
            if let Some(body) = body {
                request = request.body(body);
            }
            let response = Box::pin(request.send()).await?;
            if wire_request && wire_status_may_support_json(response.status()) {
                return Ok(DohResponseBody {
                    status: response.status(),
                    headers: response.headers().clone(),
                    body: Bytes::new(),
                });
            }
            Box::pin(buffer_doh_response(response, wire_request)).await
        });
        let remaining = self
            .budget
            .remaining()
            .map_err(|_| DnsError::dns(crate::dns::error::DnsErrorKind::Timeout))?;
        match remaining {
            Some(remaining) => tokio::time::timeout(remaining, operation)
                .await
                .map_err(|_| DnsError::dns(crate::dns::error::DnsErrorKind::Timeout))?
                .map_err(|err| DnsError::other(err.to_string())),
            None => operation
                .await
                .map_err(|err| DnsError::other(err.to_string())),
        }
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

fn validate_doh_endpoint(url: &Url) -> Result<(), DnsError> {
    if url.scheme() == "https" && url.host_str().is_some() {
        return Ok(());
    }
    // Unit tests use local plaintext servers to test protocol details without
    // adding TLS setup to each case. Production builds never allow this path.
    #[cfg(test)]
    if url.scheme() == "http"
        && url.host().is_some_and(|host| match host {
            url::Host::Ipv4(ip) => ip.is_loopback(),
            url::Host::Ipv6(ip) => ip.is_loopback(),
            url::Host::Domain(name) => name.eq_ignore_ascii_case("localhost"),
        })
    {
        return Ok(());
    }
    Err(DnsError::other("DoH endpoints must use HTTPS".to_string()))
}

async fn buffer_doh_response(
    response: Response,
    wire_request: bool,
) -> Result<DohResponseBody, FetchError> {
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(media_type);
    let (max_body_bytes, limit_error) = if !response.status().is_success() {
        (DOH_ERROR_MAX_BYTES, DOH_ERROR_LIMIT_ERROR)
    } else if content_type.is_some_and(has_json_media_type) {
        (DOH_JSON_MAX_BYTES, DOH_JSON_LIMIT_ERROR)
    } else if wire_request
        || content_type.is_some_and(|value| value.eq_ignore_ascii_case(APPLICATION_DNS_MESSAGE))
    {
        (DNS_MESSAGE_MAX_BYTES, DNS_MESSAGE_LIMIT_ERROR)
    } else {
        (DOH_JSON_MAX_BYTES, DOH_JSON_LIMIT_ERROR)
    };
    buffer_response_with_limit(response, max_body_bytes, limit_error).await
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

fn doh_records_from_json_response(
    raw: &[u8],
    expected_name: &str,
) -> Result<Vec<DohRecord>, DnsError> {
    let body = serde_json::from_slice::<DohResponse>(raw)
        .map_err(|err| DnsError::other(err.to_string()))?;
    if body.status != 0 {
        let rcode = u16::try_from(body.status)
            .map_err(|_| DnsError::dns(crate::dns::error::DnsErrorKind::Malformed))?;
        let kind = if rcode == 16 {
            // JSON responses do not carry an OPT record. In this context,
            // extended RCODE 16 is the TSIG status BADSIG, not EDNS BADVERS.
            crate::dns::error::DnsErrorKind::BadSig
        } else {
            crate::dns::error::DnsErrorKind::from_rcode(rcode)
                .expect("nonzero RCODE has an error kind")
        };
        return Err(DnsError::dns(kind));
    }

    let expected = wire::parse_presentation_name(expected_name)
        .map_err(|err| DnsError::other(err.to_string()))?;
    let owners = body
        .answer
        .iter()
        .map(|answer| wire::parse_presentation_name(&answer.name))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| DnsError::other(err.to_string()))?;
    let types = body
        .answer
        .iter()
        .map(|answer| Some(answer.answer_type))
        .collect::<Vec<_>>();
    let reachable = wire::reachable_answer_names(expected, &owners, &types, |index| {
        wire::parse_presentation_name(&body.answer[index].data)
            .map_err(|_| wire::malformed_rdata(wire::TYPE_CNAME))
    })
    .map_err(|err| DnsError::other(err.to_string()))?;

    Ok(body
        .answer
        .into_iter()
        .zip(owners)
        .filter(|(_, owner)| reachable.contains(owner))
        .map(|(answer, _)| DohRecord {
            answer_type: answer.answer_type,
            data: answer.data,
            ttl: answer.ttl,
        })
        .collect())
}

fn doh_response_age(headers: &HeaderMap) -> u32 {
    let Some(value) = headers.get_all(AGE).iter().next() else {
        return 0;
    };
    // RFC 9111 requires recipients to use the first member when a broken
    // sender generates a list-based Age field.
    let first = value.as_bytes().split(|byte| *byte == b',').next().unwrap();
    let first = first.trim_ascii();
    if first.is_empty() || first.iter().any(|byte| !byte.is_ascii_digit()) {
        return 0;
    }
    first.iter().fold(0_u32, |age, byte| {
        age.saturating_mul(10)
            .saturating_add(u32::from(byte - b'0'))
    })
}

fn subtract_age_from_ttls(records: &mut [DohRecord], age: u32) {
    for record in records {
        record.ttl = record.ttl.map(|ttl| ttl.saturating_sub(age));
    }
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
        return Err(DnsError::dns(crate::dns::error::DnsErrorKind::NoData));
    }

    Ok(records)
}

fn doh_records_from_wire_response(
    raw: &[u8],
    expected_id: u16,
    expected_name: &str,
    expected_type: u16,
) -> Result<Vec<DohRecord>, DnsError> {
    let records =
        wire::parse_response(raw, expected_id, expected_name, expected_type, DNS_CLASS_IN)
            .map_err(DnsError::from)?;
    let mut out = Vec::new();
    for record in records {
        if record.class != DNS_CLASS_IN {
            continue;
        }
        out.push(DohRecord {
            answer_type: record.typ,
            data: wire_record_data(raw, &record)?,
            ttl: Some(record.ttl),
        });
    }
    Ok(out)
}

fn wire_record_data(packet: &[u8], record: &wire::ResourceRecord<'_>) -> Result<String, DnsError> {
    let decoded = wire::decode_rdata(packet, record.typ, record.data_offset, record.data.len())
        .map_err(|err| DnsError::other(err.to_string()))?;
    let value = match decoded {
        wire::DecodedRdata::Address(address) => address.to_string(),
        wire::DecodedRdata::Name(name) => name,
        wire::DecodedRdata::Text(text) => text,
        wire::DecodedRdata::Mx {
            preference,
            exchange,
        } => format!("{preference} {exchange}"),
        wire::DecodedRdata::Soa {
            ns,
            mailbox,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => format!(
            "{ns} {mailbox} serial={serial} refresh={refresh} retry={retry} expire={expire} minttl={minimum}"
        ),
        wire::DecodedRdata::Srv {
            priority,
            weight,
            port,
            target,
        } => format!("{priority} {weight} {port} {target}"),
        wire::DecodedRdata::Raw(raw) => generic_rdata(raw),
    };
    Ok(value)
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
        return DnsError::other(format!(
            "{}: {}",
            status.as_u16(),
            doh_error_excerpt(&message),
        ));
    }
    let body = String::from_utf8_lossy(response.body());
    DnsError::other(format!("{}: {}", status.as_u16(), doh_error_excerpt(&body),))
}

fn doh_error_excerpt(body: &str) -> String {
    let suffix_len = DOH_ERROR_TRUNCATION_SUFFIX.len();
    let content_limit = DOH_ERROR_EXCERPT_MAX_BYTES.saturating_sub(suffix_len);
    let content = truncate_utf8(body, content_limit);
    let truncated = content.len() < body.len();

    let mut excerpt = String::with_capacity(content.len() + if truncated { suffix_len } else { 0 });
    excerpt.push_str(content);
    if truncated {
        excerpt.push_str(DOH_ERROR_TRUNCATION_SUFFIX);
    }
    core::escape_terminal_text(&excerpt)
}

fn truncate_utf8(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
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
        .is_some_and(|value| has_json_media_type(media_type(value)))
}

fn has_json_media_type(value: &str) -> bool {
    let media_type = value.to_ascii_lowercase();
    media_type == APPLICATION_DNS_JSON
        || media_type == "application/json"
        || media_type.ends_with("+json")
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
    !matches!(
        err.kind,
        crate::dns::error::DnsErrorKind::Other | crate::dns::error::DnsErrorKind::Malformed
    )
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

impl From<wire::WireError> for DnsError {
    fn from(error: wire::WireError) -> Self {
        let kind = error.kind();
        match kind {
            crate::dns::error::DnsErrorKind::Other => Self::other(error.to_string()),
            crate::dns::error::DnsErrorKind::Malformed => Self {
                kind,
                detail: Some(error.to_string()),
            },
            _ => Self::dns(kind),
        }
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
    name: String,
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
                    let mut raw = format!(
                        "HTTP/1.1 {status} {reason}\r\ncontent-length: {}\r\ncontent-type: application/json\r\nconnection: close\r\n",
                        body.len()
                    );
                    for (name, value) in &parts.headers {
                        raw.push_str(name.as_str());
                        raw.push_str(": ");
                        raw.push_str(value.to_str().unwrap());
                        raw.push_str("\r\n");
                    }
                    raw.push_str("\r\n");
                    raw.push_str(&body);
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
                            r#"{"Status":0,"Answer":[{"name":"example.com.","type":1,"data":"127.0.0.1"}]}"#.to_string(),
                        ),
                        "AAAA" => http::Response::new(
                            r#"{"Status":0,"Answer":[{"name":"example.com.","type":28,"data":"::1"}]}"#.to_string(),
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

    async fn start_stalled_family_server() -> (Url, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let Some(request) = read_wire_test_request(&mut stream).await else {
                        return;
                    };
                    let Some((_, query_type, _)) = test_dns_question(&request.body) else {
                        return;
                    };
                    if query_type == DNS_TYPE_AAAA {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        return;
                    }
                    let body =
                        wire_response(&request.body, vec![(DNS_TYPE_A, 60, vec![127, 0, 0, 1])]);
                    let headers = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\ncontent-type: {APPLICATION_DNS_MESSAGE}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(headers.as_bytes()).await;
                    let _ = stream.write_all(&body).await;
                });
            }
        });
        (
            Url::parse(&format!("http://{addr}/dns-query")).unwrap(),
            task,
        )
    }

    async fn start_stalling_response_server(
        send_partial_body: bool,
    ) -> (Url, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            if send_partial_body {
                let Some(_) = read_wire_test_request(&mut stream).await else {
                    return;
                };
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\ncontent-type: application/dns-message\r\nconnection: close\r\n\r\n\0",
                    )
                    .await;
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
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

    #[test]
    fn wire_response_rejects_malformed_rdata_before_adjacent_record() {
        let query = wire::build_query(0x1234, "example.com", wire::TYPE_MX).unwrap();
        let response = wire_response(
            &query,
            vec![
                (wire::TYPE_MX, 30, vec![0, 10, 3, b'm']),
                (wire::TYPE_MX, 30, vec![0, 10, 0]),
            ],
        );

        let err = doh_records_from_wire_response(&response, 0x1234, "example.com", wire::TYPE_MX)
            .unwrap_err();

        assert!(err.to_string().contains("short DNS name label"));
    }

    #[test]
    fn wire_response_rejects_mismatched_zero_id() {
        let query = wire::build_query(0, "example.com", wire::TYPE_A).unwrap();
        let mut response = wire_response(&query, vec![(wire::TYPE_A, 30, vec![192, 0, 2, 1])]);
        response[0..2].copy_from_slice(&1_u16.to_be_bytes());

        let err =
            doh_records_from_wire_response(&response, 0, "example.com", wire::TYPE_A).unwrap_err();

        assert_eq!(
            err.to_string(),
            "malformed DNS response: mismatched response ID"
        );
    }

    #[test]
    fn wire_response_rejects_unrelated_answer_owner() {
        let query = wire::build_query(0x1234, "example.com", wire::TYPE_A).unwrap();
        let (_, _, question_end) = test_dns_question(&query).unwrap();
        let mut response = wire_response(&query, vec![(wire::TYPE_A, 30, vec![192, 0, 2, 1])]);
        let mut owner = Vec::new();
        for label in "unrelated.example".split('.') {
            owner.push(label.len() as u8);
            owner.extend_from_slice(label.as_bytes());
        }
        owner.push(0);
        response.splice(question_end..question_end + 2, owner);

        let records =
            doh_records_from_wire_response(&response, 0x1234, "example.com", wire::TYPE_A).unwrap();

        assert!(records.is_empty());
    }

    #[test]
    fn json_response_status_codes_use_json_context() {
        let cases = [
            (16, crate::dns::error::DnsErrorKind::BadSig),
            (99, crate::dns::error::DnsErrorKind::OtherRcode(99)),
        ];

        for (status, expected) in cases {
            let raw = format!(r#"{{"Status":{status}}}"#);
            let error = doh_records_from_json_response(raw.as_bytes(), "example.com").unwrap_err();
            assert_eq!(error.kind, expected);
        }
    }

    #[test]
    fn json_response_rejects_unrelated_address_owner() {
        let raw =
            br#"{"Status":0,"Answer":[{"name":"unrelated.example.","type":1,"data":"192.0.2.1"}]}"#;

        let records = doh_records_from_json_response(raw, "example.com").unwrap();

        assert!(records.is_empty());
    }

    #[test]
    fn json_response_accepts_valid_cname_chain() {
        let raw = br#"{"Status":0,"Answer":[
            {"name":"EXAMPLE.com.","type":5,"data":"Alias.Example."},
            {"name":"alias.example.","type":1,"data":"192.0.2.1"}
        ]}"#;

        let records = doh_records_from_json_response(raw, "example.com").unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[1].data, "192.0.2.1");
    }

    #[test]
    fn json_response_accepts_rrsig_with_cname() {
        let raw = br#"{"Status":0,"Answer":[
            {"name":"example.com.","type":5,"data":"alias.example."},
            {"name":"example.com.","type":46,"data":"5 13 300 0 0 0 example. signature"},
            {"name":"alias.example.","type":1,"data":"192.0.2.1"}
        ]}"#;

        let records = doh_records_from_json_response(raw, "example.com").unwrap();

        assert_eq!(records.len(), 3);
        assert_eq!(records[2].data, "192.0.2.1");
    }

    #[test]
    fn json_response_rejects_malformed_cname_chain() {
        let raw = br#"{"Status":0,"Answer":[
            {"name":"example.com.","type":5,"data":"first.example."},
            {"name":"example.com.","type":5,"data":"second.example."}
        ]}"#;

        let err = doh_records_from_json_response(raw, "example.com").unwrap_err();

        assert_eq!(err.to_string(), "DNS CNAME owner has conflicting targets");
    }

    #[test]
    fn json_response_filters_mixed_reachable_and_unrelated_answers() {
        let raw = br#"{"Status":0,"Answer":[
            {"name":"example.com.","type":5,"data":"alias.example."},
            {"name":"unrelated.example.","type":1,"data":"192.0.2.200"},
            {"name":"alias.example.","type":1,"data":"192.0.2.1"},
            {"name":"other.example.","type":28,"data":"2001:db8::1"}
        ]}"#;

        let records = doh_records_from_json_response(raw, "example.com").unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].answer_type, wire::TYPE_CNAME);
        assert_eq!(records[1].data, "192.0.2.1");
    }

    #[test]
    fn json_response_requires_valid_owner_names() {
        let missing = br#"{"Status":0,"Answer":[{"type":1,"data":"192.0.2.1"}]}"#;
        let malformed =
            br#"{"Status":0,"Answer":[{"name":"bad..example.","type":1,"data":"192.0.2.1"}]}"#;

        assert!(doh_records_from_json_response(missing, "example.com").is_err());
        assert!(doh_records_from_json_response(malformed, "example.com").is_err());
    }

    #[test]
    fn json_response_compares_escaped_owner_octets_without_loss() {
        let raw = br#"{"Status":0,"Answer":[
            {"name":"example.com.","type":5,"data":"\\255.example."},
            {"name":"\\254.example.","type":1,"data":"192.0.2.200"},
            {"name":"\\255.example.","type":1,"data":"192.0.2.1"}
        ]}"#;

        let records = doh_records_from_json_response(raw, "example.com").unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[1].data, "192.0.2.1");
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
            assert_eq!(&request.body[..2], &[0, 0], "DoH query ID must be zero");
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
                    r#"{"Status":0,"Answer":[{"name":"example.com.","type":5,"data":"alias.example"},{"name":"alias.example.","type":1,"data":"127.0.0.1"}]}"#
                        .to_string(),
                ),
                "AAAA" => http::Response::new(
                    r#"{"Status":0,"Answer":[{"name":"example.com.","type":28,"data":"::1"}]}"#.to_string(),
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
                r#"{"Status":0,"Answer":[{"name":"example.com.","type":1,"data":"127.0.0.1"}]}"#
                    .to_string(),
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

    #[tokio::test]
    async fn lookup_doh_returns_after_one_family_succeeds() {
        let (url, task) = start_stalled_family_server().await;
        let start = Instant::now();

        let addrs = lookup_doh(&url, "example.com", Some(Duration::from_millis(500)))
            .await
            .unwrap();

        assert_eq!(addrs, ["127.0.0.1".parse::<IpAddr>().unwrap()]);
        assert!(
            start.elapsed() < Duration::from_millis(350),
            "positive family waited for the DNS timeout"
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
    async fn lookup_doh_default_timeout_covers_response_headers() {
        let (url, task) = start_stalling_response_server(false).await;
        let start = Instant::now();

        let err = lookup_doh_type(&url, "example.com", "A", DNS_TYPE_A, None)
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "DNS lookup timed out");
        assert!(
            start.elapsed() < Duration::from_secs(7),
            "DoH response headers exceeded the default timeout"
        );
        task.abort();
    }

    #[tokio::test]
    async fn lookup_doh_default_timeout_covers_slow_body() {
        let (url, task) = start_stalling_response_server(true).await;
        let start = Instant::now();

        let err = lookup_doh_type(&url, "example.com", "A", DNS_TYPE_A, None)
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "DNS lookup timed out");
        assert!(
            start.elapsed() < Duration::from_secs(7),
            "DoH response body exceeded the default timeout"
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

        assert_eq!(err.to_string(), "DNS lookup timed out");
        assert!(
            elapsed < Duration::from_millis(350),
            "lookup took {elapsed:?}, expected timeout to cover POST and JSON fallback"
        );
        task.abort();
    }

    #[tokio::test]
    async fn lookup_doh_falls_back_without_buffering_oversized_post_error() {
        let (url, task) = start_wire_test_server(|request| {
            if request.method == "POST" {
                return http::Response::builder()
                    .status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
                    .body(vec![b'x'; DOH_ERROR_MAX_BYTES + 1])
                    .unwrap();
            }
            http::Response::builder()
                .header(CONTENT_TYPE, APPLICATION_DNS_JSON)
                .body(
                    br#"{"Status":0,"Answer":[{"name":"example.com.","type":1,"data":"192.0.2.1"}]}"#
                        .to_vec(),
                )
                .unwrap()
        })
        .await;

        let records = lookup_doh_type(&url, "example.com", "A", DNS_TYPE_A, None)
            .await
            .unwrap();

        assert_eq!(records[0].ip, "192.0.2.1".parse::<IpAddr>().unwrap());
        task.abort();
    }

    #[tokio::test]
    async fn lookup_doh_nxdomain_mentions_rcode() {
        let (url, task) =
            start_test_server(|_| http::Response::new(r#"{"Status":3}"#.to_string())).await;

        let err = lookup_doh(&url, "missing.example", None).await.unwrap_err();

        assert!(err.to_string().contains("NXDOMAIN"));
        task.abort();
    }

    #[tokio::test]
    async fn lookup_doh_type_subtracts_age_from_json_ttl() {
        let (url, task) = start_test_server(|_| {
            http::Response::builder()
                .header(AGE, "23")
                .body(
                    r#"{"Status":0,"Answer":[{"name":"example.com.","type":1,"data":"127.0.0.1","TTL":123}]}"#
                        .to_string(),
                )
                .unwrap()
        })
        .await;

        let records = lookup_doh_type(&url, "example.com", "A", DNS_TYPE_A, None)
            .await
            .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].ip.to_string(), "127.0.0.1");
        assert_eq!(records[0].ttl, Some(100));
        task.abort();
    }

    #[tokio::test]
    async fn lookup_doh_records_saturates_wire_https_ttl_at_zero() {
        let (url, task) = start_wire_test_server(|request| {
            let body = wire_response(&request.body, vec![(wire::TYPE_HTTPS, 20, vec![0, 1, 0])]);
            http::Response::builder()
                .header(CONTENT_TYPE, APPLICATION_DNS_MESSAGE)
                .header(AGE, "30")
                .body(body)
                .unwrap()
        })
        .await;
        let client = client(None).unwrap();

        let records = lookup_doh_records_with_client(&client, &url, "example.com", "HTTPS")
            .await
            .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].ttl, Some(0));
        task.abort();
    }

    #[test]
    fn doh_age_parsing_is_conservative_and_saturating() {
        for (value, expected) in [
            (None, 0),
            (Some("0"), 0),
            (Some("123"), 123),
            (Some(" 12"), 12),
            (Some("12, 13"), 12),
            (Some(""), 0),
            (Some("not-a-number"), 0),
            (Some("999999999999999999999999"), u32::MAX),
        ] {
            let mut headers = HeaderMap::new();
            if let Some(value) = value {
                headers.insert(AGE, HeaderValue::from_str(value).unwrap());
            }
            assert_eq!(doh_response_age(&headers), expected, "Age: {value:?}");
        }

        let mut repeated = HeaderMap::new();
        repeated.append(AGE, HeaderValue::from_static("7"));
        repeated.append(AGE, HeaderValue::from_static("9"));
        assert_eq!(doh_response_age(&repeated), 7);
    }

    #[test]
    fn doh_status_error_truncates_oversized_json_message() {
        let message = "x".repeat(DOH_ERROR_EXCERPT_MAX_BYTES + 1);
        let body = format!(r#"{{"error":"{message}"}}"#);
        let response = DohResponseBody {
            status: StatusCode::BAD_REQUEST,
            headers: HeaderMap::new(),
            body: Bytes::from(body),
        };

        let error = doh_status_error(&response).to_string();
        let excerpt = error.strip_prefix("400: ").unwrap();

        assert_eq!(excerpt.len(), DOH_ERROR_EXCERPT_MAX_BYTES);
        assert!(excerpt.ends_with(DOH_ERROR_TRUNCATION_SUFFIX));
        assert_eq!(
            excerpt.trim_end_matches(DOH_ERROR_TRUNCATION_SUFFIX).len(),
            DOH_ERROR_EXCERPT_MAX_BYTES - DOH_ERROR_TRUNCATION_SUFFIX.len()
        );
    }

    #[test]
    fn doh_status_error_escapes_control_characters() {
        let response = DohResponseBody {
            status: StatusCode::BAD_REQUEST,
            headers: HeaderMap::new(),
            body: Bytes::from_static(br#"{"error":"bad \u001b[2J\r\nforged"}"#),
        };

        let error = doh_status_error(&response).to_string();

        assert_eq!(error, r"400: bad \u001b[2J\r\nforged");
        assert!(!error.contains('\x1b'));
        assert!(!error.contains('\r'));
        assert!(!error.contains('\n'));
    }

    #[tokio::test]
    async fn lookup_doh_rejects_oversized_dns_message_response() {
        let (url, task) = start_wire_test_server(|_| {
            http::Response::builder()
                .header(CONTENT_TYPE, APPLICATION_DNS_MESSAGE)
                .body(vec![0; DNS_MESSAGE_MAX_BYTES + 1])
                .unwrap()
        })
        .await;

        let err = lookup_doh_type(&url, "example.com", "A", DNS_TYPE_A, None)
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), DNS_MESSAGE_LIMIT_ERROR);
        task.abort();
    }

    #[tokio::test]
    async fn lookup_doh_rejects_oversized_wire_response_without_content_type() {
        let (url, task) = start_wire_test_server(|_| {
            http::Response::builder()
                .body(vec![0; DNS_MESSAGE_MAX_BYTES + 1])
                .unwrap()
        })
        .await;

        let err = lookup_doh_type(&url, "example.com", "A", DNS_TYPE_A, None)
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), DNS_MESSAGE_LIMIT_ERROR);
        task.abort();
    }

    #[tokio::test]
    async fn lookup_doh_rejects_oversized_error_response() {
        let (url, task) = start_wire_test_server(|_| {
            http::Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(CONTENT_TYPE, APPLICATION_DNS_JSON)
                .body(vec![b'x'; DOH_ERROR_MAX_BYTES + 1])
                .unwrap()
        })
        .await;

        let err = lookup_doh_type(&url, "example.com", "A", DNS_TYPE_A, None)
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), DOH_ERROR_LIMIT_ERROR);
        task.abort();
    }

    #[tokio::test]
    async fn lookup_doh_rejects_oversized_json_response() {
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
            let oversized = vec![b' '; DOH_JSON_MAX_BYTES + 1];
            let _ = stream.write_all(&oversized).await;
        });
        let url = Url::parse(&format!("http://{addr}/dns-query")).unwrap();

        let err = lookup_doh_type(&url, "example.com", "A", DNS_TYPE_A, None)
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), DOH_JSON_LIMIT_ERROR);
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
