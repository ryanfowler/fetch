use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use bytes::Bytes;
use http::header::{ACCEPT, USER_AGENT};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use serde::Deserialize;
use tokio::sync::Mutex;
use url::Url;

use crate::core;
use crate::duration::TimeoutBudget;
use crate::http::transport::hyper_client::{
    BufferedResponse, SharedHttpClient, connect_shared_http,
};

const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;

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
    timeout: Option<Duration>,
    tls_config: rustls::ClientConfig,
    connection: Mutex<Option<DohConnection>>,
}

struct DohConnection {
    origin: String,
    client: SharedHttpClient,
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
    Ok(DohClient {
        timeout,
        tls_config: crate::tls::rustls_platform_client_config()
            .map_err(|err| DnsError(err.to_string()))?,
        connection: Mutex::new(None),
    })
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
    let url = doh_query_url(server_url, host, dns_type);

    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/dns-json"));
    headers.insert(
        USER_AGENT,
        HeaderValue::from_str(&core::user_agent()).expect("valid user agent"),
    );
    let response = client.get(url, headers).await?;

    let status = response.status();
    if !status.is_success() {
        if let Ok(err_response) = serde_json::from_slice::<DohErrorResponse>(response.body())
            && let Some(message) = err_response.error.filter(|message| !message.is_empty())
        {
            return Err(DnsError(format!("{}: {message}", status.as_u16())));
        }
        return Err(DnsError(format!(
            "{}: {}",
            status.as_u16(),
            String::from_utf8_lossy(response.body())
        )));
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
        let budget = TimeoutBudget::new(self.timeout);
        let response = budget
            .run(async move { self.get_inner(url, headers, budget).await })
            .await
            .map_err(|err| DnsError(err.to_string()))?;
        Ok(DohResponseBody(response))
    }

    async fn get_inner(
        &self,
        url: Url,
        headers: HeaderMap,
        budget: TimeoutBudget,
    ) -> Result<BufferedResponse, crate::error::FetchError> {
        let client = self
            .shared_client(&url, budget)
            .await
            .map_err(|err| crate::error::FetchError::Runtime(err.to_string()))?;
        if let SharedHttpClient::Http1(client) = &client {
            match client
                .try_send_buffered(Method::GET, url.clone(), headers.clone(), Bytes::new())
                .await
            {
                Ok(Some(response)) => return Ok(response),
                Ok(None) => {
                    return self
                        .send_with_new_connection(url, headers, budget)
                        .await
                        .map_err(|err| crate::error::FetchError::Runtime(err.to_string()));
                }
                Err(err) => {
                    self.clear_connection(&url).await;
                    if matches!(err, crate::error::FetchError::Runtime(_)) {
                        return self
                            .send_with_new_connection(url, headers, budget)
                            .await
                            .map_err(|err| crate::error::FetchError::Runtime(err.to_string()));
                    }
                    return Err(err);
                }
            }
        }
        match client
            .send_buffered(Method::GET, url.clone(), headers.clone(), Bytes::new())
            .await
        {
            Ok(response) => Ok(response),
            Err(err) => {
                self.clear_connection(&url).await;
                if matches!(err, crate::error::FetchError::Runtime(_)) {
                    let client = self
                        .shared_client(&url, budget)
                        .await
                        .map_err(|err| crate::error::FetchError::Runtime(err.to_string()))?;
                    return client
                        .send_buffered(Method::GET, url, headers, Bytes::new())
                        .await;
                }
                Err(err)
            }
        }
    }

    async fn send_with_new_connection(
        &self,
        url: Url,
        headers: HeaderMap,
        budget: TimeoutBudget,
    ) -> Result<BufferedResponse, DnsError> {
        let client = Box::pin(connect_shared_http(
            &url,
            None,
            budget,
            Some(self.tls_config.clone()),
        ))
        .await
        .map_err(|err| DnsError(err.to_string()))?;
        client
            .send_buffered(Method::GET, url, headers, Bytes::new())
            .await
            .map_err(|err| DnsError(err.to_string()))
    }

    async fn shared_client(
        &self,
        url: &Url,
        budget: TimeoutBudget,
    ) -> Result<SharedHttpClient, DnsError> {
        let origin = doh_origin(url)?;
        let mut connection = self.connection.lock().await;
        if let Some(existing) = connection.as_ref()
            && existing.origin == origin
        {
            return Ok(existing.client.clone());
        }

        let client = Box::pin(connect_shared_http(
            url,
            None,
            budget,
            Some(self.tls_config.clone()),
        ))
        .await
        .map_err(|err| DnsError(err.to_string()))?;
        *connection = Some(DohConnection {
            origin,
            client: client.clone(),
        });
        Ok(client)
    }

    async fn clear_connection(&self, url: &Url) {
        let Ok(origin) = doh_origin(url) else {
            return;
        };
        let mut connection = self.connection.lock().await;
        if connection
            .as_ref()
            .is_some_and(|existing| existing.origin == origin)
        {
            *connection = None;
        }
    }
}

struct DohResponseBody(BufferedResponse);

impl DohResponseBody {
    fn status(&self) -> StatusCode {
        self.0.status
    }

    fn body(&self) -> &[u8] {
        &self.0.body
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
        return Err(DnsError("no such host".to_string()));
    }

    Ok(records)
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

fn doh_origin(url: &Url) -> Result<String, DnsError> {
    let host = url
        .host_str()
        .ok_or_else(|| DnsError("DoH URL host is required".to_string()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| DnsError("DoH URL port is required".to_string()))?;
    Ok(format!("{}://{}:{port}", url.scheme(), host))
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
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    async fn start_test_server<F>(handler: F) -> (Url, tokio::task::JoinHandle<()>)
    where
        F: Fn(http::Request<String>) -> http::Response<String> + Send + Sync + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = Arc::new(handler);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
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
                    let path = first_line.split_whitespace().nth(1).unwrap_or("/");
                    let req = http::Request::builder()
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
                    let _ = stream.writable().await;
                    let _ = stream.try_write(raw.as_bytes());
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
                let Ok((stream, _)) = listener.accept().await else {
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
                    let path = first_line.split_whitespace().nth(1).unwrap_or("/");
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
                    let _ = stream.writable().await;
                    let _ = stream.try_write(raw.as_bytes());
                });
            }
        });
        (
            Url::parse(&format!("http://{addr}/dns-query")).unwrap(),
            task,
        )
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
