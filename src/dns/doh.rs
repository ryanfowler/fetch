use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use reqwest::header::{ACCEPT, USER_AGENT};
use serde::Deserialize;
use url::Url;

use crate::core;

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

pub async fn lookup_doh(
    server_url: &Url,
    host: &str,
    timeout: Option<Duration>,
) -> Result<Vec<IpAddr>, DnsError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    let client = doh_client(timeout)?;
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
    let client = doh_client(timeout)?;
    lookup_doh_type_with_client(&client, server_url, host, dns_type, answer_type).await
}

fn doh_client(timeout: Option<Duration>) -> Result<reqwest::Client, DnsError> {
    let mut builder = reqwest::Client::builder().use_rustls_tls();
    if let Some(timeout) = timeout {
        builder = builder.timeout(timeout);
    }
    builder.build().map_err(|err| DnsError(err.to_string()))
}

async fn lookup_doh_type_with_client(
    client: &reqwest::Client,
    server_url: &Url,
    host: &str,
    dns_type: &str,
    answer_type: u16,
) -> Result<Vec<DnsRecord>, DnsError> {
    let url = doh_query_url(server_url, host, dns_type);

    let response = client
        .get(url)
        .header(ACCEPT, "application/dns-json")
        .header(USER_AGENT, core::user_agent())
        .send()
        .await
        .map_err(|err| DnsError(err.to_string()))?;

    let status = response.status();
    if !status.is_success() {
        let body = response.bytes().await.unwrap_or_default();
        if let Ok(err_response) = serde_json::from_slice::<DohErrorResponse>(&body)
            && let Some(message) = err_response.error.filter(|message| !message.is_empty())
        {
            return Err(DnsError(format!("{}: {message}", status.as_u16())));
        }
        return Err(DnsError(format!(
            "{}: {}",
            status.as_u16(),
            String::from_utf8_lossy(&body)
        )));
    }

    let body = response
        .json::<DohResponse>()
        .await
        .map_err(|err| DnsError(err.to_string()))?;

    if body.status != 0 || body.answer.is_empty() {
        let name = rcode_name(body.status);
        if name.is_empty() {
            return Err(DnsError("no such host".to_string()));
        }
        return Err(DnsError(format!("no such host: {name}")));
    }

    let records: Vec<DnsRecord> = body
        .answer
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

pub fn socket_addrs_for_override(addrs: &[IpAddr]) -> Vec<SocketAddr> {
    addrs.iter().map(|addr| SocketAddr::new(*addr, 0)).collect()
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn lookup_doh_queries_a_and_aaaa_concurrently() {
        let delay = Duration::from_millis(250);
        let (url, task) = start_delayed_test_server(delay).await;

        let _ = doh_client(None).unwrap();
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
    fn socket_addrs_use_zero_port_for_reqwest_override() {
        let addrs = socket_addrs_for_override(&["127.0.0.1".parse().unwrap()]);

        assert_eq!(addrs, [SocketAddr::new("127.0.0.1".parse().unwrap(), 0)]);
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
