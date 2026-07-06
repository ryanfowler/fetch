use super::body::H3UploadTask;
use super::client::replace_headers;
use super::h3::{
    auto_http3_hint_addrs, http3_endpoint_local_addr, race_primary_fallback,
    spawn_auto_http3_origin_addrs, take_finished_auto_http3_origin_addrs,
};
use super::proxy::proxy_for_config;
use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::Bytes;
use http::Method;
use http::header::{HeaderMap, HeaderValue, PROXY_AUTHORIZATION};
use url::Url;

use crate::dns::svcb::SvcbRecord;
use crate::duration::TimeoutBudget;
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

fn https_record(priority: u16, target: &str, alpn: &[&str], port: Option<u16>) -> SvcbRecord {
    SvcbRecord {
        priority,
        target: target.to_string(),
        alpn: alpn.iter().map(|value| value.to_string()).collect(),
        no_default_alpn: false,
        port,
        ipv4_hint: Vec::new(),
        ech: None,
        ipv6_hint: Vec::new(),
        mandatory: Vec::new(),
        unsupported_mandatory: Vec::new(),
        ttl: Some(60),
    }
}

#[test]
fn dynamic_auto_http3_hints_follow_origin_family_preference_and_interleave() {
    let mut record = https_record(1, ".", &["h3"], None);
    record.ipv4_hint = vec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()];
    record.ipv6_hint = vec![
        "2001:db8::1".parse().unwrap(),
        "2001:db8::2".parse().unwrap(),
    ];

    let ipv4_first = auto_http3_hint_addrs(
        &record,
        &[SocketAddr::new("198.51.100.1".parse().unwrap(), 443)],
        443,
    );
    assert_eq!(
        ipv4_first,
        [
            SocketAddr::new("192.0.2.1".parse().unwrap(), 443),
            SocketAddr::new("2001:db8::1".parse().unwrap(), 443),
            SocketAddr::new("192.0.2.2".parse().unwrap(), 443),
            SocketAddr::new("2001:db8::2".parse().unwrap(), 443),
        ]
    );

    let ipv6_first = auto_http3_hint_addrs(
        &record,
        &[SocketAddr::new("2001:db8::10".parse().unwrap(), 443)],
        443,
    );
    assert_eq!(
        ipv6_first,
        [
            SocketAddr::new("2001:db8::1".parse().unwrap(), 443),
            SocketAddr::new("192.0.2.1".parse().unwrap(), 443),
            SocketAddr::new("2001:db8::2".parse().unwrap(), 443),
            SocketAddr::new("192.0.2.2".parse().unwrap(), 443),
        ]
    );
}

#[test]
fn dynamic_auto_http3_hints_default_to_ipv6_preference_without_origin_addrs() {
    let mut record = https_record(1, ".", &["h3"], None);
    record.ipv4_hint = vec!["192.0.2.1".parse().unwrap()];
    record.ipv6_hint = vec!["2001:db8::1".parse().unwrap()];

    let got = auto_http3_hint_addrs(&record, &[], 443);

    assert_eq!(
        got,
        [
            SocketAddr::new("2001:db8::1".parse().unwrap(), 443),
            SocketAddr::new("192.0.2.1".parse().unwrap(), 443),
        ]
    );
}

#[tokio::test]
async fn dynamic_auto_http3_origin_preference_lookup_allows_custom_dns() {
    let handle = spawn_auto_http3_origin_addrs(
        Some("https://dns.example/dns-query".to_string()),
        "192.0.2.1".to_string(),
        None,
        TimeoutBudget::new(None),
    );

    let got = take_finished_auto_http3_origin_addrs(handle).await;

    assert_eq!(got, [SocketAddr::new("192.0.2.1".parse().unwrap(), 0)]);
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
async fn auto_protocol_race_uses_primary_when_it_wins() {
    let fallback_started = Arc::new(AtomicUsize::new(0));
    let fallback_started_for_task = fallback_started.clone();

    let result = race_primary_fallback(
        || async { Ok("h3") },
        move || {
            fallback_started_for_task.fetch_add(1, Ordering::SeqCst);
            async { Ok("tcp") }
        },
        std::time::Duration::from_secs(1),
    )
    .await
    .unwrap();

    assert_eq!(result, "h3");
    assert_eq!(fallback_started.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn auto_protocol_race_uses_fallback_after_delay() {
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        race_primary_fallback(
            || async { std::future::pending::<Result<&'static str, Error>>().await },
            || async { Ok("tcp") },
            std::time::Duration::from_millis(10),
        ),
    )
    .await
    .expect("fallback should start after delay")
    .unwrap();

    assert_eq!(result, "tcp");
}

#[tokio::test]
async fn auto_protocol_race_starts_fallback_after_primary_failure() {
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        race_primary_fallback(
            || async { Err(Error::connect("h3 failed")) },
            || async { Ok("tcp") },
            std::time::Duration::from_secs(1),
        ),
    )
    .await
    .expect("fallback should start immediately after primary failure")
    .unwrap();

    assert_eq!(result, "tcp");
}

#[tokio::test]
async fn auto_protocol_race_reports_fallback_error_when_both_fail() {
    let err = race_primary_fallback(
        || async { Err::<&'static str, _>(Error::connect("h3 failed")) },
        || async { Err::<&'static str, _>(Error::connect("tcp failed")) },
        std::time::Duration::from_secs(1),
    )
    .await
    .unwrap_err();

    assert_eq!(err.to_string(), "tcp failed");
}

#[tokio::test]
async fn auto_protocol_race_drops_losing_primary() {
    struct NotifyOnDrop(Option<tokio::sync::oneshot::Sender<()>>);

    impl Drop for NotifyOnDrop {
        fn drop(&mut self) {
            if let Some(tx) = self.0.take() {
                let _ = tx.send(());
            }
        }
    }

    let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
    let result = race_primary_fallback(
        || async move {
            let _notify = NotifyOnDrop(Some(dropped_tx));
            std::future::pending::<Result<&'static str, Error>>().await
        },
        || async { Ok("tcp") },
        std::time::Duration::from_millis(10),
    )
    .await
    .unwrap();

    assert_eq!(result, "tcp");
    tokio::time::timeout(std::time::Duration::from_secs(1), dropped_rx)
        .await
        .unwrap()
        .unwrap();
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
