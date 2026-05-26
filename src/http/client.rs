use std::env;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use reqwest::{Client, redirect};
use tower::{Layer, Service};
use url::Url;

use crate::cli::{Cli, HttpVersion};
use crate::error::FetchError;
use crate::timing::DnsTiming;

#[derive(Clone, Copy, Debug)]
pub(crate) enum ClientMode {
    Request(Option<HttpVersion>),
    GrpcReflection,
}

impl ClientMode {
    pub(crate) fn http_version(self) -> Option<HttpVersion> {
        match self {
            Self::Request(version) => version,
            Self::GrpcReflection => Some(HttpVersion::Http2),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DnsResolution {
    pub(crate) socket_addrs: Vec<SocketAddr>,
    pub(crate) timing: Option<DnsTiming>,
}

#[derive(Clone)]
pub(crate) struct UrlClient {
    pub(crate) client: Client,
    pub(crate) dns_resolution: Option<DnsResolution>,
}

pub(crate) struct ClientBuildContext<'a> {
    pub(crate) mode: ClientMode,
    pub(crate) request_timeout: Option<Duration>,
    pub(crate) connect_timeout: Option<Duration>,
    pub(crate) request_start: Instant,
    pub(crate) session: Option<&'a crate::session::Session>,
    pub(crate) connect_timing: Option<&'a ConnectionTiming>,
}

pub(crate) async fn build_client_for_url(
    cli: &Cli,
    url: &Url,
    context: &ClientBuildContext<'_>,
) -> Result<UrlClient, FetchError> {
    let http_version = context.mode.http_version();
    let dns_timeout = dns_resolution_timeout(
        context.request_timeout,
        context.connect_timeout,
        context.request_start,
    )?;
    let dns_resolution = resolve_dns_for_client(cli, url, http_version, dns_timeout).await?;
    let mut builder = Client::builder()
        .use_rustls_tls()
        .no_brotli()
        .no_gzip()
        .no_zstd();
    builder = configure_http_version(builder, context.mode);
    builder = configure_unix_socket(builder, cli.unix.as_deref())?;
    builder = configure_http3_local_address(builder, http_version, url, dns_resolution.as_ref());
    builder = configure_dns_resolution(builder, url.host_str(), dns_resolution.as_ref());
    if let Some(connect_timing) = context.connect_timing
        && (cli.timing || (cli.verbose >= 3 && !cli.silent))
    {
        builder = builder.connector_layer(ConnectionTimingLayer::new(connect_timing.clone()));
    }
    builder = configure_tls(builder, cli)?;
    builder = configure_proxy(builder, cli.proxy.as_deref(), http_version, url)?;
    if cli.insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    if let Some(timeout) =
        remaining_request_timeout(context.request_timeout, context.request_start)?
    {
        builder = builder.timeout(timeout);
    }
    if let Some(timeout) = context.connect_timeout {
        builder = builder.connect_timeout(timeout);
    }
    if let Some(session) = context.session {
        builder = builder.cookie_provider(session.cookie_provider());
    }
    builder = builder.redirect(redirect::Policy::none());
    Ok(UrlClient {
        client: builder.build()?,
        dns_resolution,
    })
}

pub(crate) fn configure_unix_socket(
    builder: reqwest::ClientBuilder,
    path: Option<&str>,
) -> Result<reqwest::ClientBuilder, FetchError> {
    let Some(path) = path else {
        return Ok(builder);
    };

    #[cfg(unix)]
    {
        Ok(builder.unix_socket(path))
    }

    #[cfg(not(unix))]
    {
        let _ = path;
        Err("--unix is not supported on this platform".into())
    }
}

fn dns_resolution_timeout(
    request_timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
    start: Instant,
) -> Result<Option<Duration>, FetchError> {
    let remaining = remaining_request_timeout(request_timeout, start)?;
    Ok(match (connect_timeout, remaining) {
        (Some(connect), Some(remaining)) => Some(connect.min(remaining)),
        (Some(connect), None) => Some(connect),
        (None, remaining) => remaining,
    })
}

fn remaining_request_timeout(
    timeout: Option<Duration>,
    start: Instant,
) -> Result<Option<Duration>, FetchError> {
    let Some(timeout) = timeout else {
        return Ok(None);
    };
    let elapsed = start.elapsed();
    if elapsed >= timeout {
        return Err(FetchError::Runtime(format!(
            "request timed out after {}",
            crate::http::format_go_duration(timeout)
        )));
    }
    Ok(Some(timeout - elapsed))
}

async fn resolve_dns_for_client(
    cli: &Cli,
    url: &Url,
    http_version: Option<HttpVersion>,
    timeout: Option<Duration>,
) -> Result<Option<DnsResolution>, FetchError> {
    let resolve = resolve_dns_for_client_inner(cli, url, http_version, timeout);
    if let Some(timeout) = timeout {
        match tokio::time::timeout(timeout, resolve).await {
            Ok(result) => result,
            Err(_) => Err(FetchError::Runtime(format!(
                "request timed out after {}",
                crate::http::format_go_duration(timeout)
            ))),
        }
    } else {
        resolve.await
    }
}

async fn resolve_dns_for_client_inner(
    cli: &Cli,
    url: &Url,
    http_version: Option<HttpVersion>,
    timeout: Option<Duration>,
) -> Result<Option<DnsResolution>, FetchError> {
    let Some(host) = url.host_str() else {
        return Ok(None);
    };
    if host.parse::<IpAddr>().is_ok() || cli.proxy.is_some() || cli.unix.is_some() {
        return Ok(None);
    }

    let debug_dns = (cli.timing || (cli.verbose >= 3 && !cli.silent))
        && !matches!(http_version, Some(HttpVersion::Http3));

    if let Some(dns_server) = cli.dns_server.as_deref() {
        let start = Instant::now();
        let addrs = if dns_server.starts_with("http://") || dns_server.starts_with("https://") {
            let server_url = Url::parse(dns_server).map_err(|err| {
                FetchError::Message(format!("invalid dns-server '{dns_server}': {err}"))
            })?;
            crate::dns::doh::lookup_doh(&server_url, host, timeout)
                .await
                .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))?
        } else {
            let server_addr = crate::dns::resolver::normalize_udp_dns_server(dns_server)
                .map_err(|err| FetchError::Message(err.to_string()))?;
            crate::dns::resolver::lookup_udp(&server_addr, host, timeout)
                .await
                .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))?
        };
        let addrs = sorted_unique_ips(addrs);
        return Ok(Some(DnsResolution {
            socket_addrs: crate::dns::doh::socket_addrs_for_override(&addrs),
            timing: debug_dns.then(|| DnsTiming {
                host: host.to_string(),
                addrs,
                duration: start.elapsed(),
            }),
        }));
    }

    if !debug_dns {
        return Ok(None);
    }

    let port = url.port_or_known_default().unwrap_or_else(|| {
        if url.scheme().eq_ignore_ascii_case("https") {
            443
        } else {
            80
        }
    });
    let start = Instant::now();
    let mut socket_addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))?
        .collect::<Vec<_>>();
    sort_socket_addrs(&mut socket_addrs);
    let addrs = sorted_unique_ips(socket_addrs.iter().map(|addr| addr.ip()).collect());
    Ok(Some(DnsResolution {
        socket_addrs,
        timing: Some(DnsTiming {
            host: host.to_string(),
            addrs,
            duration: start.elapsed(),
        }),
    }))
}

fn configure_dns_resolution(
    builder: reqwest::ClientBuilder,
    host: Option<&str>,
    resolution: Option<&DnsResolution>,
) -> reqwest::ClientBuilder {
    match (host, resolution) {
        (Some(host), Some(resolution)) if !resolution.socket_addrs.is_empty() => {
            builder.resolve_to_addrs(host, &resolution.socket_addrs)
        }
        _ => builder,
    }
}

fn configure_http3_local_address(
    builder: reqwest::ClientBuilder,
    version: Option<HttpVersion>,
    url: &Url,
    resolution: Option<&DnsResolution>,
) -> reqwest::ClientBuilder {
    if !matches!(version, Some(HttpVersion::Http3)) {
        return builder;
    }

    match http3_local_address(url, resolution) {
        Some(addr) => builder.local_address(addr),
        None => builder,
    }
}

pub(crate) fn http3_local_address(url: &Url, resolution: Option<&DnsResolution>) -> Option<IpAddr> {
    let destination_ip = url
        .host_str()
        .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
        .and_then(|host| host.parse::<IpAddr>().ok())
        .or_else(|| resolution?.socket_addrs.first().map(SocketAddr::ip));

    match destination_ip {
        Some(IpAddr::V4(_)) => Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        Some(IpAddr::V6(_)) => Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
        None => None,
    }
}

fn sorted_unique_ips(mut addrs: Vec<IpAddr>) -> Vec<IpAddr> {
    addrs.sort_by(compare_ip_addrs);
    addrs.dedup();
    addrs
}

fn sort_socket_addrs(addrs: &mut [SocketAddr]) {
    addrs.sort_by(|left, right| {
        compare_ip_addrs(&left.ip(), &right.ip()).then_with(|| left.port().cmp(&right.port()))
    });
}

fn compare_ip_addrs(left: &IpAddr, right: &IpAddr) -> std::cmp::Ordering {
    match (left, right) {
        (IpAddr::V4(left), IpAddr::V4(right)) => left.octets().cmp(&right.octets()),
        (IpAddr::V6(left), IpAddr::V6(right)) => left.octets().cmp(&right.octets()),
        (IpAddr::V4(_), IpAddr::V6(_)) => std::cmp::Ordering::Less,
        (IpAddr::V6(_), IpAddr::V4(_)) => std::cmp::Ordering::Greater,
    }
}

pub(crate) fn configure_tls(
    mut builder: reqwest::ClientBuilder,
    cli: &Cli,
) -> Result<reqwest::ClientBuilder, FetchError> {
    let min_tls = cli.min_tls.as_deref().or(cli.tls.as_deref());
    crate::tls::ensure_rustls_supported_range(
        min_tls.map(|value| {
            if cli.min_tls.is_some() {
                ("min-tls", value)
            } else {
                ("tls", value)
            }
        }),
        cli.max_tls.as_deref(),
    )?;
    let min_version = match min_tls {
        Some(value) => crate::tls::reqwest_tls_version(
            if cli.min_tls.is_some() {
                "min-tls"
            } else {
                "tls"
            },
            value,
        )?,
        None => crate::tls::default_min_tls_version(),
    };
    builder = builder.min_tls_version(min_version);
    if let Some(value) = cli.max_tls.as_deref() {
        builder = builder.max_tls_version(crate::tls::reqwest_tls_version("max-tls", value)?);
    }
    for cert in crate::tls::ca_certificates(&cli.ca_cert)? {
        builder = builder.add_root_certificate(cert);
    }
    if let Some(identity) = crate::tls::client_identity(cli.cert.as_deref(), cli.key.as_deref())? {
        builder = builder.identity(identity);
    }
    Ok(builder)
}

fn configure_proxy(
    builder: reqwest::ClientBuilder,
    proxy: Option<&str>,
    version: Option<HttpVersion>,
    url: &Url,
) -> Result<reqwest::ClientBuilder, FetchError> {
    validate_proxy_for_http_version(proxy, version)?;

    if let Some(proxy) = proxy {
        let proxy_config = reqwest::Proxy::all(proxy)
            .map_err(|err| FetchError::Message(format!("invalid proxy '{proxy}': {err}")))?;
        return Ok(builder.proxy(proxy_config));
    }

    if matches!(version, Some(HttpVersion::Http2 | HttpVersion::Http3)) {
        if environment_proxy_for_url(url).is_some() {
            return Err(proxy_http_version_error());
        }
        return Ok(builder);
    }

    configure_environment_proxies(builder)
}

fn configure_environment_proxies(
    mut builder: reqwest::ClientBuilder,
) -> Result<reqwest::ClientBuilder, FetchError> {
    let no_proxy = reqwest::NoProxy::from_env();

    if let Some(proxy) = env_proxy_value(&["HTTP_PROXY", "http_proxy"]) {
        let proxy_config = reqwest::Proxy::http(&proxy)
            .map_err(|err| FetchError::Message(format!("invalid proxy '{proxy}': {err}")))?
            .no_proxy(no_proxy.clone());
        builder = builder.proxy(proxy_config);
    }

    if let Some(proxy) = env_proxy_value(&["HTTPS_PROXY", "https_proxy"]) {
        let proxy_config = reqwest::Proxy::https(&proxy)
            .map_err(|err| FetchError::Message(format!("invalid proxy '{proxy}': {err}")))?
            .no_proxy(no_proxy.clone());
        builder = builder.proxy(proxy_config);
    }

    if let Some(proxy) = env_proxy_value(&["ALL_PROXY", "all_proxy"]) {
        let proxy_config = reqwest::Proxy::all(&proxy)
            .map_err(|err| FetchError::Message(format!("invalid proxy '{proxy}': {err}")))?
            .no_proxy(no_proxy);
        builder = builder.proxy(proxy_config);
    }

    Ok(builder)
}

fn env_proxy_value(keys: &[&str]) -> Option<String> {
    for key in keys {
        if *key == "HTTP_PROXY"
            && env::var("REQUEST_METHOD")
                .map(|value| !value.is_empty())
                .unwrap_or(false)
        {
            continue;
        }
        let Ok(value) = env::var(key) else {
            continue;
        };
        if !value.trim().is_empty() {
            return Some(value);
        }
    }
    None
}

fn environment_proxy_for_url(url: &Url) -> Option<String> {
    if no_proxy_matches_url(url, env_no_proxy_value().as_deref()) {
        return None;
    }

    match url.scheme() {
        "http" => env_proxy_value(&["HTTP_PROXY", "http_proxy"])
            .or_else(|| env_proxy_value(&["ALL_PROXY", "all_proxy"])),
        "https" => env_proxy_value(&["HTTPS_PROXY", "https_proxy"])
            .or_else(|| env_proxy_value(&["ALL_PROXY", "all_proxy"])),
        _ => env_proxy_value(&["ALL_PROXY", "all_proxy"]),
    }
}

fn env_no_proxy_value() -> Option<String> {
    env::var("NO_PROXY").or_else(|_| env::var("no_proxy")).ok()
}

pub(crate) fn no_proxy_matches_url(url: &Url, no_proxy: Option<&str>) -> bool {
    let Some(no_proxy) = no_proxy else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    no_proxy.split(',').any(|entry| {
        let entry = entry.trim();
        if entry == "*" {
            return true;
        }
        if entry.is_empty() {
            return false;
        }
        let entry = entry.trim_start_matches('.').to_ascii_lowercase();
        host == entry
            || host
                .strip_suffix(&entry)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

fn configure_http_version(
    builder: reqwest::ClientBuilder,
    mode: ClientMode,
) -> reqwest::ClientBuilder {
    match mode {
        ClientMode::Request(Some(HttpVersion::Http1)) => builder.http1_only(),
        ClientMode::Request(Some(HttpVersion::Http2)) | ClientMode::GrpcReflection => {
            builder.http2_prior_knowledge()
        }
        ClientMode::Request(Some(HttpVersion::Http3)) => builder.http3_prior_knowledge(),
        ClientMode::Request(None) => builder,
    }
}

pub(crate) fn validate_proxy_for_http_version(
    proxy: Option<&str>,
    version: Option<HttpVersion>,
) -> Result<(), FetchError> {
    if proxy.is_some() && matches!(version, Some(HttpVersion::Http2 | HttpVersion::Http3)) {
        return Err(proxy_http_version_error());
    }
    Ok(())
}

fn proxy_http_version_error() -> FetchError {
    "a proxy can only be used with HTTP/1.1".into()
}

#[derive(Clone, Default)]
pub(crate) struct ConnectionTiming {
    duration: Arc<Mutex<Option<Duration>>>,
}

impl ConnectionTiming {
    pub(crate) fn clear(&self) {
        if let Ok(mut duration) = self.duration.lock() {
            *duration = None;
        }
    }

    fn set(&self, value: Duration) {
        if let Ok(mut duration) = self.duration.lock() {
            *duration = Some(value);
        }
    }

    pub(crate) fn duration(&self) -> Option<Duration> {
        self.duration.lock().ok().and_then(|duration| *duration)
    }
}

#[derive(Clone)]
struct ConnectionTimingLayer {
    timing: ConnectionTiming,
}

impl ConnectionTimingLayer {
    fn new(timing: ConnectionTiming) -> Self {
        Self { timing }
    }
}

impl<S> Layer<S> for ConnectionTimingLayer {
    type Service = ConnectionTimingService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ConnectionTimingService {
            inner,
            timing: self.timing.clone(),
        }
    }
}

#[derive(Clone)]
struct ConnectionTimingService<S> {
    inner: S,
    timing: ConnectionTiming,
}

impl<S, Request> Service<Request> for ConnectionTimingService<S>
where
    S: Service<Request> + Clone + Send + Sync + 'static,
    S::Future: Send + 'static,
    S::Response: Send + 'static,
    S::Error: Send + 'static,
    Request: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let mut inner = self.inner.clone();
        let timing = self.timing.clone();
        Box::pin(async move {
            let start = Instant::now();
            let result = inner.call(request).await;
            if result.is_ok() {
                timing.set(start.elapsed());
            }
            result
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http3_local_address_matches_ip_literal_family() {
        let ipv4_url = Url::parse("https://127.0.0.1:3000/").unwrap();
        assert_eq!(
            http3_local_address(&ipv4_url, None),
            Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        );

        let ipv6_url = Url::parse("https://[::1]:3000/").unwrap();
        assert_eq!(
            http3_local_address(&ipv6_url, None),
            Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
        );
    }

    #[test]
    fn proxy_rejects_http2_and_http3_like_go_app() {
        let err = validate_proxy_for_http_version(
            Some("http://proxy.example:8080"),
            Some(HttpVersion::Http2),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "a proxy can only be used with HTTP/1.1");

        let err = validate_proxy_for_http_version(
            Some("http://proxy.example:8080"),
            Some(HttpVersion::Http3),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "a proxy can only be used with HTTP/1.1");
    }

    #[test]
    fn proxy_allows_default_and_http1_like_go_app() {
        validate_proxy_for_http_version(Some("http://proxy.example:8080"), None).unwrap();
        validate_proxy_for_http_version(
            Some("http://proxy.example:8080"),
            Some(HttpVersion::Http1),
        )
        .unwrap();
    }

    #[test]
    fn no_proxy_matching_for_env_proxy_guard() {
        let url = Url::parse("https://api.example.com:443/path").unwrap();

        assert!(no_proxy_matches_url(&url, Some("*")));
        assert!(no_proxy_matches_url(&url, Some("example.com")));
        assert!(no_proxy_matches_url(&url, Some(".example.com")));
        assert!(no_proxy_matches_url(&url, Some("EXAMPLE.COM")));
        assert!(no_proxy_matches_url(
            &url,
            Some("localhost, api.example.com")
        ));
        assert!(!no_proxy_matches_url(&url, Some("notexample.com")));
        assert!(!no_proxy_matches_url(&url, Some("")));
        assert!(!no_proxy_matches_url(&url, None));
    }

    #[test]
    fn socks_proxy_urls_are_accepted_by_reqwest_feature() {
        reqwest::Proxy::all("socks5://127.0.0.1:1080").unwrap();
        reqwest::Proxy::http("socks5://127.0.0.1:1080").unwrap();
        reqwest::Proxy::all("socks5h://localhost:1080").unwrap();
    }
}
