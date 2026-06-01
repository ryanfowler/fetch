use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ipnet::IpNet;
use url::Url;

use super::transport::{Client, ClientBuilder, NoProxy, Proxy, redirect};
use crate::cli::{Cli, HttpVersion};
use crate::dns::custom;
use crate::duration::{TimeoutBudget, request_timeout_message};
use crate::error::FetchError;
use crate::timing::{DnsTiming, TransportTiming};

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
    let dns_timeout = TimeoutBudget::for_connect(
        context.connect_timeout,
        context.request_timeout,
        context.request_start,
    )?
    .timeout();
    let dns_resolution = resolve_dns_for_client(cli, url, dns_timeout).await?;
    let mut builder = Client::builder()
        .use_rustls_tls()
        .no_brotli()
        .no_gzip()
        .no_zstd();
    builder = configure_http_version(builder, context.mode);
    builder = configure_unix_socket(builder, cli.unix.as_deref())?;
    builder = configure_http3_local_address(builder, http_version, url);
    builder = configure_dns_resolution(builder, url.host_str(), dns_resolution.as_ref());
    if let Some(connect_timing) = context.connect_timing
        && (cli.timing || (cli.verbose >= 3 && !cli.silent))
    {
        builder = builder.connection_timing(connect_timing.clone());
    }
    if should_configure_tls(cli, url) {
        builder = configure_tls(builder, cli)?;
    }
    builder = configure_proxy(builder, cli.proxy.as_deref(), http_version, url)?;
    if let Some(timeout) =
        TimeoutBudget::started_at(context.request_timeout, context.request_start).remaining()?
    {
        let timeout_message = context
            .request_timeout
            .map(request_timeout_message)
            .unwrap_or_else(|| request_timeout_message(timeout));
        builder = builder.timeout_with_message(timeout, timeout_message);
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
    builder: ClientBuilder,
    path: Option<&str>,
) -> Result<ClientBuilder, FetchError> {
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

async fn resolve_dns_for_client(
    cli: &Cli,
    url: &Url,
    timeout: Option<Duration>,
) -> Result<Option<DnsResolution>, FetchError> {
    let resolve = resolve_dns_for_client_inner(cli, url, timeout);
    TimeoutBudget::new(timeout).run(resolve).await
}

async fn resolve_dns_for_client_inner(
    cli: &Cli,
    url: &Url,
    timeout: Option<Duration>,
) -> Result<Option<DnsResolution>, FetchError> {
    let Some(host) = url.host_str() else {
        return Ok(None);
    };
    if host.parse::<IpAddr>().is_ok()
        || cli.unix.is_some()
        || cli
            .proxy
            .as_deref()
            .is_some_and(|proxy| !proxy_uses_local_target_dns(proxy))
    {
        return Ok(None);
    }

    let debug_dns = cli.timing || (cli.verbose >= 3 && !cli.silent);

    if let Some(dns_server) = cli.dns_server.as_deref() {
        let start = Instant::now();
        let addrs = custom::lookup_ips(dns_server, host, timeout).await?;
        let timing_addrs = dns_timing_addrs(addrs.iter().copied());
        return Ok(Some(DnsResolution {
            socket_addrs: custom::socket_addrs_for_override(&addrs),
            timing: debug_dns.then(|| DnsTiming {
                host: host.to_string(),
                addrs: timing_addrs,
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
    let socket_addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))?
        .collect::<Vec<_>>();
    let addrs = dns_timing_addrs(socket_addrs.iter().map(|addr| addr.ip()));
    Ok(Some(DnsResolution {
        socket_addrs,
        timing: Some(DnsTiming {
            host: host.to_string(),
            addrs,
            duration: start.elapsed(),
        }),
    }))
}

fn dns_timing_addrs(addrs: impl IntoIterator<Item = IpAddr>) -> Vec<IpAddr> {
    let mut unique = Vec::new();
    for addr in addrs {
        if !unique.contains(&addr) {
            unique.push(addr);
        }
    }
    unique
}

fn configure_dns_resolution(
    builder: ClientBuilder,
    host: Option<&str>,
    resolution: Option<&DnsResolution>,
) -> ClientBuilder {
    match (host, resolution) {
        (Some(host), Some(resolution)) if !resolution.socket_addrs.is_empty() => {
            builder.resolve_to_addrs(host, &resolution.socket_addrs)
        }
        _ => builder,
    }
}

fn configure_http3_local_address(
    builder: ClientBuilder,
    version: Option<HttpVersion>,
    url: &Url,
) -> ClientBuilder {
    if !matches!(version, Some(HttpVersion::Http3)) {
        return builder;
    }

    match http3_local_address(url) {
        Some(addr) => builder.local_address(addr),
        None => builder,
    }
}

pub(crate) fn http3_local_address(url: &Url) -> Option<IpAddr> {
    let destination_ip = url
        .host_str()
        .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
        .and_then(|host| host.parse::<IpAddr>().ok());

    match destination_ip {
        Some(IpAddr::V4(_)) => Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        Some(IpAddr::V6(_)) => Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
        None => None,
    }
}

pub(crate) fn configure_tls(
    mut builder: ClientBuilder,
    cli: &Cli,
) -> Result<ClientBuilder, FetchError> {
    let min_tls = cli.min_tls.as_deref().or(cli.tls.as_deref());
    let min_tls_option = min_tls.map(|value| {
        if cli.min_tls.is_some() {
            ("min-tls", value)
        } else {
            ("tls", value)
        }
    });
    crate::tls::ensure_rustls_supported_range(min_tls_option, cli.max_tls.as_deref())?;
    builder = builder.tls_config(crate::tls::rustls_platform_client_config_with_options(
        &cli.ca_cert,
        cli.cert.as_deref(),
        cli.key.as_deref(),
        cli.insecure,
        min_tls_option,
        cli.max_tls.as_deref(),
    )?);
    Ok(builder)
}

fn should_configure_tls(cli: &Cli, url: &Url) -> bool {
    url.scheme() == "https"
        || cli.insecure
        || !cli.ca_cert.is_empty()
        || cli.cert.is_some()
        || cli.key.is_some()
        || cli.min_tls.is_some()
        || cli.max_tls.is_some()
        || cli.tls.is_some()
}

fn configure_proxy(
    builder: ClientBuilder,
    proxy: Option<&str>,
    version: Option<HttpVersion>,
    url: &Url,
) -> Result<ClientBuilder, FetchError> {
    validate_proxy_for_http_version(proxy, version)?;

    if let Some(proxy) = proxy {
        let proxy_config = Proxy::all(proxy)
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

fn configure_environment_proxies(mut builder: ClientBuilder) -> Result<ClientBuilder, FetchError> {
    let no_proxy = NoProxy::from_env();

    if let Some(proxy) = env_proxy_value(&["HTTP_PROXY", "http_proxy"]) {
        let proxy_config = Proxy::http(&proxy)
            .map_err(|err| FetchError::Message(format!("invalid proxy '{proxy}': {err}")))?
            .no_proxy(no_proxy.clone());
        builder = builder.proxy(proxy_config);
    }

    if let Some(proxy) = env_proxy_value(&["HTTPS_PROXY", "https_proxy"]) {
        let proxy_config = Proxy::https(&proxy)
            .map_err(|err| FetchError::Message(format!("invalid proxy '{proxy}': {err}")))?
            .no_proxy(no_proxy.clone());
        builder = builder.proxy(proxy_config);
    }

    if let Some(proxy) = env_proxy_value(&["ALL_PROXY", "all_proxy"]) {
        let proxy_config = Proxy::all(&proxy)
            .map_err(|err| FetchError::Message(format!("invalid proxy '{proxy}': {err}")))?
            .no_proxy(no_proxy);
        builder = builder.proxy(proxy_config);
    }

    builder = builder.proxy(Proxy::system());

    Ok(builder)
}

pub(crate) fn proxy_uses_local_target_dns(proxy: &str) -> bool {
    crate::net::parse_proxy_url(proxy).is_ok_and(|url| url.scheme() == "socks5")
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
            .or_else(|| env_proxy_value(&["ALL_PROXY", "all_proxy"]))
            .or_else(|| Proxy::system().matches_url(url).then(String::new)),
        "https" => env_proxy_value(&["HTTPS_PROXY", "https_proxy"])
            .or_else(|| env_proxy_value(&["ALL_PROXY", "all_proxy"]))
            .or_else(|| Proxy::system().matches_url(url).then(String::new)),
        _ => env_proxy_value(&["ALL_PROXY", "all_proxy"])
            .or_else(|| Proxy::system().matches_url(url).then(String::new)),
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
    let host_ip = host.parse::<IpAddr>().ok();
    no_proxy.split(',').any(|entry| {
        let entry = entry.trim();
        if entry == "*" {
            return true;
        }
        if entry.is_empty() {
            return false;
        }
        if let Some(host_ip) = host_ip {
            return entry
                .parse::<IpNet>()
                .is_ok_and(|network| network.contains(&host_ip))
                || entry.parse::<IpAddr>().is_ok_and(|ip| ip == host_ip);
        }
        let entry = entry.trim_start_matches('.').to_ascii_lowercase();
        host == entry
            || host
                .strip_suffix(&entry)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

fn configure_http_version(builder: ClientBuilder, mode: ClientMode) -> ClientBuilder {
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
    timing: Arc<Mutex<Option<TransportTiming>>>,
}

impl ConnectionTiming {
    pub(crate) fn clear(&self) {
        if let Ok(mut timing) = self.timing.lock() {
            *timing = None;
        }
    }

    pub(crate) fn set(&self, value: TransportTiming) {
        if let Ok(mut timing) = self.timing.lock() {
            *timing = Some(value);
        }
    }

    pub(crate) fn timing(&self) -> Option<TransportTiming> {
        self.timing.lock().ok().and_then(|timing| *timing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn dns_timing_addrs_preserve_resolver_order_and_dedupe_display_addrs() {
        let addrs = [
            "::2".parse().unwrap(),
            "127.0.0.2".parse().unwrap(),
            "::1".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
            "::2".parse().unwrap(),
        ];

        let display_addrs = dns_timing_addrs(addrs);

        assert_eq!(
            display_addrs,
            [
                "::2".parse().unwrap(),
                "127.0.0.2".parse().unwrap(),
                "::1".parse().unwrap(),
                "127.0.0.1".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn http3_local_address_matches_ip_literal_family() {
        let ipv4_url = Url::parse("https://127.0.0.1:3000/").unwrap();
        assert_eq!(
            http3_local_address(&ipv4_url),
            Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        );

        let ipv6_url = Url::parse("https://[::1]:3000/").unwrap();
        assert_eq!(
            http3_local_address(&ipv6_url),
            Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
        );
    }

    #[test]
    fn http3_local_address_uses_dual_stack_bind_for_named_hosts() {
        let url = Url::parse("https://localhost:3000/").unwrap();

        assert_eq!(http3_local_address(&url), None);
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
    fn no_proxy_matching_supports_ip_and_cidr_entries() {
        let ipv4_url = Url::parse("https://192.168.1.42/api").unwrap();
        let ipv6_url = Url::parse("https://[fd00::42]/api").unwrap();

        assert!(no_proxy_matches_url(&ipv4_url, Some("192.168.1.42")));
        assert!(no_proxy_matches_url(&ipv4_url, Some("192.168.1.0/24")));
        assert!(!no_proxy_matches_url(&ipv4_url, Some(".192.168.1.42")));
        assert!(no_proxy_matches_url(
            &ipv4_url,
            Some("10.0.0.0/8, 192.168.0.0/16")
        ));
        assert!(!no_proxy_matches_url(&ipv4_url, Some("192.168.2.0/24")));

        assert!(no_proxy_matches_url(&ipv6_url, Some("fd00::42")));
        assert!(no_proxy_matches_url(&ipv6_url, Some("fd00::/8")));
        assert!(!no_proxy_matches_url(&ipv6_url, Some("fe80::/10")));
    }

    #[test]
    fn socks_proxy_urls_are_accepted_by_transport_adapter() {
        Proxy::all("socks5://127.0.0.1:1080").unwrap();
        Proxy::http("socks5://127.0.0.1:1080").unwrap();
        Proxy::all("socks5h://localhost:1080").unwrap();
    }
    #[test]
    fn regular_http_rejects_legacy_tls_versions_on_rustls_path() {
        let cli =
            Cli::try_parse_from(["fetch", "--min-tls", "1.0", "https://example.com"]).unwrap();

        let err = configure_tls(Client::builder().use_rustls_tls(), &cli).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid value '1.0' for option '--min-tls': must be one of [1.2, 1.3]"
        );

        let cli =
            Cli::try_parse_from(["fetch", "--max-tls", "1.1", "https://example.com"]).unwrap();

        let err = configure_tls(Client::builder().use_rustls_tls(), &cli).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid value '1.1' for option '--max-tls': must be one of [1.2, 1.3]"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_socket_configures_transport_builder_on_unix() {
        assert!(configure_unix_socket(Client::builder(), Some("/tmp/fetch.sock")).is_ok());
    }
}
