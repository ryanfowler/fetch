use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ipnet::IpNet;
use tokio::task::JoinHandle;
use url::Url;

use super::http3_cache::Http3Cache;
use super::transport::{AutoHttp3Config, Client, ClientBuilder, NoProxy, Proxy, redirect};
use crate::cli::{Cli, HttpVersion};
use crate::dns::custom;
use crate::dns::svcb::{HttpsRecordResolver, SvcbRecord};
use crate::duration::{TimeoutBudget, request_timeout_message};
use crate::error::FetchError;
use crate::timing::{DnsTiming, TransportTiming};
use rustls::client::EchMode;

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
    pub(crate) runtime_dns_resolution: Option<DnsResolutionHandle>,
}

impl UrlClient {
    pub(crate) fn clear_runtime_dns_resolution(&self) {
        if let Some(resolution) = &self.runtime_dns_resolution {
            resolution.clear();
        }
    }

    pub(crate) fn current_dns_resolution(&self) -> Option<DnsResolution> {
        self.runtime_dns_resolution
            .as_ref()
            .and_then(DnsResolutionHandle::resolution)
            .or_else(|| self.dns_resolution.clone())
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct EffectiveProxy {
    uses_local_target_dns: bool,
}

impl EffectiveProxy {
    pub(crate) fn uses_local_target_dns(self) -> bool {
        self.uses_local_target_dns
    }
}

pub(crate) struct ClientBuildContext<'a> {
    pub(crate) mode: ClientMode,
    pub(crate) request_timeout: Option<Duration>,
    pub(crate) connect_timeout: Option<Duration>,
    pub(crate) request_start: Instant,
    pub(crate) session: Option<&'a crate::session::Session>,
    pub(crate) connect_timing: Option<&'a ConnectionTiming>,
}

#[derive(Clone, Debug)]
struct ClientDnsDiscovery {
    dns_resolution: Option<DnsResolution>,
    runtime_dns_resolution: Option<DnsResolutionHandle>,
    dns_server: Option<String>,
    auto_http3: Option<AutoHttp3Config>,
    auto_http3_discovery: bool,
    ech_https_records: Vec<SvcbRecord>,
}

pub(crate) async fn build_client_for_url(
    cli: &Cli,
    url: &Url,
    context: &ClientBuildContext<'_>,
) -> Result<UrlClient, FetchError> {
    let http_version = context.mode.http_version();
    validate_client_auth_for_url(cli, url)?;
    let dns_timeout = TimeoutBudget::for_connect(
        context.connect_timeout,
        context.request_timeout,
        context.request_start,
    )?
    .timeout();
    let effective_proxy = effective_proxy_for_url(cli.proxy.as_deref(), http_version, url)?;
    let auto_http3 = auto_http3_allowed(context.mode, url, cli.unix.as_deref(), effective_proxy);
    let discovery = if dynamic_dns_for_client(cli, url, effective_proxy) {
        let debug_dns = cli.timing || (cli.verbose >= 3 && !cli.silent);
        ClientDnsDiscovery {
            dns_resolution: None,
            runtime_dns_resolution: debug_dns.then(DnsResolutionHandle::default),
            dns_server: cli.dns_server.clone(),
            auto_http3: None,
            auto_http3_discovery: auto_http3,
            ech_https_records: Vec::new(),
        }
    } else {
        resolve_dns_for_client(cli, url, dns_timeout, effective_proxy, auto_http3).await?
    };
    // Resolve ECH mode before extracting fields from discovery
    let ech_mode = if should_configure_tls(cli, url) {
        resolve_ech_mode(cli, &discovery)?
    } else {
        None
    };
    let dns_resolution = discovery.dns_resolution;
    let runtime_dns_resolution = discovery.runtime_dns_resolution;
    let auto_http3_config = discovery.auto_http3;
    let auto_http3_discovery = discovery.auto_http3_discovery;
    let dns_server = discovery.dns_server;
    let mut builder = Client::builder()
        .use_rustls_tls()
        .no_brotli()
        .no_gzip()
        .no_zstd();
    builder = configure_http_version(builder, context.mode);
    builder = configure_unix_socket(builder, cli.unix.as_deref())?;
    builder = configure_http3_local_address(builder, http_version, url);
    if let Some(auto_http3) = auto_http3_config {
        builder = builder.auto_http3(auto_http3);
    }
    if auto_http3_discovery {
        builder = builder.auto_http3_discovery();
    }
    if auto_http3 {
        let cache = Http3Cache::new();
        if cache.is_enabled() {
            builder = builder.http3_cache(Arc::new(cache), !cli.insecure);
        }
    }
    if let Some(dns_server) = dns_server {
        builder = builder.dns_server(dns_server);
    }
    if let Some(resolution) = &runtime_dns_resolution {
        builder = builder.dns_resolution(resolution.clone());
    }
    builder = configure_dns_resolution(builder, url.host_str(), dns_resolution.as_ref());
    if let Some(connect_timing) = context.connect_timing
        && (cli.timing || (cli.verbose >= 3 && !cli.silent))
    {
        builder = builder.connection_timing(connect_timing.clone());
    }
    if should_configure_tls(cli, url) {
        let hard_fail = matches!(cli.ech.as_deref(), Some("on"));
        builder = builder.ech_hard_fail(hard_fail);
        builder = configure_tls(builder, cli, ech_mode)?;
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
        runtime_dns_resolution,
    })
}

fn validate_client_auth_for_url(cli: &Cli, url: &Url) -> Result<(), FetchError> {
    if url.scheme() == "https" {
        crate::tls::validate_client_auth_for_tls(cli.cert.as_deref(), cli.key.as_deref())?;
    }
    Ok(())
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
    effective_proxy: Option<EffectiveProxy>,
    auto_http3: bool,
) -> Result<ClientDnsDiscovery, FetchError> {
    let timeout = TimeoutBudget::new(timeout);
    let resolve = resolve_dns_for_client_inner(cli, url, timeout, effective_proxy, auto_http3);
    timeout.run(resolve).await
}

async fn resolve_dns_for_client_inner(
    cli: &Cli,
    url: &Url,
    timeout: TimeoutBudget,
    effective_proxy: Option<EffectiveProxy>,
    auto_http3: bool,
) -> Result<ClientDnsDiscovery, FetchError> {
    let need_ech_svcb = url.scheme() == "https" && is_ech_active(cli);
    let need_svcb = auto_http3 || need_ech_svcb;
    let Some(host) = url.host_str() else {
        return Ok(ClientDnsDiscovery {
            dns_resolution: None,
            runtime_dns_resolution: None,
            dns_server: None,
            auto_http3: None,
            auto_http3_discovery: false,
            ech_https_records: Vec::new(),
        });
    };
    if host.parse::<IpAddr>().is_ok() || cli.unix.is_some() {
        return Ok(ClientDnsDiscovery {
            dns_resolution: None,
            runtime_dns_resolution: None,
            dns_server: None,
            auto_http3: None,
            auto_http3_discovery: false,
            ech_https_records: Vec::new(),
        });
    }
    // Proxy resolves target addresses remotely: skip A/AAAA but still
    // query HTTPS/SVCB records when ECH is active so the client can
    // discover the server's ECH configuration. Do not enable auto-H3
    // through a proxy; auto_http3_allowed already blocks that path.
    if effective_proxy.is_some_and(|proxy| !proxy.uses_local_target_dns()) {
        if need_ech_svcb {
            let ech_timeout = timeout
                .remaining()
                .ok()
                .flatten()
                .unwrap_or(Duration::from_secs(5));
            let https_records = if let Some(dns_server) = cli.dns_server.as_deref() {
                lookup_ech_https_records(Some(dns_server), host, ech_timeout).await
            } else {
                lookup_ech_https_records(None, host, ech_timeout).await
            };
            return Ok(ClientDnsDiscovery {
                dns_resolution: None,
                runtime_dns_resolution: None,
                dns_server: None,
                auto_http3: None,
                auto_http3_discovery: false,
                ech_https_records: https_records,
            });
        }
        return Ok(ClientDnsDiscovery {
            dns_resolution: None,
            runtime_dns_resolution: None,
            dns_server: None,
            auto_http3: None,
            auto_http3_discovery: false,
            ech_https_records: Vec::new(),
        });
    }

    let debug_dns = cli.timing || (cli.verbose >= 3 && !cli.silent);
    let auto_http3_discovery = auto_http3
        .then(|| AutoHttp3DiscoveryBudget::new(timeout))
        .flatten();

    if let Some(dns_server) = cli.dns_server.as_deref() {
        let start = Instant::now();
        let (addrs, https_records) = if need_ech_svcb {
            // ECH requires HTTPS records; don't use the abort-early auto-H3
            // pattern which may discard them before the SVCB query finishes.
            let ech_timeout = timeout
                .remaining()
                .ok()
                .flatten()
                .unwrap_or(Duration::from_secs(5));
            let https_records = lookup_ech_https_records(Some(dns_server), host, ech_timeout).await;
            let addrs = custom::lookup_ips(dns_server, host, timeout.timeout()).await;
            (addrs?, https_records)
        } else if let Some(auto_http3_budget) = auto_http3_discovery {
            let https = spawn_auto_http3_https_records(
                Some(dns_server.to_string()),
                host.to_string(),
                Some(auto_http3_budget),
            );
            let addrs = custom::lookup_ips(dns_server, host, timeout.timeout()).await;
            let https_records = take_finished_auto_http3_https_records(https).await;
            (addrs?, https_records)
        } else {
            (
                custom::lookup_ips(dns_server, host, timeout.timeout()).await?,
                Vec::new(),
            )
        };
        let timing_addrs = dns_timing_addrs(addrs.iter().copied());
        let socket_addrs = custom::socket_addrs_for_override(&addrs);
        let auto_http3_config = auto_http3_config_for_records(
            Some(dns_server),
            url,
            &https_records,
            &socket_addrs,
            auto_http3_discovery,
            false,
        )
        .await;
        if auto_http3 {
            Http3Cache::new().store_https_records(url, Some(dns_server), &https_records);
        }
        return Ok(ClientDnsDiscovery {
            dns_resolution: Some(DnsResolution {
                socket_addrs,
                timing: debug_dns.then(|| DnsTiming {
                    host: host.to_string(),
                    addrs: timing_addrs,
                    duration: start.elapsed(),
                }),
            }),
            runtime_dns_resolution: None,
            dns_server: None,
            auto_http3: auto_http3_config,
            auto_http3_discovery: false,
            ech_https_records: https_records,
        });
    }

    if !debug_dns && !need_svcb {
        return Ok(ClientDnsDiscovery {
            dns_resolution: None,
            runtime_dns_resolution: None,
            dns_server: None,
            auto_http3: None,
            auto_http3_discovery: false,
            ech_https_records: Vec::new(),
        });
    }

    let port = url.port_or_known_default().unwrap_or_else(|| {
        if url.scheme().eq_ignore_ascii_case("https") {
            443
        } else {
            80
        }
    });
    let start = Instant::now();
    let lookup = tokio::net::lookup_host((host, port));
    let (socket_addrs, https_records) = if need_ech_svcb {
        // ECH requires HTTPS records; await the SVCB query properly instead
        // of using the abort-early auto-H3 pattern.
        let ech_timeout = timeout
            .remaining()
            .ok()
            .flatten()
            .unwrap_or(Duration::from_secs(5));
        let https_records = lookup_ech_https_records(None, host, ech_timeout).await;
        let socket_addrs = lookup.await;
        (
            socket_addrs
                .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))?
                .collect::<Vec<_>>(),
            https_records,
        )
    } else if let Some(auto_http3_budget) = auto_http3_discovery {
        let https = spawn_auto_http3_https_records(None, host.to_string(), Some(auto_http3_budget));
        let socket_addrs = lookup.await;
        let https_records = take_finished_auto_http3_https_records(https).await;
        (
            socket_addrs
                .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))?
                .collect::<Vec<_>>(),
            https_records,
        )
    } else {
        (
            lookup
                .await
                .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))?
                .collect::<Vec<_>>(),
            Vec::new(),
        )
    };
    let addrs = dns_timing_addrs(socket_addrs.iter().map(|addr| addr.ip()));
    let auto_http3_config = auto_http3_config_for_records(
        None,
        url,
        &https_records,
        &socket_addrs,
        auto_http3_discovery,
        false,
    )
    .await;
    if auto_http3 {
        Http3Cache::new().store_https_records(url, None, &https_records);
    }
    Ok(ClientDnsDiscovery {
        dns_resolution: Some(DnsResolution {
            socket_addrs,
            timing: debug_dns.then(|| DnsTiming {
                host: host.to_string(),
                addrs,
                duration: start.elapsed(),
            }),
        }),
        runtime_dns_resolution: None,
        dns_server: None,
        auto_http3: auto_http3_config,
        auto_http3_discovery: false,
        ech_https_records: https_records,
    })
}

fn dynamic_dns_for_client(cli: &Cli, url: &Url, effective_proxy: Option<EffectiveProxy>) -> bool {
    url.host_str()
        .is_some_and(|host| host.parse::<IpAddr>().is_err())
        && cli.unix.is_none()
        && effective_proxy.is_none()
        && !is_ech_active(cli)
}

fn is_ech_active(cli: &Cli) -> bool {
    crate::tls::ech::is_ech_active(cli)
}

fn resolve_ech_mode(
    cli: &Cli,
    discovery: &ClientDnsDiscovery,
) -> Result<Option<EchMode>, FetchError> {
    let candidates = ech_candidates_from_records(&discovery.ech_https_records);
    crate::tls::ech::resolve_ech_mode(cli, &candidates)
}

/// Extract ECH candidate byte slices from SVCB records, filtered and sorted
/// by SvcPriority. Excludes alias-mode (priority 0) and records with
/// unsupported mandatory parameters.
fn ech_candidates_from_records(records: &[SvcbRecord]) -> Vec<&[u8]> {
    let mut usable: Vec<&SvcbRecord> = records
        .iter()
        .filter(|r| !r.is_alias_mode() && r.is_usable())
        .collect();
    // Lower priority values are more preferred (RFC 9460 §2.4.2).
    usable.sort_by_key(|r| r.priority);
    usable
        .iter()
        .filter_map(|r| r.ech.as_deref().filter(|b| !b.is_empty()))
        .collect()
}

async fn lookup_auto_http3_https_records(
    dns_server: Option<&str>,
    host: &str,
    discovery_budget: Option<AutoHttp3DiscoveryBudget>,
) -> Vec<SvcbRecord> {
    let Some(timeout) = discovery_budget.and_then(AutoHttp3DiscoveryBudget::remaining) else {
        return Vec::new();
    };
    let resolver = dns_server
        .map(HttpsRecordResolver::Custom)
        .unwrap_or(HttpsRecordResolver::System);
    tokio::time::timeout(
        timeout,
        crate::dns::svcb::lookup_https_records(resolver, host, Some(timeout)),
    )
    .await
    .ok()
    .and_then(Result::ok)
    .unwrap_or_default()
}

async fn lookup_ech_https_records(
    dns_server: Option<&str>,
    host: &str,
    timeout: Duration,
) -> Vec<SvcbRecord> {
    let resolver = dns_server
        .map(HttpsRecordResolver::Custom)
        .unwrap_or(HttpsRecordResolver::System);
    tokio::time::timeout(
        timeout,
        crate::dns::svcb::lookup_https_records(resolver, host, Some(timeout)),
    )
    .await
    .ok()
    .and_then(Result::ok)
    .unwrap_or_default()
}

fn spawn_auto_http3_https_records(
    dns_server: Option<String>,
    host: String,
    discovery_budget: Option<AutoHttp3DiscoveryBudget>,
) -> JoinHandle<Vec<SvcbRecord>> {
    tokio::spawn(async move {
        lookup_auto_http3_https_records(dns_server.as_deref(), &host, discovery_budget).await
    })
}

async fn take_finished_auto_http3_https_records(
    handle: JoinHandle<Vec<SvcbRecord>>,
) -> Vec<SvcbRecord> {
    if !handle.is_finished() {
        tokio::task::yield_now().await;
    }
    if handle.is_finished() {
        handle.await.unwrap_or_default()
    } else {
        handle.abort();
        Vec::new()
    }
}

#[derive(Clone, Copy, Debug)]
struct AutoHttp3DiscoveryBudget {
    timeout: TimeoutBudget,
}

impl AutoHttp3DiscoveryBudget {
    fn new(timeout: TimeoutBudget) -> Option<Self> {
        auto_http3_optional_lookup_timeout(timeout).map(|timeout| Self {
            timeout: TimeoutBudget::new(Some(timeout)),
        })
    }

    fn remaining(self) -> Option<Duration> {
        self.timeout.remaining().ok().flatten()
    }
}

fn auto_http3_optional_lookup_timeout(timeout: TimeoutBudget) -> Option<Duration> {
    auto_http3_optional_lookup_timeout_for_remaining(timeout.remaining().ok()?)
}

fn auto_http3_optional_lookup_timeout_for_remaining(
    remaining: Option<Duration>,
) -> Option<Duration> {
    let max_lookup = crate::net::HAPPY_EYEBALLS_FALLBACK_DELAY;
    match remaining {
        None => Some(max_lookup),
        Some(timeout) if timeout <= max_lookup => None,
        Some(timeout) => Some((timeout - max_lookup).min(max_lookup)),
    }
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

fn auto_http3_allowed(
    mode: ClientMode,
    url: &Url,
    unix_socket: Option<&str>,
    effective_proxy: Option<EffectiveProxy>,
) -> bool {
    matches!(mode, ClientMode::Request(None))
        && url.scheme() == "https"
        && unix_socket.is_none()
        && effective_proxy.is_none()
        && url
            .host_str()
            .is_some_and(|host| host.parse::<IpAddr>().is_err())
}

async fn auto_http3_config_for_records(
    dns_server: Option<&str>,
    url: &Url,
    records: &[SvcbRecord],
    origin_addrs: &[SocketAddr],
    discovery_budget: Option<AutoHttp3DiscoveryBudget>,
    allow_target_dns_lookup: bool,
) -> Option<AutoHttp3Config> {
    let origin_host = url.host_str()?;
    let origin_port = url.port_or_known_default()?;
    let mut sorted = records.iter().collect::<Vec<_>>();
    sorted.sort_by_key(|record| record.priority);

    let mut addrs = Vec::new();
    for record in sorted {
        if record.is_alias_mode() || !record.is_usable() || !record.advertises_alpn("h3") {
            continue;
        }
        let port = record.port.unwrap_or(origin_port);
        let record_addrs = auto_http3_record_addrs(
            dns_server,
            origin_host,
            record,
            origin_addrs,
            port,
            discovery_budget,
            allow_target_dns_lookup,
        )
        .await;
        append_unique_socket_addrs(&mut addrs, record_addrs);
    }

    (!addrs.is_empty()).then_some(AutoHttp3Config { addrs })
}

async fn auto_http3_record_addrs(
    dns_server: Option<&str>,
    origin_host: &str,
    record: &SvcbRecord,
    origin_addrs: &[SocketAddr],
    port: u16,
    discovery_budget: Option<AutoHttp3DiscoveryBudget>,
    allow_target_dns_lookup: bool,
) -> Vec<SocketAddr> {
    let hinted = auto_http3_hint_addrs(record, origin_addrs, port);
    if !hinted.is_empty() {
        return hinted;
    }

    let target = auto_http3_target_host(origin_host, &record.target);
    if target.eq_ignore_ascii_case(origin_host) && !origin_addrs.is_empty() {
        return origin_addrs
            .iter()
            .map(|addr| SocketAddr::new(addr.ip(), port))
            .collect();
    }
    if let Ok(ip) = target.parse::<IpAddr>() {
        return vec![SocketAddr::new(ip, port)];
    }
    if !allow_target_dns_lookup {
        return Vec::new();
    }
    let Some(timeout) = discovery_budget.and_then(AutoHttp3DiscoveryBudget::remaining) else {
        return Vec::new();
    };
    let timeout = TimeoutBudget::new(Some(timeout));
    let Ok(mut addrs) = timeout
        .run(crate::net::resolve_host(&target, dns_server, timeout))
        .await
    else {
        return Vec::new();
    };
    for addr in &mut addrs {
        addr.set_port(port);
    }
    addrs
}

fn auto_http3_hint_addrs(
    record: &SvcbRecord,
    origin_addrs: &[SocketAddr],
    port: u16,
) -> Vec<SocketAddr> {
    let ipv4 = record
        .ipv4_hint
        .iter()
        .copied()
        .map(|addr| SocketAddr::new(IpAddr::V4(addr), port))
        .collect::<Vec<_>>();
    let ipv6 = record
        .ipv6_hint
        .iter()
        .copied()
        .map(|addr| SocketAddr::new(IpAddr::V6(addr), port))
        .collect::<Vec<_>>();

    match origin_addrs.first().map(|addr| addr.ip()) {
        Some(IpAddr::V4(_)) => crate::net::interleave_socket_addr_families(&ipv4, &ipv6),
        Some(IpAddr::V6(_)) | None => crate::net::interleave_socket_addr_families(&ipv6, &ipv4),
    }
}

fn auto_http3_target_host(origin_host: &str, target: &str) -> String {
    if target == "." {
        origin_host.to_string()
    } else {
        target.trim_end_matches('.').to_string()
    }
}

fn append_unique_socket_addrs(target: &mut Vec<SocketAddr>, addrs: Vec<SocketAddr>) {
    for addr in addrs {
        if !target.contains(&addr) {
            target.push(addr);
        }
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

pub(crate) async fn resolve_websocket_ech_mode(
    cli: &Cli,
    url: &Url,
    timeout: TimeoutBudget,
) -> Result<Option<EchMode>, FetchError> {
    if url.scheme() != "wss" || !is_ech_active(cli) {
        return Ok(None);
    }
    let Some(host) = url.host_str() else {
        return Ok(None);
    };
    if host.parse::<IpAddr>().is_ok() {
        return Ok(None);
    }
    let ech_timeout = timeout
        .remaining()
        .ok()
        .flatten()
        .unwrap_or(Duration::from_secs(5));
    let resolver = cli
        .dns_server
        .as_deref()
        .map(crate::dns::svcb::HttpsRecordResolver::Custom)
        .unwrap_or(crate::dns::svcb::HttpsRecordResolver::System);
    let records = tokio::time::timeout(
        ech_timeout,
        crate::dns::svcb::lookup_https_records(resolver, host, Some(ech_timeout)),
    )
    .await
    .ok()
    .and_then(Result::ok)
    .unwrap_or_default();
    let candidates = ech_candidates_from_records(&records);
    crate::tls::ech::resolve_ech_mode(cli, &candidates)
}

pub(crate) fn configure_tls(
    mut builder: ClientBuilder,
    cli: &Cli,
    ech_mode: Option<EchMode>,
) -> Result<ClientBuilder, FetchError> {
    let min_tls = cli.min_tls.as_deref().or(cli.tls.as_deref());
    let min_tls_option = min_tls.map(|value| {
        if cli.min_tls.is_some() {
            ("min-tls", value)
        } else {
            ("tls", value)
        }
    });
    if ech_mode.is_some() {
        if let Some(min_tls_option) = min_tls_option
            && crate::tls::tls_order(min_tls_option.0, min_tls_option.1).is_ok_and(|o| o < 13)
        {
            return Err(
                "--ech requires TLS 1.3 or higher; use --min-tls 1.3 or remove --ech".into(),
            );
        }
        if let Some(max_tls) = cli.max_tls.as_deref()
            && crate::tls::tls_order("max-tls", max_tls).is_ok_and(|o| o < 13)
        {
            return Err(
                "--ech requires TLS 1.3 or higher; remove --max-tls or use --max-tls 1.3".into(),
            );
        }
    }
    crate::tls::ensure_rustls_supported_range(min_tls_option, cli.max_tls.as_deref())?;
    builder = builder.tls_config(crate::tls::rustls_platform_client_config_with_options(
        &cli.ca_cert,
        cli.cert.as_deref(),
        cli.key.as_deref(),
        cli.insecure,
        min_tls_option,
        cli.max_tls.as_deref(),
        ech_mode,
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

    let proxy_configs = proxy_configs(proxy)?;
    if proxy.is_none()
        && matches!(version, Some(HttpVersion::Http2 | HttpVersion::Http3))
        && effective_proxy_from_configs(&proxy_configs, url).is_some()
    {
        return Err(proxy_http_version_error());
    }

    Ok(configure_proxy_configs(builder, proxy_configs))
}

pub(crate) fn effective_proxy_for_url(
    proxy: Option<&str>,
    version: Option<HttpVersion>,
    url: &Url,
) -> Result<Option<EffectiveProxy>, FetchError> {
    validate_proxy_for_http_version(proxy, version)?;
    let proxy_configs = proxy_configs(proxy)?;
    let effective_proxy = effective_proxy_from_configs(&proxy_configs, url);
    if proxy.is_none()
        && matches!(version, Some(HttpVersion::Http2 | HttpVersion::Http3))
        && effective_proxy.is_some()
    {
        return Err(proxy_http_version_error());
    }
    Ok(effective_proxy)
}

fn effective_proxy_from_configs(proxy_configs: &[Proxy], url: &Url) -> Option<EffectiveProxy> {
    proxy_configs
        .iter()
        .find_map(|proxy| proxy.selected_for_url(url))
        .map(|proxy| EffectiveProxy {
            uses_local_target_dns: proxy.uses_local_target_dns(),
        })
}

fn proxy_configs(proxy: Option<&str>) -> Result<Vec<Proxy>, FetchError> {
    if let Some(proxy) = proxy {
        let proxy_config = Proxy::all(proxy).map_err(|err| invalid_proxy_error(proxy, err))?;
        return Ok(vec![proxy_config]);
    }

    environment_proxy_configs()
}

fn environment_proxy_configs() -> Result<Vec<Proxy>, FetchError> {
    let mut proxies = Vec::new();
    let no_proxy = NoProxy::from_env();

    if let Some(proxy) = env_proxy_value(&["HTTP_PROXY", "http_proxy"]) {
        let proxy_config = Proxy::http(&proxy)
            .map_err(|err| invalid_proxy_error(&proxy, err))?
            .no_proxy(no_proxy.clone());
        proxies.push(proxy_config);
    }

    if let Some(proxy) = env_proxy_value(&["HTTPS_PROXY", "https_proxy"]) {
        let proxy_config = Proxy::https(&proxy)
            .map_err(|err| invalid_proxy_error(&proxy, err))?
            .no_proxy(no_proxy.clone());
        proxies.push(proxy_config);
    }

    if let Some(proxy) = env_proxy_value(&["ALL_PROXY", "all_proxy"]) {
        let proxy_config = Proxy::all(&proxy)
            .map_err(|err| invalid_proxy_error(&proxy, err))?
            .no_proxy(no_proxy);
        proxies.push(proxy_config);
    }

    proxies.push(Proxy::system());

    Ok(proxies)
}

fn configure_proxy_configs(mut builder: ClientBuilder, proxy_configs: Vec<Proxy>) -> ClientBuilder {
    for proxy_config in proxy_configs {
        builder = builder.proxy(proxy_config);
    }
    builder
}

fn invalid_proxy_error(proxy: &str, err: impl std::fmt::Display) -> FetchError {
    FetchError::Message(format!("invalid proxy '{proxy}': {err}"))
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
    let url_port = url.port_or_known_default();
    no_proxy.split(',').any(|entry| {
        let entry = entry.trim();
        if entry == "*" {
            return true;
        }
        let Some(entry) = parse_no_proxy_entry(entry) else {
            return false;
        };
        if entry
            .port
            .is_some_and(|entry_port| url_port != Some(entry_port))
        {
            return false;
        }
        no_proxy_host_matches(&host, host_ip, entry.host)
    })
}

struct ParsedNoProxyEntry<'a> {
    host: &'a str,
    port: Option<u16>,
}

fn parse_no_proxy_entry(entry: &str) -> Option<ParsedNoProxyEntry<'_>> {
    if entry.is_empty() {
        return None;
    }

    if let Some(rest) = entry.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        let port = match tail.strip_prefix(':') {
            Some(port) if !port.is_empty() => Some(port.parse().ok()?),
            Some(_) => return None,
            None if tail.is_empty() => None,
            None => return None,
        };
        return Some(ParsedNoProxyEntry { host, port });
    }

    if entry.bytes().filter(|byte| *byte == b':').count() == 1 {
        let (host, port) = entry.split_once(':')?;
        if host.is_empty() || port.is_empty() {
            return None;
        }
        return Some(ParsedNoProxyEntry {
            host,
            port: Some(port.parse().ok()?),
        });
    }

    Some(ParsedNoProxyEntry {
        host: entry,
        port: None,
    })
}

fn no_proxy_host_matches(host: &str, host_ip: Option<IpAddr>, entry: &str) -> bool {
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

#[derive(Clone, Debug, Default)]
pub(crate) struct DnsResolutionHandle {
    resolution: Arc<Mutex<Option<DnsResolution>>>,
}

impl DnsResolutionHandle {
    pub(crate) fn clear(&self) {
        if let Ok(mut resolution) = self.resolution.lock() {
            *resolution = None;
        }
    }

    pub(crate) fn set(&self, value: DnsResolution) {
        if let Ok(mut resolution) = self.resolution.lock() {
            *resolution = Some(value);
        }
    }

    pub(crate) fn resolution(&self) -> Option<DnsResolution> {
        self.resolution
            .lock()
            .ok()
            .and_then(|resolution| resolution.clone())
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
    fn auto_http3_optional_lookup_timeout_is_short_cap() {
        assert_eq!(
            auto_http3_optional_lookup_timeout_for_remaining(None),
            Some(crate::net::HAPPY_EYEBALLS_FALLBACK_DELAY)
        );
        assert_eq!(
            auto_http3_optional_lookup_timeout_for_remaining(Some(Duration::from_millis(50))),
            None
        );
        assert_eq!(
            auto_http3_optional_lookup_timeout_for_remaining(Some(Duration::from_millis(500))),
            Some(Duration::from_millis(200))
        );
        assert_eq!(
            auto_http3_optional_lookup_timeout_for_remaining(Some(Duration::from_secs(5))),
            Some(crate::net::HAPPY_EYEBALLS_FALLBACK_DELAY)
        );
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

    fn auto_http3_test_discovery_budget() -> Option<AutoHttp3DiscoveryBudget> {
        AutoHttp3DiscoveryBudget::new(TimeoutBudget::new(None))
    }

    #[test]
    fn auto_http3_allowed_only_for_default_direct_https() {
        let url = Url::parse("https://example.com/").unwrap();
        assert!(auto_http3_allowed(
            ClientMode::Request(None),
            &url,
            None,
            None
        ));
        assert!(!auto_http3_allowed(
            ClientMode::Request(Some(HttpVersion::Http2)),
            &url,
            None,
            None
        ));
        assert!(!auto_http3_allowed(
            ClientMode::Request(Some(HttpVersion::Http3)),
            &url,
            None,
            None
        ));
        assert!(!auto_http3_allowed(
            ClientMode::GrpcReflection,
            &url,
            None,
            None
        ));
        assert!(!auto_http3_allowed(
            ClientMode::Request(None),
            &Url::parse("http://example.com/").unwrap(),
            None,
            None
        ));
        assert!(!auto_http3_allowed(
            ClientMode::Request(None),
            &url,
            Some("/tmp/fetch.sock"),
            None
        ));
        assert!(!auto_http3_allowed(
            ClientMode::Request(None),
            &url,
            None,
            Some(EffectiveProxy {
                uses_local_target_dns: false,
            })
        ));
        assert!(!auto_http3_allowed(
            ClientMode::Request(None),
            &Url::parse("https://127.0.0.1/").unwrap(),
            None,
            None
        ));
    }

    #[tokio::test]
    async fn auto_http3_candidate_builder_uses_h3_records_and_port_overrides() {
        let url = Url::parse("https://example.com:8443/").unwrap();
        let origin_addrs = [SocketAddr::new("127.0.0.1".parse().unwrap(), 8443)];
        let records = [
            https_record(5, ".", &["h2"], Some(9443)),
            https_record(1, ".", &["h3", "h2"], Some(9443)),
        ];

        let got = auto_http3_config_for_records(
            None,
            &url,
            &records,
            &origin_addrs,
            auto_http3_test_discovery_budget(),
            false,
        )
        .await
        .unwrap();

        assert_eq!(
            got.addrs,
            [SocketAddr::new("127.0.0.1".parse().unwrap(), 9443)]
        );
    }

    #[tokio::test]
    async fn auto_http3_candidate_builder_orders_hints_by_resolver_family_preference() {
        let url = Url::parse("https://example.com/").unwrap();
        let mut record = https_record(1, ".", &["h3"], None);
        record.ipv4_hint = vec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()];
        record.ipv6_hint = vec![
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
        ];

        let ipv4_first = auto_http3_config_for_records(
            None,
            &url,
            &[record.clone()],
            &[
                SocketAddr::new("198.51.100.1".parse().unwrap(), 443),
                SocketAddr::new("2001:db8::10".parse().unwrap(), 443),
            ],
            auto_http3_test_discovery_budget(),
            false,
        )
        .await
        .unwrap();

        assert_eq!(
            ipv4_first.addrs,
            [
                SocketAddr::new("192.0.2.1".parse().unwrap(), 443),
                SocketAddr::new("2001:db8::1".parse().unwrap(), 443),
                SocketAddr::new("192.0.2.2".parse().unwrap(), 443),
                SocketAddr::new("2001:db8::2".parse().unwrap(), 443),
            ]
        );

        let ipv6_first = auto_http3_config_for_records(
            None,
            &url,
            &[record],
            &[
                SocketAddr::new("2001:db8::10".parse().unwrap(), 443),
                SocketAddr::new("198.51.100.1".parse().unwrap(), 443),
            ],
            auto_http3_test_discovery_budget(),
            false,
        )
        .await
        .unwrap();

        assert_eq!(
            ipv6_first.addrs,
            [
                SocketAddr::new("2001:db8::1".parse().unwrap(), 443),
                SocketAddr::new("192.0.2.1".parse().unwrap(), 443),
                SocketAddr::new("2001:db8::2".parse().unwrap(), 443),
                SocketAddr::new("192.0.2.2".parse().unwrap(), 443),
            ]
        );
    }

    #[tokio::test]
    async fn auto_http3_candidate_builder_ignores_missing_or_unusable_h3() {
        let url = Url::parse("https://example.com/").unwrap();
        let origin_addrs = [SocketAddr::new("127.0.0.1".parse().unwrap(), 443)];
        assert!(
            auto_http3_config_for_records(
                None,
                &url,
                &[],
                &origin_addrs,
                auto_http3_test_discovery_budget(),
                false,
            )
            .await
            .is_none()
        );
        assert!(
            auto_http3_config_for_records(
                None,
                &url,
                &[https_record(1, ".", &["h2"], None)],
                &origin_addrs,
                auto_http3_test_discovery_budget(),
                false,
            )
            .await
            .is_none()
        );
        let mut unsupported = https_record(1, ".", &["h3"], None);
        unsupported.unsupported_mandatory = vec![9];
        assert!(
            auto_http3_config_for_records(
                None,
                &url,
                &[unsupported],
                &origin_addrs,
                auto_http3_test_discovery_budget(),
                false,
            )
            .await
            .is_none()
        );
    }

    #[tokio::test]
    async fn auto_http3_candidate_builder_skips_target_dns_when_not_allowed() {
        let url = Url::parse("https://example.com/").unwrap();
        let origin_addrs = [SocketAddr::new("127.0.0.1".parse().unwrap(), 443)];

        assert!(
            auto_http3_config_for_records(
                None,
                &url,
                &[https_record(1, "h3.example.com.", &["h3"], None)],
                &origin_addrs,
                auto_http3_test_discovery_budget(),
                false,
            )
            .await
            .is_none()
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
    fn no_proxy_matching_supports_port_qualified_entries() {
        let host_url = Url::parse("https://api.example.com/path").unwrap();
        let wrong_port_url = Url::parse("https://api.example.com:444/path").unwrap();
        let ipv4_url = Url::parse("http://127.0.0.1:3000/api").unwrap();
        let ipv6_url = Url::parse("http://[::1]:8080/api").unwrap();

        assert!(no_proxy_matches_url(&host_url, Some("api.example.com:443")));
        assert!(no_proxy_matches_url(&host_url, Some("example.com:443")));
        assert!(!no_proxy_matches_url(
            &wrong_port_url,
            Some("api.example.com:443")
        ));

        assert!(no_proxy_matches_url(&ipv4_url, Some("127.0.0.1:3000")));
        assert!(!no_proxy_matches_url(&ipv4_url, Some("127.0.0.1:3001")));
        assert!(no_proxy_matches_url(&ipv4_url, Some("127.0.0.0/8:3000")));

        assert!(no_proxy_matches_url(&ipv6_url, Some("[::1]:8080")));
        assert!(!no_proxy_matches_url(&ipv6_url, Some("[::1]:8081")));
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

        let err = configure_tls(Client::builder().use_rustls_tls(), &cli, None).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid value '1.0' for option '--min-tls': must be one of [1.2, 1.3]"
        );

        let cli =
            Cli::try_parse_from(["fetch", "--max-tls", "1.1", "https://example.com"]).unwrap();

        let err = configure_tls(Client::builder().use_rustls_tls(), &cli, None).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid value '1.1' for option '--max-tls': must be one of [1.2, 1.3]"
        );
    }

    // --- ech_candidates_from_records ---

    fn ech_record(priority: u16, ech: Option<&[u8]>) -> SvcbRecord {
        let mut record = https_record(priority, ".", &["h2"], None);
        record.ech = ech.map(|b| b.to_vec());
        record
    }

    #[test]
    fn ech_candidates_empty_records() {
        let candidates = ech_candidates_from_records(&[]);
        assert!(candidates.is_empty());
    }

    #[test]
    fn ech_candidates_alias_mode_excluded() {
        let records = [ech_record(0, Some(b"valid-alias"))];
        let candidates = ech_candidates_from_records(&records);
        assert!(
            candidates.is_empty(),
            "alias-mode (priority 0) records should be excluded"
        );
    }

    #[test]
    fn ech_candidates_unsupported_mandatory_excluded() {
        let mut record = ech_record(1, Some(b"has-mandatory"));
        record.unsupported_mandatory = vec![99];
        let records = [record];
        let candidates = ech_candidates_from_records(&records);
        assert!(
            candidates.is_empty(),
            "records with unsupported mandatory params should be excluded"
        );
    }

    #[test]
    fn ech_candidates_one_valid_config() {
        let records = [ech_record(1, Some(b"ech-bytes"))];
        let candidates = ech_candidates_from_records(&records);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0], b"ech-bytes");
    }

    #[test]
    fn ech_candidates_malformed_then_valid_preserves_order() {
        let records = [
            ech_record(10, Some(b"malformed-first")),
            ech_record(20, Some(b"valid-second")),
        ];
        let candidates = ech_candidates_from_records(&records);
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0], b"malformed-first");
        assert_eq!(candidates[1], b"valid-second");
    }

    #[test]
    fn ech_candidates_sorted_by_priority() {
        // Lower priority is more preferred (RFC 9460).
        let records = [
            ech_record(30, Some(b"low-priority")),
            ech_record(10, Some(b"high-priority")),
            ech_record(20, Some(b"mid-priority")),
        ];
        let candidates = ech_candidates_from_records(&records);
        assert_eq!(candidates.len(), 3);
        assert_eq!(candidates[0], b"high-priority");
        assert_eq!(candidates[1], b"mid-priority");
        assert_eq!(candidates[2], b"low-priority");
    }

    #[test]
    fn ech_candidates_mixed_usable_and_unusable_records() {
        // Alias and unusable records are removed; remaining are sorted.
        let mut unsupported = ech_record(5, Some(b"unsupported-ech"));
        unsupported.unsupported_mandatory = vec![99];

        let records = [
            ech_record(0, Some(b"alias-ech")), // alias mode - excluded
            unsupported,                       // unsupported mandatory - excluded
            ech_record(30, Some(b"low-priority")),
            ech_record(10, Some(b"high-priority")),
        ];
        let candidates = ech_candidates_from_records(&records);
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0], b"high-priority");
        assert_eq!(candidates[1], b"low-priority");
    }

    #[test]
    fn ech_candidates_record_without_ech_is_skipped() {
        let records = [ech_record(10, None), ech_record(20, Some(b"has-ech"))];
        let candidates = ech_candidates_from_records(&records);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0], b"has-ech");
    }

    #[test]
    fn ech_candidates_empty_ech_slice_is_skipped() {
        let records = [ech_record(10, Some(b"")), ech_record(20, Some(b"has-ech"))];
        let candidates = ech_candidates_from_records(&records);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0], b"has-ech");
    }

    #[test]
    fn ech_candidates_multiple_service_priorities() {
        // Multiple service-mode records with different priorities.
        let records = [
            ech_record(50, Some(b"lowest")),
            ech_record(10, Some(b"highest")),
            ech_record(30, Some(b"mid")),
            ech_record(20, Some(b"mid-high")),
            ech_record(40, Some(b"mid-low")),
        ];
        let candidates = ech_candidates_from_records(&records);
        assert_eq!(candidates.len(), 5);
        assert_eq!(candidates[0], b"highest");
        assert_eq!(candidates[1], b"mid-high");
        assert_eq!(candidates[2], b"mid");
        assert_eq!(candidates[3], b"mid-low");
        assert_eq!(candidates[4], b"lowest");
    }

    #[cfg(unix)]
    #[test]
    fn unix_socket_configures_transport_builder_on_unix() {
        assert!(configure_unix_socket(Client::builder(), Some("/tmp/fetch.sock")).is_ok());
    }
}
