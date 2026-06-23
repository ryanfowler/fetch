use std::collections::VecDeque;
use std::future::{self, Future};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{StreamExt, stream::FuturesUnordered};
use http::header::HeaderMap;
use http::{Method, Request, Version};
use quinn::crypto::rustls::QuicClientConfig;
use tokio::task::JoinHandle;
use url::Url;

use super::body::{Body, BodyDeadline, H3UploadTask, Response, send_h3_body};
use super::client::{
    AutoTcpConnection, Client, absolute_uri, build_request, default_tls_config, empty_request_body,
    record_dns_addrs_trace,
};
use super::{Error, ErrorKind};
use crate::dns::svcb::{HttpsRecordResolver, SvcbRecord};
use crate::duration::TimeoutBudget;
use crate::error::FetchError;
use crate::http::http3_cache::Http3CacheCandidate;
use crate::timing::TransportTiming;

type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AutoHttp3Config {
    pub(crate) addrs: Vec<SocketAddr>,
}

#[derive(Clone)]
pub(super) struct H3PooledClient {
    pub(super) origin: String,
    sender: H3SendRequest,
    remote_addr: SocketAddr,
}

struct Http3ConnectResult {
    client: H3PooledClient,
    timing: TransportTiming,
}

enum AutoRaceWinner {
    Http3(Http3ConnectResult),
    Tcp(AutoTcpConnection),
}

impl Client {
    pub(super) async fn send_auto_http3(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Option<Body>,
        body_deadline: Option<BodyDeadline>,
    ) -> Result<Response, Error> {
        match self.race_auto_http3_connection(url.clone()).await? {
            AutoRaceWinner::Http3(result) => {
                if let Some(timing) = &self.config.connection_timing {
                    timing.set(result.timing);
                }
                self.store_http3_client(result.client.clone()).await;
                let (req, body) = build_h3_request(method, &url, headers, body)?;
                self.send_http3_request(url, req, body, body_deadline, result.client)
                    .await
            }
            AutoRaceWinner::Tcp(connection) => {
                if let Some(timing) = &self.config.connection_timing {
                    timing.set(connection.timing);
                }
                self.send_tcp_one_shot(method, url, headers, body, body_deadline, connection)
                    .await
            }
        }
    }

    async fn race_auto_http3_connection(&self, url: Url) -> Result<AutoRaceWinner, Error> {
        if self.config.auto_http3_discovery
            || (self.config.auto_http3.is_none() && self.config.http3_cache.is_some())
        {
            return self.race_dynamic_auto_http3_connection(url).await;
        }
        let connect_timeout = TimeoutBudget::new(self.config.connect_timeout);
        race_primary_fallback(
            {
                let client = self.clone();
                let url = url.clone();
                move || async move {
                    client
                        .connect_auto_http3_client(&url, connect_timeout)
                        .await
                        .map(AutoRaceWinner::Http3)
                }
            },
            {
                let client = self.clone();
                move || {
                    let client = client.clone();
                    let url = url.clone();
                    async move {
                        client
                            .connect_auto_tcp_tls(&url, connect_timeout)
                            .await
                            .map(AutoRaceWinner::Tcp)
                    }
                }
            },
            crate::net::HAPPY_EYEBALLS_FALLBACK_DELAY,
        )
        .await
    }

    async fn race_dynamic_auto_http3_connection(&self, url: Url) -> Result<AutoRaceWinner, Error> {
        let connect_timeout = TimeoutBudget::new(self.config.connect_timeout);
        let h3 = {
            let client = self.clone();
            let url = url.clone();
            async move {
                client
                    .connect_dynamic_auto_http3_client(&url, connect_timeout)
                    .await
                    .map(AutoRaceWinner::Http3)
            }
        };
        let tcp = {
            let client = self.clone();
            async move {
                client
                    .connect_auto_tcp_tls(&url, connect_timeout)
                    .await
                    .map(AutoRaceWinner::Tcp)
            }
        };
        race_started_auto_connections(h3, tcp).await
    }

    async fn connect_dynamic_auto_http3_client(
        &self,
        url: &Url,
        timeout: TimeoutBudget,
    ) -> Result<Http3ConnectResult, Error> {
        let origin = http3_origin(url)?;
        if let Some(client) = self.h3_pool.lock().await.get(&origin).cloned() {
            return Ok(Http3ConnectResult {
                client,
                timing: TransportTiming::default(),
            });
        }
        let host = url
            .host_str()
            .ok_or_else(|| Error::request("URL host is required"))?;
        let discovery_start = std::time::Instant::now();
        let cached_candidates = self
            .config
            .http3_cache
            .as_ref()
            .map(|cache| cache.candidates(url, self.config.dns_server.as_deref()))
            .unwrap_or_default();
        let fresh = self.connect_fresh_dynamic_auto_http3_client(
            url,
            origin.clone(),
            host.to_string(),
            discovery_start,
            timeout,
        );
        let cached =
            self.connect_cached_dynamic_auto_http3_client(url, origin, cached_candidates, timeout);
        race_dynamic_auto_http3_candidates(fresh, cached).await
    }

    async fn connect_fresh_dynamic_auto_http3_client(
        &self,
        url: &Url,
        origin: String,
        host: String,
        discovery_start: std::time::Instant,
        timeout: TimeoutBudget,
    ) -> DynamicHttp3ConnectOutcome {
        let origin_addrs_task =
            spawn_auto_http3_origin_addrs(self.config.dns_server.clone(), host.clone(), timeout);
        let records =
            lookup_auto_http3_https_records(self.config.dns_server.as_deref(), &host, timeout)
                .await;
        if let Some(cache) = &self.config.http3_cache {
            cache.store_https_records(url, self.config.dns_server.as_deref(), &records);
        }
        if records.is_empty() {
            origin_addrs_task.abort();
            return DynamicHttp3ConnectOutcome::NoCandidates;
        }
        let origin_addrs = take_finished_auto_http3_origin_addrs(origin_addrs_task).await;
        let addrs = auto_http3_addrs_for_records(
            self.config.dns_server.as_deref(),
            url,
            &records,
            &origin_addrs,
            timeout,
        )
        .await;
        if addrs.is_empty() {
            return DynamicHttp3ConnectOutcome::NoCandidates;
        }
        record_dns_addrs_trace(&self.config, url, &addrs, discovery_start.elapsed());
        match self
            .connect_http3_client_with_addrs(url, origin, addrs, timeout)
            .await
        {
            Ok(result) => DynamicHttp3ConnectOutcome::Connected(result),
            Err(err) => DynamicHttp3ConnectOutcome::Failed(err),
        }
    }

    async fn connect_cached_dynamic_auto_http3_client(
        &self,
        url: &Url,
        origin: String,
        candidates: Vec<Http3CacheCandidate>,
        timeout: TimeoutBudget,
    ) -> DynamicHttp3ConnectOutcome {
        match self
            .connect_cached_auto_http3_client_with_candidates(url, origin, candidates, timeout)
            .await
        {
            Some(Ok(result)) => DynamicHttp3ConnectOutcome::Connected(result),
            Some(Err(err)) => DynamicHttp3ConnectOutcome::Failed(err),
            None => DynamicHttp3ConnectOutcome::NoCandidates,
        }
    }
}

pub(super) async fn race_primary_fallback<
    T,
    StartPrimary,
    StartFallback,
    PrimaryFuture,
    FallbackFuture,
>(
    start_primary: StartPrimary,
    start_fallback: StartFallback,
    fallback_delay: Duration,
) -> Result<T, Error>
where
    StartPrimary: FnOnce() -> PrimaryFuture,
    StartFallback: FnOnce() -> FallbackFuture,
    PrimaryFuture: Future<Output = Result<T, Error>>,
    FallbackFuture: Future<Output = Result<T, Error>>,
{
    let mut primary = Box::pin(start_primary());
    let mut start_fallback = Some(start_fallback);
    let mut fallback_task: Option<Pin<Box<FallbackFuture>>> = None;
    let mut primary_err = None;
    let mut fallback_err = None;
    let delay = tokio::time::sleep(fallback_delay);
    tokio::pin!(delay);

    loop {
        if primary_err.is_some() && fallback_err.is_some() {
            return Err(fallback_err
                .take()
                .or(primary_err)
                .expect("at least one race error exists"));
        }

        if primary_err.is_some() {
            if fallback_task.is_none() && fallback_err.is_none() {
                fallback_task = Some(Box::pin(start_fallback
                    .take()
                    .expect("fallback has not started yet")(
                )));
            }
            if let Some(task) = fallback_task.as_mut() {
                match task.as_mut().await {
                    Ok(winner) => return Ok(winner),
                    Err(err) => {
                        fallback_err = Some(err);
                        fallback_task = None;
                    }
                }
            }
            continue;
        }

        if fallback_err.is_some() {
            match primary.as_mut().await {
                Ok(winner) => return Ok(winner),
                Err(err) => primary_err = Some(err),
            }
            continue;
        }

        if fallback_task.is_none() {
            tokio::select! {
                result = &mut primary => match result {
                    Ok(winner) => return Ok(winner),
                    Err(err) => {
                        primary_err = Some(err);
                        fallback_task = Some(Box::pin(
                            start_fallback
                                .take()
                                .expect("fallback has not started yet")(),
                        ));
                    }
                },
                _ = &mut delay => {
                    fallback_task = Some(Box::pin(
                        start_fallback
                            .take()
                            .expect("fallback has not started yet")(),
                    ));
                }
            }
        } else {
            let fallback = fallback_task.as_mut().expect("fallback task exists");
            tokio::select! {
                result = &mut primary => match result {
                    Ok(winner) => return Ok(winner),
                    Err(err) => primary_err = Some(err),
                },
                result = fallback.as_mut() => match result {
                    Ok(winner) => return Ok(winner),
                    Err(err) => {
                        fallback_err = Some(err);
                        fallback_task = None;
                    }
                },
            }
        }
    }
}

async fn race_started_auto_connections<H3Future, TcpFuture>(
    h3: H3Future,
    tcp: TcpFuture,
) -> Result<AutoRaceWinner, Error>
where
    H3Future: Future<Output = Result<AutoRaceWinner, Error>>,
    TcpFuture: Future<Output = Result<AutoRaceWinner, Error>>,
{
    let mut h3 = Box::pin(h3);
    let mut tcp = Box::pin(tcp);
    let mut h3_err = None;
    let mut tcp_err = None;

    loop {
        if h3_err.is_some() && tcp_err.is_some() {
            return Err(tcp_err
                .take()
                .or(h3_err)
                .expect("at least one race error exists"));
        }

        match (h3_err.is_some(), tcp_err.is_some()) {
            (false, false) => {
                tokio::select! {
                    result = h3.as_mut() => match result {
                        Ok(winner) => return Ok(winner),
                        Err(err) => h3_err = Some(err),
                    },
                    result = tcp.as_mut() => match result {
                        Ok(winner) => return Ok(winner),
                        Err(err) => tcp_err = Some(err),
                    },
                }
            }
            (true, false) => match tcp.as_mut().await {
                Ok(winner) => return Ok(winner),
                Err(err) => tcp_err = Some(err),
            },
            (false, true) => match h3.as_mut().await {
                Ok(winner) => return Ok(winner),
                Err(err) => h3_err = Some(err),
            },
            (true, true) => unreachable!("handled at top of loop"),
        }
    }
}

enum DynamicHttp3ConnectOutcome {
    Connected(Http3ConnectResult),
    Failed(Error),
    NoCandidates,
}

async fn race_dynamic_auto_http3_candidates<FreshFuture, CachedFuture>(
    fresh: FreshFuture,
    cached: CachedFuture,
) -> Result<Http3ConnectResult, Error>
where
    FreshFuture: Future<Output = DynamicHttp3ConnectOutcome>,
    CachedFuture: Future<Output = DynamicHttp3ConnectOutcome>,
{
    let mut fresh = Box::pin(fresh);
    let prompt_fresh = tokio::task::yield_now();
    tokio::pin!(prompt_fresh);

    let mut fresh_done = false;
    let mut cached_done = false;
    let mut fresh_err = None;
    let mut cached_err = None;

    tokio::select! {
        result = fresh.as_mut() => {
            fresh_done = true;
            if let Some(result) = record_dynamic_http3_outcome(result, &mut fresh_err) {
                return Ok(result);
            }
        }
        _ = &mut prompt_fresh => {}
    }

    let mut cached = Box::pin(cached);

    loop {
        if fresh_done && cached_done {
            return Err(fresh_err
                .or(cached_err)
                .unwrap_or_else(|| Error::connect("no HTTP/3 candidates discovered")));
        }

        match (fresh_done, cached_done) {
            (false, false) => {
                tokio::select! {
                    result = fresh.as_mut() => {
                        fresh_done = true;
                        if let Some(result) = record_dynamic_http3_outcome(result, &mut fresh_err) {
                            return Ok(result);
                        }
                    }
                    result = cached.as_mut() => {
                        cached_done = true;
                        if let Some(result) = record_dynamic_http3_outcome(result, &mut cached_err) {
                            return Ok(result);
                        }
                    }
                }
            }
            (false, true) => {
                let result = fresh.as_mut().await;
                fresh_done = true;
                if let Some(result) = record_dynamic_http3_outcome(result, &mut fresh_err) {
                    return Ok(result);
                }
            }
            (true, false) => {
                let result = cached.as_mut().await;
                cached_done = true;
                if let Some(result) = record_dynamic_http3_outcome(result, &mut cached_err) {
                    return Ok(result);
                }
            }
            (true, true) => unreachable!("handled at top of loop"),
        }
    }
}

fn record_dynamic_http3_outcome(
    outcome: DynamicHttp3ConnectOutcome,
    error: &mut Option<Error>,
) -> Option<Http3ConnectResult> {
    match outcome {
        DynamicHttp3ConnectOutcome::Connected(result) => Some(result),
        DynamicHttp3ConnectOutcome::Failed(err) => {
            *error = Some(err);
            None
        }
        DynamicHttp3ConnectOutcome::NoCandidates => None,
    }
}

pub(super) fn spawn_auto_http3_origin_addrs(
    dns_server: Option<String>,
    host: String,
    timeout: TimeoutBudget,
) -> JoinHandle<Vec<SocketAddr>> {
    tokio::spawn(async move {
        crate::net::resolve_host(&host, dns_server.as_deref(), timeout)
            .await
            .unwrap_or_default()
    })
}

pub(super) async fn take_finished_auto_http3_origin_addrs(
    handle: JoinHandle<Vec<SocketAddr>>,
) -> Vec<SocketAddr> {
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

async fn lookup_auto_http3_https_records(
    dns_server: Option<&str>,
    host: &str,
    timeout: TimeoutBudget,
) -> Vec<SvcbRecord> {
    let Some(timeout) = auto_http3_lookup_timeout(timeout) else {
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

fn auto_http3_lookup_timeout(timeout: TimeoutBudget) -> Option<Duration> {
    let max_lookup = crate::net::HAPPY_EYEBALLS_FALLBACK_DELAY;
    match timeout.remaining().ok()? {
        None => Some(max_lookup),
        Some(remaining) if remaining <= max_lookup => None,
        Some(remaining) => Some((remaining - max_lookup).min(max_lookup)),
    }
}

async fn auto_http3_addrs_for_records(
    dns_server: Option<&str>,
    url: &Url,
    records: &[SvcbRecord],
    origin_addrs: &[SocketAddr],
    timeout: TimeoutBudget,
) -> Vec<SocketAddr> {
    let Some(origin_host) = url.host_str() else {
        return Vec::new();
    };
    let Some(origin_port) = url.port_or_known_default() else {
        return Vec::new();
    };
    let mut sorted = records.iter().collect::<Vec<_>>();
    sorted.sort_by_key(|record| record.priority);

    let mut addrs = Vec::new();
    for record in sorted {
        if record.is_alias_mode() || !record.is_usable() || !record.advertises_alpn("h3") {
            continue;
        }
        let port = record.port.unwrap_or(origin_port);
        let mut record_addrs = auto_http3_hint_addrs(record, origin_addrs, port);
        if record_addrs.is_empty() {
            let target = auto_http3_target_host(origin_host, &record.target);
            if target.eq_ignore_ascii_case(origin_host) && !origin_addrs.is_empty() {
                record_addrs = origin_addrs
                    .iter()
                    .map(|addr| SocketAddr::new(addr.ip(), port))
                    .collect();
            } else if target.eq_ignore_ascii_case(origin_host) {
                record_addrs = crate::net::resolve_host(origin_host, dns_server, timeout)
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(|addr| SocketAddr::new(addr.ip(), port))
                    .collect();
            } else if let Ok(ip) = target.parse::<IpAddr>() {
                record_addrs.push(SocketAddr::new(ip, port));
            }
        }
        append_unique_socket_addrs(&mut addrs, record_addrs);
    }
    addrs
}

async fn auto_http3_addrs_for_cached_candidates(
    dns_server: Option<&str>,
    candidates: &[Http3CacheCandidate],
    timeout: TimeoutBudget,
) -> Vec<SocketAddr> {
    let mut sorted = candidates.iter().collect::<Vec<_>>();
    sorted.sort_by_key(|candidate| candidate.priority.unwrap_or(u16::MAX));
    let mut addrs = Vec::new();
    for candidate in sorted {
        let record_addrs = if let Ok(ip) = candidate.alt_host.parse::<IpAddr>() {
            vec![SocketAddr::new(ip, candidate.alt_port)]
        } else {
            crate::net::resolve_host(&candidate.alt_host, dns_server, timeout)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|addr| SocketAddr::new(addr.ip(), candidate.alt_port))
                .collect()
        };
        append_unique_socket_addrs(&mut addrs, record_addrs);
    }
    addrs
}

pub(super) fn auto_http3_hint_addrs(
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

impl Client {
    pub(super) async fn send_http3(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Option<Body>,
        body_deadline: Option<BodyDeadline>,
    ) -> Result<Response, Error> {
        if url.scheme() != "https" {
            return Err(Error::request(format!(
                "http3: unsupported protocol scheme: {}",
                url.scheme()
            )));
        }
        let (req, body) = build_h3_request(method, &url, headers, body)?;
        let pooled = self.http3_client(&url).await?;
        self.send_http3_request(url, req, body, body_deadline, pooled)
            .await
    }

    async fn send_http3_request(
        &self,
        url: Url,
        req: Request<()>,
        body: Option<Body>,
        body_deadline: Option<BodyDeadline>,
        pooled: H3PooledClient,
    ) -> Result<Response, Error> {
        let mut sender = pooled.sender.clone();
        let stream = match sender.send_request(req).await {
            Ok(stream) => stream,
            Err(err) => {
                self.remove_http3_client(&pooled.origin).await;
                return Err(Error::with_source(
                    ErrorKind::Request,
                    format!("http3 request: {err}"),
                    err,
                ));
            }
        };
        let (mut send, mut recv) = stream.split();
        let upload_deadline = body_deadline.clone();
        let send_task = H3UploadTask::new(tokio::spawn(async move {
            match body {
                Some(body) => send_h3_body(&mut send, body, upload_deadline).await,
                None => send
                    .finish()
                    .await
                    .map_err(|err| Error::body(format!("http3 request body: {err}"))),
            }
        }));
        let response = recv.recv_response().await.map_err(|err| {
            Error::with_source(ErrorKind::Request, format!("http3 response: {err}"), err)
        })?;
        let upload_task = if send_task.is_finished() {
            send_task.await?;
            None
        } else {
            Some(send_task)
        };
        Ok(Response::from_h3(
            url,
            response,
            recv,
            sender,
            upload_task,
            body_deadline,
            pooled.remote_addr,
        ))
    }

    async fn http3_client(&self, url: &Url) -> Result<H3PooledClient, Error> {
        let origin = http3_origin(url)?;
        if let Some(client) = self.h3_pool.lock().await.get(&origin).cloned() {
            return Ok(client);
        }

        let result = self.connect_http3_client(url, origin.clone()).await?;
        if let Some(timing) = &self.config.connection_timing {
            timing.set(result.timing);
        }
        let client = result.client;
        let mut pool = self.h3_pool.lock().await;
        Ok(pool.entry(origin).or_insert_with(|| client.clone()).clone())
    }

    async fn store_http3_client(&self, client: H3PooledClient) {
        self.h3_pool
            .lock()
            .await
            .insert(client.origin.clone(), client);
    }

    async fn remove_http3_client(&self, origin: &str) {
        self.h3_pool.lock().await.remove(origin);
    }

    async fn connect_auto_http3_client(
        &self,
        url: &Url,
        timeout: TimeoutBudget,
    ) -> Result<Http3ConnectResult, Error> {
        let origin = http3_origin(url)?;
        if let Some(client) = self.h3_pool.lock().await.get(&origin).cloned() {
            return Ok(Http3ConnectResult {
                client,
                timing: TransportTiming::default(),
            });
        }
        let mut fresh_error = None;
        if let Some(addrs) = self
            .config
            .auto_http3
            .as_ref()
            .map(|config| config.addrs.clone())
            .filter(|addrs| !addrs.is_empty())
        {
            match self
                .connect_http3_client_with_addrs(url, origin.clone(), addrs, timeout)
                .await
            {
                Ok(result) => return Ok(result),
                Err(err) => fresh_error = Some(err),
            }
        }
        let cached_error = match self
            .connect_cached_auto_http3_client(url, origin, timeout)
            .await
        {
            Some(Ok(result)) => return Ok(result),
            Some(Err(err)) => Some(err),
            None => None,
        };
        Err(fresh_error
            .or(cached_error)
            .unwrap_or_else(|| Error::connect("no HTTP/3 candidates discovered")))
    }

    async fn connect_cached_auto_http3_client(
        &self,
        url: &Url,
        origin: String,
        timeout: TimeoutBudget,
    ) -> Option<Result<Http3ConnectResult, Error>> {
        let cache = self.config.http3_cache.as_ref()?;
        let candidates = cache.candidates(url, self.config.dns_server.as_deref());
        self.connect_cached_auto_http3_client_with_candidates(url, origin, candidates, timeout)
            .await
    }

    async fn connect_cached_auto_http3_client_with_candidates(
        &self,
        url: &Url,
        origin: String,
        candidates: Vec<Http3CacheCandidate>,
        timeout: TimeoutBudget,
    ) -> Option<Result<Http3ConnectResult, Error>> {
        let cache = self.config.http3_cache.as_ref()?;
        let addrs = auto_http3_addrs_for_cached_candidates(
            self.config.dns_server.as_deref(),
            &candidates,
            timeout,
        )
        .await;
        if addrs.is_empty() {
            return None;
        }
        let result = self
            .connect_http3_client_with_addrs(url, origin, addrs, timeout)
            .await;
        if result.is_err() {
            cache.remove_candidates(url, self.config.dns_server.as_deref(), &candidates);
        }
        Some(result)
    }

    async fn connect_http3_client(
        &self,
        url: &Url,
        origin: String,
    ) -> Result<Http3ConnectResult, Error> {
        let host = url
            .host_str()
            .ok_or_else(|| Error::request("URL host is required"))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| Error::request("URL port is required"))?;
        let timeout = TimeoutBudget::new(self.config.connect_timeout);
        let (addrs, dns_duration) = if let Some(addrs) = self.config.dns_overrides.get(host) {
            let mut addrs = addrs.clone();
            for addr in &mut addrs {
                addr.set_port(port);
            }
            (addrs, None)
        } else {
            let dns_start = std::time::Instant::now();
            let addrs = crate::net::resolve_host(host, self.config.dns_server.as_deref(), timeout)
                .await
                .map_err(|err| Error::from_fetch(ErrorKind::Connect, err))?
                .into_iter()
                .map(|mut addr| {
                    addr.set_port(port);
                    addr
                })
                .collect();
            (addrs, Some(dns_start.elapsed()))
        };
        if let Some(duration) = dns_duration {
            record_dns_addrs_trace(&self.config, url, &addrs, duration);
        }
        self.connect_http3_client_with_addrs(url, origin, addrs, timeout)
            .await
    }

    async fn connect_http3_client_with_addrs(
        &self,
        url: &Url,
        origin: String,
        mut addrs: Vec<SocketAddr>,
        timeout: TimeoutBudget,
    ) -> Result<Http3ConnectResult, Error> {
        let host = url
            .host_str()
            .ok_or_else(|| Error::request("URL host is required"))?;
        let (mut endpoint, family_filter) = http3_client_endpoint(self.config.local_address)?;
        if let Some(local_ip) = family_filter {
            addrs.retain(|addr| addr.ip().is_ipv4() == local_ip.is_ipv4());
        }
        let mut tls = self
            .config
            .tls_config
            .clone()
            .unwrap_or_else(default_tls_config);
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let client_config = QuicClientConfig::try_from(tls)
            .map(|config| quinn::ClientConfig::new(Arc::new(config)))
            .map_err(|err| Error::request(format!("invalid QUIC TLS configuration: {err}")))?;
        endpoint.set_default_client_config(client_config);
        let start = std::time::Instant::now();
        let connection = connect_http3(endpoint, addrs, host.to_string(), timeout)
            .await
            .map_err(|err| Error::from_fetch(ErrorKind::Connect, err))?;
        let remote_addr = connection.remote_address();
        let timing = TransportTiming {
            tcp: None,
            tls: None,
            quic: Some(start.elapsed()),
        };
        let h3_connection = h3_quinn::Connection::new(connection);
        let (mut driver, sender) = h3::client::new(h3_connection)
            .await
            .map_err(|err| Error::connect(format!("http3 handshake: {err}")))?;
        tokio::spawn(async move {
            let _ = future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        Ok(Http3ConnectResult {
            client: H3PooledClient {
                origin,
                sender,
                remote_addr,
            },
            timing,
        })
    }
}

fn http3_origin(url: &Url) -> Result<String, Error> {
    let host = url
        .host_str()
        .ok_or_else(|| Error::request("URL host is required"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| Error::request("URL port is required"))?;
    Ok(format!("{}://{}:{}", url.scheme(), host, port))
}

fn http3_client_endpoint(
    local_address: Option<IpAddr>,
) -> Result<(quinn::Endpoint, Option<IpAddr>), Error> {
    let local_addr = http3_endpoint_local_addr(local_address);
    match quinn::Endpoint::client(local_addr) {
        Ok(endpoint) => Ok((endpoint, local_address)),
        Err(err) if local_address.is_none() => {
            let fallback_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            quinn::Endpoint::client(fallback_addr)
                .map(|endpoint| (endpoint, Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED))))
                .map_err(|fallback_err| {
                    Error::connect(format!(
                        "failed to bind HTTP/3 client endpoint to {local_addr}: {err}; \
                         IPv4 fallback {fallback_addr} also failed: {fallback_err}"
                    ))
                })
        }
        Err(err) => Err(Error::with_source(ErrorKind::Connect, err.to_string(), err)),
    }
}

pub(super) fn http3_endpoint_local_addr(local_address: Option<IpAddr>) -> SocketAddr {
    SocketAddr::new(
        local_address.unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
        0,
    )
}

async fn connect_http3(
    endpoint: quinn::Endpoint,
    addrs: Vec<SocketAddr>,
    host: String,
    timeout: TimeoutBudget,
) -> Result<quinn::Connection, FetchError> {
    if addrs.is_empty() {
        return Err(FetchError::Runtime(
            "lookup returned no addresses".to_string(),
        ));
    }
    connect_http3_staggered(endpoint, addrs, host, timeout).await
}

async fn connect_http3_staggered(
    endpoint: quinn::Endpoint,
    addrs: Vec<SocketAddr>,
    host: String,
    timeout: TimeoutBudget,
) -> Result<quinn::Connection, FetchError> {
    let mut pending = VecDeque::from(addrs);
    let mut active = FuturesUnordered::new();
    let mut last_err = None;
    start_next_http3_connect(&endpoint, &host, timeout, &mut pending, &mut active);
    let delay = tokio::time::sleep(crate::net::HAPPY_EYEBALLS_FALLBACK_DELAY);
    tokio::pin!(delay);

    loop {
        if active.is_empty() {
            return Err(last_err.unwrap_or_else(|| {
                FetchError::Runtime("lookup returned no addresses".to_string())
            }));
        }
        if pending.is_empty() {
            match active.next().await {
                Some(Ok(connection)) => return Ok(connection),
                Some(Err(err)) => last_err = Some(err),
                None => {}
            }
            continue;
        }

        tokio::select! {
            result = active.next() => match result {
                Some(Ok(connection)) => return Ok(connection),
                Some(Err(err)) => {
                    last_err = Some(err);
                    start_next_http3_connect(&endpoint, &host, timeout, &mut pending, &mut active);
                    delay.as_mut().reset(tokio::time::Instant::now() + crate::net::HAPPY_EYEBALLS_FALLBACK_DELAY);
                }
                None => {}
            },
            _ = &mut delay => {
                start_next_http3_connect(&endpoint, &host, timeout, &mut pending, &mut active);
                delay.as_mut().reset(tokio::time::Instant::now() + crate::net::HAPPY_EYEBALLS_FALLBACK_DELAY);
            }
        }
    }
}

fn start_next_http3_connect(
    endpoint: &quinn::Endpoint,
    host: &str,
    timeout: TimeoutBudget,
    pending: &mut VecDeque<SocketAddr>,
    active: &mut FuturesUnordered<Http3ConnectTask>,
) {
    if let Some(addr) = pending.pop_front() {
        active.push(Http3ConnectTask::new(connect_http3_addr(
            endpoint.clone(),
            addr,
            host.to_string(),
            timeout,
        )));
    }
}

async fn connect_http3_addr(
    endpoint: quinn::Endpoint,
    addr: SocketAddr,
    host: String,
    timeout: TimeoutBudget,
) -> Result<quinn::Connection, FetchError> {
    let connecting = endpoint
        .connect(addr, &host)
        .map_err(|err| FetchError::Runtime(format!("http3 connect {addr}: {err}")))?;
    timeout
        .run(async {
            connecting
                .await
                .map_err(|err| FetchError::Runtime(format!("http3 connect {addr}: {err}")))
        })
        .await
}

struct Http3ConnectTask {
    handle: JoinHandle<Result<quinn::Connection, FetchError>>,
}

impl Http3ConnectTask {
    fn new(
        future: impl Future<Output = Result<quinn::Connection, FetchError>> + Send + 'static,
    ) -> Self {
        Self {
            handle: tokio::spawn(future),
        }
    }
}

impl Future for Http3ConnectTask {
    type Output = Result<quinn::Connection, FetchError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.handle).poll(cx).map(|result| {
            result.unwrap_or_else(|err| {
                Err(FetchError::Runtime(format!(
                    "http3 connect task failed: {err}"
                )))
            })
        })
    }
}

impl Drop for Http3ConnectTask {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

fn build_h3_request(
    method: Method,
    url: &Url,
    headers: HeaderMap,
    body: Option<Body>,
) -> Result<(Request<()>, Option<Body>), Error> {
    match body {
        Some(body) => {
            let request = build_request(method, absolute_uri(url)?, Version::HTTP_3, headers, body)
                .map_err(Error::request)?;
            let (parts, body) = request.into_parts();
            Ok((Request::from_parts(parts, ()), Some(body)))
        }
        None => {
            let request = build_request(
                method,
                absolute_uri(url)?,
                Version::HTTP_3,
                headers,
                empty_request_body(),
            )
            .map_err(Error::request)?;
            let (parts, _) = request.into_parts();
            Ok((Request::from_parts(parts, ()), None))
        }
    }
}
