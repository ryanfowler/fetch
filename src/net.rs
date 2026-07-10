use std::collections::VecDeque;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
#[cfg(unix)]
use std::{
    ffi::{CStr, CString},
    ptr,
};

use base64::Engine;
use futures_util::{StreamExt, stream::FuturesUnordered};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::task::JoinHandle;
use url::{Host, Url};

use crate::core;
use crate::duration::TimeoutBudget;
use crate::error::FetchError;

pub(crate) trait AsyncIo: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> AsyncIo for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub(crate) type DialStream = Pin<Box<dyn AsyncIo>>;

pub(crate) const HAPPY_EYEBALLS_RESOLUTION_DELAY: Duration = Duration::from_millis(50);
pub(crate) const HAPPY_EYEBALLS_FALLBACK_DELAY: Duration = Duration::from_millis(300);
const TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(15);
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const TCP_KEEPALIVE_RETRIES: u32 = 3;
#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
const TCP_USER_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AddressFamily {
    Ipv4,
    Ipv6,
}

pub(crate) struct TcpConnectTrace {
    pub(crate) stream: TcpStream,
    pub(crate) resolved_addrs: Vec<SocketAddr>,
    pub(crate) dns_duration: Option<Duration>,
    pub(crate) tcp_duration: Duration,
}

struct SharedDohResolver {
    server_url: Url,
    client: crate::dns::doh::DohClient,
}

pub(crate) async fn dial_url(
    url: &Url,
    proxy: Option<&str>,
    dns_server: Option<&str>,
    doh_tls_config: Option<rustls::ClientConfig>,
    timeout: TimeoutBudget,
) -> Result<DialStream, FetchError> {
    if let Some(proxy) = proxy {
        return dial_proxy(proxy, url, dns_server, doh_tls_config, timeout).await;
    }
    let stream = connect_tcp_with_doh_tls(url, dns_server, doh_tls_config, timeout).await?;
    Ok(Box::pin(stream))
}

pub(crate) async fn connect_tcp_with_doh_tls(
    url: &Url,
    dns_server: Option<&str>,
    doh_tls_config: Option<rustls::ClientConfig>,
    timeout: TimeoutBudget,
) -> Result<TcpStream, FetchError> {
    connect_tcp_traced_with_doh_tls(url, dns_server, doh_tls_config, timeout)
        .await
        .map(|trace| trace.stream)
}

pub(crate) async fn connect_tcp_traced_with_doh_tls(
    url: &Url,
    dns_server: Option<&str>,
    doh_tls_config: Option<rustls::ClientConfig>,
    timeout: TimeoutBudget,
) -> Result<TcpConnectTrace, FetchError> {
    let host = url
        .host_str()
        .ok_or_else(|| FetchError::Message("URL host is required".to_string()))?
        .trim_matches(['[', ']']);
    let port = url
        .port_or_known_default()
        .ok_or_else(|| FetchError::Message("URL port is required".to_string()))?;

    if let Ok(ip) = host.parse::<IpAddr>() {
        return timeout_fetch(
            timeout,
            connect_addr_timed(SocketAddr::new(ip, port), timeout),
        )
        .await
        .map(|outcome| TcpConnectTrace {
            stream: outcome.stream,
            resolved_addrs: Vec::new(),
            dns_duration: None,
            tcp_duration: outcome.duration,
        });
    }

    timeout_fetch(
        timeout,
        connect_host_happy_eyeballs_traced(host, port, dns_server, doh_tls_config, timeout),
    )
    .await
}

pub(crate) async fn resolve_host_with_doh_tls(
    host: &str,
    dns_server: Option<&str>,
    doh_tls_config: Option<rustls::ClientConfig>,
    timeout: TimeoutBudget,
) -> Result<Vec<SocketAddr>, FetchError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, 0)]);
    }
    let Some(dns_server) = dns_server else {
        return tokio::net::lookup_host((host, 0))
            .await
            .map(|addrs| addrs.collect())
            .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")));
    };

    let addrs = if is_doh_dns_server(dns_server) {
        let shared_doh = shared_doh_resolver(dns_server, host, timeout, doh_tls_config.as_ref())?;
        resolve_doh_ips(host, dns_server, Some(&shared_doh), timeout).await?
    } else {
        crate::dns::custom::lookup_ips(dns_server, host, timeout.remaining()?).await?
    };
    Ok(addrs
        .into_iter()
        .map(|addr| SocketAddr::new(addr, 0))
        .collect())
}

async fn resolve_host_family(
    host: &str,
    port: u16,
    dns_server: Option<&str>,
    shared_doh: Option<&SharedDohResolver>,
    family: AddressFamily,
    timeout: TimeoutBudget,
) -> Result<Vec<SocketAddr>, FetchError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(match (family, ip) {
            (AddressFamily::Ipv4, IpAddr::V4(_)) | (AddressFamily::Ipv6, IpAddr::V6(_)) => {
                vec![SocketAddr::new(ip, port)]
            }
            _ => Vec::new(),
        });
    }

    match dns_server {
        Some(dns_server) => {
            let addrs =
                resolve_custom_host_family(host, dns_server, shared_doh, family, timeout).await?;
            Ok(socket_addrs_with_port(addrs, port))
        }
        None => resolve_system_host_family(host, port, family).await,
    }
}

async fn resolve_custom_host_family(
    host: &str,
    dns_server: &str,
    shared_doh: Option<&SharedDohResolver>,
    family: AddressFamily,
    timeout: TimeoutBudget,
) -> Result<Vec<IpAddr>, FetchError> {
    let (label, answer_type) = match family {
        AddressFamily::Ipv4 => ("A", crate::dns::wire::TYPE_A),
        AddressFamily::Ipv6 => ("AAAA", crate::dns::wire::TYPE_AAAA),
    };
    match crate::dns::custom::parse_dns_server(dns_server)? {
        crate::dns::custom::ParsedDnsServer::Doh(_) => {
            resolve_doh_host_family(host, dns_server, shared_doh, label, answer_type, timeout).await
        }
        crate::dns::custom::ParsedDnsServer::Udp(addr) => {
            let server_addr = addr.to_string();
            let timeout = crate::dns::util::udp_dns_timeout(timeout.remaining()?);
            crate::dns::resolver::lookup_udp_type(&server_addr, host, answer_type, timeout)
                .await
                .map(|records| records.into_iter().map(|record| record.ip).collect())
                .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))
        }
        crate::dns::custom::ParsedDnsServer::Tcp(addr) => {
            let timeout = crate::dns::util::udp_dns_timeout(timeout.remaining()?);
            crate::dns::resolver::lookup_tcp_type(&addr, host, answer_type, timeout)
                .await
                .map(|records| records.into_iter().map(|record| record.ip).collect())
                .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))
        }
        crate::dns::custom::ParsedDnsServer::Tls {
            server_name,
            host: server_host,
            port,
        } => {
            let addrs =
                crate::dns::custom::resolve_server_host(&server_host, port, timeout.remaining()?)
                    .await?;
            let timeout = crate::dns::util::udp_dns_timeout(timeout.remaining()?);
            crate::dns::resolver::lookup_tls_type(
                &server_name,
                &addrs,
                host,
                answer_type,
                timeout,
                false,
            )
            .await
            .map(|records| records.into_iter().map(|record| record.ip).collect())
            .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))
        }
        crate::dns::custom::ParsedDnsServer::Quic {
            server_name,
            host: server_host,
            port,
        } => {
            let addrs =
                crate::dns::custom::resolve_server_host(&server_host, port, timeout.remaining()?)
                    .await?;
            let timeout = crate::dns::util::udp_dns_timeout(timeout.remaining()?);
            crate::dns::resolver::lookup_quic_type(
                &server_name,
                &addrs,
                host,
                answer_type,
                timeout,
                false,
            )
            .await
            .map(|records| records.into_iter().map(|record| record.ip).collect())
            .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))
        }
    }
}

fn shared_doh_resolver(
    dns_server: &str,
    host: &str,
    timeout: TimeoutBudget,
    doh_tls_config: Option<&rustls::ClientConfig>,
) -> Result<SharedDohResolver, FetchError> {
    let server_url = parse_doh_dns_server(dns_server)?;
    let client =
        crate::dns::doh::client_with_budget_and_tls_config(timeout, doh_tls_config.cloned())
            .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))?;
    Ok(SharedDohResolver { server_url, client })
}

fn is_doh_dns_server(dns_server: &str) -> bool {
    dns_server.starts_with("http://") || dns_server.starts_with("https://")
}

fn parse_doh_dns_server(dns_server: &str) -> Result<Url, FetchError> {
    Url::parse(dns_server)
        .map_err(|err| FetchError::Message(format!("invalid dns-server '{dns_server}': {err}")))
}

async fn resolve_doh_ips(
    host: &str,
    dns_server: &str,
    shared_doh: Option<&SharedDohResolver>,
    timeout: TimeoutBudget,
) -> Result<Vec<IpAddr>, FetchError> {
    let (ipv4, ipv6) = tokio::join!(
        resolve_doh_host_family(
            host,
            dns_server,
            shared_doh,
            "A",
            crate::dns::wire::TYPE_A,
            timeout,
        ),
        resolve_doh_host_family(
            host,
            dns_server,
            shared_doh,
            "AAAA",
            crate::dns::wire::TYPE_AAAA,
            timeout,
        )
    );

    let mut addrs = Vec::new();
    if let Ok(records) = &ipv4 {
        addrs.extend(records.iter().copied());
    }
    if let Ok(records) = &ipv6 {
        addrs.extend(records.iter().copied());
    }
    if !addrs.is_empty() {
        return Ok(addrs);
    }
    ipv4?;
    ipv6?;
    Err(FetchError::Runtime(format!("lookup {host}: no such host")))
}

async fn resolve_doh_host_family(
    host: &str,
    dns_server: &str,
    shared_doh: Option<&SharedDohResolver>,
    label: &str,
    answer_type: u16,
    timeout: TimeoutBudget,
) -> Result<Vec<IpAddr>, FetchError> {
    let records = if let Some(shared_doh) = shared_doh {
        crate::dns::doh::lookup_doh_type_with_client(
            &shared_doh.client,
            &shared_doh.server_url,
            host,
            label,
            answer_type,
        )
        .await
    } else {
        let server_url = parse_doh_dns_server(dns_server)?;
        crate::dns::doh::lookup_doh_type(
            &server_url,
            host,
            label,
            answer_type,
            timeout.remaining()?,
        )
        .await
    };
    records
        .map(|records| records.into_iter().map(|record| record.ip).collect())
        .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))
}

#[cfg(unix)]
async fn resolve_system_host_family(
    host: &str,
    port: u16,
    family: AddressFamily,
) -> Result<Vec<SocketAddr>, FetchError> {
    let host = host.to_string();
    let lookup_host = host.clone();
    tokio::task::spawn_blocking(move || {
        resolve_system_host_family_blocking(&lookup_host, port, family)
    })
    .await
    .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))?
}

#[cfg(unix)]
fn resolve_system_host_family_blocking(
    host: &str,
    port: u16,
    family: AddressFamily,
) -> Result<Vec<SocketAddr>, FetchError> {
    let c_host = CString::new(host)
        .map_err(|_| FetchError::Message(format!("invalid hostname '{host}'")))?;
    let c_service = CString::new(port.to_string()).expect("numeric port is a valid C string");
    let mut hints = unsafe { std::mem::zeroed::<libc::addrinfo>() };
    hints.ai_family = match family {
        AddressFamily::Ipv4 => libc::AF_INET,
        AddressFamily::Ipv6 => libc::AF_INET6,
    };
    hints.ai_socktype = libc::SOCK_STREAM;
    hints.ai_protocol = libc::IPPROTO_TCP;

    let mut result = ptr::null_mut();
    let rc = unsafe { libc::getaddrinfo(c_host.as_ptr(), c_service.as_ptr(), &hints, &mut result) };
    if rc != 0 {
        return Err(FetchError::Runtime(format!(
            "lookup {host}: {}",
            gai_error(rc)
        )));
    }

    let mut addrs = Vec::new();
    let mut current = result;
    while !current.is_null() {
        let info = unsafe { &*current };
        if info.ai_family == libc::AF_INET && !info.ai_addr.is_null() {
            let sockaddr = unsafe { &*(info.ai_addr as *const libc::sockaddr_in) };
            addrs.push(socket_addr_from_sockaddr_in(sockaddr));
        } else if info.ai_family == libc::AF_INET6 && !info.ai_addr.is_null() {
            let sockaddr = unsafe { &*(info.ai_addr as *const libc::sockaddr_in6) };
            addrs.push(socket_addr_from_sockaddr_in6(sockaddr));
        }
        current = info.ai_next;
    }
    unsafe { libc::freeaddrinfo(result) };
    dedupe_socket_addrs(&mut addrs);
    Ok(addrs)
}

#[cfg(unix)]
fn socket_addr_from_sockaddr_in(sockaddr: &libc::sockaddr_in) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::from(u32::from_be(sockaddr.sin_addr.s_addr)),
        u16::from_be(sockaddr.sin_port),
    ))
}

#[cfg(unix)]
fn socket_addr_from_sockaddr_in6(sockaddr: &libc::sockaddr_in6) -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(sockaddr.sin6_addr.s6_addr),
        u16::from_be(sockaddr.sin6_port),
        sockaddr.sin6_flowinfo,
        sockaddr.sin6_scope_id,
    ))
}

#[cfg(unix)]
fn gai_error(code: libc::c_int) -> String {
    let message = unsafe { libc::gai_strerror(code) };
    if message.is_null() {
        return format!("getaddrinfo error {code}");
    }
    unsafe { CStr::from_ptr(message) }
        .to_string_lossy()
        .into_owned()
}

#[cfg(not(unix))]
async fn resolve_system_host_family(
    host: &str,
    port: u16,
    family: AddressFamily,
) -> Result<Vec<SocketAddr>, FetchError> {
    tokio::net::lookup_host((host, port))
        .await
        .map(|addrs| {
            let mut addrs = addrs
                .filter(|addr| match (family, *addr) {
                    (AddressFamily::Ipv4, SocketAddr::V4(_))
                    | (AddressFamily::Ipv6, SocketAddr::V6(_)) => true,
                    _ => false,
                })
                .collect::<Vec<_>>();
            dedupe_socket_addrs(&mut addrs);
            addrs
        })
        .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))
}

fn socket_addrs_with_port(addrs: Vec<IpAddr>, port: u16) -> Vec<SocketAddr> {
    let mut out = addrs
        .into_iter()
        .map(|addr| SocketAddr::new(addr, port))
        .collect::<Vec<_>>();
    dedupe_socket_addrs(&mut out);
    out
}

fn dedupe_socket_addrs(addrs: &mut Vec<SocketAddr>) {
    let mut unique = Vec::new();
    for addr in addrs.drain(..) {
        if !unique.contains(&addr) {
            unique.push(addr);
        }
    }
    *addrs = unique;
}

pub(crate) async fn connect_first(
    addrs: Vec<SocketAddr>,
    timeout: TimeoutBudget,
) -> Result<TcpStream, FetchError> {
    connect_staggered(interleave_socket_addrs(addrs)?, timeout).await
}

#[cfg(test)]
pub(crate) fn split_addrs_by_first_family(
    addrs: Vec<SocketAddr>,
) -> Result<(Vec<SocketAddr>, Vec<SocketAddr>), FetchError> {
    let Some(first) = addrs.first() else {
        return Err(FetchError::Runtime(
            "lookup returned no addresses".to_string(),
        ));
    };
    let first_is_ipv4 = first.is_ipv4();
    Ok(addrs
        .into_iter()
        .partition(|addr| addr.is_ipv4() == first_is_ipv4))
}

pub(crate) fn interleave_socket_addrs(
    addrs: Vec<SocketAddr>,
) -> Result<Vec<SocketAddr>, FetchError> {
    let Some(first) = addrs.first() else {
        return Err(FetchError::Runtime(
            "lookup returned no addresses".to_string(),
        ));
    };
    let first_is_ipv4 = first.is_ipv4();
    let mut preferred = VecDeque::new();
    let mut fallback = VecDeque::new();
    for addr in addrs {
        if addr.is_ipv4() == first_is_ipv4 {
            preferred.push_back(addr);
        } else {
            fallback.push_back(addr);
        }
    }

    let mut ordered = Vec::with_capacity(preferred.len() + fallback.len());
    while !preferred.is_empty() || !fallback.is_empty() {
        if let Some(addr) = preferred.pop_front()
            && !ordered.contains(&addr)
        {
            ordered.push(addr);
        }
        if let Some(addr) = fallback.pop_front()
            && !ordered.contains(&addr)
        {
            ordered.push(addr);
        }
    }
    Ok(ordered)
}

pub(crate) async fn connect_host_happy_eyeballs_traced(
    host: &str,
    port: u16,
    dns_server: Option<&str>,
    doh_tls_config: Option<rustls::ClientConfig>,
    timeout: TimeoutBudget,
) -> Result<TcpConnectTrace, FetchError> {
    let shared_doh = match dns_server.filter(|s| is_doh_dns_server(s)) {
        Some(server) => Some(shared_doh_resolver(
            server,
            host,
            timeout,
            doh_tls_config.as_ref(),
        )?),
        None => None,
    };
    let dns_start = Instant::now();
    let mut ipv4 = Box::pin(resolve_host_family(
        host,
        port,
        dns_server,
        shared_doh.as_ref(),
        AddressFamily::Ipv4,
        timeout,
    ));
    let mut ipv6 = Box::pin(resolve_host_family(
        host,
        port,
        dns_server,
        shared_doh.as_ref(),
        AddressFamily::Ipv6,
        timeout,
    ));
    let mut ipv4_done = false;
    let mut ipv6_done = false;
    let mut ipv4_addrs = Vec::new();
    let mut ipv6_addrs = Vec::new();
    let mut resolved_addrs = Vec::new();
    let mut pending = VecDeque::new();
    let mut scheduled_addrs = Vec::new();
    let mut active = FuturesUnordered::new();
    let mut last_err = None;
    let mut first_positive_family: Option<AddressFamily> = None;
    let mut held_ipv4_until_resolution_delay = false;
    let mut connection_delay_running = false;
    let resolution_delay = tokio::time::sleep(HAPPY_EYEBALLS_RESOLUTION_DELAY);
    tokio::pin!(resolution_delay);
    let connection_delay = tokio::time::sleep(HAPPY_EYEBALLS_FALLBACK_DELAY);
    tokio::pin!(connection_delay);

    loop {
        if active.is_empty()
            && pending.is_empty()
            && ipv4_done
            && ipv6_done
            && !held_ipv4_until_resolution_delay
        {
            return Err(last_err.take().unwrap_or_else(|| {
                FetchError::Runtime("lookup returned no addresses".to_string())
            }));
        }

        if active.is_empty()
            && !pending.is_empty()
            && !held_ipv4_until_resolution_delay
            && !connection_delay_running
        {
            start_next_tcp_connect(timeout, &mut pending, &mut active);
            connection_delay
                .as_mut()
                .reset(tokio::time::Instant::now() + HAPPY_EYEBALLS_FALLBACK_DELAY);
            connection_delay_running = true;
            continue;
        }

        tokio::select! {
            result = &mut ipv4, if !ipv4_done => {
                ipv4_done = true;
                match result {
                    Ok(addrs) => {
                        if !addrs.is_empty() {
                            append_unique_socket_addrs(&mut resolved_addrs, &addrs);
                            ipv4_addrs = addrs;
                            if first_positive_family.is_none() && !ipv6_done {
                                first_positive_family = Some(AddressFamily::Ipv4);
                                held_ipv4_until_resolution_delay = true;
                                resolution_delay.as_mut().reset(tokio::time::Instant::now() + HAPPY_EYEBALLS_RESOLUTION_DELAY);
                            } else {
                                enqueue_interleaved(
                                    &mut pending,
                                    &mut scheduled_addrs,
                                    &ipv4_addrs,
                                    &ipv6_addrs,
                                );
                            }
                        }
                    }
                    Err(err) => last_err = Some(err),
                }
            }
            result = &mut ipv6, if !ipv6_done => {
                ipv6_done = true;
                match result {
                    Ok(addrs) => {
                        if !addrs.is_empty() {
                            append_unique_socket_addrs(&mut resolved_addrs, &addrs);
                            ipv6_addrs = addrs;
                            if first_positive_family.is_none() {
                                first_positive_family = Some(AddressFamily::Ipv6);
                            }
                            enqueue_interleaved(
                                &mut pending,
                                &mut scheduled_addrs,
                                &ipv4_addrs,
                                &ipv6_addrs,
                            );
                            held_ipv4_until_resolution_delay = false;
                        } else if held_ipv4_until_resolution_delay {
                            enqueue_interleaved(
                                &mut pending,
                                &mut scheduled_addrs,
                                &ipv4_addrs,
                                &ipv6_addrs,
                            );
                            held_ipv4_until_resolution_delay = false;
                        }
                    }
                    Err(err) => {
                        last_err = Some(err);
                        if held_ipv4_until_resolution_delay {
                            enqueue_interleaved(
                                &mut pending,
                                &mut scheduled_addrs,
                                &ipv4_addrs,
                                &ipv6_addrs,
                            );
                            held_ipv4_until_resolution_delay = false;
                        }
                    }
                }
            }
            _ = &mut resolution_delay, if held_ipv4_until_resolution_delay => {
                enqueue_interleaved(
                    &mut pending,
                    &mut scheduled_addrs,
                    &ipv4_addrs,
                    &ipv6_addrs,
                );
                held_ipv4_until_resolution_delay = false;
            }
            result = active.next(), if !active.is_empty() => {
                match result {
                    Some(Ok(outcome)) => return Ok(TcpConnectTrace {
                        stream: outcome.stream,
                        resolved_addrs,
                        dns_duration: Some(dns_start.elapsed()),
                        tcp_duration: outcome.duration,
                    }),
                    Some(Err(err)) => {
                        last_err = Some(err);
                        if !pending.is_empty() {
                            start_next_tcp_connect(timeout, &mut pending, &mut active);
                            connection_delay.as_mut().reset(tokio::time::Instant::now() + HAPPY_EYEBALLS_FALLBACK_DELAY);
                            connection_delay_running = true;
                        } else if active.is_empty() {
                            connection_delay_running = false;
                        }
                    }
                    None => {
                        connection_delay_running = false;
                    }
                }
            }
            _ = &mut connection_delay, if connection_delay_running && !pending.is_empty() => {
                start_next_tcp_connect(timeout, &mut pending, &mut active);
                if pending.is_empty() {
                    connection_delay_running = false;
                } else {
                    connection_delay.as_mut().reset(tokio::time::Instant::now() + HAPPY_EYEBALLS_FALLBACK_DELAY);
                }
            }
        }
    }
}

fn append_unique_socket_addrs(target: &mut Vec<SocketAddr>, addrs: &[SocketAddr]) {
    for addr in addrs {
        if !target.contains(addr) {
            target.push(*addr);
        }
    }
}

fn enqueue_interleaved(
    pending: &mut VecDeque<SocketAddr>,
    scheduled_addrs: &mut Vec<SocketAddr>,
    ipv4_addrs: &[SocketAddr],
    ipv6_addrs: &[SocketAddr],
) {
    let ordered = if ipv6_addrs.is_empty() {
        ipv4_addrs.to_vec()
    } else if ipv4_addrs.is_empty() {
        ipv6_addrs.to_vec()
    } else {
        interleave_socket_addr_families(ipv6_addrs, ipv4_addrs)
    };
    for addr in ordered {
        if !scheduled_addrs.contains(&addr) {
            scheduled_addrs.push(addr);
            pending.push_back(addr);
        }
    }
}

pub(crate) fn interleave_socket_addr_families(
    first: &[SocketAddr],
    second: &[SocketAddr],
) -> Vec<SocketAddr> {
    let mut first = VecDeque::from(first.to_vec());
    let mut second = VecDeque::from(second.to_vec());
    let mut out = Vec::with_capacity(first.len() + second.len());
    while !first.is_empty() || !second.is_empty() {
        if let Some(addr) = first.pop_front() {
            out.push(addr);
        }
        if let Some(addr) = second.pop_front() {
            out.push(addr);
        }
    }
    out
}

async fn connect_staggered(
    addrs: Vec<SocketAddr>,
    timeout: TimeoutBudget,
) -> Result<TcpStream, FetchError> {
    race_staggered(
        addrs,
        HAPPY_EYEBALLS_FALLBACK_DELAY,
        "lookup returned no addresses",
        "connect",
        move |addr| connect_addr_timed(addr, timeout),
    )
    .await
    .map(|outcome| outcome.stream)
}

pub(crate) async fn race_staggered<I, T, Start, Fut>(
    items: Vec<I>,
    fallback_delay: Duration,
    empty_error: &'static str,
    task_name: &'static str,
    mut start: Start,
) -> Result<T, FetchError>
where
    I: Send + 'static,
    T: Send + 'static,
    Start: FnMut(I) -> Fut + Send,
    Fut: Future<Output = Result<T, FetchError>> + Send + 'static,
{
    let mut pending = VecDeque::from(items);
    let mut active = FuturesUnordered::new();
    let mut last_err = None;
    start_next_staggered(task_name, &mut pending, &mut active, &mut start);
    let delay = tokio::time::sleep(fallback_delay);
    tokio::pin!(delay);

    loop {
        if active.is_empty() {
            return Err(last_err.unwrap_or_else(|| FetchError::Runtime(empty_error.to_string())));
        }
        if pending.is_empty() {
            match active.next().await {
                Some(Ok(outcome)) => return Ok(outcome),
                Some(Err(err)) => last_err = Some(err),
                None => {}
            }
            continue;
        }

        tokio::select! {
            result = active.next() => match result {
                Some(Ok(outcome)) => return Ok(outcome),
                Some(Err(err)) => {
                    last_err = Some(err);
                    start_next_staggered(task_name, &mut pending, &mut active, &mut start);
                    delay.as_mut().reset(tokio::time::Instant::now() + fallback_delay);
                }
                None => {}
            },
            _ = &mut delay => {
                start_next_staggered(task_name, &mut pending, &mut active, &mut start);
                delay.as_mut().reset(tokio::time::Instant::now() + fallback_delay);
            }
        }
    }
}

fn start_next_staggered<I, T, Start, Fut>(
    task_name: &'static str,
    pending: &mut VecDeque<I>,
    active: &mut FuturesUnordered<AbortOnDropJoin<T>>,
    start: &mut Start,
) where
    I: Send + 'static,
    T: Send + 'static,
    Start: FnMut(I) -> Fut + Send,
    Fut: Future<Output = Result<T, FetchError>> + Send + 'static,
{
    if let Some(item) = pending.pop_front() {
        active.push(AbortOnDropJoin::new(start(item), task_name));
    }
}

fn start_next_tcp_connect(
    timeout: TimeoutBudget,
    pending: &mut VecDeque<SocketAddr>,
    active: &mut FuturesUnordered<AbortOnDropJoin<TimedTcpStream>>,
) {
    if let Some(addr) = pending.pop_front() {
        active.push(AbortOnDropJoin::new(
            connect_addr_timed(addr, timeout),
            "connect",
        ));
    }
}

async fn connect_addr_timed(
    addr: SocketAddr,
    timeout: TimeoutBudget,
) -> Result<TimedTcpStream, FetchError> {
    let start = Instant::now();
    let stream = timeout.run(connect_addr(addr)).await?;
    Ok(TimedTcpStream {
        stream,
        duration: start.elapsed(),
    })
}

struct TimedTcpStream {
    stream: TcpStream,
    duration: Duration,
}

pub(crate) struct AbortOnDropJoin<T> {
    handle: JoinHandle<Result<T, FetchError>>,
    task_name: &'static str,
}

impl<T> AbortOnDropJoin<T>
where
    T: Send + 'static,
{
    fn new(
        future: impl Future<Output = Result<T, FetchError>> + Send + 'static,
        task_name: &'static str,
    ) -> Self {
        Self {
            handle: tokio::spawn(future),
            task_name,
        }
    }
}

impl<T> Future for AbortOnDropJoin<T> {
    type Output = Result<T, FetchError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let task_name = self.task_name;
        Pin::new(&mut self.handle).poll(cx).map(|result| {
            result.unwrap_or_else(|err| {
                Err(FetchError::Runtime(format!(
                    "{task_name} task failed: {err}"
                )))
            })
        })
    }
}

impl<T> Drop for AbortOnDropJoin<T> {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[cfg(test)]
fn per_address_timeout(addrs_len: usize, timeout: TimeoutBudget) -> Option<Duration> {
    let addrs_len = u32::try_from(addrs_len).ok()?;
    if addrs_len == 0 {
        return None;
    }
    timeout
        .timeout()
        .and_then(|timeout| timeout.checked_div(addrs_len))
}

async fn connect_addr(addr: SocketAddr) -> Result<TcpStream, FetchError> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }?;
    socket.set_nodelay(true)?;
    let _ = socket.set_keepalive(true);
    let stream = socket.connect(addr).await?;
    configure_tcp_stream(&stream);
    Ok(stream)
}

fn configure_tcp_stream(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let socket = socket2::SockRef::from(stream);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE_IDLE)
        .with_interval(TCP_KEEPALIVE_INTERVAL)
        .with_retries(TCP_KEEPALIVE_RETRIES);
    let _ = socket.set_tcp_keepalive(&keepalive);
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    let _ = socket.set_tcp_user_timeout(Some(TCP_USER_TIMEOUT));
}

pub(crate) fn http_host_header_value(url: &Url) -> Result<String, FetchError> {
    let host = match url.host() {
        Some(Host::Domain(host)) => host.to_string(),
        Some(Host::Ipv4(host)) => host.to_string(),
        Some(Host::Ipv6(host)) => format!("[{host}]"),
        None => return Err(FetchError::Message("URL host is required".to_string())),
    };
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

pub(crate) async fn dial_proxy(
    proxy: &str,
    target: &Url,
    dns_server: Option<&str>,
    doh_tls_config: Option<rustls::ClientConfig>,
    timeout: TimeoutBudget,
) -> Result<DialStream, FetchError> {
    let proxy_url = parse_proxy_url(proxy)?;
    match proxy_url.scheme() {
        "http" | "https" => {
            dial_http_proxy_tunnel(proxy, &proxy_url, target, timeout, None, None).await
        }
        "socks5" | "socks5h" => {
            dial_socks5_proxy(&proxy_url, target, dns_server, doh_tls_config, timeout).await
        }
        scheme => Err(FetchError::Message(format!(
            "invalid proxy '{proxy}': unsupported proxy scheme '{scheme}'"
        ))),
    }
}

pub(crate) fn parse_proxy_url(proxy: &str) -> Result<Url, FetchError> {
    Url::parse(proxy)
        .or_else(|err| {
            if matches!(err, url::ParseError::RelativeUrlWithoutBase) {
                Url::parse(&format!("http://{proxy}"))
            } else {
                Err(err)
            }
        })
        .map_err(|err| FetchError::Message(format!("invalid proxy '{proxy}': {err}")))
}

pub(crate) async fn dial_http_proxy_tunnel(
    raw_proxy: &str,
    proxy_url: &Url,
    target: &Url,
    timeout: TimeoutBudget,
    proxy_tls_config: Option<rustls::ClientConfig>,
    proxy_authorization: Option<String>,
) -> Result<DialStream, FetchError> {
    let mut stream = match proxy_tls_config {
        Some(config) => {
            dial_http_proxy_stream_with_tls(raw_proxy, proxy_url, timeout, Some(config)).await?
        }
        None => dial_http_proxy_stream(raw_proxy, proxy_url, timeout).await?,
    };

    let authority = url_authority(target)?;
    let mut request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: {}\r\n",
        core::user_agent()
    );
    let proxy_authorization = match proxy_authorization {
        Some(auth) => Some(auth),
        None => proxy_basic_auth(proxy_url)?,
    };
    if let Some(auth) = proxy_authorization {
        request.push_str("Proxy-Authorization: ");
        request.push_str(&auth);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    timeout_fetch(timeout, async {
        stream.write_all(request.as_bytes()).await?;

        let mut raw = Vec::new();
        let mut buf = [0_u8; 1];
        while !raw.ends_with(b"\r\n\r\n") {
            if raw.len() >= 16 * 1024 {
                return Err(FetchError::Runtime(
                    "proxy CONNECT response was too large".to_string(),
                ));
            }
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                return Err(FetchError::Runtime(
                    "proxy closed connection during CONNECT".to_string(),
                ));
            }
            raw.extend_from_slice(&buf[..n]);
        }
        let response = String::from_utf8_lossy(&raw);
        let status = response
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(0);
        if !(200..300).contains(&status) {
            return Err(FetchError::Runtime(format!(
                "proxy CONNECT failed with status {status}"
            )));
        }
        Ok(())
    })
    .await?;
    Ok(stream)
}

pub(crate) async fn dial_http_proxy_stream(
    raw_proxy: &str,
    proxy_url: &Url,
    timeout: TimeoutBudget,
) -> Result<DialStream, FetchError> {
    dial_http_proxy_stream_with_tls(raw_proxy, proxy_url, timeout, None).await
}

pub(crate) async fn dial_http_proxy_stream_with_tls(
    raw_proxy: &str,
    proxy_url: &Url,
    timeout: TimeoutBudget,
    proxy_tls_config: Option<rustls::ClientConfig>,
) -> Result<DialStream, FetchError> {
    let stream = connect_proxy_tcp(proxy_url, timeout).await?;
    if proxy_url.scheme() == "https" {
        let host = proxy_url.host_str().ok_or_else(|| {
            FetchError::Message(format!("invalid proxy '{raw_proxy}': missing host"))
        })?;
        let server_name =
            rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|_| {
                FetchError::Message(format!("invalid proxy '{raw_proxy}': invalid host"))
            })?;
        let mut config = match proxy_tls_config {
            Some(config) => config,
            None => crate::tls::rustls_platform_client_config()?,
        };
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let stream = timeout_fetch(timeout, async {
            tokio_rustls::TlsConnector::from(Arc::new(config))
                .connect(server_name, stream)
                .await
                .map_err(FetchError::from)
        })
        .await?;
        Ok(Box::pin(stream))
    } else {
        Ok(Box::pin(stream))
    }
}

pub(crate) async fn connect_proxy_tcp(
    proxy_url: &Url,
    timeout: TimeoutBudget,
) -> Result<TcpStream, FetchError> {
    let host = proxy_url
        .host_str()
        .ok_or_else(|| FetchError::Message("proxy host is required".to_string()))?;
    let port = proxy_url.port_or_known_default().unwrap_or_else(|| {
        if matches!(proxy_url.scheme(), "socks5" | "socks5h") {
            1080
        } else if proxy_url.scheme() == "https" {
            443
        } else {
            80
        }
    });
    timeout_fetch(timeout, async {
        let addrs = tokio::net::lookup_host((host, port))
            .await
            .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))?
            .collect();
        connect_first(addrs, timeout).await
    })
    .await
}

pub(crate) fn proxy_basic_auth(proxy_url: &Url) -> Result<Option<String>, FetchError> {
    if proxy_url.username().is_empty() && proxy_url.password().is_none() {
        return Ok(None);
    }
    let username = percent_encoding::percent_decode_str(proxy_url.username())
        .decode_utf8()
        .map_err(|err| FetchError::Message(format!("invalid proxy username: {err}")))?;
    let password = proxy_url.password().unwrap_or("");
    let password = percent_encoding::percent_decode_str(password)
        .decode_utf8()
        .map_err(|err| FetchError::Message(format!("invalid proxy password: {err}")))?;
    let raw = format!("{username}:{password}");
    Ok(Some(format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(raw)
    )))
}

pub(crate) async fn dial_socks5_proxy(
    proxy_url: &Url,
    target: &Url,
    dns_server: Option<&str>,
    doh_tls_config: Option<rustls::ClientConfig>,
    timeout: TimeoutBudget,
) -> Result<DialStream, FetchError> {
    let stream = connect_socks5_proxy(proxy_url, timeout).await?;
    let mut request = vec![0x05, 0x01, 0x00];
    timeout_fetch(
        timeout,
        write_socks5_target(
            &mut request,
            proxy_url.scheme() == "socks5h",
            target,
            dns_server,
            doh_tls_config,
            timeout,
        ),
    )
    .await?;
    send_socks5_connect(stream, request, timeout).await
}

pub(crate) async fn dial_socks5_proxy_to_addr(
    proxy_url: &Url,
    target_addr: SocketAddr,
    timeout: TimeoutBudget,
) -> Result<DialStream, FetchError> {
    let stream = connect_socks5_proxy(proxy_url, timeout).await?;
    let mut request = vec![0x05, 0x01, 0x00];
    write_socks5_ip(&mut request, target_addr.ip());
    request.extend_from_slice(&target_addr.port().to_be_bytes());
    send_socks5_connect(stream, request, timeout).await
}

async fn connect_socks5_proxy(
    proxy_url: &Url,
    timeout: TimeoutBudget,
) -> Result<TcpStream, FetchError> {
    let mut stream = connect_proxy_tcp(proxy_url, timeout).await?;
    let username = percent_encoding::percent_decode_str(proxy_url.username())
        .decode_utf8()
        .map_err(|err| FetchError::Message(format!("invalid proxy username: {err}")))?;
    let password = proxy_url
        .password()
        .map(|password| percent_encoding::percent_decode_str(password).decode_utf8())
        .transpose()
        .map_err(|err| FetchError::Message(format!("invalid proxy password: {err}")))?;
    let has_credentials = !username.is_empty() || password.is_some();
    let password = password.unwrap_or(std::borrow::Cow::Borrowed(""));

    if has_credentials {
        if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
            return Err(FetchError::Message(
                "SOCKS5 proxy credentials are too long".to_string(),
            ));
        }
        timeout_fetch(timeout, async {
            stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
            Ok(())
        })
        .await?;
    } else {
        timeout_fetch(timeout, async {
            stream.write_all(&[0x05, 0x01, 0x00]).await?;
            Ok(())
        })
        .await?;
    }

    let mut method = [0_u8; 2];
    timeout_fetch(timeout, async {
        stream.read_exact(&mut method).await?;
        Ok(())
    })
    .await?;
    if method[0] != 0x05 {
        return Err(FetchError::Runtime(
            "SOCKS5 proxy returned an invalid greeting".to_string(),
        ));
    }
    match method[1] {
        0x00 => {}
        0x02 => {
            if !has_credentials {
                return Err(FetchError::Runtime(
                    "SOCKS5 proxy requires authentication".to_string(),
                ));
            }
            let mut auth = Vec::with_capacity(3 + username.len() + password.len());
            auth.push(0x01);
            auth.push(username.len() as u8);
            auth.extend_from_slice(username.as_bytes());
            auth.push(password.len() as u8);
            auth.extend_from_slice(password.as_bytes());
            timeout_fetch(timeout, async {
                stream.write_all(&auth).await?;
                Ok(())
            })
            .await?;
            let mut response = [0_u8; 2];
            timeout_fetch(timeout, async {
                stream.read_exact(&mut response).await?;
                Ok(())
            })
            .await?;
            if response != [0x01, 0x00] {
                return Err(FetchError::Runtime(
                    "SOCKS5 proxy authentication failed".to_string(),
                ));
            }
        }
        0xff => {
            return Err(FetchError::Runtime(
                "SOCKS5 proxy rejected authentication methods".to_string(),
            ));
        }
        _ => {
            return Err(FetchError::Runtime(
                "SOCKS5 proxy selected an unsupported authentication method".to_string(),
            ));
        }
    }

    Ok(stream)
}

async fn send_socks5_connect(
    mut stream: TcpStream,
    request: Vec<u8>,
    timeout: TimeoutBudget,
) -> Result<DialStream, FetchError> {
    timeout_fetch(timeout, async {
        stream.write_all(&request).await?;
        Ok(())
    })
    .await?;

    let mut response = [0_u8; 4];
    timeout_fetch(timeout, async {
        stream.read_exact(&mut response).await?;
        Ok(())
    })
    .await?;
    if response[0] != 0x05 || response[1] != 0x00 {
        return Err(FetchError::Runtime(format!(
            "SOCKS5 proxy CONNECT failed with status {}",
            response[1]
        )));
    }
    timeout_fetch(timeout, read_socks5_bound_addr(&mut stream, response[3])).await?;
    Ok(Box::pin(stream))
}

async fn write_socks5_target(
    request: &mut Vec<u8>,
    remote_dns: bool,
    target: &Url,
    dns_server: Option<&str>,
    doh_tls_config: Option<rustls::ClientConfig>,
    timeout: TimeoutBudget,
) -> Result<(), FetchError> {
    let host = target
        .host_str()
        .ok_or_else(|| FetchError::Message("URL host is required".to_string()))?;
    let port = target
        .port_or_known_default()
        .ok_or_else(|| FetchError::Message("URL port is required".to_string()))?;

    if remote_dns {
        if host.len() > u8::MAX as usize {
            return Err(FetchError::Message(
                "SOCKS5 target hostname is too long".to_string(),
            ));
        }
        request.push(0x03);
        request.push(host.len() as u8);
        request.extend_from_slice(host.as_bytes());
    } else if let Ok(ip) = host.parse::<IpAddr>() {
        write_socks5_ip(request, ip);
    } else {
        let addr = resolve_host_with_doh_tls(host, dns_server, doh_tls_config, timeout)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| FetchError::Runtime(format!("lookup {host}: no addresses")))?;
        write_socks5_ip(request, addr.ip());
    }
    request.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

fn write_socks5_ip(request: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(ip) => {
            request.push(0x01);
            request.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            request.push(0x04);
            request.extend_from_slice(&ip.octets());
        }
    }
}

async fn read_socks5_bound_addr(stream: &mut TcpStream, atyp: u8) -> Result<(), FetchError> {
    match atyp {
        0x01 => {
            let mut raw = [0_u8; 6];
            stream.read_exact(&mut raw).await?;
        }
        0x03 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len).await?;
            let mut raw = vec![0_u8; len[0] as usize + 2];
            stream.read_exact(&mut raw).await?;
        }
        0x04 => {
            let mut raw = [0_u8; 18];
            stream.read_exact(&mut raw).await?;
        }
        _ => {
            return Err(FetchError::Runtime(
                "SOCKS5 proxy returned an invalid address type".to_string(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn url_authority(url: &Url) -> Result<String, FetchError> {
    let host = url
        .host_str()
        .ok_or_else(|| FetchError::Message("URL host is required".to_string()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| FetchError::Message("URL port is required".to_string()))?;
    Ok(if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    })
}

async fn timeout_fetch<T>(
    timeout: TimeoutBudget,
    future: impl Future<Output = Result<T, FetchError>>,
) -> Result<T, FetchError> {
    timeout.run(future).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_header_value_brackets_ipv6_literals() {
        let url = Url::parse("http://[::1]/").unwrap();
        assert_eq!(http_host_header_value(&url).unwrap(), "[::1]");

        let url = Url::parse("http://[::1]:3000/path").unwrap();
        assert_eq!(http_host_header_value(&url).unwrap(), "[::1]:3000");
    }

    #[test]
    fn host_header_value_keeps_domain_and_ipv4_authorities() {
        let url = Url::parse("https://example.com/path").unwrap();
        assert_eq!(http_host_header_value(&url).unwrap(), "example.com");

        let url = Url::parse("http://127.0.0.1:3000/path").unwrap();
        assert_eq!(http_host_header_value(&url).unwrap(), "127.0.0.1:3000");
    }

    #[test]
    fn per_address_timeout_splits_connect_timeout_across_addresses() {
        let timeout = TimeoutBudget::new(Some(Duration::from_secs(9)));
        assert_eq!(
            per_address_timeout(3, timeout),
            Some(Duration::from_secs(3))
        );
        assert_eq!(per_address_timeout(0, timeout), None);
        assert_eq!(per_address_timeout(3, TimeoutBudget::new(None)), None);
    }

    #[test]
    fn split_addrs_by_first_family_preserves_resolver_family_preference() {
        let addrs = vec![
            SocketAddr::new("::1".parse().unwrap(), 443),
            SocketAddr::new("127.0.0.1".parse().unwrap(), 443),
            SocketAddr::new("::2".parse().unwrap(), 443),
            SocketAddr::new("127.0.0.2".parse().unwrap(), 443),
        ];

        let (preferred, fallback) = split_addrs_by_first_family(addrs).unwrap();

        assert_eq!(
            preferred,
            [
                SocketAddr::new("::1".parse().unwrap(), 443),
                SocketAddr::new("::2".parse().unwrap(), 443)
            ]
        );
        assert_eq!(
            fallback,
            [
                SocketAddr::new("127.0.0.1".parse().unwrap(), 443),
                SocketAddr::new("127.0.0.2".parse().unwrap(), 443)
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn sockaddr_in6_conversion_preserves_scope_id() {
        let mut sockaddr = unsafe { std::mem::zeroed::<libc::sockaddr_in6>() };
        sockaddr.sin6_port = u16::to_be(8443);
        sockaddr.sin6_flowinfo = 123;
        sockaddr.sin6_scope_id = 42;
        sockaddr.sin6_addr = libc::in6_addr {
            s6_addr: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        };

        let addr = socket_addr_from_sockaddr_in6(&sockaddr);

        let SocketAddr::V6(addr) = addr else {
            panic!("expected IPv6 socket address");
        };
        assert_eq!(*addr.ip(), Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(addr.port(), 8443);
        assert_eq!(addr.flowinfo(), 123);
        assert_eq!(addr.scope_id(), 42);
    }

    #[tokio::test]
    async fn happy_eyeballs_starts_fallback_immediately_after_preferred_failure() {
        let addrs = vec![
            SocketAddr::new("::1".parse().unwrap(), 443),
            SocketAddr::new("127.0.0.1".parse().unwrap(), 443),
        ];

        let result = tokio::time::timeout(
            Duration::from_millis(100),
            race_staggered(
                addrs,
                Duration::from_secs(1),
                "lookup returned no addresses",
                "test connect",
                |addr| async move {
                    if addr.is_ipv4() {
                        Ok("fallback")
                    } else {
                        Err(FetchError::Runtime("preferred failed".to_string()))
                    }
                },
            ),
        )
        .await
        .expect("fallback should not wait for the delay")
        .unwrap();

        assert_eq!(result, "fallback");
    }

    #[tokio::test]
    async fn happy_eyeballs_starts_fallback_after_delay_while_preferred_is_pending() {
        let addrs = vec![
            SocketAddr::new("::1".parse().unwrap(), 443),
            SocketAddr::new("127.0.0.1".parse().unwrap(), 443),
        ];

        let result = tokio::time::timeout(
            Duration::from_millis(200),
            race_staggered(
                addrs,
                Duration::from_millis(20),
                "lookup returned no addresses",
                "test connect",
                |addr| async move {
                    if addr.is_ipv4() {
                        Ok("fallback")
                    } else {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        Ok("preferred")
                    }
                },
            ),
        )
        .await
        .expect("fallback should start after the delay")
        .unwrap();

        assert_eq!(result, "fallback");
    }

    #[tokio::test]
    async fn happy_eyeballs_prefers_fallback_error_when_both_families_fail() {
        let addrs = vec![
            SocketAddr::new("::1".parse().unwrap(), 443),
            SocketAddr::new("127.0.0.1".parse().unwrap(), 443),
        ];

        let err = race_staggered(
            addrs,
            Duration::from_secs(1),
            "lookup returned no addresses",
            "test connect",
            |addr| async move {
                if addr.is_ipv4() {
                    Err::<(), _>(FetchError::Runtime("fallback failed".to_string()))
                } else {
                    Err::<(), _>(FetchError::Runtime("preferred failed".to_string()))
                }
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.to_string(), "fallback failed");
    }
}
