use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::dns::util::{dns_query_id, udp_dns_timeout};
use crate::dns::wire;
use crate::duration::TimeoutBudget;

const DNS_TYPE_A: u16 = wire::TYPE_A;
const DNS_TYPE_AAAA: u16 = wire::TYPE_AAAA;
const DNS_CLASS_IN: u16 = wire::CLASS_IN;
pub(crate) const DOQ_MESSAGE_ID: u16 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverError(String);

impl fmt::Display for ResolverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ResolverError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    pub ip: IpAddr,
    pub ttl: Option<u32>,
}

pub async fn lookup_udp(
    server_addr: &str,
    host: &str,
    timeout: Option<Duration>,
) -> Result<Vec<IpAddr>, ResolverError> {
    let addr = parse_normalized_addr(server_addr)?;
    lookup_udp_addr(&addr, host, timeout).await
}

pub(crate) async fn lookup_udp_addr(
    addr: &SocketAddr,
    host: &str,
    timeout: Option<Duration>,
) -> Result<Vec<IpAddr>, ResolverError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    let budget = TimeoutBudget::new(timeout);
    let (a, aaaa) = tokio::join!(
        lookup_udp_type_with_budget(addr, host, DNS_TYPE_A, budget),
        lookup_udp_type_with_budget(addr, host, DNS_TYPE_AAAA, budget)
    );

    combine_results(a, aaaa)
}

pub async fn lookup_udp_type(
    server_addr: &str,
    host: &str,
    dns_type: u16,
    timeout: Duration,
) -> Result<Vec<DnsRecord>, ResolverError> {
    let addr = parse_normalized_addr(server_addr)?;
    lookup_udp_type_with_budget(&addr, host, dns_type, TimeoutBudget::new(Some(timeout))).await
}

async fn lookup_udp_type_with_budget(
    server_addr: &SocketAddr,
    host: &str,
    dns_type: u16,
    budget: TimeoutBudget,
) -> Result<Vec<DnsRecord>, ResolverError> {
    let id = dns_query_id();
    let raw = wire::build_query(id, host, dns_type).map_err(resolver_error)?;
    let timeout = udp_dns_timeout(budget.remaining().map_err(resolver_error)?);
    let response = crate::dns::transport::query_udp(*server_addr, &raw, timeout)
        .await
        .map_err(resolver_error)?;
    match dns_records_from_response(&response, id) {
        Ok(records) => Ok(records),
        Err(err) if err.is_truncated() => {
            let response = crate::dns::transport::query_tcp(*server_addr, &raw, budget)
                .await
                .map_err(resolver_error)?;
            dns_records_from_response(&response, id).map_err(resolver_error)
        }
        Err(err) => Err(resolver_error(err)),
    }
}

pub(crate) async fn lookup_tcp_addr(
    addr: &SocketAddr,
    host: &str,
    timeout: Option<Duration>,
) -> Result<Vec<IpAddr>, ResolverError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let budget = TimeoutBudget::new(timeout);
    let connect_timeout = udp_dns_timeout(budget.remaining().map_err(resolver_error)?);
    let mut stream = crate::dns::transport::tcp_connection(addr, connect_timeout)
        .await
        .map_err(resolver_error)?;
    run_stream_lookup(&mut stream, host, budget).await
}

pub(crate) async fn lookup_tls(
    server_name: &ServerName<'static>,
    server_addrs: &[SocketAddr],
    host: &str,
    timeout: Option<Duration>,
    insecure: bool,
) -> Result<Vec<IpAddr>, ResolverError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let budget = TimeoutBudget::new(timeout);
    let connect_timeout = udp_dns_timeout(budget.remaining().map_err(resolver_error)?);
    let mut stream =
        crate::dns::transport::tls_connection(server_name, server_addrs, connect_timeout, insecure)
            .await
            .map_err(resolver_error)?;
    run_stream_lookup(&mut stream, host, budget).await
}

pub(crate) async fn lookup_quic(
    server_name: &ServerName<'static>,
    server_addrs: &[SocketAddr],
    host: &str,
    timeout: Option<Duration>,
    insecure: bool,
) -> Result<Vec<IpAddr>, ResolverError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let budget = TimeoutBudget::new(timeout);
    let connect_timeout = udp_dns_timeout(budget.remaining().map_err(resolver_error)?);
    let connection = crate::dns::transport::quic_connection(
        server_name,
        server_addrs,
        connect_timeout,
        insecure,
    )
    .await
    .map_err(resolver_error)?;
    run_quic_lookup(&connection, host, budget).await
}

pub(crate) async fn lookup_tcp_type(
    addr: &SocketAddr,
    host: &str,
    dns_type: u16,
    timeout: Duration,
) -> Result<Vec<DnsRecord>, ResolverError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![DnsRecord { ip, ttl: None }]);
    }
    let budget = TimeoutBudget::new(Some(timeout));
    let connect_timeout = udp_dns_timeout(budget.remaining().map_err(resolver_error)?);
    let mut stream = crate::dns::transport::tcp_connection(addr, connect_timeout)
        .await
        .map_err(resolver_error)?;
    lookup_stream_type(&mut stream, host, dns_type, budget).await
}

pub(crate) async fn lookup_tls_type(
    server_name: &ServerName<'static>,
    server_addrs: &[SocketAddr],
    host: &str,
    dns_type: u16,
    timeout: Duration,
    insecure: bool,
) -> Result<Vec<DnsRecord>, ResolverError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![DnsRecord { ip, ttl: None }]);
    }
    let budget = TimeoutBudget::new(Some(timeout));
    let connect_timeout = udp_dns_timeout(budget.remaining().map_err(resolver_error)?);
    let mut stream =
        crate::dns::transport::tls_connection(server_name, server_addrs, connect_timeout, insecure)
            .await
            .map_err(resolver_error)?;
    lookup_stream_type(&mut stream, host, dns_type, budget).await
}

pub(crate) async fn lookup_quic_type(
    server_name: &ServerName<'static>,
    server_addrs: &[SocketAddr],
    host: &str,
    dns_type: u16,
    timeout: Duration,
    insecure: bool,
) -> Result<Vec<DnsRecord>, ResolverError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![DnsRecord { ip, ttl: None }]);
    }
    let budget = TimeoutBudget::new(Some(timeout));
    let connect_timeout = udp_dns_timeout(budget.remaining().map_err(resolver_error)?);
    let connection = crate::dns::transport::quic_connection(
        server_name,
        server_addrs,
        connect_timeout,
        insecure,
    )
    .await
    .map_err(resolver_error)?;
    let query = wire::build_query(DOQ_MESSAGE_ID, host, dns_type).map_err(resolver_error)?;
    let timeout = budget.remaining().map_err(resolver_error)?;
    let response = with_optional_timeout(timeout, async {
        crate::dns::transport::quic_query(&connection, &query)
            .await
            .map_err(resolver_error)
    })
    .await?;
    dns_records_from_response(&response, DOQ_MESSAGE_ID).map_err(resolver_error)
}

async fn lookup_stream_type<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    host: &str,
    dns_type: u16,
    budget: TimeoutBudget,
) -> Result<Vec<DnsRecord>, ResolverError> {
    let id = dns_query_id();
    let query = wire::build_query(id, host, dns_type).map_err(resolver_error)?;
    let timeout = budget.remaining().map_err(resolver_error)?;
    let response = with_optional_timeout(timeout, async {
        crate::dns::transport::write_framed_query(stream, &query)
            .await
            .map_err(resolver_error)?;
        crate::dns::transport::read_framed_response(stream)
            .await
            .map_err(resolver_error)
    })
    .await?;
    if response.len() < 2 {
        return Err(ResolverError("short DNS response".to_string()));
    }
    dns_records_from_response(&response, id).map_err(resolver_error)
}

async fn run_stream_lookup<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    host: &str,
    budget: TimeoutBudget,
) -> Result<Vec<IpAddr>, ResolverError> {
    let id_a = dns_query_id();
    let query_a = wire::build_query(id_a, host, DNS_TYPE_A).map_err(resolver_error)?;
    let id_aaaa = dns_query_id();
    let query_aaaa = wire::build_query(id_aaaa, host, DNS_TYPE_AAAA).map_err(resolver_error)?;

    let timeout = budget.remaining().map_err(resolver_error)?;
    let (a_response, aaaa_response) = with_optional_timeout(timeout, async {
        crate::dns::transport::write_framed_query(stream, &query_a)
            .await
            .map_err(resolver_error)?;
        crate::dns::transport::write_framed_query(stream, &query_aaaa)
            .await
            .map_err(resolver_error)?;
        let mut a_response = None;
        let mut aaaa_response = None;
        for _ in 0..2 {
            let response = crate::dns::transport::read_framed_response(stream)
                .await
                .map_err(resolver_error)?;
            if response.len() < 2 {
                return Err(ResolverError("short DNS response".to_string()));
            }
            let response_id = u16::from_be_bytes([response[0], response[1]]);
            if response_id == id_a {
                a_response = Some(response);
            } else if response_id == id_aaaa {
                aaaa_response = Some(response);
            } else {
                return Err(ResolverError("mismatched DNS response ID".to_string()));
            }
        }
        Ok::<_, ResolverError>((a_response, aaaa_response))
    })
    .await?;

    let a_response = a_response.ok_or_else(|| ResolverError("missing DNS response".to_string()))?;
    let aaaa_response =
        aaaa_response.ok_or_else(|| ResolverError("missing DNS response".to_string()))?;
    let a_records = dns_records_from_response(&a_response, id_a).map_err(resolver_error);
    let aaaa_records = dns_records_from_response(&aaaa_response, id_aaaa).map_err(resolver_error);
    combine_results(a_records, aaaa_records)
}

async fn run_quic_lookup(
    connection: &quinn::Connection,
    host: &str,
    budget: TimeoutBudget,
) -> Result<Vec<IpAddr>, ResolverError> {
    // RFC 9250 requires DNS message ID 0 for DoQ.
    let query_a = wire::build_query(DOQ_MESSAGE_ID, host, DNS_TYPE_A).map_err(resolver_error)?;
    let query_aaaa =
        wire::build_query(DOQ_MESSAGE_ID, host, DNS_TYPE_AAAA).map_err(resolver_error)?;

    let timeout = budget.remaining().map_err(resolver_error)?;
    let (a_records, aaaa_records) = with_optional_timeout(timeout, async {
        let (a_result, aaaa_result) = tokio::join!(
            quic_single_query(connection, query_a, DOQ_MESSAGE_ID),
            quic_single_query(connection, query_aaaa, DOQ_MESSAGE_ID),
        );
        Ok::<_, ResolverError>((a_result, aaaa_result))
    })
    .await?;

    combine_results(a_records, aaaa_records)
}

async fn with_optional_timeout<T, Fut>(
    timeout: Option<Duration>,
    fut: Fut,
) -> Result<T, ResolverError>
where
    Fut: std::future::Future<Output = Result<T, ResolverError>>,
{
    tokio::time::timeout(udp_dns_timeout(timeout), fut)
        .await
        .map_err(|_| ResolverError("DNS lookup timed out".to_string()))?
}

async fn quic_single_query(
    connection: &quinn::Connection,
    query: Vec<u8>,
    expected_id: u16,
) -> Result<Vec<DnsRecord>, ResolverError> {
    let response = crate::dns::transport::quic_query(connection, &query)
        .await
        .map_err(resolver_error)?;
    dns_records_from_response(&response, expected_id).map_err(resolver_error)
}

fn combine_results(
    a: Result<Vec<DnsRecord>, ResolverError>,
    aaaa: Result<Vec<DnsRecord>, ResolverError>,
) -> Result<Vec<IpAddr>, ResolverError> {
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
    Err(ResolverError("no such host".to_string()))
}

fn parse_normalized_addr(server: &str) -> Result<SocketAddr, ResolverError> {
    normalize_udp_dns_server(server)?
        .parse::<SocketAddr>()
        .map_err(|err| ResolverError(format!("invalid DNS server address: {err}")))
}

pub fn normalize_udp_dns_server(server: &str) -> Result<String, ResolverError> {
    if server.contains("://") {
        return Err(dns_server_value_error(server));
    }
    if server.parse::<SocketAddr>().is_ok() {
        return Ok(server.to_string());
    }
    if let Ok(ip) = server.parse::<IpAddr>() {
        return Ok(match ip {
            IpAddr::V4(_) => format!("{ip}:53"),
            IpAddr::V6(_) => format!("[{ip}]:53"),
        });
    }
    Err(dns_server_value_error(server))
}

fn dns_server_value_error(server: &str) -> ResolverError {
    ResolverError(format!(
        "invalid value '{server}' for option '--dns-server': must be in the format <IP[:PORT]>"
    ))
}

fn dns_records_from_response(
    raw: &[u8],
    expected_id: u16,
) -> Result<Vec<DnsRecord>, wire::WireError> {
    let records = wire::parse_response(raw, expected_id)?;
    Ok(records.into_iter().filter_map(ip_record).collect())
}

fn ip_record(record: wire::ResourceRecord<'_>) -> Option<DnsRecord> {
    if record.class != DNS_CLASS_IN {
        return None;
    }
    let ip = match (record.typ, record.data.len()) {
        (DNS_TYPE_A, 4) => IpAddr::from([
            record.data[0],
            record.data[1],
            record.data[2],
            record.data[3],
        ]),
        (DNS_TYPE_AAAA, 16) => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(record.data);
            IpAddr::from(octets)
        }
        _ => return None,
    };
    Some(DnsRecord {
        ip,
        ttl: Some(record.ttl),
    })
}

fn resolver_error(err: impl ToString) -> ResolverError {
    ResolverError(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{IpAddr, TcpListener, TcpStream as StdTcpStream, UdpSocket as StdUdpSocket};
    use std::sync::{
        Arc, Barrier, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use std::thread;
    use std::time::{Duration, Instant};

    use quinn::crypto::rustls::QuicServerConfig;
    use rustls::pki_types::ServerName;
    use tokio::net::TcpListener as TokioTcpListener;
    use tokio::net::TcpStream as TokioTcpStream;
    use tokio_rustls::{TlsAcceptor, server::TlsStream as ServerTlsStream};

    #[tokio::test]
    async fn lookup_udp_returns_a_and_aaaa() {
        let (addr, stop) = start_udp_server(DnsServerMode::Success);

        let addrs = lookup_udp(&addr, "example.com", None).await.unwrap();

        assert_eq!(
            addrs.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["127.0.0.1", "::1"]
        );
        stop();
    }

    #[tokio::test]
    async fn lookup_udp_queries_a_and_aaaa_concurrently() {
        let delay = Duration::from_millis(100);
        let timeout = Duration::from_millis(700);
        let (addr, stop) = start_delayed_udp_server(delay);

        let start = Instant::now();
        let addrs = lookup_udp(&addr, "example.com", Some(timeout))
            .await
            .unwrap();
        let elapsed = start.elapsed();

        assert_eq!(
            addrs.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["127.0.0.1", "::1"]
        );
        assert!(
            elapsed < Duration::from_millis(450),
            "lookup took {elapsed:?}, expected parallel A/AAAA queries near {delay:?}"
        );
        stop();
    }

    #[tokio::test]
    async fn lookup_udp_type_returns_ttl() {
        let (addr, stop) = start_udp_server(DnsServerMode::Success);

        let records = lookup_udp_type(&addr, "example.com", DNS_TYPE_A, Duration::from_secs(1))
            .await
            .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].ip.to_string(), "127.0.0.1");
        assert_eq!(records[0].ttl, Some(42));
        stop();
    }

    #[tokio::test]
    async fn lookup_udp_type_falls_back_to_tcp_on_truncated_udp_response() {
        let (addr, stop) = start_truncated_udp_tcp_server();

        let records = lookup_udp_type(&addr, "example.com", DNS_TYPE_A, Duration::from_secs(1))
            .await
            .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].ip.to_string(), "203.0.113.10");
        assert_eq!(records[0].ttl, Some(55));
        stop();
    }

    #[tokio::test]
    async fn lookup_udp_type_timeout_budget_covers_truncated_tcp_fallback() {
        let timeout = Duration::from_millis(250);
        let (addr, tcp_accepts, stop) =
            start_delayed_truncated_udp_slow_tcp_server(Duration::from_millis(150));

        let start = Instant::now();
        let err = lookup_udp_type(&addr, "example.com", DNS_TYPE_A, timeout)
            .await
            .unwrap_err();
        let elapsed = start.elapsed();

        assert_eq!(err.to_string(), "DNS lookup timed out");
        assert_eq!(tcp_accepts.load(Ordering::SeqCst), 1);
        assert!(
            elapsed < Duration::from_millis(350),
            "lookup took {elapsed:?}, expected timeout to cover UDP and TCP fallback"
        );
        stop();
    }

    #[tokio::test]
    async fn lookup_udp_ip_literal_skips_server() {
        let addrs = lookup_udp("127.0.0.1:9", "127.0.0.1", None).await.unwrap();

        assert_eq!(addrs, ["127.0.0.1".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn lookup_udp_nxdomain_mentions_rcode() {
        let (addr, stop) = start_udp_server(DnsServerMode::NxDomain);

        let err = lookup_udp(&addr, "missing.example", None)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("NXDomain"));
        stop();
    }

    #[tokio::test]
    async fn lookup_udp_type_times_out_waiting_for_response() {
        let socket = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap().to_string();

        let err = lookup_udp_type(&addr, "example.com", DNS_TYPE_A, Duration::from_millis(10))
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "DNS lookup timed out");
        drop(socket);
    }

    #[test]
    fn normalize_udp_dns_server_matches_go_parser() {
        assert_eq!(
            normalize_udp_dns_server("127.0.0.1").unwrap(),
            "127.0.0.1:53"
        );
        assert_eq!(
            normalize_udp_dns_server("127.0.0.1:5353").unwrap(),
            "127.0.0.1:5353"
        );
        assert_eq!(normalize_udp_dns_server("::1").unwrap(), "[::1]:53");
        assert_eq!(
            normalize_udp_dns_server("[::1]:5353").unwrap(),
            "[::1]:5353"
        );
        assert!(normalize_udp_dns_server("dns.example").is_err());
        assert!(normalize_udp_dns_server("https://dns.example").is_err());
    }

    #[derive(Clone, Copy)]
    enum DnsServerMode {
        Success,
        NxDomain,
    }

    fn start_udp_server(mode: DnsServerMode) -> (String, impl FnOnce()) {
        let socket = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let addr = socket.local_addr().unwrap().to_string();
        let done = Arc::new(Mutex::new(false));
        let thread_done = done.clone();
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 512];
            loop {
                if *thread_done.lock().unwrap() {
                    return;
                }
                let Ok((n, peer)) = socket.recv_from(&mut buf) else {
                    continue;
                };
                if n < 12 {
                    continue;
                }
                let query_type = read_question_type(&buf[..n]).unwrap_or_default();
                let question_name_end = question_end(&buf[..n]).unwrap_or(12);
                let question_end = (question_name_end + 4).min(n);
                let mut response = Vec::new();
                response.extend_from_slice(&buf[0..2]);
                match mode {
                    DnsServerMode::Success => {
                        let answer_count =
                            u16::from(query_type == DNS_TYPE_A || query_type == DNS_TYPE_AAAA);
                        response.extend_from_slice(&0x8180u16.to_be_bytes());
                        response.extend_from_slice(&1u16.to_be_bytes());
                        response.extend_from_slice(&answer_count.to_be_bytes());
                    }
                    DnsServerMode::NxDomain => {
                        response.extend_from_slice(&0x8183u16.to_be_bytes());
                        response.extend_from_slice(&1u16.to_be_bytes());
                        response.extend_from_slice(&0u16.to_be_bytes());
                    }
                }
                response.extend_from_slice(&0u16.to_be_bytes());
                response.extend_from_slice(&0u16.to_be_bytes());
                response.extend_from_slice(&buf[12..question_end]);
                if matches!(mode, DnsServerMode::Success) {
                    match query_type {
                        DNS_TYPE_A => write_answer(&mut response, DNS_TYPE_A, 42, &[127, 0, 0, 1]),
                        DNS_TYPE_AAAA => write_answer(
                            &mut response,
                            DNS_TYPE_AAAA,
                            43,
                            &std::net::Ipv6Addr::LOCALHOST.octets(),
                        ),
                        _ => {}
                    }
                }
                let _ = socket.send_to(&response, peer);
            }
        });

        (addr, move || {
            *done.lock().unwrap() = true;
            let _ = StdUdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .send_to(&[0], "127.0.0.1:9");
            handle.join().unwrap();
        })
    }

    fn start_delayed_udp_server(delay: Duration) -> (String, impl FnOnce()) {
        let socket = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let addr = socket.local_addr().unwrap().to_string();
        let done = Arc::new(Mutex::new(false));
        let barrier = Arc::new(Barrier::new(2));
        let thread_done = done.clone();
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 512];
            loop {
                if *thread_done.lock().unwrap() {
                    return;
                }
                let Ok((n, peer)) = socket.recv_from(&mut buf) else {
                    continue;
                };
                if n < 12 {
                    continue;
                }
                let Ok(response_socket) = socket.try_clone() else {
                    continue;
                };
                let query = buf[..n].to_vec();
                let worker_barrier = barrier.clone();
                thread::spawn(move || {
                    worker_barrier.wait();
                    thread::sleep(delay);

                    let query_type = read_question_type(&query).unwrap_or_default();
                    let question_name_end = question_end(&query).unwrap_or(12);
                    let question_end = (question_name_end + 4).min(query.len());
                    let mut response = Vec::new();
                    response.extend_from_slice(&query[0..2]);
                    let answer_count =
                        u16::from(query_type == DNS_TYPE_A || query_type == DNS_TYPE_AAAA);
                    response.extend_from_slice(&0x8180u16.to_be_bytes());
                    response.extend_from_slice(&1u16.to_be_bytes());
                    response.extend_from_slice(&answer_count.to_be_bytes());
                    response.extend_from_slice(&0u16.to_be_bytes());
                    response.extend_from_slice(&0u16.to_be_bytes());
                    response.extend_from_slice(&query[12..question_end]);
                    match query_type {
                        DNS_TYPE_A => write_answer(&mut response, DNS_TYPE_A, 42, &[127, 0, 0, 1]),
                        DNS_TYPE_AAAA => write_answer(
                            &mut response,
                            DNS_TYPE_AAAA,
                            43,
                            &std::net::Ipv6Addr::LOCALHOST.octets(),
                        ),
                        _ => {}
                    }
                    let _ = response_socket.send_to(&response, peer);
                });
            }
        });

        (addr, move || {
            *done.lock().unwrap() = true;
            let _ = StdUdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .send_to(&[0], "127.0.0.1:9");
            handle.join().unwrap();
        })
    }

    fn start_delayed_truncated_udp_slow_tcp_server(
        udp_delay: Duration,
    ) -> (String, Arc<AtomicUsize>, impl FnOnce()) {
        let udp_socket = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        udp_socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let addr = udp_socket.local_addr().unwrap();
        let tcp_listener = TcpListener::bind(addr).unwrap();
        tcp_listener.set_nonblocking(true).unwrap();
        let done = Arc::new(Mutex::new(false));
        let tcp_accepts = Arc::new(AtomicUsize::new(0));

        let udp_done = done.clone();
        let udp_handle = thread::spawn(move || {
            let mut buf = [0u8; 512];
            loop {
                if *udp_done.lock().unwrap() {
                    return;
                }
                let Ok((n, peer)) = udp_socket.recv_from(&mut buf) else {
                    continue;
                };
                if n < 12 {
                    continue;
                }
                thread::sleep(udp_delay);
                let response = truncated_response(&buf[..n]);
                let _ = udp_socket.send_to(&response, peer);
            }
        });

        let tcp_done = done.clone();
        let tcp_accepts_for_thread = tcp_accepts.clone();
        let tcp_handle = thread::spawn(move || {
            loop {
                if *tcp_done.lock().unwrap() {
                    return;
                }
                match tcp_listener.accept() {
                    Ok((mut stream, _)) => {
                        tcp_accepts_for_thread.fetch_add(1, Ordering::SeqCst);
                        if read_tcp_query(&mut stream).is_none() {
                            continue;
                        }
                        loop {
                            if *tcp_done.lock().unwrap() {
                                return;
                            }
                            thread::sleep(Duration::from_millis(10));
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => {}
                }
            }
        });

        (addr.to_string(), tcp_accepts, move || {
            *done.lock().unwrap() = true;
            let _ = StdUdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .send_to(&[0], addr);
            let _ = StdTcpStream::connect(addr);
            udp_handle.join().unwrap();
            tcp_handle.join().unwrap();
        })
    }

    fn start_truncated_udp_tcp_server() -> (String, impl FnOnce()) {
        let udp_socket = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        udp_socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let addr = udp_socket.local_addr().unwrap();
        let tcp_listener = TcpListener::bind(addr).unwrap();
        tcp_listener.set_nonblocking(true).unwrap();
        let done = Arc::new(Mutex::new(false));

        let udp_done = done.clone();
        let udp_handle = thread::spawn(move || {
            let mut buf = [0u8; 512];
            loop {
                if *udp_done.lock().unwrap() {
                    return;
                }
                let Ok((n, peer)) = udp_socket.recv_from(&mut buf) else {
                    continue;
                };
                if n < 12 {
                    continue;
                }
                let response = truncated_response(&buf[..n]);
                let _ = udp_socket.send_to(&response, peer);
            }
        });

        let tcp_done = done.clone();
        let tcp_handle = thread::spawn(move || {
            loop {
                if *tcp_done.lock().unwrap() {
                    return;
                }
                match tcp_listener.accept() {
                    Ok((mut stream, _)) => {
                        let Some(query) = read_tcp_query(&mut stream) else {
                            continue;
                        };
                        let mut response = success_response(&query);
                        let mut framed = Vec::with_capacity(response.len() + 2);
                        framed.extend_from_slice(&(response.len() as u16).to_be_bytes());
                        framed.append(&mut response);
                        let _ = stream.write_all(&framed);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => {}
                }
            }
        });

        (addr.to_string(), move || {
            *done.lock().unwrap() = true;
            let _ = StdUdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .send_to(&[0], addr);
            let _ = StdTcpStream::connect(addr);
            udp_handle.join().unwrap();
            tcp_handle.join().unwrap();
        })
    }

    fn truncated_response(query: &[u8]) -> Vec<u8> {
        let question_name_end = question_end(query).unwrap_or(12);
        let question_end = (question_name_end + 4).min(query.len());
        let mut response = Vec::new();
        response.extend_from_slice(&query[0..2]);
        response.extend_from_slice(&0x8380u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&query[12..question_end]);
        response
    }

    fn success_response(query: &[u8]) -> Vec<u8> {
        let query_type = read_question_type(query).unwrap_or_default();
        let question_name_end = question_end(query).unwrap_or(12);
        let question_end = (question_name_end + 4).min(query.len());
        let mut response = Vec::new();
        response.extend_from_slice(&query[0..2]);
        let answer_count = u16::from(query_type == DNS_TYPE_A);
        response.extend_from_slice(&0x8180u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&answer_count.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&query[12..question_end]);
        if query_type == DNS_TYPE_A {
            write_answer(&mut response, DNS_TYPE_A, 55, &[203, 0, 113, 10]);
        }
        response
    }

    #[tokio::test]
    async fn lookup_tcp_returns_a_and_aaaa() {
        let (addr, stop) = start_tcp_server(DnsServerMode::Success);

        let addrs = lookup_tcp_addr(&addr, "example.com", Some(Duration::from_secs(1)))
            .await
            .unwrap();

        assert_eq!(
            addrs.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["127.0.0.1", "::1"]
        );
        stop();
    }

    #[tokio::test]
    async fn lookup_tcp_queries_a_and_aaaa_over_one_connection() {
        let queries = Arc::new(Mutex::new(Vec::new()));
        let (addr, stop) = start_counting_tcp_server(queries.clone());

        let addrs = lookup_tcp_addr(&addr, "example.com", Some(Duration::from_secs(1)))
            .await
            .unwrap();

        assert_eq!(
            addrs.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["127.0.0.1", "::1"]
        );
        assert_eq!(
            queries.lock().unwrap().len(),
            1,
            "expected one TCP connection"
        );
        stop();
    }

    #[tokio::test]
    async fn lookup_tls_returns_a_and_aaaa() {
        let (addr, stop) = start_tls_server().await;

        let server_name = ServerName::IpAddress("127.0.0.1".parse::<IpAddr>().unwrap().into());
        let addrs = lookup_tls(
            &server_name,
            &[addr],
            "example.com",
            Some(Duration::from_secs(2)),
            true,
        )
        .await
        .unwrap();

        assert_eq!(
            addrs.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["127.0.0.1", "::1"]
        );
        stop();
    }

    #[tokio::test]
    async fn lookup_quic_returns_a_and_aaaa() {
        let (addr, stop) = start_quic_server().await;

        let server_name = ServerName::IpAddress("127.0.0.1".parse::<IpAddr>().unwrap().into());
        let addrs = lookup_quic(
            &server_name,
            &[addr],
            "example.com",
            Some(Duration::from_secs(2)),
            true,
        )
        .await
        .unwrap();

        assert_eq!(
            addrs.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["127.0.0.1", "::1"]
        );
        stop();
    }

    #[tokio::test]
    async fn lookup_tcp_type_returns_single_family_records() {
        let (addr, stop) = start_tcp_server(DnsServerMode::Success);

        let records = lookup_tcp_type(&addr, "example.com", DNS_TYPE_A, Duration::from_secs(1))
            .await
            .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].ip.to_string(), "127.0.0.1");
        stop();
    }

    #[tokio::test]
    async fn lookup_tcp_rejects_short_framed_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let done = Arc::new(Mutex::new(false));
        let thread_done = done.clone();
        let handle = thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            // Read one framed query, then send a 1-byte frame.
            let _ = read_tcp_query(&mut stream);
            let _ = stream.write_all(&[0x00, 0x01, 0x00]);
            loop {
                if *thread_done.lock().unwrap() {
                    return;
                }
                thread::sleep(Duration::from_millis(10));
            }
        });

        let err = lookup_tcp_addr(&addr, "example.com", Some(Duration::from_millis(500)))
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "short DNS response");
        *done.lock().unwrap() = true;
        let _ = StdTcpStream::connect(addr);
        handle.join().unwrap();
    }

    #[tokio::test]
    async fn lookup_tcp_times_out_on_unresponsive_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let done = Arc::new(Mutex::new(false));
        let thread_done = done.clone();
        let handle = thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut buf = [0u8; 2];
            let _ = stream.read_exact(&mut buf);
            loop {
                if *thread_done.lock().unwrap() {
                    return;
                }
                thread::sleep(Duration::from_millis(10));
            }
        });

        let err = lookup_tcp_addr(&addr, "example.com", Some(Duration::from_millis(50)))
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "DNS lookup timed out");
        *done.lock().unwrap() = true;
        let _ = StdTcpStream::connect(addr);
        handle.join().unwrap();
    }

    fn start_tcp_server(mode: DnsServerMode) -> (SocketAddr, impl FnOnce()) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let done = Arc::new(Mutex::new(false));
        let thread_done = done.clone();
        let handle = thread::spawn(move || {
            loop {
                if *thread_done.lock().unwrap() {
                    return;
                }
                listener
                    .set_nonblocking(true)
                    .expect("set nonblocking on TCP listener");
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        handle_tcp_connection(&mut stream, mode);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => {}
                }
            }
        });

        (addr, move || {
            *done.lock().unwrap() = true;
            let _ = StdTcpStream::connect(addr);
            handle.join().unwrap();
        })
    }

    fn start_counting_tcp_server(accepts: Arc<Mutex<Vec<()>>>) -> (SocketAddr, impl FnOnce()) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let done = Arc::new(Mutex::new(false));
        let thread_done = done.clone();
        let handle = thread::spawn(move || {
            loop {
                if *thread_done.lock().unwrap() {
                    return;
                }
                listener
                    .set_nonblocking(true)
                    .expect("set nonblocking on TCP listener");
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        accepts.lock().unwrap().push(());
                        handle_tcp_connection(&mut stream, DnsServerMode::Success);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => {}
                }
            }
        });

        (addr, move || {
            *done.lock().unwrap() = true;
            let _ = StdTcpStream::connect(addr);
            handle.join().unwrap();
        })
    }

    fn handle_tcp_connection(stream: &mut StdTcpStream, mode: DnsServerMode) {
        loop {
            let Some(query) = read_tcp_query(stream) else {
                return;
            };
            let response = tcp_response(&query, mode);
            let mut framed = Vec::with_capacity(response.len() + 2);
            framed.extend_from_slice(&(response.len() as u16).to_be_bytes());
            framed.extend_from_slice(&response);
            if stream.write_all(&framed).is_err() {
                return;
            }
            if stream.flush().is_err() {
                return;
            }
        }
    }

    fn tcp_response(query: &[u8], mode: DnsServerMode) -> Vec<u8> {
        let query_type = read_question_type(query).unwrap_or_default();
        let question_name_end = question_end(query).unwrap_or(12);
        let question_end = (question_name_end + 4).min(query.len());
        let mut response = Vec::new();
        response.extend_from_slice(&query[0..2]);
        match mode {
            DnsServerMode::Success => {
                let answer_count =
                    u16::from(query_type == DNS_TYPE_A || query_type == DNS_TYPE_AAAA);
                response.extend_from_slice(&0x8180u16.to_be_bytes());
                response.extend_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&answer_count.to_be_bytes());
            }
            DnsServerMode::NxDomain => {
                response.extend_from_slice(&0x8183u16.to_be_bytes());
                response.extend_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&0u16.to_be_bytes());
            }
        }
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&query[12..question_end]);
        if matches!(mode, DnsServerMode::Success) {
            match query_type {
                DNS_TYPE_A => write_answer(&mut response, DNS_TYPE_A, 42, &[127, 0, 0, 1]),
                DNS_TYPE_AAAA => write_answer(
                    &mut response,
                    DNS_TYPE_AAAA,
                    43,
                    &std::net::Ipv6Addr::LOCALHOST.octets(),
                ),
                _ => {}
            }
        }
        response
    }

    fn read_tcp_query(stream: &mut StdTcpStream) -> Option<Vec<u8>> {
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).ok()?;
        let len = usize::from(u16::from_be_bytes(len_buf));
        let mut query = vec![0u8; len];
        stream.read_exact(&mut query).ok()?;
        Some(query)
    }

    fn write_answer(response: &mut Vec<u8>, dns_type: u16, ttl: u32, data: &[u8]) {
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&dns_type.to_be_bytes());
        response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        response.extend_from_slice(&ttl.to_be_bytes());
        response.extend_from_slice(&(data.len() as u16).to_be_bytes());
        response.extend_from_slice(data);
    }

    fn read_question_type(raw: &[u8]) -> Option<u16> {
        let end = question_end(raw)?;
        Some(u16::from_be_bytes([raw[end], raw[end + 1]]))
    }

    fn question_end(raw: &[u8]) -> Option<usize> {
        let mut offset = 12;
        loop {
            let len = *raw.get(offset)?;
            offset += 1;
            if len == 0 {
                return Some(offset);
            }
            offset += usize::from(len);
        }
    }

    fn test_cert() -> (
        rustls::pki_types::CertificateDer<'static>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ) {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::from(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
        );
        (cert_der, key_der)
    }

    fn test_server_config() -> rustls::ServerConfig {
        let (cert, key) = test_cert();
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("valid test server config")
    }

    fn test_quic_server_config() -> rustls::ServerConfig {
        let (cert, key) = test_cert();
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("valid test server config");
        config.alpn_protocols = vec![b"doq".to_vec()];
        config
    }

    async fn start_tls_server() -> (SocketAddr, impl FnOnce()) {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = test_server_config();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let done = Arc::new(Mutex::new(false));
        let thread_done = done.clone();
        let handle = tokio::spawn(async move {
            loop {
                if *thread_done.lock().unwrap() {
                    return;
                }
                match tokio::time::timeout(Duration::from_millis(100), listener.accept()).await {
                    Ok(Ok((stream, _))) => {
                        let acceptor = acceptor.clone();
                        tokio::spawn(async move {
                            if let Ok(mut tls) = acceptor.accept(stream).await {
                                handle_tls_stream(&mut tls).await;
                            }
                        });
                    }
                    Ok(Err(_)) => {}
                    Err(_) => {}
                }
            }
        });

        (addr, move || {
            *done.lock().unwrap() = true;
            handle.abort();
        })
    }

    async fn handle_tls_stream(stream: &mut ServerTlsStream<TokioTcpStream>) {
        loop {
            let query = match crate::dns::transport::read_framed_response(stream).await {
                Ok(q) => q,
                Err(_) => return,
            };
            let response = tcp_response(&query, DnsServerMode::Success);
            if crate::dns::transport::write_framed_query(stream, &response)
                .await
                .is_err()
            {
                return;
            }
        }
    }

    async fn start_quic_server() -> (SocketAddr, impl FnOnce()) {
        let config = test_quic_server_config();
        let quic_config = QuicServerConfig::try_from(config).expect("valid QUIC server config");
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));
        let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
            .expect("bind QUIC server");
        let addr = endpoint.local_addr().unwrap();
        let done = Arc::new(Mutex::new(false));
        let thread_done = done.clone();
        let handle = tokio::spawn(async move {
            loop {
                if *thread_done.lock().unwrap() {
                    return;
                }
                if let Ok(Some(incoming)) =
                    tokio::time::timeout(Duration::from_millis(100), endpoint.accept()).await
                {
                    tokio::spawn(async move {
                        if let Ok(connection) = incoming.await {
                            handle_quic_connection(connection).await;
                        }
                    });
                }
            }
        });

        (addr, move || {
            *done.lock().unwrap() = true;
            handle.abort();
        })
    }

    async fn handle_quic_connection(connection: quinn::Connection) {
        loop {
            match connection.accept_bi().await {
                Ok((mut send, mut recv)) => {
                    let query = match crate::dns::transport::read_framed_response(&mut recv).await {
                        Ok(q) => q,
                        Err(_) => continue,
                    };
                    // RFC 9250 requires DoQ queries to use message ID 0.
                    if query.len() < 2 || u16::from_be_bytes([query[0], query[1]]) != DOQ_MESSAGE_ID
                    {
                        continue;
                    }
                    let response = tcp_response(&query, DnsServerMode::Success);
                    if crate::dns::transport::write_framed_query(&mut send, &response)
                        .await
                        .is_err()
                    {
                        continue;
                    }
                    let _ = send.finish();
                }
                Err(_) => return,
            }
        }
    }
}
