use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::dns::util::{dns_query_id, udp_dns_timeout};
use crate::dns::wire;

const DNS_TYPE_A: u16 = wire::TYPE_A;
const DNS_TYPE_AAAA: u16 = wire::TYPE_AAAA;
const DNS_CLASS_IN: u16 = wire::CLASS_IN;

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
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    let timeout = udp_dns_timeout(timeout);
    let (a, aaaa) = tokio::join!(
        lookup_udp_type(server_addr, host, DNS_TYPE_A, timeout),
        lookup_udp_type(server_addr, host, DNS_TYPE_AAAA, timeout)
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
    Err(ResolverError("no such host".to_string()))
}

pub async fn lookup_udp_type(
    server_addr: &str,
    host: &str,
    dns_type: u16,
    timeout: Duration,
) -> Result<Vec<DnsRecord>, ResolverError> {
    let id = dns_query_id();
    let raw = wire::build_query(id, host, dns_type).map_err(resolver_error)?;
    let bind_addr = if server_addr.starts_with('[') {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|err| ResolverError(err.to_string()))?;
    socket
        .connect(server_addr)
        .await
        .map_err(|err| ResolverError(err.to_string()))?;
    socket
        .send(&raw)
        .await
        .map_err(|err| ResolverError(err.to_string()))?;

    let mut buf = vec![0u8; 4096];
    let n = match tokio::time::timeout(timeout, socket.recv(&mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(err)) => return Err(ResolverError(err.to_string())),
        Err(_) => return Err(ResolverError("DNS lookup timed out".to_string())),
    };
    dns_records_from_response(&buf[..n], id)
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
) -> Result<Vec<DnsRecord>, ResolverError> {
    let records = wire::parse_response(raw, expected_id).map_err(resolver_error)?;
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
    use std::net::UdpSocket as StdUdpSocket;
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

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
}
