use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;

const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_CLASS_IN: u16 = 1;

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

pub async fn lookup_udp(server_addr: &str, host: &str) -> Result<Vec<IpAddr>, ResolverError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    let a = lookup_udp_type(server_addr, host, DNS_TYPE_A).await;
    let aaaa = lookup_udp_type(server_addr, host, DNS_TYPE_AAAA).await;

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
) -> Result<Vec<DnsRecord>, ResolverError> {
    let id = dns_query_id();
    let raw = build_dns_query(id, host, dns_type)?;
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
    let n = socket
        .recv(&mut buf)
        .await
        .map_err(|err| ResolverError(err.to_string()))?;
    parse_dns_response(&buf[..n], id)
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

fn dns_query_id() -> u16 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos() as u16)
        .unwrap_or_default()
}

fn build_dns_query(id: u16, host: &str, dns_type: u16) -> Result<Vec<u8>, ResolverError> {
    let mut raw = Vec::with_capacity(512);
    raw.extend_from_slice(&id.to_be_bytes());
    raw.extend_from_slice(&0x0100u16.to_be_bytes());
    raw.extend_from_slice(&1u16.to_be_bytes());
    raw.extend_from_slice(&0u16.to_be_bytes());
    raw.extend_from_slice(&0u16.to_be_bytes());
    raw.extend_from_slice(&0u16.to_be_bytes());
    write_dns_name(&mut raw, host)?;
    raw.extend_from_slice(&dns_type.to_be_bytes());
    raw.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    Ok(raw)
}

fn write_dns_name(raw: &mut Vec<u8>, host: &str) -> Result<(), ResolverError> {
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        raw.push(0);
        return Ok(());
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ResolverError(format!("invalid DNS name: {host}")));
        }
        raw.push(label.len() as u8);
        raw.extend_from_slice(label.as_bytes());
    }
    raw.push(0);
    Ok(())
}

fn parse_dns_response(raw: &[u8], expected_id: u16) -> Result<Vec<DnsRecord>, ResolverError> {
    if raw.len() < 12 {
        return Err(ResolverError("short DNS response".to_string()));
    }
    let id = read_u16(raw, 0)?;
    if id != expected_id {
        return Err(ResolverError("mismatched DNS response ID".to_string()));
    }
    let flags = read_u16(raw, 2)?;
    let rcode = i32::from(flags & 0x000f);
    if rcode != 0 {
        let name = rcode_name(rcode);
        if name.is_empty() {
            return Err(ResolverError("no such host".to_string()));
        }
        return Err(ResolverError(format!("no such host: {name}")));
    }
    if flags & 0x0200 != 0 {
        return Err(ResolverError("DNS response was truncated".to_string()));
    }

    let question_count = usize::from(read_u16(raw, 4)?);
    let answer_count = usize::from(read_u16(raw, 6)?);
    let mut offset = 12;
    for _ in 0..question_count {
        let (_, next) = read_dns_name(raw, offset)?;
        offset = next + 4;
        if offset > raw.len() {
            return Err(ResolverError("short DNS question".to_string()));
        }
    }

    let mut records = Vec::new();
    for _ in 0..answer_count {
        let (_, next) = read_dns_name(raw, offset)?;
        offset = next;
        let typ = read_u16(raw, offset)?;
        let class = read_u16(raw, offset + 2)?;
        let ttl = read_u32(raw, offset + 4)?;
        let rdlen = usize::from(read_u16(raw, offset + 8)?);
        offset += 10;
        if offset + rdlen > raw.len() {
            return Err(ResolverError("short DNS resource".to_string()));
        }
        let data = &raw[offset..offset + rdlen];
        offset += rdlen;
        if class != DNS_CLASS_IN {
            continue;
        }
        let ip = match (typ, data.len()) {
            (DNS_TYPE_A, 4) => IpAddr::from([data[0], data[1], data[2], data[3]]),
            (DNS_TYPE_AAAA, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(data);
                IpAddr::from(octets)
            }
            _ => continue,
        };
        records.push(DnsRecord { ip, ttl: Some(ttl) });
    }
    Ok(records)
}

fn read_dns_name(packet: &[u8], offset: usize) -> Result<(String, usize), ResolverError> {
    let mut labels = Vec::new();
    let mut pos = offset;
    let mut next = offset;
    let mut jumped = false;
    let mut jumps = 0usize;

    loop {
        if pos >= packet.len() {
            return Err(ResolverError("short DNS name".to_string()));
        }
        let len = packet[pos];
        if len & 0xc0 == 0xc0 {
            if pos + 1 >= packet.len() {
                return Err(ResolverError("short DNS name pointer".to_string()));
            }
            let pointer = usize::from(u16::from_be_bytes([len & 0x3f, packet[pos + 1]]));
            if !jumped {
                next = pos + 2;
            }
            pos = pointer;
            jumped = true;
            jumps += 1;
            if jumps > 128 {
                return Err(ResolverError("DNS name pointer loop".to_string()));
            }
            continue;
        }
        if len & 0xc0 != 0 {
            return Err(ResolverError("invalid DNS name label".to_string()));
        }
        pos += 1;
        if len == 0 {
            if !jumped {
                next = pos;
            }
            break;
        }
        let len = usize::from(len);
        if pos + len > packet.len() {
            return Err(ResolverError("short DNS name label".to_string()));
        }
        labels.push(String::from_utf8_lossy(&packet[pos..pos + len]).into_owned());
        pos += len;
        if !jumped {
            next = pos;
        }
    }

    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        format!("{}.", labels.join("."))
    };
    Ok((name, next))
}

fn read_u16(raw: &[u8], offset: usize) -> Result<u16, ResolverError> {
    let bytes = raw
        .get(offset..offset + 2)
        .ok_or_else(|| ResolverError("short DNS message".to_string()))?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(raw: &[u8], offset: usize) -> Result<u32, ResolverError> {
    let bytes = raw
        .get(offset..offset + 4)
        .ok_or_else(|| ResolverError("short DNS message".to_string()))?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn rcode_name(status: i32) -> &'static str {
    match status {
        1 => "FormatError",
        2 => "ServerFailure",
        3 => "NXDomain",
        4 => "NotImplemented",
        5 => "Refused",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket as StdUdpSocket;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    #[tokio::test]
    async fn lookup_udp_returns_a_and_aaaa() {
        let (addr, stop) = start_udp_server(DnsServerMode::Success);

        let addrs = lookup_udp(&addr, "example.com").await.unwrap();

        assert_eq!(
            addrs.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["127.0.0.1", "::1"]
        );
        stop();
    }

    #[tokio::test]
    async fn lookup_udp_type_returns_ttl() {
        let (addr, stop) = start_udp_server(DnsServerMode::Success);

        let records = lookup_udp_type(&addr, "example.com", DNS_TYPE_A)
            .await
            .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].ip.to_string(), "127.0.0.1");
        assert_eq!(records[0].ttl, Some(42));
        stop();
    }

    #[tokio::test]
    async fn lookup_udp_ip_literal_skips_server() {
        let addrs = lookup_udp("127.0.0.1:9", "127.0.0.1").await.unwrap();

        assert_eq!(addrs, ["127.0.0.1".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn lookup_udp_nxdomain_mentions_rcode() {
        let (addr, stop) = start_udp_server(DnsServerMode::NxDomain);

        let err = lookup_udp(&addr, "missing.example").await.unwrap_err();

        assert!(err.to_string().contains("NXDomain"));
        stop();
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
