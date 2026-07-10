use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use rustls::pki_types::ServerName;
use url::Url;

use crate::error::FetchError;

const DEFAULT_DNS_PORT: u16 = 53;
const DEFAULT_DNS_OVER_TLS_PORT: u16 = 853;
const DEFAULT_DNS_OVER_QUIC_PORT: u16 = 853;

#[derive(Debug, Clone)]
pub(crate) enum ParsedDnsServer {
    Udp(SocketAddr),
    Tcp(SocketAddr),
    Tls {
        server_name: ServerName<'static>,
        host: String,
        port: u16,
    },
    Quic {
        server_name: ServerName<'static>,
        host: String,
        port: u16,
    },
    Doh(Url),
}

pub(crate) fn parse_dns_server(value: &str) -> Result<ParsedDnsServer, FetchError> {
    if value.starts_with("http://") || value.starts_with("https://") {
        let url = Url::parse(value).map_err(|err| {
            FetchError::Message(format!(
                "invalid value '{value}' for option '--dns-server': {err}"
            ))
        })?;
        return Ok(ParsedDnsServer::Doh(url));
    }

    let url = if value.contains("://") {
        Url::parse(value).map_err(|err| {
            FetchError::Message(format!(
                "invalid value '{value}' for option '--dns-server': {err}"
            ))
        })?
    } else if let Some(addr) = parse_bare_dns_server(value) {
        // Bare IP[:PORT] is treated as udp:// for backward compatibility.
        return Ok(ParsedDnsServer::Udp(addr));
    } else {
        Url::parse(&format!("udp://{value}")).map_err(|err| {
            FetchError::Message(format!(
                "invalid value '{value}' for option '--dns-server': {err}"
            ))
        })?
    };

    let scheme = url.scheme();
    let (host, port) = host_and_port(&url)?;
    match scheme {
        "udp" => Ok(ParsedDnsServer::Udp(socket_addr(
            &host,
            port,
            DEFAULT_DNS_PORT,
        )?)),
        "tcp" => Ok(ParsedDnsServer::Tcp(socket_addr(
            &host,
            port,
            DEFAULT_DNS_PORT,
        )?)),
        "tls" | "dot" => Ok(ParsedDnsServer::Tls {
            server_name: server_name(&host)?,
            host,
            port: port.unwrap_or(DEFAULT_DNS_OVER_TLS_PORT),
        }),
        "quic" | "doq" => Ok(ParsedDnsServer::Quic {
            server_name: server_name(&host)?,
            host,
            port: port.unwrap_or(DEFAULT_DNS_OVER_QUIC_PORT),
        }),
        _ => Err(FetchError::Message(format!(
            "invalid value '{value}' for option '--dns-server': unsupported scheme '{scheme}'"
        ))),
    }
}

fn parse_bare_dns_server(value: &str) -> Option<SocketAddr> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Some(addr);
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, DEFAULT_DNS_PORT));
    }
    None
}

fn host_and_port(url: &Url) -> Result<(String, Option<u16>), FetchError> {
    let host = url
        .host_str()
        .ok_or_else(|| {
            FetchError::Message(format!(
                "invalid value '{}' for option '--dns-server': missing host",
                url
            ))
        })?
        .to_string();
    Ok((host, url.port()))
}

fn socket_addr(
    host: &str,
    explicit_port: Option<u16>,
    default_port: u16,
) -> Result<SocketAddr, FetchError> {
    let port = explicit_port.unwrap_or(default_port);
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    Err(FetchError::Message(format!(
        "invalid value '{host}:{port}' for option '--dns-server': must be an IP address"
    )))
}

fn server_name(host: &str) -> Result<ServerName<'static>, FetchError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(host.to_owned())
        .map_err(|_| FetchError::Message(format!("invalid DNS server name '{host}'")))
}

pub(crate) async fn resolve_server_host(
    host: &str,
    port: u16,
    timeout: Option<Duration>,
) -> Result<Vec<SocketAddr>, FetchError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let timeout = timeout.unwrap_or(Duration::from_secs(5));
    let addrs = tokio::time::timeout(timeout, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| {
            FetchError::Message(format!(
                "DNS server hostname resolution timed out after {timeout:?}: {host}"
            ))
        })?
        .map_err(|err| {
            FetchError::Message(format!(
                "DNS server hostname resolution failed for '{host}:{port}': {err}"
            ))
        })?;
    let addrs: Vec<_> = addrs.collect();
    if addrs.is_empty() {
        return Err(FetchError::Message(format!(
            "DNS server hostname resolved no addresses: {host}:{port}"
        )));
    }
    Ok(addrs)
}

pub(crate) async fn lookup_ips(
    dns_server: &str,
    host: &str,
    timeout: Option<Duration>,
) -> Result<Vec<IpAddr>, FetchError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    match parse_dns_server(dns_server)? {
        ParsedDnsServer::Udp(addr) => crate::dns::resolver::lookup_udp_addr(&addr, host, timeout)
            .await
            .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}"))),
        ParsedDnsServer::Tcp(addr) => crate::dns::resolver::lookup_tcp_addr(&addr, host, timeout)
            .await
            .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}"))),
        ParsedDnsServer::Tls {
            server_name,
            host: server_host,
            port,
        } => {
            let resolve_start = std::time::Instant::now();
            let addrs = resolve_server_host(&server_host, port, timeout).await?;
            let remaining = timeout.map(|t| t.saturating_sub(resolve_start.elapsed()));
            crate::dns::resolver::lookup_tls(&server_name, &addrs, host, remaining, false)
                .await
                .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))
        }
        ParsedDnsServer::Quic {
            server_name,
            host: server_host,
            port,
        } => {
            let resolve_start = std::time::Instant::now();
            let addrs = resolve_server_host(&server_host, port, timeout).await?;
            let remaining = timeout.map(|t| t.saturating_sub(resolve_start.elapsed()));
            crate::dns::resolver::lookup_quic(&server_name, &addrs, host, remaining, false)
                .await
                .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))
        }
        ParsedDnsServer::Doh(url) => crate::dns::doh::lookup_doh(&url, host, timeout)
            .await
            .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}"))),
    }
}

pub(crate) fn socket_addrs_for_override(addrs: &[IpAddr]) -> Vec<SocketAddr> {
    addrs.iter().map(|addr| SocketAddr::new(*addr, 0)).collect()
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn socket_addrs_use_zero_port_for_transport_override() {
        let addrs = socket_addrs_for_override(&["127.0.0.1".parse().unwrap()]);

        assert_eq!(addrs, [SocketAddr::new("127.0.0.1".parse().unwrap(), 0)]);
    }

    #[test]
    fn parse_dns_server_accepts_bare_ip_for_udp() {
        let parsed = parse_dns_server("1.1.1.1").unwrap();
        assert!(matches!(
            parsed,
            ParsedDnsServer::Udp(addr) if addr == SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)
        ));
    }

    #[test]
    fn parse_dns_server_accepts_bare_ip_with_port_for_udp() {
        let parsed = parse_dns_server("1.1.1.1:5353").unwrap();
        assert!(matches!(
            parsed,
            ParsedDnsServer::Udp(addr) if addr == SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 5353)
        ));
    }

    #[test]
    fn parse_dns_server_accepts_bare_ipv6_for_udp() {
        let parsed = parse_dns_server("::1").unwrap();
        assert!(matches!(
            parsed,
            ParsedDnsServer::Udp(addr) if addr == SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53)
        ));
    }

    #[test]
    fn parse_dns_server_accepts_bare_ipv6_with_port_for_udp() {
        let parsed = parse_dns_server("[::1]:5353").unwrap();
        assert!(matches!(
            parsed,
            ParsedDnsServer::Udp(addr) if addr == SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5353)
        ));
    }

    #[test]
    fn parse_dns_server_accepts_udp_scheme() {
        let parsed = parse_dns_server("udp://[::1]:5353").unwrap();
        assert!(matches!(
            parsed,
            ParsedDnsServer::Udp(addr) if addr == SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5353)
        ));
    }

    #[test]
    fn parse_dns_server_accepts_tcp_scheme() {
        let parsed = parse_dns_server("tcp://1.1.1.1").unwrap();
        assert!(matches!(
            parsed,
            ParsedDnsServer::Tcp(addr) if addr == SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)
        ));
    }

    #[test]
    fn parse_dns_server_accepts_tls_scheme_with_ip() {
        let parsed = parse_dns_server("tls://1.1.1.1").unwrap();
        assert!(matches!(
            parsed,
            ParsedDnsServer::Tls { server_name, host, port }
            if host == "1.1.1.1" && port == 853 && matches!(server_name, ServerName::IpAddress(_))
        ));
    }

    #[test]
    fn parse_dns_server_accepts_dot_scheme_with_hostname() {
        let parsed = parse_dns_server("dot://dns.google:8853").unwrap();
        assert!(matches!(
            parsed,
            ParsedDnsServer::Tls { server_name, host, port }
            if host == "dns.google" && port == 8853 && matches!(server_name, ServerName::DnsName(_))
        ));
    }

    #[test]
    fn parse_dns_server_accepts_quic_scheme_with_ip() {
        let parsed = parse_dns_server("quic://1.1.1.1").unwrap();
        assert!(matches!(
            parsed,
            ParsedDnsServer::Quic { server_name, host, port }
            if host == "1.1.1.1" && port == 853 && matches!(server_name, ServerName::IpAddress(_))
        ));
    }

    #[test]
    fn parse_dns_server_accepts_doq_scheme_with_hostname() {
        let parsed = parse_dns_server("doq://dns.google").unwrap();
        assert!(matches!(
            parsed,
            ParsedDnsServer::Quic { server_name, host, port }
            if host == "dns.google" && port == 853 && matches!(server_name, ServerName::DnsName(_))
        ));
    }

    #[test]
    fn parse_dns_server_accepts_doh_url() {
        let parsed = parse_dns_server("https://dns.example/dns-query").unwrap();
        assert!(
            matches!(parsed, ParsedDnsServer::Doh(url) if url.as_str() == "https://dns.example/dns-query")
        );
    }

    #[test]
    fn parse_dns_server_rejects_hostname_for_udp() {
        assert!(parse_dns_server("udp://dns.example").is_err());
    }

    #[test]
    fn parse_dns_server_rejects_unsupported_scheme() {
        assert!(parse_dns_server("ftp://1.1.1.1").is_err());
    }
}
