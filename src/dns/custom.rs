use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use rustls::pki_types::ServerName;
use url::Url;

use crate::duration::TimeoutBudget;
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

impl ParsedDnsServer {
    /// Returns whether DNS responses have transport authentication.
    ///
    /// DoT and DoQ always verify the configured resolver identity. HTTPS DoH
    /// is authenticated unless certificate verification was disabled by the
    /// caller. Plain HTTP, UDP, and TCP do not authenticate responses.
    pub(crate) fn is_authenticated(&self, verify_doh_certificate: bool) -> bool {
        match self {
            Self::Tls { .. } | Self::Quic { .. } => true,
            Self::Doh(url) => url.scheme() == "https" && verify_doh_certificate,
            Self::Udp(_) | Self::Tcp(_) => false,
        }
    }
}

pub(crate) fn dns_server_is_authenticated(
    value: &str,
    verify_doh_certificate: bool,
) -> Result<bool, FetchError> {
    Ok(parse_dns_server(value)?.is_authenticated(verify_doh_certificate))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DnsRecordData {
    Wire(Vec<u8>),
    Text(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsQueryRecord {
    pub(crate) typ: u16,
    pub(crate) ttl: Option<u32>,
    pub(crate) data: DnsRecordData,
}

pub(crate) fn parse_dns_server(value: &str) -> Result<ParsedDnsServer, FetchError> {
    if let Some(addr) = parse_bare_dns_server(value) {
        // Bare IP[:PORT] is treated as udp:// for backward compatibility.
        return nonzero_socket_addr(value, addr).map(ParsedDnsServer::Udp);
    }

    let url = if value.contains("://") {
        Url::parse(value)
    } else {
        Url::parse(&format!("udp://{value}"))
    }
    .map_err(|err| dns_server_error(value, &err.to_string()))?;

    let scheme = url.scheme();
    if scheme == "http" || scheme == "https" {
        validate_doh_url(value, &url)?;
        if scheme == "https" {
            return Ok(ParsedDnsServer::Doh(url));
        }

        // DNS unit tests use loopback HTTP fixtures. This branch is absent
        // from production builds, which always require HTTPS for DoH.
        #[cfg(test)]
        if url.host().is_some_and(|host| match host {
            url::Host::Ipv4(ip) => ip.is_loopback(),
            url::Host::Ipv6(ip) => ip.is_loopback(),
            url::Host::Domain(name) => name.eq_ignore_ascii_case("localhost"),
        }) {
            return Ok(ParsedDnsServer::Doh(url));
        }
        return Err(dns_server_error(value, "DoH endpoints must use HTTPS"));
    }

    validate_non_http_url(value, &url)?;
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
        _ => Err(dns_server_error(
            value,
            &format!("unsupported scheme '{scheme}'"),
        )),
    }
}

fn validate_doh_url(value: &str, url: &Url) -> Result<(), FetchError> {
    host_and_port(url)?;
    validate_nonzero_port(value, url.port())?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(dns_server_error(value, "credentials are not allowed"));
    }
    if url.fragment().is_some() {
        return Err(dns_server_error(value, "fragments are not allowed"));
    }
    Ok(())
}

fn validate_non_http_url(value: &str, url: &Url) -> Result<(), FetchError> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err(dns_server_error(value, "credentials are not allowed"));
    }
    if !url.path().is_empty() {
        return Err(dns_server_error(value, "paths are not allowed"));
    }
    if url.query().is_some() {
        return Err(dns_server_error(value, "queries are not allowed"));
    }
    if url.fragment().is_some() {
        return Err(dns_server_error(value, "fragments are not allowed"));
    }
    validate_nonzero_port(value, url.port())
}

fn validate_nonzero_port(value: &str, port: Option<u16>) -> Result<(), FetchError> {
    if port == Some(0) {
        return Err(dns_server_error(value, "port must be greater than zero"));
    }
    Ok(())
}

fn nonzero_socket_addr(value: &str, addr: SocketAddr) -> Result<SocketAddr, FetchError> {
    validate_nonzero_port(value, Some(addr.port()))?;
    Ok(addr)
}

fn dns_server_error(value: &str, message: &str) -> FetchError {
    FetchError::Message(format!(
        "invalid value '{value}' for option '--dns-server': {message}"
    ))
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

pub(crate) async fn query_type(
    server: &ParsedDnsServer,
    host: &str,
    dns_type: u16,
    dns_type_name: &str,
    budget: TimeoutBudget,
    doh_tls_config: Option<rustls::ClientConfig>,
) -> Result<Vec<DnsQueryRecord>, FetchError> {
    let wire_records = match server {
        ParsedDnsServer::Udp(addr) => {
            crate::dns::resolver::query_udp_type(addr, host, dns_type, budget).await
        }
        ParsedDnsServer::Tcp(addr) => {
            crate::dns::resolver::query_tcp_type(addr, host, dns_type, budget).await
        }
        ParsedDnsServer::Tls {
            server_name,
            host: server_host,
            port,
        } => {
            let addrs = resolve_server_host(server_host, *port, budget.remaining()?).await?;
            crate::dns::resolver::query_tls_type(server_name, &addrs, host, dns_type, budget, false)
                .await
        }
        ParsedDnsServer::Quic {
            server_name,
            host: server_host,
            port,
        } => {
            let addrs = resolve_server_host(server_host, *port, budget.remaining()?).await?;
            crate::dns::resolver::query_quic_type(
                server_name,
                &addrs,
                host,
                dns_type,
                budget,
                false,
            )
            .await
        }
        ParsedDnsServer::Doh(url) => {
            let client = crate::dns::doh::client_with_budget_and_tls_config(budget, doh_tls_config)
                .map_err(|err| FetchError::Message(err.to_string()))?;
            let answers = match crate::dns::doh::lookup_doh_records_with_client(
                &client,
                url,
                host,
                dns_type_name,
            )
            .await
            {
                Ok(answers) => answers,
                Err(err) if err.is_nxdomain() => return Ok(Vec::new()),
                Err(err) => {
                    return Err(FetchError::Runtime(format!("lookup {host}: {err}")));
                }
            };
            return Ok(answers
                .into_iter()
                .map(|answer| DnsQueryRecord {
                    typ: answer.answer_type,
                    ttl: answer.ttl,
                    data: DnsRecordData::Text(answer.data),
                })
                .collect());
        }
    };

    match wire_records {
        Ok(records) => Ok(records
            .into_iter()
            .map(|record| DnsQueryRecord {
                typ: record.typ,
                ttl: Some(record.ttl),
                data: DnsRecordData::Wire(record.data),
            })
            .collect()),
        Err(err) if err.is_nxdomain() => Ok(Vec::new()),
        Err(err) => Err(FetchError::Runtime(format!("lookup {host}: {err}"))),
    }
}

pub(crate) async fn lookup_ips_with_server(
    dns_server: &ParsedDnsServer,
    host: &str,
    timeout: Option<Duration>,
) -> Result<Vec<IpAddr>, FetchError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    match dns_server {
        ParsedDnsServer::Udp(addr) => crate::dns::resolver::lookup_udp_addr(addr, host, timeout)
            .await
            .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}"))),
        ParsedDnsServer::Tcp(addr) => crate::dns::resolver::lookup_tcp_addr(addr, host, timeout)
            .await
            .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}"))),
        ParsedDnsServer::Tls {
            server_name,
            host: server_host,
            port,
        } => {
            let resolve_start = std::time::Instant::now();
            let addrs = resolve_server_host(server_host, *port, timeout).await?;
            let remaining = timeout.map(|t| t.saturating_sub(resolve_start.elapsed()));
            crate::dns::resolver::lookup_tls(server_name, &addrs, host, remaining, false)
                .await
                .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))
        }
        ParsedDnsServer::Quic {
            server_name,
            host: server_host,
            port,
        } => {
            let resolve_start = std::time::Instant::now();
            let addrs = resolve_server_host(server_host, *port, timeout).await?;
            let remaining = timeout.map(|t| t.saturating_sub(resolve_start.elapsed()));
            crate::dns::resolver::lookup_quic(server_name, &addrs, host, remaining, false)
                .await
                .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))
        }
        ParsedDnsServer::Doh(url) => crate::dns::doh::lookup_doh(url, host, timeout)
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
    fn classifies_authenticated_dns_transports() {
        assert!(
            !parse_dns_server("udp://127.0.0.1")
                .unwrap()
                .is_authenticated(true)
        );
        assert!(
            !parse_dns_server("tcp://127.0.0.1")
                .unwrap()
                .is_authenticated(true)
        );
        assert!(
            !parse_dns_server("https://resolver.example/dns-query")
                .unwrap()
                .is_authenticated(false)
        );
        assert!(
            parse_dns_server("https://resolver.example/dns-query")
                .unwrap()
                .is_authenticated(true)
        );
        assert!(
            parse_dns_server("tls://resolver.example")
                .unwrap()
                .is_authenticated(true)
        );
        assert!(
            parse_dns_server("doq://resolver.example")
                .unwrap()
                .is_authenticated(true)
        );
    }

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
        let parsed = parse_dns_server("https://dns.example/dns-query?profile=secure").unwrap();
        assert!(
            matches!(parsed, ParsedDnsServer::Doh(url) if url.as_str() == "https://dns.example/dns-query?profile=secure")
        );
    }

    #[test]
    fn parse_dns_server_normalizes_mixed_case_schemes() {
        assert!(matches!(
            parse_dns_server("UdP://1.1.1.1").unwrap(),
            ParsedDnsServer::Udp(_)
        ));
        assert!(matches!(
            parse_dns_server("TcP://1.1.1.1").unwrap(),
            ParsedDnsServer::Tcp(_)
        ));
        assert!(matches!(
            parse_dns_server("DoT://dns.example").unwrap(),
            ParsedDnsServer::Tls { .. }
        ));
        assert!(matches!(
            parse_dns_server("DoQ://dns.example").unwrap(),
            ParsedDnsServer::Quic { .. }
        ));
        assert!(matches!(
            parse_dns_server("HtTpS://dns.example/dns-query").unwrap(),
            ParsedDnsServer::Doh(url) if url.scheme() == "https"
        ));
    }

    #[test]
    fn parse_dns_server_rejects_non_http_url_components() {
        for scheme in ["udp", "tcp", "tls", "dot", "quic", "doq"] {
            for suffix in ["/dns-query", "?profile=x", "#fragment"] {
                let value = format!("{scheme}://1.1.1.1{suffix}");
                assert!(parse_dns_server(&value).is_err(), "accepted {value}");
            }
            for authority in ["user@1.1.1.1", "user:pass@1.1.1.1"] {
                let value = format!("{scheme}://{authority}");
                assert!(parse_dns_server(&value).is_err(), "accepted {value}");
            }
        }
    }

    #[test]
    fn parse_dns_server_rejects_doh_credentials_and_fragments() {
        for value in [
            "https://user@dns.example/dns-query",
            "https://user:pass@dns.example/dns-query",
            "https://dns.example/dns-query#fragment",
        ] {
            assert!(parse_dns_server(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn parse_dns_server_rejects_port_zero() {
        for value in [
            "1.1.1.1:0",
            "udp://1.1.1.1:0",
            "tcp://1.1.1.1:0",
            "tls://dns.example:0",
            "doq://dns.example:0",
            "https://dns.example:0/dns-query",
        ] {
            assert!(parse_dns_server(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn parse_dns_server_rejects_plaintext_doh_url() {
        let err = parse_dns_server("http://dns.example/dns-query").unwrap_err();

        assert!(err.to_string().contains("DoH endpoints must use HTTPS"));
    }

    #[test]
    fn parse_dns_server_allows_plaintext_loopback_only_in_unit_tests() {
        let parsed = parse_dns_server("http://127.0.0.1:8080/dns-query").unwrap();

        assert!(matches!(parsed, ParsedDnsServer::Doh(_)));
    }

    #[test]
    fn parse_dns_server_rejects_doh_url_without_host() {
        assert!(parse_dns_server("https://").is_err());
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
