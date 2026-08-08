use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;

use crate::dns::util::{dns_transaction_budget, udp_dns_timeout};
use crate::dns::wire::ResponseMatcher;
use crate::duration::TimeoutBudget;
use crate::error::FetchError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsTransportError {
    kind: crate::dns::error::DnsErrorKind,
    detail: Option<String>,
}

impl fmt::Display for DnsTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.detail {
            Some(detail) => f.write_str(detail),
            None => self.kind.fmt(f),
        }
    }
}

impl std::error::Error for DnsTransportError {}

impl DnsTransportError {
    fn timeout() -> Self {
        Self {
            kind: crate::dns::error::DnsErrorKind::Timeout,
            detail: None,
        }
    }

    fn other(detail: impl Into<String>) -> Self {
        Self {
            kind: crate::dns::error::DnsErrorKind::Other,
            detail: Some(detail.into()),
        }
    }

    pub(crate) fn kind(&self) -> crate::dns::error::DnsErrorKind {
        self.kind
    }
}

const UDP_MAX_ATTEMPTS: usize = 3;
const UDP_INITIAL_RETRANSMIT_DELAY: Duration = Duration::from_millis(100);
const UDP_MAX_RETRANSMIT_DELAY: Duration = Duration::from_millis(250);

pub(crate) async fn query_udp(
    server_addr: SocketAddr,
    query: &[u8],
    matcher: &ResponseMatcher,
    budget: TimeoutBudget,
) -> Result<Vec<u8>, DnsTransportError> {
    let budget = dns_transaction_budget(budget);
    let socket = udp_socket(server_addr, budget).await?;
    query_udp_on_socket(&socket, query, matcher, budget).await
}

pub(crate) async fn udp_socket(
    server_addr: SocketAddr,
    budget: TimeoutBudget,
) -> Result<UdpSocket, DnsTransportError> {
    let budget = dns_transaction_budget(budget);
    let bind_addr = if server_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = run_udp_budgeted(budget, UdpSocket::bind(bind_addr)).await?;
    run_udp_budgeted(budget, socket.connect(server_addr)).await?;
    Ok(socket)
}

pub(crate) async fn query_udp_on_socket(
    socket: &UdpSocket,
    query: &[u8],
    matcher: &ResponseMatcher,
    budget: TimeoutBudget,
) -> Result<Vec<u8>, DnsTransportError> {
    let budget = dns_transaction_budget(budget);
    let remaining = udp_remaining(budget)?;
    // TCP fallback uses this same absolute budget if a truncated reply arrives.
    let deadline = tokio::time::Instant::now() + remaining;
    let expected_source = socket.peer_addr().map_err(transport_error)?;
    let mut retransmit_delay = UDP_INITIAL_RETRANSMIT_DELAY;
    let mut buf = vec![0u8; 4096];

    for attempt in 0..UDP_MAX_ATTEMPTS {
        match tokio::time::timeout_at(deadline, socket.send(query)).await {
            Ok(Ok(_)) => {}
            Ok(Err(err)) => return Err(transport_error(err)),
            Err(_) => return Err(udp_timeout_error()),
        }

        let receive_deadline = if attempt + 1 == UDP_MAX_ATTEMPTS {
            deadline
        } else {
            deadline.min(tokio::time::Instant::now() + retransmit_delay)
        };
        loop {
            let (n, source) =
                match tokio::time::timeout_at(receive_deadline, socket.recv_from(&mut buf)).await {
                    Ok(Ok(received)) => received,
                    Ok(Err(err)) => return Err(transport_error(err)),
                    Err(_) if receive_deadline < deadline => break,
                    Err(_) => return Err(udp_timeout_error()),
                };
            if source != expected_source || !matcher.matches(&buf[..n]) {
                continue;
            }
            buf.truncate(n);
            return Ok(buf);
        }
        retransmit_delay = (retransmit_delay * 2).min(UDP_MAX_RETRANSMIT_DELAY);
    }

    Err(udp_timeout_error())
}

async fn run_udp_budgeted<T>(
    budget: TimeoutBudget,
    future: impl std::future::Future<Output = std::io::Result<T>>,
) -> Result<T, DnsTransportError> {
    let remaining = udp_remaining(budget)?;
    tokio::time::timeout(remaining, future)
        .await
        .map_err(|_| udp_timeout_error())?
        .map_err(transport_error)
}

fn udp_remaining(budget: TimeoutBudget) -> Result<Duration, DnsTransportError> {
    budget
        .remaining()
        .map_err(|_| udp_timeout_error())?
        .ok_or_else(udp_timeout_error)
}

fn udp_timeout_error() -> DnsTransportError {
    DnsTransportError::timeout()
}

pub(crate) async fn query_tcp(
    server_addr: SocketAddr,
    query: &[u8],
    budget: TimeoutBudget,
) -> Result<Vec<u8>, DnsTransportError> {
    let connect_timeout = udp_dns_timeout(budget.remaining().map_err(transport_error)?);
    let mut stream = tcp_connection(&server_addr, connect_timeout).await?;
    let query_timeout = udp_dns_timeout(budget.remaining().map_err(transport_error)?);
    tokio::time::timeout(query_timeout, async {
        write_framed_query(&mut stream, query).await?;
        read_framed_response(&mut stream).await
    })
    .await
    .map_err(|_| DnsTransportError::timeout())?
}

pub(crate) async fn tcp_connection(
    server_addr: &SocketAddr,
    timeout: Duration,
) -> Result<TcpStream, DnsTransportError> {
    tokio::time::timeout(timeout, TcpStream::connect(server_addr))
        .await
        .map_err(|_| DnsTransportError::timeout())?
        .map_err(transport_error)
}

pub(crate) async fn write_framed_query<W: AsyncWrite + Unpin>(
    stream: &mut W,
    query: &[u8],
) -> Result<(), DnsTransportError> {
    if query.len() > usize::from(u16::MAX) {
        return Err(DnsTransportError::other("DNS query is too large"));
    }
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed.extend_from_slice(query);
    stream.write_all(&framed).await.map_err(transport_error)
}

pub(crate) async fn read_framed_response<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> Result<Vec<u8>, DnsTransportError> {
    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(transport_error)?;
    let response_len = usize::from(u16::from_be_bytes(len_buf));
    let mut response = vec![0u8; response_len];
    stream
        .read_exact(&mut response)
        .await
        .map_err(transport_error)?;
    Ok(response)
}

pub(crate) async fn tls_connection(
    server_name: &ServerName<'static>,
    server_addrs: &[SocketAddr],
    timeout: Duration,
    insecure: bool,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, DnsTransportError> {
    let connector = tls_connector(insecure).await?;
    tokio::time::timeout(
        timeout,
        crate::net::race_staggered(
            server_addrs.to_vec(),
            crate::net::HAPPY_EYEBALLS_FALLBACK_DELAY,
            "DNS server resolved no addresses",
            "dns over tls connect",
            move |addr| {
                let connector = connector.clone();
                let server_name = server_name.clone();
                async move {
                    let stream = TcpStream::connect(addr).await.map_err(|err| {
                        FetchError::Runtime(format!("dns over tls connect {addr}: {err}"))
                    })?;
                    connector
                        .connect(server_name, stream)
                        .await
                        .map_err(|err| FetchError::Runtime(format!("dns over tls {addr}: {err}")))
                }
            },
        ),
    )
    .await
    .map_err(|_| DnsTransportError::timeout())?
    .map_err(|err| DnsTransportError::other(err.to_string()))
}

async fn tls_connector(insecure: bool) -> Result<TlsConnector, DnsTransportError> {
    let config = crate::tls::rustls_platform_client_config_with_options(
        &[],
        None,
        None,
        insecure,
        None,
        None,
        None,
    )
    .map_err(|err| DnsTransportError::other(err.to_string()))?;
    Ok(TlsConnector::from(Arc::new(config)))
}

pub(crate) async fn quic_connection(
    server_name: &ServerName<'static>,
    server_addrs: &[SocketAddr],
    timeout: Duration,
    insecure: bool,
) -> Result<quinn::Connection, DnsTransportError> {
    let mut endpoint = quinn_client_endpoint()?;
    let mut tls = crate::tls::rustls_platform_client_config_with_options(
        &[],
        None,
        None,
        insecure,
        None,
        None,
        None,
    )
    .map_err(|err| DnsTransportError::other(err.to_string()))?;
    tls.alpn_protocols = vec![b"doq".to_vec()];
    let client_config = QuicClientConfig::try_from(tls).map_err(|err| {
        DnsTransportError::other(format!("invalid QUIC TLS configuration: {err}"))
    })?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_config)));
    tokio::time::timeout(
        timeout,
        crate::net::race_staggered(
            server_addrs.to_vec(),
            crate::net::HAPPY_EYEBALLS_FALLBACK_DELAY,
            "DNS server resolved no addresses",
            "dns over quic connect",
            move |addr| {
                let endpoint = endpoint.clone();
                let server_name = server_name_to_str(server_name);
                async move {
                    let connecting = endpoint.connect(addr, &server_name).map_err(|err| {
                        FetchError::Runtime(format!("dns over quic connect {addr}: {err}"))
                    })?;
                    connecting
                        .await
                        .map_err(|err| FetchError::Runtime(format!("dns over quic {addr}: {err}")))
                }
            },
        ),
    )
    .await
    .map_err(|_| DnsTransportError::timeout())?
    .map_err(|err| DnsTransportError::other(err.to_string()))
}

fn quinn_client_endpoint() -> Result<quinn::Endpoint, DnsTransportError> {
    let local_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
    match quinn::Endpoint::client(local_addr) {
        Ok(endpoint) => Ok(endpoint),
        Err(err) => {
            let fallback_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            quinn::Endpoint::client(fallback_addr).map_err(|fallback_err| {
                DnsTransportError::other(format!(
                    "failed to bind QUIC endpoint to {local_addr}: {err}; \
                     IPv4 fallback {fallback_addr} also failed: {fallback_err}"
                ))
            })
        }
    }
}

fn server_name_to_str(server_name: &ServerName<'_>) -> String {
    match server_name {
        ServerName::DnsName(name) => name.as_ref().to_string(),
        ServerName::IpAddress(ip) => std::net::IpAddr::from(*ip).to_string(),
        _ => String::new(),
    }
}

pub(crate) async fn quic_query(
    connection: &quinn::Connection,
    query: &[u8],
) -> Result<Vec<u8>, DnsTransportError> {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|err| DnsTransportError::other(format!("dns over quic open stream: {err}")))?;
    write_framed_query(&mut send, query).await?;
    send.finish()
        .map_err(|err| DnsTransportError::other(format!("dns over quic finish stream: {err}")))?;
    read_framed_response(&mut recv).await
}

fn transport_error(err: impl ToString) -> DnsTransportError {
    DnsTransportError::other(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::wire::{self, CLASS_IN, TYPE_A, TYPE_AAAA};

    fn response_for(query: &[u8], flags: u16) -> Vec<u8> {
        let mut response = query.to_vec();
        response[2..4].copy_from_slice(&flags.to_be_bytes());
        response
    }

    #[tokio::test]
    async fn udp_discards_stale_response_from_timed_out_query() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = udp_socket(
            server_addr,
            TimeoutBudget::new(Some(Duration::from_secs(1))),
        )
        .await
        .unwrap();
        let first = wire::build_query(0x1001, "example.com", TYPE_A).unwrap();
        let second = wire::build_query(0x1002, "example.com", TYPE_AAAA).unwrap();

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (first_len, peer) = server.recv_from(&mut buf).await.unwrap();
            let first_response = response_for(&buf[..first_len], 0x8180);
            let (second_len, second_peer) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(peer, second_peer);
            let second_response = response_for(&buf[..second_len], 0x8180);
            server.send_to(&first_response, peer).await.unwrap();
            server.send_to(&second_response, peer).await.unwrap();
        });

        let first_matcher = ResponseMatcher::new(0x1001, "example.com", TYPE_A, CLASS_IN);
        let err = query_udp_on_socket(
            &client,
            &first,
            &first_matcher,
            TimeoutBudget::new(Some(Duration::from_millis(20))),
        )
        .await
        .unwrap_err();
        assert_eq!(err.to_string(), "DNS lookup timed out");

        let second_matcher = ResponseMatcher::new(0x1002, "example.com", TYPE_AAAA, CLASS_IN);
        let response = query_udp_on_socket(
            &client,
            &second,
            &second_matcher,
            TimeoutBudget::new(Some(Duration::from_secs(1))),
        )
        .await
        .unwrap();
        assert_eq!(u16::from_be_bytes([response[0], response[1]]), 0x1002);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn udp_discards_mismatched_response_fields() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let query = wire::build_query(0x2001, "example.com", TYPE_A).unwrap();
        let matcher = ResponseMatcher::new(0x2001, "example.com", TYPE_A, CLASS_IN);
        let server_query = query.clone();

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_, peer) = server.recv_from(&mut buf).await.unwrap();
            let mut wrong_class = response_for(&server_query, 0x8180);
            wrong_class[27..29].copy_from_slice(&2u16.to_be_bytes());
            let packets = vec![
                response_for(&server_query, 0x0100),
                response_for(&server_query, 0x8800),
                response_for(
                    &wire::build_query(0x2001, "other.example", TYPE_A).unwrap(),
                    0x8180,
                ),
                response_for(
                    &wire::build_query(0x2001, "example.com", TYPE_AAAA).unwrap(),
                    0x8180,
                ),
                wrong_class,
                response_for(&server_query, 0x8180),
            ];
            for packet in packets {
                server.send_to(&packet, peer).await.unwrap();
            }
        });

        let response = query_udp(
            server_addr,
            &query,
            &matcher,
            TimeoutBudget::new(Some(Duration::from_secs(1))),
        )
        .await
        .unwrap();
        assert_eq!(response, response_for(&query, 0x8180));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn udp_discards_response_from_wrong_source() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let query = wire::build_query(0x3001, "example.com", TYPE_A).unwrap();
        let matcher = ResponseMatcher::new(0x3001, "example.com", TYPE_A, CLASS_IN);

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = server.recv_from(&mut buf).await.unwrap();
            let spoof = response_for(&buf[..len], 0x8183);
            attacker.send_to(&spoof, peer).await.unwrap();
            let valid = response_for(&buf[..len], 0x8180);
            server.send_to(&valid, peer).await.unwrap();
        });

        let response = query_udp(
            server_addr,
            &query,
            &matcher,
            TimeoutBudget::new(Some(Duration::from_secs(1))),
        )
        .await
        .unwrap();
        assert_eq!(u16::from_be_bytes([response[2], response[3]]), 0x8180);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn udp_retransmits_after_dropped_query() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let query = wire::build_query(0x4001, "example.com", TYPE_A).unwrap();
        let matcher = ResponseMatcher::new(0x4001, "example.com", TYPE_A, CLASS_IN);

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let _dropped = server.recv_from(&mut buf).await.unwrap();
            let (len, peer) = server.recv_from(&mut buf).await.unwrap();
            server
                .send_to(&response_for(&buf[..len], 0x8180), peer)
                .await
                .unwrap();
        });

        let response = query_udp(
            server_addr,
            &query,
            &matcher,
            TimeoutBudget::new(Some(Duration::from_secs(1))),
        )
        .await
        .unwrap();
        assert_eq!(response, response_for(&query, 0x8180));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn udp_retransmits_after_dropped_reply() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let query = wire::build_query(0x4002, "example.com", TYPE_A).unwrap();
        let matcher = ResponseMatcher::new(0x4002, "example.com", TYPE_A, CLASS_IN);

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (first_len, _) = server.recv_from(&mut buf).await.unwrap();
            let _dropped_reply = response_for(&buf[..first_len], 0x8180);
            let (second_len, peer) = server.recv_from(&mut buf).await.unwrap();
            server
                .send_to(&response_for(&buf[..second_len], 0x8180), peer)
                .await
                .unwrap();
        });

        let response = query_udp(
            server_addr,
            &query,
            &matcher,
            TimeoutBudget::new(Some(Duration::from_secs(1))),
        )
        .await
        .unwrap();
        assert_eq!(response, response_for(&query, 0x8180));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn udp_setup_obeys_expired_budget() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let budget = TimeoutBudget::started_at(
            Some(Duration::from_millis(10)),
            std::time::Instant::now() - Duration::from_millis(20),
        );

        let err = udp_socket(server.local_addr().unwrap(), budget)
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "DNS lookup timed out");
    }

    #[tokio::test]
    async fn write_read_framed_query_round_trips() {
        let query = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
        let mut buf = Vec::new();

        write_framed_query(&mut buf, query).await.unwrap();
        assert_eq!(&buf[..2], &(query.len() as u16).to_be_bytes());
        assert_eq!(&buf[2..], query);

        let mut cursor = std::io::Cursor::new(buf);
        let response = read_framed_response(&mut cursor).await.unwrap();
        assert_eq!(response, query);
    }
}
