use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;

use crate::dns::util::udp_dns_timeout;
use crate::duration::TimeoutBudget;
use crate::error::FetchError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsTransportError(String);

impl fmt::Display for DnsTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DnsTransportError {}

pub(crate) async fn query_udp(
    server_addr: SocketAddr,
    query: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, DnsTransportError> {
    let socket = UdpSocket::bind(if server_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    })
    .await
    .map_err(transport_error)?;
    socket.connect(server_addr).await.map_err(transport_error)?;
    socket.send(query).await.map_err(transport_error)?;

    let mut buf = vec![0u8; 4096];
    let n = match tokio::time::timeout(timeout, socket.recv(&mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(err)) => return Err(transport_error(err)),
        Err(_) => return Err(DnsTransportError("DNS lookup timed out".to_string())),
    };
    buf.truncate(n);
    Ok(buf)
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
    .map_err(|_| DnsTransportError("DNS lookup timed out".to_string()))?
}

pub(crate) async fn tcp_connection(
    server_addr: &SocketAddr,
    timeout: Duration,
) -> Result<TcpStream, DnsTransportError> {
    tokio::time::timeout(timeout, TcpStream::connect(server_addr))
        .await
        .map_err(|_| DnsTransportError("DNS lookup timed out".to_string()))?
        .map_err(transport_error)
}

pub(crate) async fn write_framed_query<W: AsyncWrite + Unpin>(
    stream: &mut W,
    query: &[u8],
) -> Result<(), DnsTransportError> {
    if query.len() > usize::from(u16::MAX) {
        return Err(DnsTransportError("DNS query is too large".to_string()));
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
    .map_err(|_| DnsTransportError("DNS lookup timed out".to_string()))?
    .map_err(|err| DnsTransportError(err.to_string()))
}

async fn tls_connector(insecure: bool) -> Result<TlsConnector, DnsTransportError> {
    let config = crate::tls::rustls_platform_client_config_with_options(
        &[],
        None,
        None,
        insecure,
        None,
        None,
    )
    .map_err(|err| DnsTransportError(err.to_string()))?;
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
    )
    .map_err(|err| DnsTransportError(err.to_string()))?;
    tls.alpn_protocols = vec![b"doq".to_vec()];
    let client_config = QuicClientConfig::try_from(tls)
        .map_err(|err| DnsTransportError(format!("invalid QUIC TLS configuration: {err}")))?;
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
    .map_err(|_| DnsTransportError("DNS lookup timed out".to_string()))?
    .map_err(|err| DnsTransportError(err.to_string()))
}

fn quinn_client_endpoint() -> Result<quinn::Endpoint, DnsTransportError> {
    let local_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
    match quinn::Endpoint::client(local_addr) {
        Ok(endpoint) => Ok(endpoint),
        Err(err) => {
            let fallback_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            quinn::Endpoint::client(fallback_addr).map_err(|fallback_err| {
                DnsTransportError(format!(
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
        .map_err(|err| DnsTransportError(format!("dns over quic open stream: {err}")))?;
    write_framed_query(&mut send, query).await?;
    send.finish()
        .map_err(|err| DnsTransportError(format!("dns over quic finish stream: {err}")))?;
    read_framed_response(&mut recv).await
}

fn transport_error(err: impl ToString) -> DnsTransportError {
    DnsTransportError(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

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
