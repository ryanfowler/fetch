use std::fmt;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsTransportError(String);

impl fmt::Display for DnsTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DnsTransportError {}

pub(crate) async fn query_udp(
    server_addr: &str,
    query: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, DnsTransportError> {
    let socket = UdpSocket::bind(if server_addr.starts_with('[') {
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
    server_addr: &str,
    query: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, DnsTransportError> {
    if query.len() > usize::from(u16::MAX) {
        return Err(DnsTransportError(
            "DNS query is too large for TCP".to_string(),
        ));
    }

    let mut framed_query = Vec::with_capacity(query.len() + 2);
    framed_query.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed_query.extend_from_slice(query);

    match tokio::time::timeout(timeout, query_tcp_inner(server_addr, &framed_query)).await {
        Ok(result) => result,
        Err(_) => Err(DnsTransportError("DNS lookup timed out".to_string())),
    }
}

async fn query_tcp_inner(
    server_addr: &str,
    framed_query: &[u8],
) -> Result<Vec<u8>, DnsTransportError> {
    let mut stream = TcpStream::connect(server_addr)
        .await
        .map_err(transport_error)?;
    stream
        .write_all(framed_query)
        .await
        .map_err(transport_error)?;

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

fn transport_error(err: impl ToString) -> DnsTransportError {
    DnsTransportError(err.to_string())
}
