use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use url::Url;

use crate::error::FetchError;

pub(crate) async fn lookup_ips(
    dns_server: &str,
    host: &str,
    timeout: Option<Duration>,
) -> Result<Vec<IpAddr>, FetchError> {
    if dns_server.starts_with("http://") || dns_server.starts_with("https://") {
        let server_url = Url::parse(dns_server).map_err(|err| {
            FetchError::Message(format!("invalid dns-server '{dns_server}': {err}"))
        })?;
        crate::dns::doh::lookup_doh(&server_url, host, timeout)
            .await
            .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))
    } else {
        let server_addr = crate::dns::resolver::normalize_udp_dns_server(dns_server)
            .map_err(|err| FetchError::Message(err.to_string()))?;
        crate::dns::resolver::lookup_udp(&server_addr, host, timeout)
            .await
            .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))
    }
}

pub(crate) fn socket_addrs_for_override(addrs: &[IpAddr]) -> Vec<SocketAddr> {
    addrs.iter().map(|addr| SocketAddr::new(*addr, 0)).collect()
}

pub(crate) fn socket_addrs_with_port(
    addrs: impl IntoIterator<Item = IpAddr>,
    port: u16,
) -> Vec<SocketAddr> {
    let mut addrs = addrs
        .into_iter()
        .map(|addr| SocketAddr::new(addr, port))
        .collect::<Vec<_>>();
    sort_socket_addrs(&mut addrs);
    addrs.dedup();
    addrs
}

pub(crate) fn sorted_unique_ips(mut addrs: Vec<IpAddr>) -> Vec<IpAddr> {
    addrs.sort_by(compare_ip_addrs);
    addrs.dedup();
    addrs
}

pub(crate) fn sort_socket_addrs(addrs: &mut [SocketAddr]) {
    addrs.sort_by(|left, right| {
        compare_ip_addrs(&left.ip(), &right.ip()).then_with(|| left.port().cmp(&right.port()))
    });
}

fn compare_ip_addrs(left: &IpAddr, right: &IpAddr) -> std::cmp::Ordering {
    match (left, right) {
        (IpAddr::V4(left), IpAddr::V4(right)) => left.octets().cmp(&right.octets()),
        (IpAddr::V6(left), IpAddr::V6(right)) => left.octets().cmp(&right.octets()),
        (IpAddr::V4(_), IpAddr::V6(_)) => std::cmp::Ordering::Less,
        (IpAddr::V6(_), IpAddr::V4(_)) => std::cmp::Ordering::Greater,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_addrs_use_zero_port_for_reqwest_override() {
        let addrs = socket_addrs_for_override(&["127.0.0.1".parse().unwrap()]);

        assert_eq!(addrs, [SocketAddr::new("127.0.0.1".parse().unwrap(), 0)]);
    }
}
