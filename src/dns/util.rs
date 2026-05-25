use std::time::Duration;

pub(crate) const DEFAULT_UDP_DNS_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn dns_query_id() -> u16 {
    rand::random::<u16>()
}

pub(crate) fn udp_dns_timeout(timeout: Option<Duration>) -> Duration {
    timeout.unwrap_or(DEFAULT_UDP_DNS_TIMEOUT)
}
