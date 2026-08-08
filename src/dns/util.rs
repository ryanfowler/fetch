use std::time::Duration;

pub(crate) const DEFAULT_UDP_DNS_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn dns_query_id() -> u16 {
    rand::random::<u16>()
}

pub(crate) fn udp_dns_timeout(timeout: Option<Duration>) -> Duration {
    timeout.unwrap_or(DEFAULT_UDP_DNS_TIMEOUT)
}

/// Resolve both address families without making a positive result depend on
/// the other family. The preferred-family order remains IPv4, then IPv6.
pub(crate) async fn resolve_address_families<F4, F6, T, E>(
    ipv4: F4,
    ipv6: F6,
    positive_result_delay: Duration,
    no_addresses: E,
) -> Result<Vec<T>, E>
where
    F4: std::future::Future<Output = Result<Vec<T>, E>>,
    F6: std::future::Future<Output = Result<Vec<T>, E>>,
{
    let mut ipv4 = Box::pin(ipv4);
    let mut ipv6 = Box::pin(ipv6);

    let (ipv4_result, ipv6_result) = tokio::select! {
        result = &mut ipv4 => {
            if result.as_ref().is_ok_and(|records| !records.is_empty()) {
                let other = tokio::time::timeout(positive_result_delay, &mut ipv6).await.ok();
                (Some(result), other)
            } else {
                (Some(result), Some(ipv6.await))
            }
        }
        result = &mut ipv6 => {
            if result.as_ref().is_ok_and(|records| !records.is_empty()) {
                let other = tokio::time::timeout(positive_result_delay, &mut ipv4).await.ok();
                (other, Some(result))
            } else {
                (Some(ipv4.await), Some(result))
            }
        }
    };

    let has_addresses = ipv4_result
        .as_ref()
        .is_some_and(|result| result.as_ref().is_ok_and(|records| !records.is_empty()))
        || ipv6_result
            .as_ref()
            .is_some_and(|result| result.as_ref().is_ok_and(|records| !records.is_empty()));
    if has_addresses {
        let mut addresses = ipv4_result.and_then(Result::ok).unwrap_or_default();
        addresses.extend(ipv6_result.and_then(Result::ok).unwrap_or_default());
        return Ok(addresses);
    }

    if let Some(result) = ipv4_result {
        result?;
    }
    if let Some(result) = ipv6_result {
        result?;
    }
    Err(no_addresses)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn positive_ipv6_does_not_wait_for_ipv4() {
        let start = tokio::time::Instant::now();
        let result = resolve_address_families(
            std::future::pending::<Result<Vec<u8>, &str>>(),
            async { Ok(vec![6]) },
            Duration::from_millis(10),
            "no addresses",
        )
        .await
        .unwrap();

        assert_eq!(result, [6]);
        assert!(start.elapsed() < Duration::from_millis(100));
    }

    #[tokio::test]
    async fn result_order_remains_ipv4_then_ipv6() {
        let result = resolve_address_families(
            async { Ok::<_, &str>(vec![4]) },
            async { Ok::<_, &str>(vec![6]) },
            Duration::from_millis(10),
            "no addresses",
        )
        .await
        .unwrap();

        assert_eq!(result, [4, 6]);
    }
}
