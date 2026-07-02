use std::future::Future;
use std::time::{Duration, Instant};

use crate::error::FetchError;

const NANOS_PER_MICRO: u128 = 1_000;
const NANOS_PER_MILLI: u128 = 1_000_000;
const NANOS_PER_SECOND: u128 = 1_000_000_000;
const NANOS_PER_MINUTE: u128 = 60 * NANOS_PER_SECOND;
const NANOS_PER_HOUR: u128 = 60 * NANOS_PER_MINUTE;
const NANOS_PER_DAY: u128 = 24 * NANOS_PER_HOUR;

pub(crate) const MAX_DURATION_SECONDS: f64 = i64::MAX as f64 / 1_000_000_000_f64;

#[derive(Clone, Copy, Debug)]
pub(crate) struct TimeoutBudget {
    timeout: Option<Duration>,
    started_at: Instant,
}

impl TimeoutBudget {
    pub(crate) fn new(timeout: Option<Duration>) -> Self {
        Self::started_at(timeout, Instant::now())
    }

    pub(crate) fn started_at(timeout: Option<Duration>, started_at: Instant) -> Self {
        Self {
            timeout,
            started_at,
        }
    }

    pub(crate) fn for_connect(
        connect_timeout: Option<Duration>,
        request_timeout: Option<Duration>,
        request_started_at: Instant,
    ) -> Result<Self, FetchError> {
        let request_remaining = remaining_timeout(request_timeout, request_started_at)?;
        Ok(Self::new(min_timeout(connect_timeout, request_remaining)))
    }

    pub(crate) fn timeout(self) -> Option<Duration> {
        self.timeout
    }

    pub(crate) fn remaining(self) -> Result<Option<Duration>, FetchError> {
        remaining_timeout(self.timeout, self.started_at)
    }

    pub(crate) fn timeout_error(self) -> FetchError {
        request_timeout_error(self.timeout.expect("timeout checked by caller"))
    }

    pub(crate) async fn run<T>(
        self,
        future: impl Future<Output = Result<T, FetchError>>,
    ) -> Result<T, FetchError> {
        let Some(remaining) = self.remaining()? else {
            return future.await;
        };
        let started_at = Instant::now();
        match tokio::time::timeout(remaining, future).await {
            Ok(Err(err)) if started_at.elapsed() >= remaining && is_timeout_error(&err) => {
                Err(self.timeout_error())
            }
            Ok(result) => result,
            Err(_) => Err(self.timeout_error()),
        }
    }
}

pub(crate) fn duration_from_seconds(
    flag: &str,
    seconds: f64,
) -> Result<Option<Duration>, FetchError> {
    if !seconds.is_finite() || !(0.0..=MAX_DURATION_SECONDS).contains(&seconds) {
        return Err(format!(
            "invalid value '{seconds}' for option '--{flag}': must be a non-negative number"
        )
        .into());
    }
    if seconds == 0.0 {
        return Ok(None); // 0 means no timeout (curl-compatible)
    }
    Ok(Some(Duration::from_secs_f64(seconds)))
}

pub(crate) fn remaining_timeout(
    timeout: Option<Duration>,
    started_at: Instant,
) -> Result<Option<Duration>, FetchError> {
    let Some(timeout) = timeout else {
        return Ok(None);
    };
    let elapsed = started_at.elapsed();
    if elapsed >= timeout {
        return Err(request_timeout_error(timeout));
    }
    Ok(Some(timeout - elapsed))
}

pub(crate) fn request_timeout_error(timeout: Duration) -> FetchError {
    FetchError::Runtime(request_timeout_message(timeout))
}

pub(crate) fn request_timeout_message(timeout: Duration) -> String {
    format!("request timed out after {}", format_go_duration(timeout))
}

pub(crate) fn format_go_duration(duration: Duration) -> String {
    let nanos = duration.as_nanos();
    if nanos < 1_000 {
        return format!("{nanos}ns");
    }
    if nanos < 1_000_000 {
        return format_duration_unit(nanos, 1_000, "us");
    }
    if nanos < 1_000_000_000 {
        return format_duration_unit(nanos, 1_000_000, "ms");
    }
    format_duration_unit(nanos, 1_000_000_000, "s")
}

pub(crate) fn parse_duration_interval(value: &str) -> Option<Duration> {
    let mut rest = value.trim();
    if rest.is_empty() || rest.starts_with('-') {
        return None;
    }
    rest = rest.strip_prefix('+').unwrap_or(rest);
    if rest.is_empty() {
        return None;
    }

    let mut total = 0u128;
    while !rest.is_empty() {
        let (nanos, next) = parse_duration_part(rest)?;
        total = total.checked_add(nanos)?;
        rest = next;
    }

    u64::try_from(total).ok().map(Duration::from_nanos)
}

fn parse_duration_part(value: &str) -> Option<(u128, &str)> {
    let whole_len = value
        .bytes()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    let mut rest = &value[whole_len..];
    let whole = if whole_len == 0 {
        0
    } else {
        value[..whole_len].parse::<u128>().ok()?
    };

    let mut fraction = 0u128;
    let mut scale = 1u128;
    if let Some(after_dot) = rest.strip_prefix('.') {
        let frac_len = after_dot
            .bytes()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if whole_len == 0 && frac_len == 0 {
            return None;
        }
        for byte in after_dot[..frac_len].bytes() {
            fraction = fraction
                .checked_mul(10)?
                .checked_add(u128::from(byte - b'0'))?;
            scale = scale.checked_mul(10)?;
        }
        rest = &after_dot[frac_len..];
    } else if whole_len == 0 {
        return None;
    }

    let (unit, multiplier) = duration_unit(rest)?;
    rest = &rest[unit.len()..];
    let nanos = whole
        .checked_mul(multiplier)?
        .checked_add(fraction.checked_mul(multiplier)?.checked_div(scale)?)?;

    Some((nanos, rest))
}

fn duration_unit(value: &str) -> Option<(&'static str, u128)> {
    for (unit, nanos) in [
        ("ms", NANOS_PER_MILLI),
        ("us", NANOS_PER_MICRO),
        ("\u{00B5}s", NANOS_PER_MICRO),
        ("\u{03BC}s", NANOS_PER_MICRO),
        ("ns", 1),
        ("d", NANOS_PER_DAY),
        ("h", NANOS_PER_HOUR),
        ("m", NANOS_PER_MINUTE),
        ("s", NANOS_PER_SECOND),
    ] {
        if value.starts_with(unit) {
            return Some((unit, nanos));
        }
    }
    None
}

fn min_timeout(left: Option<Duration>, right: Option<Duration>) -> Option<Duration> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(left), None) => Some(left),
        (None, right) => right,
    }
}

fn is_timeout_error(err: &FetchError) -> bool {
    match err {
        FetchError::Message(message) | FetchError::Runtime(message) => {
            message.contains("timed out")
        }
        FetchError::Transport(err) => err.is_timeout(),
        _ => false,
    }
}

fn format_duration_unit(nanos: u128, unit_nanos: u128, suffix: &str) -> String {
    let whole = nanos / unit_nanos;
    let remainder = nanos % unit_nanos;
    if remainder == 0 {
        return format!("{whole}{suffix}");
    }

    let digits = match suffix {
        "us" => 3_u32,
        "ms" => 6_u32,
        _ => 9_u32,
    };
    let scale = 10_u128.pow(digits);
    let fraction_value = remainder * scale / unit_nanos;
    let fraction = format!(
        "{fraction_value:0width$}",
        width = usize::try_from(digits).expect("small duration precision")
    );
    let fraction = fraction.trim_end_matches('0');
    format!("{whole}.{fraction}{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fractional_positive_and_day_durations() {
        assert_eq!(
            parse_duration_interval("1.5h"),
            Some(Duration::from_secs(90 * 60))
        );
        assert_eq!(
            parse_duration_interval("+30m"),
            Some(Duration::from_secs(30 * 60))
        );
        assert_eq!(
            parse_duration_interval("1d"),
            Some(Duration::from_secs(24 * 60 * 60))
        );
    }

    #[test]
    fn parses_compound_and_subsecond_durations() {
        assert_eq!(
            parse_duration_interval("1h30m"),
            Some(Duration::from_secs(90 * 60))
        );
        assert_eq!(
            parse_duration_interval(".5s"),
            Some(Duration::from_millis(500))
        );
        assert_eq!(
            parse_duration_interval("250ms"),
            Some(Duration::from_millis(250))
        );
        assert_eq!(
            parse_duration_interval("1.5ms"),
            Some(Duration::from_micros(1500))
        );
    }

    #[test]
    fn rejects_invalid_or_negative_durations() {
        assert_eq!(parse_duration_interval(""), None);
        assert_eq!(parse_duration_interval("+"), None);
        assert_eq!(parse_duration_interval("0"), None);
        assert_eq!(parse_duration_interval("-1h"), None);
        assert_eq!(parse_duration_interval("1sec"), None);
        assert_eq!(parse_duration_interval("garbage"), None);
    }

    #[test]
    fn duration_from_seconds_handles_zero_as_no_timeout() {
        // 0 means "no timeout" (curl-compatible)
        assert_eq!(duration_from_seconds("timeout", 0.0).unwrap(), None);
        assert_eq!(duration_from_seconds("connect-timeout", 0.0).unwrap(), None);

        // Non-zero values still produce a duration
        assert_eq!(
            duration_from_seconds("timeout", 1.5).unwrap(),
            Some(Duration::from_millis(1500))
        );
    }

    #[test]
    fn duration_from_seconds_rejects_values_outside_supported_range() {
        assert_eq!(
            duration_from_seconds("timeout", 1.5).unwrap(),
            Some(Duration::from_millis(1500))
        );

        for seconds in [-1.0, f64::NAN, f64::INFINITY, 1e100] {
            let err = duration_from_seconds("timeout", seconds).unwrap_err();
            assert_eq!(
                err.to_string(),
                format!(
                    "invalid value '{seconds}' for option '--timeout': must be a non-negative number"
                )
            );
        }
    }

    #[test]
    fn timeout_budget_for_connect_uses_shortest_available_timeout() {
        let budget = TimeoutBudget::for_connect(
            Some(Duration::from_secs(5)),
            Some(Duration::from_millis(250)),
            Instant::now() - Duration::from_millis(100),
        )
        .unwrap();
        let remaining = budget.remaining().unwrap().unwrap();

        assert!(remaining <= Duration::from_millis(150));
        assert!(remaining > Duration::from_millis(100));

        let budget = TimeoutBudget::for_connect(
            Some(Duration::from_millis(250)),
            Some(Duration::from_secs(5)),
            Instant::now(),
        )
        .unwrap();
        assert!(budget.timeout().unwrap() <= Duration::from_millis(250));
    }

    #[test]
    fn remaining_timeout_reports_expired_request_budget() {
        let err = remaining_timeout(
            Some(Duration::from_millis(10)),
            Instant::now() - Duration::from_millis(20),
        )
        .unwrap_err();

        assert_eq!(err.to_string(), "request timed out after 10ms");
    }

    #[test]
    fn request_timeout_message_uses_go_duration_units() {
        assert_eq!(
            request_timeout_message(Duration::from_nanos(100)),
            "request timed out after 100ns"
        );
        assert_eq!(
            request_timeout_message(Duration::from_millis(50)),
            "request timed out after 50ms"
        );
    }

    #[test]
    fn format_go_duration_matches_common_go_units() {
        assert_eq!(format_go_duration(Duration::from_nanos(100)), "100ns");
        assert_eq!(format_go_duration(Duration::from_nanos(1_500)), "1.5us");
        assert_eq!(format_go_duration(Duration::from_nanos(1_500_000)), "1.5ms");
        assert_eq!(
            format_go_duration(Duration::from_nanos(1_500_000_000)),
            "1.5s"
        );
    }
}
