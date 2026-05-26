use std::time::Duration;

const NANOS_PER_MICRO: u128 = 1_000;
const NANOS_PER_MILLI: u128 = 1_000_000;
const NANOS_PER_SECOND: u128 = 1_000_000_000;
const NANOS_PER_MINUTE: u128 = 60 * NANOS_PER_SECOND;
const NANOS_PER_HOUR: u128 = 60 * NANOS_PER_MINUTE;
const NANOS_PER_DAY: u128 = 24 * NANOS_PER_HOUR;

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
}
