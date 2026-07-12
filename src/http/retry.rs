use super::*;

pub(super) const MAX_PROTOCOL_NACK_RETRIES: usize = 2;

pub(super) fn redirect_requires_client_refresh(
    cli: &Cli,
    http_version: Option<HttpVersion>,
    current: &Url,
    next: &Url,
) -> bool {
    if url_client_endpoint(current) == url_client_endpoint(next) {
        return false;
    }
    if cli.unix.is_some() {
        return false;
    }
    if client::effective_proxy_for_url(cli.proxy.as_deref(), http_version, next)
        .ok()
        .flatten()
        .is_some_and(|proxy| !proxy.uses_local_target_dns())
    {
        return false;
    }
    cli.dns_server.is_some()
        || matches!(http_version, Some(HttpVersion::Http3))
        || cli.timing
        || (cli.verbose >= 3 && !cli.silent)
}

pub(super) fn url_client_endpoint(url: &Url) -> Option<(&str, &str, Option<u16>)> {
    Some((url.scheme(), url.host_str()?, url.port_or_known_default()))
}

pub(super) fn should_retry_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::TOO_MANY_REQUESTS
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

pub(super) fn parse_retry_after(headers: &HeaderMap) -> Duration {
    let Some(value) = headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
    else {
        return Duration::ZERO;
    };

    if let Ok(seconds) = value.parse::<i64>() {
        if seconds <= 0 {
            return Duration::ZERO;
        }
        return Duration::from_secs(seconds as u64);
    }

    let Ok(time) = httpdate::parse_http_date(value) else {
        return Duration::ZERO;
    };
    time.duration_since(SystemTime::now())
        .unwrap_or(Duration::ZERO)
}

pub(super) fn is_retryable_error(err: &transport::Error) -> bool {
    if is_certificate_validation_error(err) {
        return false;
    }
    err.is_timeout() || err.is_connect()
}

pub(super) fn is_protocol_nack_error(err: &transport::Error) -> bool {
    let mut source = err.source();
    while let Some(err) = source {
        if err
            .downcast_ref::<h2::Error>()
            .is_some_and(is_h2_protocol_nack)
        {
            return true;
        }
        if err
            .downcast_ref::<h3::error::ConnectionError>()
            .is_some_and(is_h3_protocol_nack)
        {
            return true;
        }
        source = err.source();
    }
    false
}

fn is_h2_protocol_nack(err: &h2::Error) -> bool {
    (err.is_go_away() && err.is_remote() && err.reason() == Some(h2::Reason::NO_ERROR))
        || (err.is_reset() && err.is_remote() && err.reason() == Some(h2::Reason::REFUSED_STREAM))
}

fn is_h3_protocol_nack(err: &h3::error::ConnectionError) -> bool {
    err.to_string() == "timeout"
}

#[derive(Debug)]
pub(super) struct RedirectLimitError {
    max: usize,
}

impl fmt::Display for RedirectLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "exceeded maximum number of redirects: {}", self.max)
    }
}

impl StdError for RedirectLimitError {}

pub(super) fn redirect_target(
    cli: &Cli,
    response: &Response,
    redirect_count: usize,
) -> Result<Option<Url>, FetchError> {
    if cli.redirects == Some(0) || !is_redirect_status(response.status()) {
        return Ok(None);
    }
    let Some(location) = response.headers().get(LOCATION) else {
        return Ok(None);
    };
    let location = location
        .to_str()
        .map_err(|err| FetchError::Runtime(format!("invalid redirect location: {err}")))?;
    let max = cli.redirects.unwrap_or(10);
    if redirect_count >= max {
        return Err(FetchError::Runtime(RedirectLimitError { max }.to_string()));
    }
    let url = response
        .url()
        .join(location)
        .map_err(|err| FetchError::Runtime(format!("invalid redirect location: {err}")))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(FetchError::Runtime(format!(
            "unsupported redirect scheme '{}'",
            url.scheme()
        )));
    }
    Ok(Some(url))
}

pub(super) fn is_redirect_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

pub(super) fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str()
            .zip(b.host_str())
            .is_some_and(|(a_host, b_host)| a_host.eq_ignore_ascii_case(b_host))
        && a.port_or_known_default() == b.port_or_known_default()
}

pub(super) fn strip_cross_origin_sensitive_headers(headers: &mut HeaderMap) {
    headers.remove(AUTHORIZATION);
    headers.remove(COOKIE);
    headers.remove(PROXY_AUTHORIZATION);
}

pub(super) fn strip_entity_headers_for_bodyless_redirect(headers: &mut HeaderMap) {
    headers.remove(CONTENT_TYPE);
    headers.remove(CONTENT_LENGTH);
    headers.remove(TRANSFER_ENCODING);
}

pub(super) struct RedirectedRequest {
    pub(super) method: Method,
    pub(super) body: RequestBody,
    pub(super) strip_entity_headers: bool,
}

pub(super) fn redirected_request(
    mut method: Method,
    mut body: RequestBody,
    status: StatusCode,
) -> Result<RedirectedRequest, FetchError> {
    let mut strip_entity_headers = false;
    match status {
        StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND if method == Method::POST => {
            method = Method::GET;
            body = None;
            strip_entity_headers = true;
        }
        StatusCode::SEE_OTHER => {
            if method != Method::HEAD {
                method = Method::GET;
            }
            body = None;
            strip_entity_headers = true;
        }
        StatusCode::MOVED_PERMANENTLY
        | StatusCode::FOUND
        | StatusCode::TEMPORARY_REDIRECT
        | StatusCode::PERMANENT_REDIRECT
            if !request_body_replayable(&body) =>
        {
            return Err(FetchError::Runtime(
                "request body from stdin cannot be replayed for redirect".to_string(),
            ));
        }
        _ => {}
    }
    Ok(RedirectedRequest {
        method,
        body,
        strip_entity_headers,
    })
}

pub(super) fn request_body_replayable(body: &RequestBody) -> bool {
    body.as_ref()
        .is_none_or(|body| !request_body_source_uses_stdin(&body.source))
}

pub(super) fn request_body_source_uses_stdin(source: &RequestBodySource) -> bool {
    match source {
        RequestBodySource::Stdin => true,
        RequestBodySource::GrpcJsonStream { source, .. } => request_body_source_uses_stdin(source),
        RequestBodySource::Bytes(_)
        | RequestBodySource::File { .. }
        | RequestBodySource::Multipart(_) => false,
    }
}

pub(super) fn ensure_request_body_replayable(
    body: &RequestBody,
    action: &str,
) -> Result<(), FetchError> {
    ensure_body_replayable(request_body_replayable(body), action)
}

pub(super) fn ensure_body_replayable(replayable: bool, action: &str) -> Result<(), FetchError> {
    if replayable {
        return Ok(());
    }
    Err(FetchError::Runtime(format!(
        "request body from stdin cannot be replayed for {action}"
    )))
}

pub(super) fn print_redirect_status(cli: &Cli, response: &Response) {
    if cli.verbose < 2 || cli.silent {
        return;
    }
    let status = response.status();
    let mut printer = core::Printer::stderr(cli.color.as_deref());
    printer.write_response_prefix();
    printer.write_styled(version_label(response.version()), &[core::Sequence::Dim]);
    printer.push_str(" ");
    let status_color = color_for_status(status.as_u16());
    printer.write_styled(
        &status.as_u16().to_string(),
        &[status_color, core::Sequence::Bold],
    );
    let reason = status.canonical_reason().unwrap_or("");
    if !reason.is_empty() {
        printer.push_str(" ");
        printer.write_styled(reason, &[status_color]);
    }
    printer.push_str("\n");
    core::flush_stderr(printer);
}

pub(super) fn timeout_error_message(cli: &Cli, err: &transport::Error) -> Option<String> {
    if !err.is_timeout() {
        return None;
    }
    let seconds = cli.timeout?;
    let duration = duration_from_seconds("timeout", seconds).ok().flatten()?;
    Some(request_timeout_message(duration))
}

pub(super) fn transport_request_error_message(err: &transport::Error) -> String {
    let mut message = err.to_string();
    let mut source = err.source();
    while let Some(err) = source {
        let source_message = go_style_transport_source_message(&err.to_string());
        if !source_message.is_empty() && !message.contains(&source_message) {
            message.push_str(": ");
            message.push_str(&source_message);
        }
        source = err.source();
    }
    message
}

pub(super) fn append_schemeless_plaintext_hint(
    message: &mut String,
    cli: &Cli,
    original_url: &Url,
    request_url: &Url,
    err: &transport::Error,
) {
    if !err.is_connect()
        || url_client_endpoint(original_url) != url_client_endpoint(request_url)
        || is_certificate_validation_error(err)
    {
        return;
    }

    let Some(raw_url) = cli.url.as_deref() else {
        return;
    };
    let Some(plaintext_url) = schemeless_plaintext_hint_url(raw_url, request_url) else {
        return;
    };
    message.push('\n');
    message.push_str("If this is a plaintext service, use ");
    message.push_str(&plaintext_url);
    message.push('.');
}

pub(super) fn transport_response_body_error_message(err: &transport::Error) -> String {
    let mut details = Vec::new();
    let mut source = err.source();
    while let Some(err) = source {
        let source_message = go_style_transport_source_message(&err.to_string());
        if !source_message.is_empty()
            && source_message != "request or response body error"
            && !details.contains(&source_message)
        {
            details.push(source_message);
        }
        source = err.source();
    }

    let transport_message = err.to_string();
    if details.is_empty() && transport_message != "request or response body error" {
        details.push(transport_message);
    }

    if details.is_empty() {
        "response body error".to_string()
    } else {
        format!("response body error: {}", details.join(": "))
    }
}

pub(super) fn go_style_transport_source_message(message: &str) -> String {
    let lower = message.to_ascii_lowercase();
    if !lower.contains("tls")
        && (lower.contains("protocolversion")
            || lower.contains("certificate")
            || lower.contains("rustls"))
    {
        format!("tls: {message}")
    } else {
        message.to_string()
    }
}

pub(super) fn is_certificate_validation_error(err: &transport::Error) -> bool {
    if is_certificate_validation_message(&err.to_string()) {
        return true;
    }

    let mut source = err.source();
    while let Some(err) = source {
        if is_certificate_validation_message(&err.to_string()) {
            return true;
        }
        source = err.source();
    }

    false
}

pub(crate) fn is_certificate_validation_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("hostnameerror")
        || (lower.contains("certificate")
            && (lower.contains("unknownissuer")
                || lower.contains("unknown issuer")
                || lower.contains("unknown authority")
                || lower.contains("invalid peer certificate")
                || lower.contains("certificateverifyfailed")
                || lower.contains("certificate verify failed")
                || lower.contains("not valid")
                || lower.contains("notvalid")
                || lower.contains("expired")
                || lower.contains("hostname")))
}

pub(super) fn retry_reason(status: StatusCode) -> String {
    format!(
        "{} {}",
        status.as_u16(),
        status.canonical_reason().unwrap_or("")
    )
}

pub(super) fn compute_delay(
    initial_delay: Duration,
    attempt: usize,
    retry_after: Duration,
) -> Duration {
    let mut delay = if initial_delay.is_zero() {
        Duration::from_secs(1)
    } else {
        initial_delay
    };

    for _ in 0..attempt {
        delay = delay.saturating_mul(2);
        if delay > Duration::from_secs(30) {
            delay = Duration::from_secs(30);
            break;
        }
    }

    let jitter = delay.as_secs_f64() * 0.25;
    let jittered = delay.as_secs_f64() + rand::random_range(-jitter..=jitter);
    let delay = Duration::from_secs_f64(jittered.max(0.0));

    delay.max(retry_after)
}

pub(super) fn retry_delay_within_timeout(
    delay: Duration,
    request_timeout: Option<Duration>,
    request_start: Instant,
) -> Result<Duration, FetchError> {
    let Some(remaining) = TimeoutBudget::started_at(request_timeout, request_start).remaining()?
    else {
        return Ok(delay);
    };
    Ok(delay.min(remaining))
}

pub(super) fn ensure_retry_delay_completed(
    requested_delay: Duration,
    actual_delay: Duration,
    request_timeout: Option<Duration>,
    request_start: Instant,
) -> Result<(), FetchError> {
    if actual_delay < requested_delay {
        return Err(TimeoutBudget::started_at(request_timeout, request_start).timeout_error());
    }
    TimeoutBudget::started_at(request_timeout, request_start)
        .remaining()
        .map(|_| ())
}

pub(super) fn print_retry(
    cli: &Cli,
    next_attempt: usize,
    total_attempts: usize,
    delay: Duration,
    reason: &str,
) {
    if cli.silent {
        return;
    }

    let mut printer = core::Printer::stderr(cli.color.as_deref());
    write_retry_to(
        &mut printer,
        cli.verbose,
        next_attempt,
        total_attempts,
        delay,
        reason,
    );
    core::flush_stderr(printer);
}

fn write_retry_to(
    printer: &mut core::Printer,
    verbosity: u8,
    next_attempt: usize,
    total_attempts: usize,
    delay: Duration,
    reason: &str,
) {
    if verbosity >= 2 {
        printer.write_info_prefix();
    }
    let delay = format_delay(delay);
    core::write_status_line_no_flush(
        printer,
        format_args!("retry: attempt {next_attempt}/{total_attempts} in {delay} ({reason})"),
    );
}

pub(super) fn format_delay(delay: Duration) -> String {
    if delay < Duration::from_millis(1) {
        return "0s".to_string();
    }
    if delay < Duration::from_secs(1) {
        return format!("{:.0}ms", delay.as_secs_f64() * 1000.0);
    }
    format!("{:.1}s", delay.as_secs_f64())
}

pub(crate) fn total_attempts_for_retry(retry_count: usize) -> Result<usize, FetchError> {
    retry_count.checked_add(1).ok_or_else(|| {
        FetchError::invalid_value(
            "--retry",
            retry_count.to_string(),
            "must be less than the maximum usize value",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_body() -> RequestBody {
        Some(RequestBodyPayload::from_bytes(
            b"payload".to_vec(),
            Some("text/plain".to_string()),
        ))
    }

    #[test]
    fn redirect_method_and_body_semantics() {
        for status in [StatusCode::MOVED_PERMANENTLY, StatusCode::FOUND] {
            let redirected = redirected_request(Method::POST, test_body(), status).unwrap();
            assert_eq!(redirected.method, Method::GET);
            assert!(redirected.body.is_none());
            assert!(redirected.strip_entity_headers);

            for method in [Method::PUT, Method::PATCH, Method::DELETE, Method::GET] {
                let redirected = redirected_request(method.clone(), test_body(), status).unwrap();
                assert_eq!(redirected.method, method);
                assert!(redirected.body.is_some());
                assert!(!redirected.strip_entity_headers);
            }
        }

        for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            let redirected =
                redirected_request(method, test_body(), StatusCode::SEE_OTHER).unwrap();
            assert_eq!(redirected.method, Method::GET);
            assert!(redirected.body.is_none());
            assert!(redirected.strip_entity_headers);
        }
        let redirected =
            redirected_request(Method::HEAD, test_body(), StatusCode::SEE_OTHER).unwrap();
        assert_eq!(redirected.method, Method::HEAD);
        assert!(redirected.body.is_none());
        assert!(redirected.strip_entity_headers);

        for status in [
            StatusCode::TEMPORARY_REDIRECT,
            StatusCode::PERMANENT_REDIRECT,
        ] {
            for method in [
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
                Method::HEAD,
            ] {
                let redirected = redirected_request(method.clone(), test_body(), status).unwrap();
                assert_eq!(redirected.method, method);
                assert!(redirected.body.is_some());
                assert!(!redirected.strip_entity_headers);
            }
        }
    }

    #[test]
    fn redirect_rejects_stdin_when_body_must_be_preserved() {
        for status in [
            StatusCode::MOVED_PERMANENTLY,
            StatusCode::FOUND,
            StatusCode::TEMPORARY_REDIRECT,
            StatusCode::PERMANENT_REDIRECT,
        ] {
            let body = Some(RequestBodyPayload {
                source: RequestBodySource::Stdin,
                content_type: None,
            });
            let err = redirected_request(Method::PUT, body, status)
                .err()
                .expect("stdin-backed redirect should fail");
            assert!(err.to_string().contains("cannot be replayed for redirect"));
        }

        // Rewrites do not need to replay stdin.
        for status in [
            StatusCode::MOVED_PERMANENTLY,
            StatusCode::FOUND,
            StatusCode::SEE_OTHER,
        ] {
            let body = Some(RequestBodyPayload {
                source: RequestBodySource::Stdin,
                content_type: None,
            });
            let method = if status == StatusCode::SEE_OTHER {
                Method::PUT
            } else {
                Method::POST
            };
            assert!(redirected_request(method, body, status).is_ok());
        }
    }

    #[test]
    fn redirect_limit_error_matches_go_message() {
        assert_eq!(
            RedirectLimitError { max: 10 }.to_string(),
            "exceeded maximum number of redirects: 10"
        );
    }

    #[test]
    fn compute_delay_matches_go_backoff_bounds() {
        for attempt in 0..5 {
            let delay = compute_delay(Duration::from_secs(1), attempt, Duration::ZERO);
            let base = Duration::from_secs(1_u64 << attempt).min(Duration::from_secs(30));
            let min = base.mul_f64(0.75);
            let max = base.mul_f64(1.25);
            assert!(
                delay >= min && delay <= max,
                "attempt {attempt}: delay {delay:?} outside {min:?}..={max:?}"
            );
        }

        let delay = compute_delay(Duration::from_secs(1), 10, Duration::ZERO);
        assert!(delay <= Duration::from_secs(30).mul_f64(1.25));

        let retry_after = Duration::from_secs(60);
        let delay = compute_delay(Duration::from_secs(1), 0, retry_after);
        assert!(delay >= retry_after);

        let delay = compute_delay(Duration::ZERO, 0, Duration::ZERO);
        assert!(delay >= Duration::from_millis(750));
        assert!(delay <= Duration::from_millis(1250));
    }

    #[test]
    fn format_delay_matches_go_retry_output() {
        assert_eq!(format_delay(Duration::from_micros(500)), "0s");
        assert_eq!(format_delay(Duration::from_millis(250)), "250ms");
        assert_eq!(format_delay(Duration::from_millis(2500)), "2.5s");
        assert_eq!(format_delay(Duration::from_secs(1)), "1.0s");
    }

    #[test]
    fn retry_status_renders_through_printer() {
        let mut printer = core::Printer::new(false);
        write_retry_to(
            &mut printer,
            0,
            2,
            3,
            Duration::from_millis(250),
            "HTTP 503",
        );

        assert_eq!(
            printer.into_string().unwrap(),
            "retry: attempt 2/3 in 250ms (HTTP 503)\n"
        );
    }

    #[test]
    fn retry_debug_prefix_uses_printer_styling() {
        let mut printer = core::Printer::new(true);
        write_retry_to(
            &mut printer,
            2,
            2,
            3,
            Duration::from_secs(1),
            "connection failed",
        );

        assert_eq!(
            printer.into_string().unwrap(),
            "\x1b[2m* \x1b[0mretry: attempt 2/3 in 1.0s (connection failed)\n"
        );
    }

    #[test]
    fn total_attempts_for_retry_rejects_overflow() {
        assert_eq!(total_attempts_for_retry(0).unwrap(), 1);
        assert_eq!(total_attempts_for_retry(3).unwrap(), 4);

        let err = total_attempts_for_retry(usize::MAX).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "invalid value '{}' for option '--retry': must be less than the maximum usize value",
                usize::MAX
            )
        );
    }

    #[test]
    fn parse_retry_after_matches_go_integer_and_date_cases() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("5"));
        assert_eq!(parse_retry_after(&headers), Duration::from_secs(5));

        headers.insert(RETRY_AFTER, HeaderValue::from_static("0"));
        assert_eq!(parse_retry_after(&headers), Duration::ZERO);

        headers.insert(RETRY_AFTER, HeaderValue::from_static("-5"));
        assert_eq!(parse_retry_after(&headers), Duration::ZERO);

        headers.insert(RETRY_AFTER, HeaderValue::from_static("not-a-number"));
        assert_eq!(parse_retry_after(&headers), Duration::ZERO);

        let future = SystemTime::now() + Duration::from_secs(10);
        let future = httpdate::fmt_http_date(future);
        headers.insert(RETRY_AFTER, HeaderValue::from_str(&future).unwrap());
        let parsed = parse_retry_after(&headers);
        assert!(parsed >= Duration::from_secs(8), "parsed {parsed:?}");
        assert!(parsed <= Duration::from_secs(12), "parsed {parsed:?}");

        assert_eq!(parse_retry_after(&HeaderMap::new()), Duration::ZERO);
    }

    #[test]
    fn should_retry_status_matches_go_status_table() {
        for status in [
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            assert!(should_retry_status(status), "{status} should be retryable");
        }

        for status in [
            StatusCode::OK,
            StatusCode::BAD_REQUEST,
            StatusCode::NOT_FOUND,
        ] {
            assert!(
                !should_retry_status(status),
                "{status} should not be retryable"
            );
        }
    }

    #[test]
    fn transport_tls_source_messages_keep_go_style_tls_hint() {
        assert_eq!(
            go_style_transport_source_message("received fatal alert: ProtocolVersion"),
            "tls: received fatal alert: ProtocolVersion"
        );
        assert_eq!(
            go_style_transport_source_message("invalid peer certificate: UnknownIssuer"),
            "tls: invalid peer certificate: UnknownIssuer"
        );
        assert_eq!(
            go_style_transport_source_message("tls: handshake failure"),
            "tls: handshake failure"
        );
    }

    #[test]
    fn certificate_validation_messages_match_go_error_classes() {
        for message in [
            "invalid peer certificate: UnknownIssuer",
            "invalid peer certificate: NotValidForName",
            "x509: certificate signed by unknown authority",
            "certificate verify failed",
            "certificate has expired",
            "x509: certificate is not valid for any names",
            "x509: HostnameError",
        ] {
            assert!(
                is_certificate_validation_message(message),
                "{message} should be treated as certificate validation"
            );
        }

        for message in [
            "received fatal alert: ProtocolVersion",
            "tls: handshake failure",
            "connection refused",
        ] {
            assert!(
                !is_certificate_validation_message(message),
                "{message} should not be treated as certificate validation"
            );
        }
    }
}
