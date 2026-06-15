use super::*;

use std::collections::HashSet;
use std::net::IpAddr;

pub(crate) fn load_session(cli: &Cli) -> Result<Option<crate::session::Session>, FetchError> {
    let Some(name) = cli.session.as_deref() else {
        return Ok(None);
    };
    let loaded =
        crate::session::Session::load(name).map_err(|err| FetchError::Message(err.to_string()))?;
    if let Some(warning) = loaded.warning {
        write_warning_before_output(
            cli,
            &format!("session '{name}' is corrupted, starting fresh: {warning}"),
        );
    }
    Ok(Some(loaded.session))
}

pub(crate) fn save_session(cli: &Cli, session: Option<&crate::session::Session>) {
    let Some(session) = session else {
        return;
    };
    if let Err(err) = session.save() {
        write_warning(
            cli,
            &format!("unable to save session '{}': {err}", session.name()),
        );
    }
}

pub(super) fn write_warning(cli: &Cli, message: &str) {
    if !cli.silent {
        write_warning_with_color(message, cli.color.as_deref());
    }
}

pub(super) fn write_warning_before_output(cli: &Cli, message: &str) {
    if !cli.silent {
        write_warning_with_separator_with_color(message, cli.color.as_deref());
    }
}

pub(super) fn effective_method(cli: &Cli) -> &str {
    if cli.method.is_some() {
        cli.method()
    } else if cli.grpc || has_request_body_flag(cli) {
        "POST"
    } else {
        cli.method()
    }
}

fn has_request_body_flag(cli: &Cli) -> bool {
    cli.data.is_some()
        || cli.json.is_some()
        || cli.xml.is_some()
        || !cli.form.is_empty()
        || !cli.multipart.is_empty()
        || cli.edit
}

pub(super) fn effective_http_version(
    cli: &Cli,
    version: Option<HttpVersion>,
) -> Option<HttpVersion> {
    if cli.grpc && version.is_none() {
        Some(HttpVersion::Http2)
    } else {
        version
    }
}

pub(super) fn print_dns_debug(cli: &Cli, dns: &DnsTiming) {
    let mut printer = core::stdio().stderr_printer(cli.color.as_deref());
    timing::render_dns_debug_to(dns, &mut printer);
    let _ = printer.flush_to(&mut std::io::stderr());
}

pub(super) fn connect_debug_target(
    response: &Response,
    url: &Url,
    dns_resolution: Option<&DnsResolution>,
) -> String {
    if let Some(addr) = response.remote_addr() {
        return addr.to_string();
    }
    if let Some(addr) = dns_resolution.and_then(|resolution| resolution.socket_addrs.first()) {
        return addr.to_string();
    }
    url.host_str()
        .map(|host| {
            if let Some(port) = url.port() {
                format!("{host}:{port}")
            } else {
                host.to_string()
            }
        })
        .unwrap_or_default()
}

pub(super) fn print_request_metadata(
    cli: &Cli,
    method: &Method,
    url: &Url,
    headers: &HeaderMap,
    body: &RequestBody,
    http_version: Option<HttpVersion>,
) -> Result<(), FetchError> {
    let mut printer = core::Printer::stderr(cli.color.as_deref());
    let debug = cli.verbose >= 2;
    if debug {
        printer.write_request_prefix();
    }
    printer.write_styled(
        method.as_str(),
        &[core::Sequence::Bold, core::Sequence::Yellow],
    );
    printer.push_str(" ");
    write_request_target(&mut printer, url);
    printer.push_str(" ");
    printer.write_styled(request_protocol_label(http_version), &[core::Sequence::Dim]);
    printer.push_str("\n");
    let mut lines = header_lines(headers);
    lines.retain(|(name, _)| !name.eq_ignore_ascii_case("host"));
    if let Some(len) = inferred_request_body_content_len(headers, body)? {
        lines.push(("content-length".to_string(), len.to_string()));
    }
    let host = headers
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
        .or_else(|| crate::net::http_host_header_value(url).ok());
    if let Some(host) = host {
        lines.push(("host".to_string(), host));
    }
    if cli.sort_headers {
        sort_header_lines(&mut lines);
    }

    for (name, value) in lines {
        if debug {
            printer.write_request_prefix();
        }
        printer.write_styled(&name, &[core::Sequence::Bold, core::Sequence::Blue]);
        printer.push_str(": ");
        printer.push_str(&value);
        printer.push_str("\n");
    }
    if debug {
        printer.write_request_prefix();
        printer.push_str("\n");
    }
    flush_stderr(printer);
    Ok(())
}

pub(super) fn is_printable(bytes: &[u8]) -> bool {
    core::bytes_appear_printable(bytes)
}

pub(super) fn request_protocol_label(version: Option<HttpVersion>) -> &'static str {
    version.map(HttpVersion::label).unwrap_or("HTTP/1.1")
}

pub(super) fn write_request_target(printer: &mut core::Printer, url: &Url) {
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    printer.write_styled(path, &[core::Sequence::Bold, core::Sequence::Cyan]);
    if let Some(query) = url.query() {
        printer.write_styled("?", &[core::Sequence::Italic, core::Sequence::Cyan]);
        printer.write_styled(query, &[core::Sequence::Italic, core::Sequence::Cyan]);
    }
}

pub(super) fn header_lines(headers: &HeaderMap) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (name, value) in headers {
        if let Ok(value) = value.to_str() {
            out.push((name.as_str().to_ascii_lowercase(), value.to_string()));
        }
    }
    out
}

pub(super) fn sort_header_lines(lines: &mut [(String, String)]) {
    lines.sort_by(
        |(left, _), (right, _)| match (left.starts_with(':'), right.starts_with(':')) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => left.cmp(right),
        },
    );
}

pub(super) fn validate_http_version_options(
    version: Option<HttpVersion>,
    url: &Url,
    allow_h2c: bool,
    unix_socket: Option<&str>,
) -> Result<(), FetchError> {
    match version {
        Some(HttpVersion::Http2) if url.scheme() == "http" && !allow_h2c => {
            Err("http2: unsupported scheme".into())
        }
        Some(HttpVersion::Http3) if unix_socket.is_some() => {
            Err("cannot use a unix socket with HTTP/3.0".into())
        }
        Some(HttpVersion::Http3) if url.scheme() != "https" => {
            Err(format!("http3: unsupported protocol scheme: {}", url.scheme()).into())
        }
        _ => Ok(()),
    }
}

pub(super) fn flush_stderr(mut printer: core::Printer) {
    let mut stderr = std::io::stderr();
    let _ = printer.flush_to(&mut stderr);
}

pub(super) fn color_for_status(code: u16) -> core::Sequence {
    match code {
        200..=299 => core::Sequence::Green,
        300..=399 => core::Sequence::Yellow,
        _ => core::Sequence::Red,
    }
}

pub(crate) fn request_target(url: &Url) -> String {
    let mut target = if url.path().is_empty() {
        "/".to_string()
    } else {
        url.path().to_string()
    };
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }
    target
}

pub(crate) fn normalize_url(raw: &str) -> Result<Url, FetchError> {
    if raw.is_empty() {
        return Err("empty URL provided".into());
    }

    if has_authority_scheme(raw) {
        normalize_explicit_url(Url::parse(raw)?)
    } else {
        normalize_schemeless_url(raw)
    }
}

pub(crate) fn has_authority_scheme(raw: &str) -> bool {
    let Some(colon) = raw.find(':') else {
        return false;
    };
    let first_url_delimiter = raw.find(['/', '?', '#']).unwrap_or(raw.len());
    if colon > first_url_delimiter {
        return false;
    }
    let scheme = &raw[..colon];
    !scheme.is_empty()
        && scheme
            .bytes()
            .enumerate()
            .all(|(index, byte)| is_scheme_byte(byte, index == 0))
        && raw[colon + 1..].starts_with("//")
}

fn is_scheme_byte(byte: u8, first: bool) -> bool {
    byte.is_ascii_alphabetic()
        || (!first && (byte.is_ascii_digit() || matches!(byte, b'+' | b'-' | b'.')))
}

fn normalize_explicit_url(url: Url) -> Result<Url, FetchError> {
    match url.scheme() {
        "http" | "https" => Ok(url),
        "ws" => rewrite_url_scheme(url, "http"),
        "wss" => rewrite_url_scheme(url, "https"),
        scheme => Err(format!("unsupported url scheme: {scheme}").into()),
    }
}

fn normalize_schemeless_url(raw: &str) -> Result<Url, FetchError> {
    let probe = Url::parse(&format!("http://{raw}"))?;
    let scheme = if probe.host_str().is_some_and(defaults_to_http) {
        "http"
    } else {
        "https"
    };
    Url::parse(&format!("{scheme}://{raw}")).map_err(Into::into)
}

pub(super) fn rewrite_url_scheme(mut url: Url, scheme: &str) -> Result<Url, FetchError> {
    let original = url.scheme().to_string();
    url.set_scheme(scheme)
        .map_err(|_| FetchError::Message(format!("unsupported url scheme: {original}")))?;
    Ok(url)
}

pub(super) fn grpc_request_requires_schema(cli: &Cli) -> bool {
    cli.json.is_some()
}

pub(super) fn is_loopback(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

fn defaults_to_http(host: &str) -> bool {
    is_loopback(host) || ip_literal(host).is_some()
}

fn ip_literal(host: &str) -> Option<IpAddr> {
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    host.parse::<IpAddr>().ok()
}

pub(crate) fn apply_query(url: &mut Url, query: &[String]) {
    if query.is_empty() {
        return;
    }

    let mut pairs = url.query_pairs_mut();
    for raw in query {
        let (key, val) = raw.split_once('=').unwrap_or((raw, ""));
        pairs.append_pair(key.trim(), val);
    }
}

pub(crate) fn apply_headers(headers: &mut HeaderMap, values: &[String]) -> Result<(), FetchError> {
    let mut seen = HashSet::new();
    for raw in values {
        let Some((key, val)) = raw.split_once(':') else {
            return Err(FetchError::Message(format!(
                "invalid value '{raw}' for option '--header': must be in the format NAME:VALUE with a valid non-empty header name"
            )));
        };
        let key = key.trim();
        if key.is_empty() {
            return Err(FetchError::Message(format!(
                "invalid value '{raw}' for option '--header': must be in the format NAME:VALUE with a valid non-empty header name"
            )));
        }
        let name = HeaderName::from_bytes(key.as_bytes()).map_err(|_| {
            FetchError::Message(format!(
                "invalid value '{raw}' for option '--header': must be in the format NAME:VALUE with a valid non-empty header name"
            ))
        })?;
        let value = HeaderValue::from_str(val.trim()).map_err(|err| {
            FetchError::Message(format!("invalid header value for '{key}': {err}"))
        })?;
        if seen.insert(name.clone()) {
            headers.remove(&name);
        }
        headers.append(name, value);
    }
    Ok(())
}

pub(super) fn version_label(version: http::Version) -> &'static str {
    match version {
        http::Version::HTTP_09 => "HTTP/0.9",
        http::Version::HTTP_10 => "HTTP/1.0",
        http::Version::HTTP_11 => "HTTP/1.1",
        http::Version::HTTP_2 => "HTTP/2.0",
        http::Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use clap::Parser;

    #[test]
    fn default_scheme_loopback_is_http() {
        let url = normalize_url("localhost:3000/path").unwrap();
        assert_eq!(url.as_str(), "http://localhost:3000/path");
    }

    #[test]
    fn default_scheme_loopback_ip_literals_are_http() {
        let cases = [
            ("127.0.0.1:3000/path", "http://127.0.0.1:3000/path"),
            ("127.255.255.255/path", "http://127.255.255.255/path"),
            ("[::1]/path", "http://[::1]/path"),
        ];

        for (raw, want) in cases {
            let url = normalize_url(raw).unwrap();
            assert_eq!(url.as_str(), want, "raw URL {raw}");
        }
    }

    #[test]
    fn default_scheme_ipv6_loopback_is_http_like_go_hostname() {
        let url = normalize_url("[::1]:3000/path").unwrap();
        assert_eq!(url.as_str(), "http://[::1]:3000/path");
    }

    #[test]
    fn default_scheme_loopback_with_query_is_http_like_go_hostname() {
        let url = normalize_url("LOCALHOST?debug=true").unwrap();
        assert_eq!(url.as_str(), "http://localhost/?debug=true");
    }

    #[test]
    fn default_scheme_non_loopback_is_https() {
        let url = normalize_url("example.com/path").unwrap();
        assert_eq!(url.as_str(), "https://example.com/path");
    }

    #[test]
    fn default_scheme_ip_literals_are_http() {
        let cases = [
            ("10.0.0.1/path", "http://10.0.0.1/path"),
            ("172.16.0.1/path", "http://172.16.0.1/path"),
            ("172.31.255.255/path", "http://172.31.255.255/path"),
            ("172.32.0.1/path", "http://172.32.0.1/path"),
            ("192.168.1.1:8080/path", "http://192.168.1.1:8080/path"),
            ("169.254.10.20/path", "http://169.254.10.20/path"),
            ("1.1.1.1/path", "http://1.1.1.1/path"),
            ("[fc00::1]/path", "http://[fc00::1]/path"),
            ("[fd00::1]/path", "http://[fd00::1]/path"),
            ("[fe80::1]/path", "http://[fe80::1]/path"),
            ("[2001:db8::1]/path", "http://[2001:db8::1]/path"),
            (
                "[2001:4860:4860::8888]/path",
                "http://[2001:4860:4860::8888]/path",
            ),
        ];

        for (raw, want) in cases {
            let url = normalize_url(raw).unwrap();
            assert_eq!(url.as_str(), want, "raw URL {raw}");
        }
    }

    #[test]
    fn explicit_http_and_https_schemes_are_preserved() {
        let cases = [
            ("HTTP://EXAMPLE.COM/path", "http://example.com/path"),
            (
                "https://example.com:8443/path?x=1",
                "https://example.com:8443/path?x=1",
            ),
        ];

        for (raw, want) in cases {
            let url = normalize_url(raw).unwrap();
            assert_eq!(url.as_str(), want, "raw URL {raw}");
        }
    }

    #[test]
    fn unsupported_explicit_authority_schemes_are_rejected() {
        let err = normalize_url("ftp://example.com/file").unwrap_err();
        assert_eq!(err.to_string(), "unsupported url scheme: ftp");
    }

    #[test]
    fn authority_scheme_marker_inside_path_does_not_make_url_explicit() {
        let url = normalize_url("example.com/path://still-a-path?next=http://other").unwrap();
        assert_eq!(
            url.as_str(),
            "https://example.com/path://still-a-path?next=http://other"
        );
    }

    #[test]
    fn scheme_like_host_port_input_still_uses_default_scheme() {
        let url = normalize_url("localhost:3000").unwrap();
        assert_eq!(url.as_str(), "http://localhost:3000/");
    }

    #[test]
    fn empty_url_is_rejected_before_parsing() {
        let err = normalize_url("").unwrap_err();
        assert_eq!(err.to_string(), "empty URL provided");
    }

    #[test]
    fn invalid_schemeless_url_reports_parse_error() {
        let err = normalize_url("example.com:abc").unwrap_err();
        assert!(
            err.to_string().contains("invalid port number"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn authority_scheme_detection_requires_valid_leading_scheme() {
        let cases = [
            ("http://example.com", true),
            ("wss://example.com", true),
            ("fetch+test://example.com", true),
            ("1http://example.com", false),
            ("example.com/path://segment", false),
            ("example.com?next=https://other", false),
            ("example.com#https://other", false),
            ("localhost:3000", false),
        ];

        for (raw, want) in cases {
            assert_eq!(has_authority_scheme(raw), want, "raw URL {raw}");
        }
    }

    #[test]
    fn test_is_loopback() {
        let cases = [
            ("localhost", true),
            ("LOCALHOST", true),
            ("Localhost", true),
            ("127.0.0.1", true),
            ("127.255.255.255", true),
            ("127.0.0.100", true),
            ("::1", true),
            ("[::1]", true),
            ("myserver", false),
            ("192.168.1.1", false),
            ("10.0.0.1", false),
            ("example.com", false),
            ("0.0.0.0", false),
            ("172.16.0.1", false),
            ("::2", false),
            ("2001:db8::1", false),
            ("", false),
        ];

        for (host, want) in cases {
            assert_eq!(is_loopback(host), want, "host {host}");
        }
    }

    #[test]
    fn websocket_schemes_are_rewritten_like_go_parse_url() {
        let ws = normalize_url("WS://example.com/socket").unwrap();
        let wss = normalize_url("wss://example.com/socket").unwrap();
        assert_eq!(ws.as_str(), "http://example.com/socket");
        assert_eq!(wss.as_str(), "https://example.com/socket");
    }

    #[test]
    fn method_defaults_infer_post_for_body_flags() {
        let cli = Cli::try_parse_from(["fetch", "https://example.com"]).unwrap();
        assert_eq!(cli.method(), "GET");
        assert_eq!(effective_method(&cli), "GET");

        let cli = Cli::try_parse_from(["fetch", "--method", "PUT", "https://example.com"]).unwrap();
        assert_eq!(cli.method(), "PUT");
        assert_eq!(effective_method(&cli), "PUT");

        let cli = Cli::try_parse_from([
            "fetch",
            "--method",
            "GET",
            "--json",
            "{}",
            "https://example.com",
        ])
        .unwrap();
        assert_eq!(effective_method(&cli), "GET");

        for args in [
            vec!["fetch", "--data", "body", "https://example.com"],
            vec!["fetch", "--json", "{}", "https://example.com"],
            vec!["fetch", "--xml", "<x/>", "https://example.com"],
            vec!["fetch", "--form", "a=b", "https://example.com"],
            vec!["fetch", "--multipart", "a=b", "https://example.com"],
            vec!["fetch", "--edit", "https://example.com"],
        ] {
            let cli = Cli::try_parse_from(args).unwrap();
            assert_eq!(effective_method(&cli), "POST");
        }
    }

    #[test]
    fn apply_query_appends_and_encodes_in_order() {
        let mut url = Url::parse("https://example.com/path?z=old&space=hello+world").unwrap();
        apply_query(
            &mut url,
            &[
                "a=one".to_string(),
                "z=two".to_string(),
                "blank".to_string(),
                "space=second value".to_string(),
                "spaced= hello ".to_string(),
            ],
        );

        assert_eq!(
            url.as_str(),
            "https://example.com/path?z=old&space=hello+world&a=one&z=two&blank=&space=second+value&spaced=+hello+"
        );
    }

    #[test]
    fn apply_headers_matches_go_header_flag_validation() {
        let mut headers = HeaderMap::new();
        apply_headers(
            &mut headers,
            &["X-Test: value".to_string(), "X-Empty:".to_string()],
        )
        .unwrap();
        assert_eq!(headers.get("x-test").unwrap(), "value");
        assert_eq!(headers.get("x-empty").unwrap(), "");

        let err = apply_headers(&mut HeaderMap::new(), &[": value".to_string()])
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "invalid value ': value' for option '--header': must be in the format NAME:VALUE with a valid non-empty header name"
        );

        let err = apply_headers(&mut HeaderMap::new(), &["Bad Header: value".to_string()])
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "invalid value 'Bad Header: value' for option '--header': must be in the format NAME:VALUE with a valid non-empty header name"
        );
    }

    #[test]
    fn apply_headers_appends_duplicates_after_clearing_defaults() {
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static(core::DEFAULT_ACCEPT_HEADER),
        );
        headers.insert(USER_AGENT, HeaderValue::from_static("fetch-test"));

        apply_headers(
            &mut headers,
            &[
                "Accept: application/xml".to_string(),
                "X-Test: one".to_string(),
                "Accept: application/yaml".to_string(),
                "X-Test: two".to_string(),
            ],
        )
        .unwrap();

        let accept_values = headers
            .get_all(ACCEPT)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(accept_values, ["application/xml", "application/yaml"]);

        let test_values = headers
            .get_all("x-test")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(test_values, ["one", "two"]);
        assert_eq!(headers.get(USER_AGENT).unwrap(), "fetch-test");
    }

    #[test]
    fn header_lines_preserves_header_map_order_without_grouping() {
        let mut headers = HeaderMap::new();
        headers.insert("x-zeta", HeaderValue::from_static("first"));
        headers.insert("accept", HeaderValue::from_static("second"));
        headers.append("x-zeta", HeaderValue::from_static("third"));

        assert_eq!(
            header_lines(&headers),
            [
                ("x-zeta".to_string(), "first".to_string()),
                ("x-zeta".to_string(), "third".to_string()),
                ("accept".to_string(), "second".to_string()),
            ]
        );
    }

    #[test]
    fn sort_header_lines_orders_by_name_and_preserves_duplicates() {
        let mut lines = vec![
            ("x-zeta".to_string(), "first".to_string()),
            ("accept".to_string(), "second".to_string()),
            ("x-zeta".to_string(), "third".to_string()),
            ("content-type".to_string(), "fourth".to_string()),
        ];

        sort_header_lines(&mut lines);

        assert_eq!(
            lines,
            [
                ("accept".to_string(), "second".to_string()),
                ("content-type".to_string(), "fourth".to_string()),
                ("x-zeta".to_string(), "first".to_string()),
                ("x-zeta".to_string(), "third".to_string()),
            ]
        );
    }

    #[test]
    fn request_body_printability_matches_go_heuristic() {
        assert!(is_printable(br#"{"key":"value"}"#));
        assert!(is_printable("snowman: \u{2603}\n".as_bytes()));
        assert!(!is_printable(b"abc\0def"));
        assert!(!is_printable(&[0xff, 0xfe, 0xfd, b'a']));
    }

    #[test]
    fn http2_plain_http_rejects_like_go_transport() {
        let url = Url::parse("http://127.0.0.1:3000/").unwrap();
        let err =
            validate_http_version_options(Some(HttpVersion::Http2), &url, false, None).unwrap_err();

        assert_eq!(err.to_string(), "http2: unsupported scheme");
    }

    #[test]
    fn grpc_h2c_plain_http_is_allowed_like_go() {
        let url = Url::parse("http://127.0.0.1:3000/").unwrap();

        validate_http_version_options(Some(HttpVersion::Http2), &url, true, None).unwrap();
    }

    #[test]
    fn http3_https_is_allowed_and_plain_http_rejects_like_go_transport() {
        let url = Url::parse("https://example.com/").unwrap();
        validate_http_version_options(Some(HttpVersion::Http3), &url, false, None).unwrap();

        let url = Url::parse("http://example.com/").unwrap();
        let err =
            validate_http_version_options(Some(HttpVersion::Http3), &url, false, None).unwrap_err();
        assert_eq!(err.to_string(), "http3: unsupported protocol scheme: http");
    }

    #[test]
    fn http3_rejects_unix_socket_like_go_app() {
        let url = Url::parse("https://example.com/").unwrap();
        let err = validate_http_version_options(
            Some(HttpVersion::Http3),
            &url,
            false,
            Some("/tmp/fetch.sock"),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "cannot use a unix socket with HTTP/3.0");
    }

    #[test]
    fn grpc_defaults_to_post_and_http2_like_go() {
        let cli =
            Cli::try_parse_from(["fetch", "--grpc", "https://example.com/pkg.Svc/Method"]).unwrap();

        assert_eq!(effective_method(&cli), "POST");
        assert_eq!(effective_http_version(&cli, None), Some(HttpVersion::Http2));
        assert_eq!(
            effective_http_version(&cli, Some(HttpVersion::Http1)),
            Some(HttpVersion::Http1)
        );
    }
}
