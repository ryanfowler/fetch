use url::form_urlencoded;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormField {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataValue {
    pub value: String,
    pub is_raw: bool,
    pub is_urlencode: bool,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ParsedCurl {
    pub url: String,
    pub method: String,
    pub headers: Vec<Header>,
    pub data_values: Vec<DataValue>,
    pub basic_auth: String,
    pub digest_auth: bool,
    pub aws_sigv4: String,
    pub bearer: String,
    pub form_fields: Vec<FormField>,
    pub upload_file: String,
    pub head: bool,
    pub insecure: bool,
    pub output: String,
    pub remote_name: bool,
    pub remote_header_name: bool,
    pub follow_redirects: bool,
    pub max_redirects: i32,
    pub max_redirects_set: bool,
    pub timeout: f64,
    pub connect_timeout: f64,
    pub proxy: String,
    pub doh_url: String,
    pub http_version: String,
    pub tls_max_version: String,
    pub tls_version: String,
    pub ca_cert: String,
    pub cert: String,
    pub key: String,
    pub unix_socket: String,
    pub ranges: Vec<String>,
    pub retry: usize,
    pub retry_delay: f64,
    pub get_flag: bool,
    pub verbose: u8,
    pub silent: bool,
    pub user_agent: String,
    pub referer: String,
    pub cookie: String,
    pub has_content_type: bool,
    pub has_accept: bool,
    pub allowed_proto: String,
}

pub fn parse(command: &str) -> Result<ParsedCurl, String> {
    let mut tokens = tokenize(command)?;
    if tokens.first().is_some_and(|token| token == "curl") {
        tokens.remove(0);
    }

    let mut parsed = ParsedCurl::default();
    parse_tokens(&mut parsed, &tokens)?;
    post_process(&mut parsed)?;
    Ok(parsed)
}

fn tokenize(input: &str) -> Result<Vec<String>, String> {
    let chars: Vec<char> = input.chars().collect();
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut has_content = false;
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            ' ' | '\t' | '\n' | '\r' => {
                if has_content {
                    tokens.push(std::mem::take(&mut current));
                    has_content = false;
                }
                i += 1;
            }
            '\'' => {
                i += 1;
                while i < chars.len() && chars[i] != '\'' {
                    current.push(chars[i]);
                    i += 1;
                }
                if i >= chars.len() {
                    return Err("unterminated single quote".to_string());
                }
                i += 1;
                has_content = true;
            }
            '"' => {
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    if chars[i] == '\\' && i + 1 < chars.len() {
                        let next = chars[i + 1];
                        if matches!(next, '"' | '\\' | '$' | '`') {
                            current.push(next);
                            i += 2;
                            continue;
                        }
                    }
                    current.push(chars[i]);
                    i += 1;
                }
                if i >= chars.len() {
                    return Err("unterminated double quote".to_string());
                }
                i += 1;
                has_content = true;
            }
            '\\' => {
                if i + 1 < chars.len() {
                    let next = chars[i + 1];
                    if next == '\n' {
                        i += 2;
                    } else {
                        current.push(next);
                        i += 2;
                        has_content = true;
                    }
                } else {
                    current.push('\\');
                    i += 1;
                    has_content = true;
                }
            }
            c => {
                current.push(c);
                i += 1;
                has_content = true;
            }
        }
    }

    if has_content {
        tokens.push(current);
    }

    Ok(tokens)
}

fn post_process(parsed: &mut ParsedCurl) -> Result<(), String> {
    if parsed.get_flag && parsed.method.is_empty() {
        parsed.method = "GET".to_string();
    }

    if !parsed.data_values.is_empty() && !parsed.upload_file.is_empty() {
        return Err("cannot use both data flags and --upload-file/-T".to_string());
    }

    if parsed.method.is_empty() {
        if parsed.head {
            parsed.method = "HEAD".to_string();
        } else if !parsed.data_values.is_empty() || !parsed.form_fields.is_empty() {
            parsed.method = "POST".to_string();
        } else if !parsed.upload_file.is_empty() {
            parsed.method = "PUT".to_string();
        }
    }

    if parsed.url.is_empty() {
        return Err("no URL provided in curl command".to_string());
    }

    Ok(())
}

fn parse_tokens(parsed: &mut ParsedCurl, tokens: &[String]) -> Result<(), String> {
    let mut i = 0;
    while i < tokens.len() {
        let token = &tokens[i];

        if !token.starts_with('-') {
            set_url(parsed, token)?;
            i += 1;
            continue;
        }

        if token == "--" {
            for rest in &tokens[i + 1..] {
                set_url(parsed, rest)?;
            }
            return Ok(());
        }

        if let Some(long) = token.strip_prefix("--") {
            let (name, value, has_value) = match long.split_once('=') {
                Some((name, value)) => (name, value.to_string(), true),
                None => (long, String::new(), false),
            };
            let consumed = parse_long_flag(parsed, name, value, has_value, &tokens[i + 1..])?;
            i += consumed + 1;
            continue;
        }

        let consumed = parse_short_flags(
            parsed,
            token.strip_prefix('-').expect("token starts with dash"),
            &tokens[i + 1..],
        )?;
        i += consumed + 1;
    }

    Ok(())
}

fn set_url(parsed: &mut ParsedCurl, value: &str) -> Result<(), String> {
    if !parsed.url.is_empty() {
        return Err(format!("unexpected argument: {value:?}"));
    }
    parsed.url = value.to_string();
    Ok(())
}

fn parse_long_flag(
    parsed: &mut ParsedCurl,
    name: &str,
    value: String,
    has_value: bool,
    rest: &[String],
) -> Result<usize, String> {
    if let Some(message) = unsupported_semantic_long_flag(name) {
        return Err(message);
    }

    let consume_arg = |flag_name: &str| -> Result<(String, usize), String> {
        if has_value {
            Ok((value.clone(), 0))
        } else {
            next_arg(rest).map_err(|_| format!("--{flag_name} requires an argument"))
        }
    };

    match name {
        "request" => {
            let (value, consumed) = consume_arg(name)?;
            parsed.method = value;
            Ok(consumed)
        }
        "header" => {
            let (value, consumed) = consume_arg(name)?;
            let header = parse_header(&value)?;
            remember_header_flags(parsed, &header);
            parsed.headers.push(header);
            Ok(consumed)
        }
        "url" => {
            let (value, consumed) = consume_arg(name)?;
            set_url(parsed, &value)?;
            Ok(consumed)
        }
        "get" => {
            parsed.get_flag = true;
            Ok(0)
        }
        "head" => {
            parsed.head = true;
            Ok(0)
        }
        "data" | "data-ascii" | "data-binary" => {
            let (value, consumed) = consume_arg(name)?;
            parsed.data_values.push(DataValue {
                value,
                is_raw: false,
                is_urlencode: false,
            });
            Ok(consumed)
        }
        "data-raw" => {
            let (value, consumed) = consume_arg(name)?;
            parsed.data_values.push(DataValue {
                value,
                is_raw: true,
                is_urlencode: false,
            });
            Ok(consumed)
        }
        "data-urlencode" => {
            let (value, consumed) = consume_arg(name)?;
            parsed.data_values.push(url_encode_value(&value));
            Ok(consumed)
        }
        "json" => {
            let (value, consumed) = consume_arg(name)?;
            parsed.data_values.push(DataValue {
                value,
                is_raw: false,
                is_urlencode: false,
            });
            if !parsed.has_content_type {
                parsed.headers.push(Header {
                    name: "Content-Type".to_string(),
                    value: "application/json".to_string(),
                });
                parsed.has_content_type = true;
            }
            if !parsed.has_accept {
                parsed.headers.push(Header {
                    name: "Accept".to_string(),
                    value: "application/json".to_string(),
                });
                parsed.has_accept = true;
            }
            Ok(consumed)
        }
        "form" => {
            let (value, consumed) = consume_arg(name)?;
            parsed.form_fields.push(parse_form_field(&value));
            Ok(consumed)
        }
        "upload-file" => {
            let (value, consumed) = consume_arg(name)?;
            parsed.upload_file = value;
            Ok(consumed)
        }
        "user" => {
            let (value, consumed) = consume_arg(name)?;
            parsed.basic_auth = value;
            Ok(consumed)
        }
        "aws-sigv4" => {
            let (value, consumed) = consume_arg(name)?;
            parsed.aws_sigv4 = value;
            Ok(consumed)
        }
        "oauth2-bearer" => {
            let (value, consumed) = consume_arg(name)?;
            parsed.bearer = value;
            Ok(consumed)
        }
        "digest" => {
            parsed.digest_auth = true;
            Ok(0)
        }
        "insecure" => {
            parsed.insecure = true;
            Ok(0)
        }
        "cacert" => {
            let (value, consumed) = consume_arg(name)?;
            parsed.ca_cert = value;
            Ok(consumed)
        }
        "cert" => {
            let (value, consumed) = consume_arg(name)?;
            parsed.cert = value;
            Ok(consumed)
        }
        "key" => {
            let (value, consumed) = consume_arg(name)?;
            parsed.key = value;
            Ok(consumed)
        }
        "tlsv1" | "tlsv1.0" => {
            parsed.tls_version = "1.0".to_string();
            Ok(0)
        }
        "tlsv1.1" => {
            parsed.tls_version = "1.1".to_string();
            Ok(0)
        }
        "tlsv1.2" => {
            parsed.tls_version = "1.2".to_string();
            Ok(0)
        }
        "tlsv1.3" => {
            parsed.tls_version = "1.3".to_string();
            Ok(0)
        }
        "tls-max" => {
            let (value, consumed) = consume_arg(name)?;
            parsed.tls_max_version = value;
            Ok(consumed)
        }
        "output" => {
            let (value, consumed) = consume_arg(name)?;
            parsed.output = value;
            Ok(consumed)
        }
        "remote-name" => {
            parsed.remote_name = true;
            Ok(0)
        }
        "remote-header-name" => {
            parsed.remote_header_name = true;
            Ok(0)
        }
        "location" => {
            parsed.follow_redirects = true;
            Ok(0)
        }
        "max-redirs" => {
            let (value, consumed) = consume_arg(name)?;
            parsed.max_redirects = value
                .parse()
                .map_err(|_| format!("invalid --max-redirs value: {value}"))?;
            parsed.max_redirects_set = true;
            Ok(consumed)
        }
        "max-time" => {
            let (value, consumed) = consume_arg(name)?;
            parsed.timeout = value
                .parse()
                .map_err(|_| format!("invalid --max-time value: {value}"))?;
            Ok(consumed)
        }
        "connect-timeout" => {
            let (value, consumed) = consume_arg(name)?;
            parsed.connect_timeout = value
                .parse()
                .map_err(|_| format!("invalid --connect-timeout value: {value}"))?;
            Ok(consumed)
        }
        "proxy" => {
            let (value, consumed) = consume_arg(name)?;
            parsed.proxy = value;
            Ok(consumed)
        }
        "unix-socket" => {
            let (value, consumed) = consume_arg(name)?;
            parsed.unix_socket = value;
            Ok(consumed)
        }
        "doh-url" => {
            let (value, consumed) = consume_arg(name)?;
            parsed.doh_url = value;
            Ok(consumed)
        }
        "retry" => {
            let (value, consumed) = consume_arg(name)?;
            parsed.retry = value
                .parse()
                .map_err(|_| format!("invalid --retry value: {value}"))?;
            Ok(consumed)
        }
        "retry-delay" => {
            let (value, consumed) = consume_arg(name)?;
            parsed.retry_delay = value
                .parse()
                .map_err(|_| format!("invalid --retry-delay value: {value}"))?;
            Ok(consumed)
        }
        "range" => {
            let (value, consumed) = consume_arg(name)?;
            parsed.ranges.push(value);
            Ok(consumed)
        }
        "http1.0" => {
            parsed.http_version = "1.0".to_string();
            Ok(0)
        }
        "http1.1" => {
            parsed.http_version = "1.1".to_string();
            Ok(0)
        }
        "http2" => {
            parsed.http_version = "2".to_string();
            Ok(0)
        }
        "http3" => {
            parsed.http_version = "3".to_string();
            Ok(0)
        }
        "user-agent" => {
            let (value, consumed) = consume_arg(name)?;
            parsed.user_agent = value;
            Ok(consumed)
        }
        "referer" => {
            let (value, consumed) = consume_arg(name)?;
            parsed.referer = value;
            Ok(consumed)
        }
        "cookie" => {
            let (value, consumed) = consume_arg(name)?;
            validate_cookie_value(&value)?;
            parsed.cookie = value;
            Ok(consumed)
        }
        "verbose" => {
            parsed.verbose = parsed.verbose.saturating_add(1);
            Ok(0)
        }
        "silent" => {
            parsed.silent = true;
            Ok(0)
        }
        name if long_flag_matches_fetch_default(name) => Ok(0),
        name if long_flag_is_curl_presentation_only(name) => Ok(0),
        "proto" => {
            let (value, consumed) = consume_arg(name)?;
            parsed.allowed_proto = value;
            Ok(consumed)
        }
        _ => Err(format!("unsupported curl flag '--{name}'")),
    }
}

fn long_flag_matches_fetch_default(name: &str) -> bool {
    matches!(
        name,
        "compressed" | "fail-with-body" | "no-keepalive" | "show-error"
    )
}

fn long_flag_is_curl_presentation_only(name: &str) -> bool {
    matches!(name, "no-progress-meter" | "progress-bar")
}

fn unsupported_semantic_long_flag(name: &str) -> Option<String> {
    match name {
        "fail" => Some(unsupported_fail_flag("--fail")),
        "netrc" => Some(unsupported_netrc_flag("--netrc")),
        "no-buffer" => Some(unsupported_no_buffer_flag("--no-buffer")),
        "proto-default" => Some(
            "curl --proto-default is not supported by --from-curl; specify the URL scheme explicitly"
                .to_string(),
        ),
        "proto-redir" => Some(
            "curl --proto-redir is not supported by --from-curl; fetch only follows HTTP(S) redirects and --from-curl cannot further restrict them"
                .to_string(),
        ),
        _ => None,
    }
}

fn short_flag_matches_fetch_default(flag: char) -> bool {
    matches!(flag, 'S')
}

fn short_flag_is_curl_presentation_only(flag: char) -> bool {
    matches!(flag, '#')
}

fn unsupported_semantic_short_flag(flag: char) -> Option<String> {
    match flag {
        'f' => Some(unsupported_fail_flag("-f")),
        'n' => Some(unsupported_netrc_flag("-n/--netrc")),
        'N' => Some(unsupported_no_buffer_flag("-N/--no-buffer")),
        _ => None,
    }
}

fn unsupported_fail_flag(flag: &str) -> String {
    format!(
        "curl {flag} is not supported by --from-curl; fetch already exits non-zero for HTTP error statuses but does not suppress the response body"
    )
}

fn unsupported_netrc_flag(flag: &str) -> String {
    format!(
        "curl {flag} is not supported by --from-curl; use --basic USER:PASS, --bearer TOKEN, or an explicit Authorization header (-H 'Authorization: ...') instead"
    )
}

fn unsupported_no_buffer_flag(flag: &str) -> String {
    format!(
        "curl {flag} is not supported by --from-curl; fetch does not implement curl's unbuffered output mode"
    )
}

fn parse_short_flags(
    parsed: &mut ParsedCurl,
    flags: &str,
    rest: &[String],
) -> Result<usize, String> {
    let bytes = flags.as_bytes();
    let mut total = 0;
    let mut i = 0;

    while i < bytes.len() {
        let flag = bytes[i] as char;
        let remaining = &flags[i + 1..];
        let mut consume_arg = |flag_name: char| -> Result<(String, usize), String> {
            if !remaining.is_empty() {
                i = bytes.len();
                Ok((remaining.to_string(), 0))
            } else {
                next_arg(&rest[total..]).map_err(|_| format!("-{flag_name} requires an argument"))
            }
        };

        match flag {
            'X' => {
                let (value, consumed) = consume_arg(flag)?;
                parsed.method = value;
                total += consumed;
            }
            'H' => {
                let (value, consumed) = consume_arg(flag)?;
                let header = parse_header(&value)?;
                remember_header_flags(parsed, &header);
                parsed.headers.push(header);
                total += consumed;
            }
            'd' => {
                let (value, consumed) = consume_arg(flag)?;
                parsed.data_values.push(DataValue {
                    value,
                    is_raw: false,
                    is_urlencode: false,
                });
                total += consumed;
            }
            'F' => {
                let (value, consumed) = consume_arg(flag)?;
                parsed.form_fields.push(parse_form_field(&value));
                total += consumed;
            }
            'T' => {
                let (value, consumed) = consume_arg(flag)?;
                parsed.upload_file = value;
                total += consumed;
            }
            'u' => {
                let (value, consumed) = consume_arg(flag)?;
                parsed.basic_auth = value;
                total += consumed;
            }
            'E' => {
                let (value, consumed) = consume_arg(flag)?;
                parsed.cert = value;
                total += consumed;
            }
            'o' => {
                let (value, consumed) = consume_arg(flag)?;
                parsed.output = value;
                total += consumed;
            }
            'x' => {
                let (value, consumed) = consume_arg(flag)?;
                parsed.proxy = value;
                total += consumed;
            }
            'm' => {
                let (value, consumed) = consume_arg(flag)?;
                parsed.timeout = value
                    .parse()
                    .map_err(|_| format!("invalid -m value: {value}"))?;
                total += consumed;
            }
            'r' => {
                let (value, consumed) = consume_arg(flag)?;
                parsed.ranges.push(value);
                total += consumed;
            }
            'A' => {
                let (value, consumed) = consume_arg(flag)?;
                parsed.user_agent = value;
                total += consumed;
            }
            'e' => {
                let (value, consumed) = consume_arg(flag)?;
                parsed.referer = value;
                total += consumed;
            }
            'b' => {
                let (value, consumed) = consume_arg(flag)?;
                validate_cookie_value(&value)?;
                parsed.cookie = value;
                total += consumed;
            }
            'I' => parsed.head = true,
            'k' => parsed.insecure = true,
            'O' => parsed.remote_name = true,
            'J' => parsed.remote_header_name = true,
            'L' => parsed.follow_redirects = true,
            'G' => parsed.get_flag = true,
            'v' => parsed.verbose = parsed.verbose.saturating_add(1),
            's' => parsed.silent = true,
            '0' => parsed.http_version = "1.0".to_string(),
            flag if short_flag_matches_fetch_default(flag) => {}
            flag if short_flag_is_curl_presentation_only(flag) => {}
            flag => {
                if let Some(message) = unsupported_semantic_short_flag(flag) {
                    return Err(message);
                }
                return Err(format!("unsupported curl flag '-{flag}'"));
            }
        }

        i += 1;
    }

    Ok(total)
}

fn next_arg(rest: &[String]) -> Result<(String, usize), ()> {
    rest.first().map(|value| (value.clone(), 1)).ok_or(())
}

fn parse_header(value: &str) -> Result<Header, String> {
    let (name, value) = value
        .split_once(':')
        .ok_or_else(|| format!("invalid header: {value:?}"))?;
    Ok(Header {
        name: name.trim().to_string(),
        value: value.trim().to_string(),
    })
}

fn remember_header_flags(parsed: &mut ParsedCurl, header: &Header) {
    if header.name.eq_ignore_ascii_case("content-type") {
        parsed.has_content_type = true;
    }
    if header.name.eq_ignore_ascii_case("accept") {
        parsed.has_accept = true;
    }
}

fn parse_form_field(value: &str) -> FormField {
    let (name, value) = value.split_once('=').unwrap_or((value, ""));
    FormField {
        name: name.to_string(),
        value: value.to_string(),
    }
}

fn validate_cookie_value(value: &str) -> Result<(), String> {
    if value.contains('=') {
        Ok(())
    } else {
        Err(format!(
            "cookie jar files are not supported; -b/--cookie value {value:?} looks like a file path (use -b 'name=value' for inline cookies)"
        ))
    }
}

fn url_encode_value(value: &str) -> DataValue {
    if value.starts_with('@') {
        return DataValue {
            value: value.to_string(),
            is_raw: false,
            is_urlencode: true,
        };
    }

    let eq_idx = value.find('=');
    let at_idx = value.find('@');
    if at_idx.is_some_and(|idx| idx > 0 && eq_idx.is_none_or(|eq| idx < eq)) {
        return DataValue {
            value: value.to_string(),
            is_raw: false,
            is_urlencode: true,
        };
    }

    if let Some((name, content)) = value.split_once('=') {
        if name.is_empty() {
            return DataValue {
                value: query_escape(content),
                is_raw: false,
                is_urlencode: false,
            };
        }
        return DataValue {
            value: format!("{name}={}", query_escape(content)),
            is_raw: false,
            is_urlencode: false,
        };
    }

    DataValue {
        value: query_escape(value),
        is_raw: false,
        is_urlencode: false,
    }
}

pub fn query_escape(value: &str) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("", value);
    serializer
        .finish()
        .strip_prefix('=')
        .expect("empty key appends leading equals")
        .to_string()
}

pub fn parse_allowed_proto(value: &str) -> (bool, bool) {
    if value.is_empty() {
        return (true, true);
    }

    let exclusive = value.starts_with('=');
    let value = value.strip_prefix('=').unwrap_or(value);
    let mut allow_http = !exclusive;
    let mut allow_https = !exclusive;

    for proto in value
        .split(',')
        .map(str::trim)
        .filter(|proto| !proto.is_empty())
    {
        match proto {
            "http" | "+http" => allow_http = true,
            "https" | "+https" => allow_https = true,
            "-http" => allow_http = false,
            "-https" => allow_https = false,
            _ => {}
        }
    }

    (allow_http, allow_https)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenize() {
        let cases = [
            (
                "curl https://example.com",
                vec!["curl", "https://example.com"],
            ),
            (
                r#"curl -H "X-Test: hello world" https://example.com"#,
                vec!["curl", "-H", "X-Test: hello world", "https://example.com"],
            ),
            (
                r#"curl -d '{"key":"value"}' https://example.com"#,
                vec!["curl", "-d", r#"{"key":"value"}"#, "https://example.com"],
            ),
            (
                r#"curl -H "" https://example.com"#,
                vec!["curl", "-H", "", "https://example.com"],
            ),
            (
                "curl \\\n  https://example.com",
                vec!["curl", "https://example.com"],
            ),
        ];

        for (input, want) in cases {
            assert_eq!(tokenize(input).unwrap(), want);
        }
    }

    #[test]
    fn test_tokenize_errors() {
        assert_eq!(
            tokenize("curl 'unterminated").unwrap_err(),
            "unterminated single quote"
        );
        assert_eq!(
            tokenize("curl \"unterminated").unwrap_err(),
            "unterminated double quote"
        );
    }

    #[test]
    fn test_parse_simple() {
        let parsed = parse("curl https://example.com").unwrap();
        assert_eq!(parsed.url, "https://example.com");
        assert_eq!(parsed.method, "");

        let parsed = parse("curl -X POST https://example.com").unwrap();
        assert_eq!(parsed.method, "POST");

        let parsed = parse("curl -d hello=world https://example.com").unwrap();
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.data_values[0].value, "hello=world");

        let parsed = parse(r#"curl -H "X-Test: value" https://example.com"#).unwrap();
        assert_eq!(
            parsed.headers,
            vec![Header {
                name: "X-Test".to_string(),
                value: "value".to_string()
            }]
        );

        let parsed = parse(r#"curl --request=PUT --url https://example.com"#).unwrap();
        assert_eq!(parsed.method, "PUT");
        assert_eq!(parsed.url, "https://example.com");

        assert!(
            parse("curl -X POST")
                .unwrap_err()
                .contains("no URL provided")
        );
        assert!(
            parse("curl --unknown-flag https://example.com")
                .unwrap_err()
                .contains("unsupported curl flag")
        );
    }

    #[test]
    fn test_parse_auth() {
        let parsed = parse("curl -u user:pass https://example.com").unwrap();
        assert_eq!(parsed.basic_auth, "user:pass");

        let parsed = parse("curl --digest -u user:pass https://example.com").unwrap();
        assert!(parsed.digest_auth);
        assert_eq!(parsed.basic_auth, "user:pass");

        let parsed = parse("curl --oauth2-bearer token https://example.com").unwrap();
        assert_eq!(parsed.bearer, "token");

        let parsed =
            parse(r#"curl --aws-sigv4 "aws:amz:us-east-1:s3" https://example.com"#).unwrap();
        assert_eq!(parsed.aws_sigv4, "aws:amz:us-east-1:s3");
    }

    #[test]
    fn test_parse_default_matching_and_unsupported_semantic_flags() {
        let parsed = parse(
            "curl --compressed --show-error --fail-with-body --no-keepalive --no-progress-meter --progress-bar -S -# https://example.com",
        )
        .unwrap();
        assert_eq!(parsed.url, "https://example.com");

        for (command, flag, want) in [
            (
                "curl --fail https://example.com",
                "--fail",
                "does not suppress the response body",
            ),
            (
                "curl -f https://example.com",
                "-f",
                "does not suppress the response body",
            ),
            (
                "curl --no-buffer https://example.com",
                "--no-buffer",
                "unbuffered output mode",
            ),
            (
                "curl -N https://example.com",
                "-N/--no-buffer",
                "unbuffered output mode",
            ),
            (
                "curl --proto-default https https://example.com",
                "--proto-default",
                "specify the URL scheme explicitly",
            ),
            (
                "curl --proto-redir =https https://example.com",
                "--proto-redir",
                "cannot further restrict",
            ),
        ] {
            let err = parse(command).unwrap_err();
            assert!(err.contains(flag), "{command}: {err}");
            assert!(err.contains(want), "{command}: {err}");
        }
    }

    #[test]
    fn test_parse_netrc_is_rejected_with_auth_advice() {
        for (command, flag) in [
            ("curl --netrc https://example.com", "--netrc"),
            ("curl -n https://example.com", "-n/--netrc"),
        ] {
            let err = parse(command).unwrap_err();
            assert!(err.contains(flag), "{command}: {err}");
            assert!(err.contains("--basic"), "{command}: {err}");
            assert!(err.contains("--bearer"), "{command}: {err}");
            assert!(err.contains("Authorization"), "{command}: {err}");
        }
    }

    #[test]
    fn test_parse_network_and_retry() {
        let parsed = parse(
            "curl -L --max-redirs 5 --max-time 1.5 --connect-timeout 0.25 --retry 3 --retry-delay 0.5 https://example.com",
        )
        .unwrap();
        assert!(parsed.follow_redirects);
        assert_eq!(parsed.max_redirects, 5);
        assert!(parsed.max_redirects_set);
        assert_eq!(parsed.timeout, 1.5);
        assert_eq!(parsed.connect_timeout, 0.25);
        assert_eq!(parsed.retry, 3);
        assert_eq!(parsed.retry_delay, 0.5);
    }

    #[test]
    fn test_parse_verbosity_and_short_inline_values() {
        let parsed =
            parse("curl -vvv -XPOST -HAccept:application/json https://example.com").unwrap();
        assert_eq!(parsed.verbose, 3);
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.headers[0].name, "Accept");
        assert_eq!(parsed.headers[0].value, "application/json");
    }

    #[test]
    fn test_parse_json_adds_headers() {
        let parsed = parse(r#"curl --json '{"ok":true}' https://example.com"#).unwrap();
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.data_values[0].value, r#"{"ok":true}"#);
        assert!(
            parsed
                .headers
                .iter()
                .any(|h| h.name == "Content-Type" && h.value == "application/json")
        );
        assert!(
            parsed
                .headers
                .iter()
                .any(|h| h.name == "Accept" && h.value == "application/json")
        );
    }

    #[test]
    fn test_parse_proto() {
        let parsed = parse("curl --proto '=https' https://example.com").unwrap();
        assert_eq!(parsed.allowed_proto, "=https");
    }

    #[test]
    fn test_parse_allowed_proto() {
        assert_eq!(parse_allowed_proto(""), (true, true));
        assert_eq!(parse_allowed_proto("=https"), (false, true));
        assert_eq!(parse_allowed_proto("=http"), (true, false));
        assert_eq!(parse_allowed_proto("http,https"), (true, true));
        assert_eq!(parse_allowed_proto("-http"), (false, true));
        assert_eq!(parse_allowed_proto("-https"), (true, false));
    }

    #[test]
    fn test_url_encode_value() {
        let value = url_encode_value("key=hello world");
        assert_eq!(value.value, "key=hello+world");
        assert!(!value.is_urlencode);

        let value = url_encode_value("=hello world");
        assert_eq!(value.value, "hello+world");

        let value = url_encode_value("hello world");
        assert_eq!(value.value, "hello+world");

        let value = url_encode_value("email=user@example.com");
        assert_eq!(value.value, "email=user%40example.com");

        let value = url_encode_value("@payload.txt");
        assert_eq!(value.value, "@payload.txt");
        assert!(value.is_urlencode);

        let value = url_encode_value("field@payload.txt");
        assert_eq!(value.value, "field@payload.txt");
        assert!(value.is_urlencode);
    }

    #[test]
    fn test_cookie_file_rejection() {
        let err = parse("curl -b cookies.txt https://example.com").unwrap_err();
        assert!(err.contains("cookie jar files are not supported"));
    }

    #[test]
    fn test_data_and_upload_file_conflict() {
        let err = parse("curl -d hello -T payload.txt https://example.com").unwrap_err();
        assert!(err.contains("cannot use both data flags"));
    }
}
