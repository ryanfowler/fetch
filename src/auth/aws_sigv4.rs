use std::collections::BTreeMap;

use hmac::{Hmac, KeyInit, Mac};
use reqwest::header::{AUTHORIZATION, HOST, HeaderMap, HeaderName, HeaderValue};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use url::Url;

const HEADER_CONTENT_SHA256: &str = "x-amz-content-sha256";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
    pub region: String,
    pub service: String,
}

impl Config {
    pub fn new(region: impl Into<String>, service: impl Into<String>) -> Self {
        Self {
            access_key: String::new(),
            secret_key: String::new(),
            session_token: None,
            region: region.into(),
            service: service.into(),
        }
    }
}

#[derive(Debug, Error)]
pub enum AwsSigV4Error {
    #[error("missing environment variable '{0}' required for option '--aws-sigv4'")]
    MissingEnvVar(&'static str),
    #[error("invalid aws-sigv4 format: {0}, expected REGION/SERVICE")]
    InvalidConfig(String),
    #[error("invalid header value for AWS signing: {0}")]
    InvalidHeaderValue(String),
}

pub fn parse_config(value: &str) -> Result<Config, AwsSigV4Error> {
    let Some((region, service)) = value.split_once('/') else {
        return Err(AwsSigV4Error::InvalidConfig(value.to_string()));
    };
    let region = region.trim();
    let service = service.trim();
    if region.is_empty() || service.is_empty() {
        return Err(AwsSigV4Error::InvalidConfig(value.to_string()));
    }
    Ok(Config::new(region, service))
}

pub fn sign(
    method: &str,
    url: &Url,
    headers: &mut HeaderMap,
    body: Option<&[u8]>,
    config: &Config,
    now: OffsetDateTime,
    unsigned_payload: bool,
) -> Result<(), AwsSigV4Error> {
    let config = fill_env_credentials(config)?;
    let datetime = format_datetime(now);
    headers.insert(
        HeaderName::from_static("x-amz-date"),
        HeaderValue::from_str(&datetime)
            .map_err(|err| AwsSigV4Error::InvalidHeaderValue(err.to_string()))?,
    );

    let payload = payload_hash(headers, body, &config.service, unsigned_payload);
    headers.insert(
        HeaderName::from_static(HEADER_CONTENT_SHA256),
        HeaderValue::from_str(&payload)
            .map_err(|err| AwsSigV4Error::InvalidHeaderValue(err.to_string()))?,
    );
    if let Some(token) = config.session_token.as_deref() {
        headers.insert(
            HeaderName::from_static("x-amz-security-token"),
            HeaderValue::from_str(token)
                .map_err(|err| AwsSigV4Error::InvalidHeaderValue(err.to_string()))?,
        );
    }

    let signed_headers = signed_headers(url, headers)?;
    let canonical_request = build_canonical_request(method, url, &signed_headers, &payload);
    let string_to_sign = build_string_to_sign(
        &datetime,
        &config.region,
        &config.service,
        &canonical_request,
    );
    let signing_key = create_signing_key(
        &datetime[..8],
        &config.region,
        &config.service,
        &config.secret_key,
    );
    let signature = hex_encode(&hmac_sha256(&signing_key, string_to_sign.as_bytes()));
    let signed_header_names = signed_headers
        .iter()
        .map(|(key, _)| key.as_str())
        .collect::<Vec<_>>()
        .join(";");

    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}/{}/{}/aws4_request,SignedHeaders={},Signature={}",
        config.access_key,
        &datetime[..8],
        config.region,
        config.service,
        signed_header_names,
        signature
    );
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&auth)
            .map_err(|err| AwsSigV4Error::InvalidHeaderValue(err.to_string()))?,
    );
    Ok(())
}

fn fill_env_credentials(config: &Config) -> Result<Config, AwsSigV4Error> {
    let mut out = config.clone();
    if out.access_key.is_empty() {
        out.access_key = std::env::var("AWS_ACCESS_KEY_ID")
            .map_err(|_| AwsSigV4Error::MissingEnvVar("AWS_ACCESS_KEY_ID"))?;
        if out.access_key.is_empty() {
            return Err(AwsSigV4Error::MissingEnvVar("AWS_ACCESS_KEY_ID"));
        }
    }
    if out.secret_key.is_empty() {
        out.secret_key = std::env::var("AWS_SECRET_ACCESS_KEY")
            .map_err(|_| AwsSigV4Error::MissingEnvVar("AWS_SECRET_ACCESS_KEY"))?;
        if out.secret_key.is_empty() {
            return Err(AwsSigV4Error::MissingEnvVar("AWS_SECRET_ACCESS_KEY"));
        }
    }
    if out.session_token.is_none()
        && let Ok(token) = std::env::var("AWS_SESSION_TOKEN")
        && !token.is_empty()
    {
        out.session_token = Some(token);
    }
    Ok(out)
}

fn payload_hash(
    headers: &HeaderMap,
    body: Option<&[u8]>,
    service: &str,
    unsigned_payload: bool,
) -> String {
    if let Some(existing) = headers
        .get(HeaderName::from_static(HEADER_CONTENT_SHA256))
        .and_then(|value| value.to_str().ok())
    {
        return existing.to_string();
    }
    if unsigned_payload && service == "s3" {
        return UNSIGNED_PAYLOAD.to_string();
    }
    match body {
        Some(body) => hex_sha256(body),
        None => EMPTY_SHA256.to_string(),
    }
}

fn signed_headers(url: &Url, headers: &HeaderMap) -> Result<Vec<(String, String)>, AwsSigV4Error> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let host = headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .filter(|host| !host.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| url_host(url));
    if !host.is_empty() {
        out.entry("host".to_string()).or_default().push(host);
    }

    for (name, value) in headers {
        let name = name.as_str().trim().to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "host" | "accept-encoding" | "authorization" | "content-length" | "user-agent"
        ) {
            continue;
        }
        let value = value
            .to_str()
            .map_err(|err| AwsSigV4Error::InvalidHeaderValue(err.to_string()))?;
        out.entry(name).or_default().push(value.to_string());
    }

    Ok(out
        .into_iter()
        .map(|(key, values)| (key, canonical_header_value(&values)))
        .collect())
}

fn url_host(url: &Url) -> String {
    let Some(host) = url.host_str() else {
        return String::new();
    };
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    }
}

fn canonical_header_value(values: &[String]) -> String {
    if values.len() == 1 && is_canonical_header_value(&values[0]) {
        return values[0].clone();
    }
    values
        .iter()
        .map(|value| write_canonical_header_value(value))
        .collect::<Vec<_>>()
        .join(",")
}

fn is_canonical_header_value(value: &str) -> bool {
    let mut in_whitespace = false;
    let mut wrote_value = false;
    for ch in value.chars() {
        if !ch.is_whitespace() {
            in_whitespace = false;
            wrote_value = true;
            continue;
        }
        if ch != ' ' || in_whitespace || !wrote_value {
            return false;
        }
        in_whitespace = true;
    }
    !in_whitespace
}

fn write_canonical_header_value(value: &str) -> String {
    let mut out = String::new();
    let mut in_whitespace = true;
    let mut wrote_value = false;
    for ch in value.chars() {
        if ch.is_whitespace() {
            in_whitespace = true;
            continue;
        }
        if in_whitespace && wrote_value {
            out.push(' ');
        }
        out.push(ch);
        in_whitespace = false;
        wrote_value = true;
    }
    out
}

fn build_canonical_request(
    method: &str,
    url: &Url,
    headers: &[(String, String)],
    payload: &str,
) -> String {
    let signed_header_names = headers
        .iter()
        .map(|(key, _)| key.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let mut out = String::new();
    out.push_str(method);
    out.push('\n');
    out.push_str(&canonical_uri_path(url));
    out.push('\n');
    out.push_str(&canonical_query(url));
    out.push('\n');
    for (key, value) in headers {
        out.push_str(key);
        out.push(':');
        out.push_str(value);
        out.push('\n');
    }
    out.push('\n');
    out.push_str(&signed_header_names);
    out.push('\n');
    out.push_str(payload);
    out
}

fn canonical_uri_path(url: &Url) -> String {
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    let mut out = String::new();
    if !path.starts_with('/') {
        out.push('/');
    }
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        if byte == b'%' && i + 2 < bytes.len() && is_hex(bytes[i + 1]) && is_hex(bytes[i + 2]) {
            out.push('%');
            out.push(to_upper_hex(bytes[i + 1]) as char);
            out.push(to_upper_hex(bytes[i + 2]) as char);
            i += 3;
            continue;
        }
        if valid_uri_byte(byte) {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push_str(&hex_encode_upper(&[byte]));
        }
        i += 1;
    }
    out
}

fn canonical_query(url: &Url) -> String {
    let Some(query) = url.query() else {
        return String::new();
    };

    let mut pairs = Vec::new();
    for part in query.split('&') {
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        let key = percent_encoding::percent_decode(key.as_bytes()).collect::<Vec<_>>();
        let value = percent_encoding::percent_decode(value.as_bytes()).collect::<Vec<_>>();
        pairs.push(format!(
            "{}={}",
            aws_percent_encode(&key),
            aws_percent_encode(&value)
        ));
    }
    pairs.sort();
    pairs.join("&")
}

fn aws_percent_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &byte in bytes {
        if valid_query_byte(byte) {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push_str(&hex_encode_upper(&[byte]));
        }
    }
    out
}

fn build_string_to_sign(
    datetime: &str,
    region: &str,
    service: &str,
    canonical_request: &str,
) -> String {
    format!(
        "AWS4-HMAC-SHA256\n{}\n{}/{}/{}/aws4_request\n{}",
        datetime,
        &datetime[..8],
        region,
        service,
        hex_sha256(canonical_request.as_bytes())
    )
}

fn create_signing_key(date: &str, region: &str, service: &str, secret_key: &str) -> Vec<u8> {
    let date_key = hmac_sha256(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let date_region_key = hmac_sha256(&date_key, region.as_bytes());
    let date_region_service_key = hmac_sha256(&date_region_key, service.as_bytes());
    hmac_sha256(&date_region_service_key, b"aws4_request")
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

fn format_datetime(now: OffsetDateTime) -> String {
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

fn valid_uri_byte(byte: u8) -> bool {
    matches!(byte, b'-' | b'.' | b'/' | b'0'..=b'9' | b'A'..=b'Z' | b'_' | b'a'..=b'z' | b'~')
}

fn valid_query_byte(byte: u8) -> bool {
    matches!(byte, b'-' | b'.' | b'0'..=b'9' | b'A'..=b'Z' | b'_' | b'a'..=b'z' | b'~')
}

fn is_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

fn to_upper_hex(byte: u8) -> u8 {
    if byte.is_ascii_lowercase() {
        byte - (b'a' - b'A')
    } else {
        byte
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_encode_upper(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{DATE, RANGE};

    fn fixed_now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_369_353_600).unwrap()
    }

    fn example_config(service: &str) -> Config {
        Config {
            region: "us-east-1".to_string(),
            service: service.to_string(),
            access_key: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: None,
        }
    }

    #[test]
    fn test_sign_get_object() {
        let url = Url::parse("https://examplebucket.s3.amazonaws.com/test.txt").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(RANGE, HeaderValue::from_static("bytes=0-9"));

        sign(
            "GET",
            &url,
            &mut headers,
            None,
            &example_config("s3"),
            fixed_now(),
            false,
        )
        .unwrap();

        assert_eq!(
            headers.get(AUTHORIZATION).unwrap(),
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn test_sign_put_object() {
        let url = Url::parse("https://examplebucket.s3.amazonaws.com/test$file.text").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            DATE,
            HeaderValue::from_static("Fri, 24 May 2013 00:00:00 GMT"),
        );
        headers.insert(
            HeaderName::from_static("x-amz-storage-class"),
            HeaderValue::from_static("REDUCED_REDUNDANCY"),
        );

        sign(
            "PUT",
            &url,
            &mut headers,
            Some(b"Welcome to Amazon S3."),
            &example_config("s3"),
            fixed_now(),
            false,
        )
        .unwrap();

        assert_eq!(
            headers.get(AUTHORIZATION).unwrap(),
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class,Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
        );
    }

    #[test]
    fn test_sign_get_bucket_lifecycle() {
        let url = Url::parse("https://examplebucket.s3.amazonaws.com/?lifecycle").unwrap();
        let mut headers = HeaderMap::new();

        sign(
            "GET",
            &url,
            &mut headers,
            None,
            &example_config("s3"),
            fixed_now(),
            false,
        )
        .unwrap();

        assert_eq!(
            headers.get(AUTHORIZATION).unwrap(),
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"
        );
    }

    #[test]
    fn test_sign_list_objects() {
        let url =
            Url::parse("https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J").unwrap();
        let mut headers = HeaderMap::new();

        sign(
            "GET",
            &url,
            &mut headers,
            None,
            &example_config("s3"),
            fixed_now(),
            false,
        )
        .unwrap();

        assert_eq!(
            headers.get(AUTHORIZATION).unwrap(),
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
        );
    }

    #[test]
    fn test_sign_includes_session_token_in_signed_headers() {
        let url = Url::parse("https://examplebucket.s3.amazonaws.com/test.txt").unwrap();
        let mut headers = HeaderMap::new();
        let mut config = example_config("s3");
        config.session_token = Some("session-token".to_string());

        sign("GET", &url, &mut headers, None, &config, fixed_now(), false).unwrap();

        assert_eq!(
            headers
                .get(HeaderName::from_static("x-amz-security-token"))
                .unwrap(),
            "session-token"
        );
        assert!(
            headers
                .get(AUTHORIZATION)
                .unwrap()
                .to_str()
                .unwrap()
                .contains(
                    "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
                )
        );
    }

    #[test]
    fn test_signed_headers_canonicalizes_header_values() {
        let url = Url::parse("https://example.com").unwrap();
        let mut headers = HeaderMap::new();
        headers.append(
            HeaderName::from_static("x-foo"),
            HeaderValue::from_static("  a  "),
        );
        headers.append(
            HeaderName::from_static("x-foo"),
            HeaderValue::from_static("  b  "),
        );
        headers.insert(
            HeaderName::from_static("x-bar"),
            HeaderValue::from_static("  a\t  b  "),
        );

        let signed = signed_headers(&url, &headers).unwrap();
        assert!(signed.contains(&("x-bar".to_string(), "a b".to_string())));
        assert!(signed.contains(&("x-foo".to_string(), "a,b".to_string())));
    }

    #[test]
    fn test_canonical_request_uses_escaped_path() {
        let cases = [
            ("https://example.com/a%2Fb", "/a%2Fb"),
            ("https://example.com/space%20here", "/space%20here"),
            (
                "https://example.com/café/日本",
                "/caf%C3%A9/%E6%97%A5%E6%9C%AC",
            ),
        ];

        for (raw, want) in cases {
            let url = Url::parse(raw).unwrap();
            let canonical = build_canonical_request("GET", &url, &[], EMPTY_SHA256);
            let path = canonical.lines().nth(1).unwrap();
            assert_eq!(path, want);
        }
    }

    #[test]
    fn test_canonical_query_sorts_duplicate_values() {
        let url = Url::parse("https://example.com/?z=last&a=b&a=a&a=A").unwrap();

        assert_eq!(canonical_query(&url), "a=A&a=a&a=b&z=last");
    }

    #[test]
    fn test_canonical_query_sorts_percent_encoded_pairs() {
        let url = Url::parse(
            "https://example.com/?z=last&%C3%A9=first&space=two%20words&space=bang!&slash=/",
        )
        .unwrap();

        assert_eq!(
            canonical_query(&url),
            "%C3%A9=first&slash=%2F&space=bang%21&space=two%20words&z=last"
        );
    }

    #[test]
    fn test_canonical_query_treats_plus_as_literal() {
        let url = Url::parse("https://example.com/?plus=a+b&space=a%20b").unwrap();

        assert_eq!(canonical_query(&url), "plus=a%2Bb&space=a%20b");
    }

    #[test]
    fn test_signed_headers_uses_host_header() {
        let url = Url::parse("https://127.0.0.1").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("vhost.example"));

        let signed = signed_headers(&url, &headers).unwrap();
        assert!(signed.contains(&("host".to_string(), "vhost.example".to_string())));
    }

    #[test]
    fn test_unsigned_payload_for_s3() {
        let url = Url::parse("https://examplebucket.s3.amazonaws.com/test.txt").unwrap();
        let mut headers = HeaderMap::new();

        sign(
            "PUT",
            &url,
            &mut headers,
            Some(b"data"),
            &example_config("s3"),
            fixed_now(),
            true,
        )
        .unwrap();

        assert_eq!(
            headers
                .get(HeaderName::from_static(HEADER_CONTENT_SHA256))
                .unwrap(),
            UNSIGNED_PAYLOAD
        );
    }

    #[test]
    fn test_parse_config() {
        let config = parse_config("us-east-1/s3").unwrap();
        assert_eq!(config.region, "us-east-1");
        assert_eq!(config.service, "s3");
        assert!(parse_config("us-east-1").is_err());
    }
}
