use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use url::Url;

use crate::dns::util::{dns_query_id, udp_dns_timeout};
use crate::dns::wire;
use crate::duration::TimeoutBudget;
use crate::error::FetchError;

mod system;

const DNS_TYPE_HTTPS: u16 = wire::TYPE_HTTPS;
const DNS_CLASS_IN: u16 = wire::CLASS_IN;

const KEY_MANDATORY: u16 = 0;
const KEY_ALPN: u16 = 1;
const KEY_NO_DEFAULT_ALPN: u16 = 2;
const KEY_PORT: u16 = 3;
const KEY_IPV4HINT: u16 = 4;
const KEY_IPV6HINT: u16 = 6;
const KEY_DOH_PATH: u16 = 7;

const SUPPORTED_MANDATORY_KEYS: &[u16] = &[
    KEY_ALPN,
    KEY_NO_DEFAULT_ALPN,
    KEY_PORT,
    KEY_IPV4HINT,
    KEY_IPV6HINT,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SvcbRecord {
    pub(crate) priority: u16,
    pub(crate) target: String,
    pub(crate) alpn: Vec<String>,
    pub(crate) no_default_alpn: bool,
    pub(crate) port: Option<u16>,
    pub(crate) ipv4_hint: Vec<Ipv4Addr>,
    pub(crate) ipv6_hint: Vec<Ipv6Addr>,
    pub(crate) mandatory: Vec<u16>,
    pub(crate) unsupported_mandatory: Vec<u16>,
    pub(crate) ttl: Option<u32>,
}

impl SvcbRecord {
    pub(crate) fn is_alias_mode(&self) -> bool {
        self.priority == 0
    }

    pub(crate) fn is_usable(&self) -> bool {
        self.unsupported_mandatory.is_empty()
    }

    pub(crate) fn advertises_alpn(&self, protocol: &str) -> bool {
        self.alpn.iter().any(|alpn| alpn == protocol)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SvcParam {
    key: u16,
    value: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HttpsRecordResolver<'a> {
    Custom(&'a str),
    System,
}

pub(crate) fn parse_rdata(raw: &[u8]) -> Option<SvcbRecord> {
    if raw.len() < 3 {
        return None;
    }
    let priority = u16::from_be_bytes([raw[0], raw[1]]);
    let (target, mut offset) = unpack_dns_name(raw, 2)?;
    let mut params = Vec::new();
    while offset < raw.len() {
        if offset + 4 > raw.len() {
            return None;
        }
        let key = u16::from_be_bytes([raw[offset], raw[offset + 1]]);
        let len = usize::from(u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]));
        offset += 4;
        if offset + len > raw.len() {
            return None;
        }
        params.push(SvcParam {
            key,
            value: raw[offset..offset + len].to_vec(),
        });
        offset += len;
    }
    record_from_params(priority, target, &params)
}

fn record_from_params(priority: u16, target: String, params: &[SvcParam]) -> Option<SvcbRecord> {
    let mut record = SvcbRecord {
        priority,
        target,
        alpn: Vec::new(),
        no_default_alpn: false,
        port: None,
        ipv4_hint: Vec::new(),
        ipv6_hint: Vec::new(),
        mandatory: Vec::new(),
        unsupported_mandatory: Vec::new(),
        ttl: None,
    };

    for param in params {
        match param.key {
            KEY_MANDATORY => {
                record.mandatory = parse_mandatory(&param.value)?;
            }
            KEY_ALPN => {
                record.alpn = parse_alpn(&param.value)?;
            }
            KEY_NO_DEFAULT_ALPN => {
                if !param.value.is_empty() {
                    return None;
                }
                record.no_default_alpn = true;
            }
            KEY_PORT => {
                if param.value.len() != 2 {
                    return None;
                }
                record.port = Some(u16::from_be_bytes([param.value[0], param.value[1]]));
            }
            KEY_IPV4HINT => {
                if !param.value.len().is_multiple_of(4) {
                    return None;
                }
                record.ipv4_hint = param
                    .value
                    .chunks_exact(4)
                    .map(|chunk| Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]))
                    .collect();
            }
            KEY_IPV6HINT => {
                if !param.value.len().is_multiple_of(16) {
                    return None;
                }
                record.ipv6_hint = param
                    .value
                    .chunks_exact(16)
                    .map(|chunk| {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(chunk);
                        Ipv6Addr::from(octets)
                    })
                    .collect();
            }
            _ => {}
        }
    }

    record.unsupported_mandatory = record
        .mandatory
        .iter()
        .copied()
        .filter(|key| !SUPPORTED_MANDATORY_KEYS.contains(key))
        .collect();
    Some(record)
}

fn parse_mandatory(value: &[u8]) -> Option<Vec<u16>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    Some(
        value
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect(),
    )
}

fn parse_alpn(value: &[u8]) -> Option<Vec<String>> {
    let mut alpns = Vec::new();
    let mut offset = 0;
    while offset < value.len() {
        let len = usize::from(value[offset]);
        offset += 1;
        if len == 0 || offset + len > value.len() {
            return None;
        }
        alpns.push(String::from_utf8(value[offset..offset + len].to_vec()).ok()?);
        offset += len;
    }
    Some(alpns)
}

pub(crate) fn format_rdata(raw: &[u8]) -> Option<String> {
    if raw.len() < 3 {
        return None;
    }
    let priority = u16::from_be_bytes([raw[0], raw[1]]);
    let (target, mut offset) = unpack_dns_name(raw, 2)?;
    let mut params = Vec::new();
    while offset < raw.len() {
        if offset + 4 > raw.len() {
            return None;
        }
        let key = u16::from_be_bytes([raw[offset], raw[offset + 1]]);
        let len = usize::from(u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]));
        offset += 4;
        if offset + len > raw.len() {
            return None;
        }
        params.push(format_svc_param(key, &raw[offset..offset + len]));
        offset += len;
    }
    let mut parts = vec![priority.to_string(), target];
    parts.extend(params);
    Some(parts.join(" "))
}

pub(crate) fn parse_generic_rdata(value: &str) -> Option<Vec<u8>> {
    let fields: Vec<_> = value.split_whitespace().collect();
    if fields.len() < 3 || fields[0] != r"\#" {
        return None;
    }
    let want_len = fields[1].parse::<usize>().ok()?;
    let raw = hex_decode(&fields[2..].join(""))?;
    (raw.len() == want_len).then_some(raw)
}

pub(crate) async fn lookup_https_records(
    resolver: HttpsRecordResolver<'_>,
    host: &str,
    timeout: Option<Duration>,
) -> Result<Vec<SvcbRecord>, FetchError> {
    if let Ok(_ip) = host.parse::<IpAddr>() {
        return Ok(Vec::new());
    }
    match resolver {
        HttpsRecordResolver::Custom(server)
            if server.starts_with("http://") || server.starts_with("https://") =>
        {
            let server_url = Url::parse(server).map_err(|err| {
                FetchError::Message(format!("invalid dns-server '{server}': {err}"))
            })?;
            lookup_doh_https_records(&server_url, host, timeout).await
        }
        HttpsRecordResolver::Custom(server) => {
            let server_addr = crate::dns::resolver::normalize_udp_dns_server(server)
                .map_err(|err| FetchError::Message(err.to_string()))?;
            let server_addr = server_addr.parse::<SocketAddr>().map_err(|err| {
                FetchError::Message(format!("invalid dns-server '{server}': {err}"))
            })?;
            lookup_udp_https_records(server_addr, host, TimeoutBudget::new(timeout)).await
        }
        HttpsRecordResolver::System => {
            system::lookup_https_records(host, TimeoutBudget::new(timeout)).await
        }
    }
}

async fn lookup_doh_https_records(
    server_url: &Url,
    host: &str,
    timeout: Option<Duration>,
) -> Result<Vec<SvcbRecord>, FetchError> {
    let client = crate::dns::doh::client_with_budget(TimeoutBudget::new(timeout))
        .map_err(|err| FetchError::Message(err.to_string()))?;
    let answers =
        crate::dns::doh::lookup_doh_records_with_client(&client, server_url, host, "HTTPS")
            .await
            .map_err(|err| FetchError::Runtime(format!("lookup {host}: {err}")))?;
    Ok(answers
        .into_iter()
        .filter(|answer| answer.answer_type == DNS_TYPE_HTTPS)
        .filter_map(|answer| {
            parse_generic_rdata(&answer.data).and_then(|raw| {
                parse_rdata(&raw).map(|mut record| {
                    record.ttl = answer.ttl;
                    record
                })
            })
        })
        .collect())
}

async fn lookup_udp_https_records(
    server_addr: SocketAddr,
    host: &str,
    timeout: TimeoutBudget,
) -> Result<Vec<SvcbRecord>, FetchError> {
    let id = dns_query_id();
    let raw = wire::build_query(id, host, DNS_TYPE_HTTPS)
        .map_err(|err| FetchError::Runtime(err.to_string()))?;
    let udp_timeout = udp_dns_timeout(timeout.remaining()?);
    let mut response = crate::dns::transport::query_udp(server_addr, &raw, udp_timeout)
        .await
        .map_err(|err| FetchError::Runtime(err.to_string()))?;
    let raw_records = match wire::parse_response(&response, id) {
        Ok(records) => records,
        Err(err) if err.is_truncated() => {
            response = crate::dns::transport::query_tcp(server_addr, &raw, timeout)
                .await
                .map_err(|err| FetchError::Runtime(err.to_string()))?;
            wire::parse_response(&response, id)
                .map_err(|err| FetchError::Runtime(err.to_string()))?
        }
        Err(err) => return Err(FetchError::Runtime(err.to_string())),
    };
    Ok(raw_records
        .into_iter()
        .filter(|record| record.class == DNS_CLASS_IN && record.typ == DNS_TYPE_HTTPS)
        .filter_map(|record| {
            parse_rdata(record.data).map(|mut parsed| {
                parsed.ttl = Some(record.ttl);
                parsed
            })
        })
        .collect())
}

fn unpack_dns_name(raw: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    loop {
        let len = *raw.get(offset)?;
        offset += 1;
        if len == 0 {
            let name = if labels.is_empty() {
                ".".to_string()
            } else {
                format!("{}.", labels.join("."))
            };
            return Some((name, offset));
        }
        if len & 0xc0 != 0 {
            return None;
        }
        let len = usize::from(len);
        let label = raw.get(offset..offset + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        offset += len;
    }
}

fn format_svc_param(key: u16, value: &[u8]) -> String {
    match key {
        KEY_MANDATORY if value.len().is_multiple_of(2) => {
            let keys = value
                .chunks_exact(2)
                .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]).to_string())
                .collect::<Vec<_>>();
            format!("Mandatory={}", keys.join(","))
        }
        KEY_MANDATORY => format!("Mandatory=0x{}", hex_encode(value)),
        KEY_ALPN => match parse_alpn(value) {
            Some(alpns) => format!("ALPN={}", alpns.join(",")),
            None => format!("ALPN=0x{}", hex_encode(value)),
        },
        KEY_NO_DEFAULT_ALPN => "NoDefaultALPN".to_string(),
        KEY_PORT if value.len() == 2 => {
            let port = u16::from_be_bytes([value[0], value[1]]);
            format!("Port={port}")
        }
        KEY_PORT => format!("Port=0x{}", hex_encode(value)),
        KEY_IPV4HINT if value.len().is_multiple_of(4) => {
            let ips = value
                .chunks_exact(4)
                .map(|chunk| Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]).to_string())
                .collect::<Vec<_>>();
            format!("IPv4Hint={}", ips.join(","))
        }
        KEY_IPV4HINT => format!("IPv4Hint=0x{}", hex_encode(value)),
        KEY_IPV6HINT if value.len().is_multiple_of(16) => {
            let ips = value
                .chunks_exact(16)
                .map(|chunk| {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(chunk);
                    Ipv6Addr::from(octets).to_string()
                })
                .collect::<Vec<_>>();
            format!("IPv6Hint={}", ips.join(","))
        }
        KEY_IPV6HINT => format!("IPv6Hint=0x{}", hex_encode(value)),
        KEY_DOH_PATH => format!("DOHPath={:?}", String::from_utf8_lossy(value)),
        _ => format!("key{key}=0x{}", hex_encode(value)),
    }
}

pub(crate) fn hex_encode(raw: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(raw.len() * 2);
    for byte in raw {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(raw: &str) -> Option<Vec<u8>> {
    if !raw.len().is_multiple_of(2) {
        return None;
    }
    raw.as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let hi = hex_digit(chunk[0])?;
            let lo = hex_digit(chunk[1])?;
            Some((hi << 4) | lo)
        })
        .collect()
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(labels: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for label in labels {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn param(key: u16, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&key.to_be_bytes());
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
        out
    }

    fn record(priority: u16, target: &[&str], params: Vec<Vec<u8>>) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&priority.to_be_bytes());
        out.extend_from_slice(&name(target));
        for param in params {
            out.extend_from_slice(&param);
        }
        out
    }

    #[test]
    fn parses_service_mode_h3_port_and_hints() {
        let raw = record(
            1,
            &[],
            vec![
                param(KEY_ALPN, &[2, b'h', b'3']),
                param(KEY_PORT, &4433u16.to_be_bytes()),
                param(KEY_IPV4HINT, &[192, 0, 2, 1]),
                param(KEY_IPV6HINT, &Ipv6Addr::LOCALHOST.octets()),
            ],
        );

        let got = parse_rdata(&raw).unwrap();

        assert_eq!(got.priority, 1);
        assert_eq!(got.target, ".");
        assert_eq!(got.alpn, ["h3"]);
        assert_eq!(got.port, Some(4433));
        assert_eq!(got.ipv4_hint, [Ipv4Addr::new(192, 0, 2, 1)]);
        assert_eq!(got.ipv6_hint, [Ipv6Addr::LOCALHOST]);
        assert!(!got.is_alias_mode());
        assert!(got.is_usable());
        assert!(got.advertises_alpn("h3"));
    }

    #[test]
    fn parses_alias_mode() {
        let raw = record(0, &["svc", "example"], Vec::new());

        let got = parse_rdata(&raw).unwrap();

        assert!(got.is_alias_mode());
        assert_eq!(got.target, "svc.example.");
    }

    #[test]
    fn marks_unsupported_mandatory_keys_unusable() {
        let raw = record(
            1,
            &[],
            vec![
                param(KEY_MANDATORY, &[0, 1, 0, 9]),
                param(KEY_ALPN, &[2, b'h', b'3']),
            ],
        );

        let got = parse_rdata(&raw).unwrap();

        assert_eq!(got.mandatory, [1, 9]);
        assert_eq!(got.unsupported_mandatory, [9]);
        assert!(!got.is_usable());
    }

    #[test]
    fn rejects_malformed_records() {
        assert_eq!(parse_rdata(&[0, 1]), None);

        let bad_alpn = record(1, &[], vec![param(KEY_ALPN, &[3, b'h', b'3'])]);
        assert_eq!(parse_rdata(&bad_alpn), None);

        let bad_port = record(1, &[], vec![param(KEY_PORT, &[1])]);
        assert_eq!(parse_rdata(&bad_port), None);
    }

    #[tokio::test]
    async fn system_lookup_skips_ip_literal_hosts() {
        let records = lookup_https_records(
            HttpsRecordResolver::System,
            "127.0.0.1",
            Some(Duration::from_millis(1)),
        )
        .await
        .unwrap();

        assert!(records.is_empty());
    }

    #[test]
    fn formats_https_rdata_for_inspection() {
        let raw = record(
            1,
            &[],
            vec![
                param(KEY_ALPN, &[2, b'h', b'3']),
                param(KEY_PORT, &443u16.to_be_bytes()),
                param(KEY_IPV4HINT, &[192, 0, 2, 1]),
            ],
        );

        let got = format_rdata(&raw).unwrap();

        for want in ["1 .", "ALPN=h3", "Port=443", "IPv4Hint=192.0.2.1"] {
            assert!(got.contains(want), "missing {want:?}: {got}");
        }
    }

    #[test]
    fn parses_generic_rdata() {
        let raw = parse_generic_rdata(r"\# 3 000001").unwrap();

        assert_eq!(raw, [0, 0, 1]);
        assert_eq!(parse_generic_rdata(r"\# 4 000001"), None);
    }
}
