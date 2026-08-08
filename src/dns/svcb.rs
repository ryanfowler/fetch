use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use crate::dns::custom::DnsRecordData;
use crate::dns::wire;
use crate::duration::TimeoutBudget;
use crate::error::FetchError;
use base64::Engine;

mod system;

const DNS_TYPE_HTTPS: u16 = wire::TYPE_HTTPS;
const MAX_ALIAS_CHAIN_DEPTH: usize = 8;
const KEY_MANDATORY: u16 = 0;
const KEY_ALPN: u16 = 1;
const KEY_NO_DEFAULT_ALPN: u16 = 2;
const KEY_PORT: u16 = 3;
const KEY_IPV4HINT: u16 = 4;
const KEY_ECH: u16 = 5;
const KEY_IPV6HINT: u16 = 6;
const KEY_DOH_PATH: u16 = 7;

const SUPPORTED_MANDATORY_KEYS: &[u16] = &[
    KEY_ALPN,
    KEY_NO_DEFAULT_ALPN,
    KEY_PORT,
    KEY_IPV4HINT,
    KEY_ECH,
    KEY_IPV6HINT,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SvcbRecord {
    pub(crate) priority: u16,
    pub(crate) target: String,
    pub(crate) alpn: Vec<Vec<u8>>,
    pub(crate) no_default_alpn: bool,
    pub(crate) port: Option<u16>,
    pub(crate) ipv4_hint: Vec<Ipv4Addr>,
    pub(crate) ipv6_hint: Vec<Ipv6Addr>,
    pub(crate) ech: Option<Vec<u8>>,
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
        self.alpn.iter().any(|alpn| alpn == protocol.as_bytes())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SvcParam {
    key: u16,
    value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SvcbParseError {
    ShortRdata,
    InvalidTargetName,
    TruncatedParamHeader {
        offset: usize,
    },
    TruncatedParamValue {
        key: u16,
        expected: usize,
        actual: usize,
    },
    DuplicateParam {
        key: u16,
    },
    OutOfOrderParam {
        previous: u16,
        key: u16,
    },
    EmptyMandatory,
    InvalidMandatoryLength {
        length: usize,
    },
    MandatoryKeyZero,
    DuplicateMandatoryKey {
        key: u16,
    },
    OutOfOrderMandatoryKey {
        previous: u16,
        key: u16,
    },
    MissingMandatoryParam {
        key: u16,
    },
    EmptyAlpn,
    EmptyAlpnId,
    TruncatedAlpnId {
        expected: usize,
        actual: usize,
    },
    NonEmptyNoDefaultAlpn,
    NoDefaultAlpnWithoutAlpn,
    InvalidPortLength {
        length: usize,
    },
    EmptyIpv4Hint,
    InvalidIpv4HintLength {
        length: usize,
    },
    InvalidEchConfigListLength {
        declared: Option<usize>,
        actual: usize,
    },
    EmptyEchConfigList,
    TruncatedEchConfigHeader {
        offset: usize,
        actual: usize,
    },
    TruncatedEchConfig {
        offset: usize,
        expected: usize,
        actual: usize,
    },
    InvalidEchConfigContents(&'static str),
    EmptyIpv6Hint,
    InvalidIpv6HintLength {
        length: usize,
    },
}

impl std::fmt::Display for SvcbParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ShortRdata => write!(formatter, "RDATA is too short"),
            Self::InvalidTargetName => write!(formatter, "TargetName is malformed"),
            Self::TruncatedParamHeader { offset } => {
                write!(formatter, "SvcParam header at offset {offset} is truncated")
            }
            Self::TruncatedParamValue {
                key,
                expected,
                actual,
            } => write!(
                formatter,
                "SvcParam key {key} declares {expected} value bytes but only {actual} remain"
            ),
            Self::DuplicateParam { key } => write!(formatter, "SvcParam key {key} is repeated"),
            Self::OutOfOrderParam { previous, key } => write!(
                formatter,
                "SvcParam key {key} is not greater than preceding key {previous}"
            ),
            Self::EmptyMandatory => write!(formatter, "mandatory has an empty value"),
            Self::InvalidMandatoryLength { length } => write!(
                formatter,
                "mandatory value length {length} is not a nonzero multiple of 2"
            ),
            Self::MandatoryKeyZero => write!(formatter, "mandatory lists key 0 (mandatory)"),
            Self::DuplicateMandatoryKey { key } => {
                write!(formatter, "mandatory key {key} is repeated")
            }
            Self::OutOfOrderMandatoryKey { previous, key } => write!(
                formatter,
                "mandatory key {key} is not greater than preceding key {previous}"
            ),
            Self::MissingMandatoryParam { key } => {
                write!(formatter, "mandatory lists absent SvcParam key {key}")
            }
            Self::EmptyAlpn => write!(formatter, "alpn has an empty value"),
            Self::EmptyAlpnId => write!(formatter, "alpn contains an empty protocol ID"),
            Self::TruncatedAlpnId { expected, actual } => write!(
                formatter,
                "alpn protocol ID declares {expected} bytes but only {actual} remain"
            ),
            Self::NonEmptyNoDefaultAlpn => {
                write!(formatter, "no-default-alpn must have an empty value")
            }
            Self::NoDefaultAlpnWithoutAlpn => {
                write!(formatter, "no-default-alpn is present without alpn")
            }
            Self::InvalidPortLength { length } => {
                write!(formatter, "port value length is {length}, not 2")
            }
            Self::EmptyIpv4Hint => write!(formatter, "ipv4hint has an empty value"),
            Self::InvalidIpv4HintLength { length } => write!(
                formatter,
                "ipv4hint value length {length} is not a nonzero multiple of 4"
            ),
            Self::InvalidEchConfigListLength { declared, actual } => match declared {
                Some(declared) => write!(
                    formatter,
                    "ech ECHConfigList declares {declared} bytes but contains {actual}"
                ),
                None => write!(
                    formatter,
                    "ech ECHConfigList is shorter than its length prefix"
                ),
            },
            Self::EmptyEchConfigList => write!(formatter, "ech ECHConfigList is empty"),
            Self::TruncatedEchConfigHeader { offset, actual } => write!(
                formatter,
                "ech ECHConfig header at offset {offset} has only {actual} bytes"
            ),
            Self::TruncatedEchConfig {
                offset,
                expected,
                actual,
            } => write!(
                formatter,
                "ech ECHConfig at offset {offset} declares {expected} content bytes but only {actual} remain"
            ),
            Self::InvalidEchConfigContents(reason) => {
                write!(formatter, "ech ECHConfigContents is malformed: {reason}")
            }
            Self::EmptyIpv6Hint => write!(formatter, "ipv6hint has an empty value"),
            Self::InvalidIpv6HintLength { length } => write!(
                formatter,
                "ipv6hint value length {length} is not a nonzero multiple of 16"
            ),
        }
    }
}

impl std::error::Error for SvcbParseError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HttpsRecordResolver<'a> {
    Custom(&'a str),
    System,
}

/// The result of RFC 9460 service binding resolution.
///
/// `fallback_target` is the effective name to resolve with A/AAAA when the
/// final name has no usable ServiceMode records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HttpsLookup {
    pub(crate) records: Vec<SvcbRecord>,
    pub(crate) fallback_target: String,
}

pub(crate) fn parse_rdata(raw: &[u8]) -> Result<SvcbRecord, SvcbParseError> {
    if raw.len() < 3 {
        return Err(SvcbParseError::ShortRdata);
    }
    let priority = u16::from_be_bytes([raw[0], raw[1]]);
    let (target, mut offset) = unpack_dns_name(raw, 2).ok_or(SvcbParseError::InvalidTargetName)?;
    let mut params = Vec::new();
    let mut previous_key = None;
    while offset < raw.len() {
        if offset + 4 > raw.len() {
            return Err(SvcbParseError::TruncatedParamHeader { offset });
        }
        let key = u16::from_be_bytes([raw[offset], raw[offset + 1]]);
        if let Some(previous) = previous_key {
            if key == previous {
                return Err(SvcbParseError::DuplicateParam { key });
            }
            if key < previous {
                return Err(SvcbParseError::OutOfOrderParam { previous, key });
            }
        }
        previous_key = Some(key);
        let len = usize::from(u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]));
        offset += 4;
        if offset + len > raw.len() {
            return Err(SvcbParseError::TruncatedParamValue {
                key,
                expected: len,
                actual: raw.len() - offset,
            });
        }
        params.push(SvcParam {
            key,
            value: raw[offset..offset + len].to_vec(),
        });
        offset += len;
    }
    if priority == 0 {
        // RFC 9460 section 2.4.2 requires clients to ignore all SvcParams in
        // AliasMode. Their wire framing and key order were validated above.
        return Ok(SvcbRecord {
            priority,
            target,
            alpn: Vec::new(),
            no_default_alpn: false,
            port: None,
            ipv4_hint: Vec::new(),
            ipv6_hint: Vec::new(),
            ech: None,
            mandatory: Vec::new(),
            unsupported_mandatory: Vec::new(),
            ttl: None,
        });
    }
    record_from_params(priority, target, &params)
}

fn record_from_params(
    priority: u16,
    target: String,
    params: &[SvcParam],
) -> Result<SvcbRecord, SvcbParseError> {
    let mut record = SvcbRecord {
        priority,
        target,
        alpn: Vec::new(),
        no_default_alpn: false,
        port: None,
        ipv4_hint: Vec::new(),
        ech: None,
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
                    return Err(SvcbParseError::NonEmptyNoDefaultAlpn);
                }
                record.no_default_alpn = true;
            }
            KEY_PORT => {
                if param.value.len() != 2 {
                    return Err(SvcbParseError::InvalidPortLength {
                        length: param.value.len(),
                    });
                }
                record.port = Some(u16::from_be_bytes([param.value[0], param.value[1]]));
            }
            KEY_IPV4HINT => {
                if param.value.is_empty() {
                    return Err(SvcbParseError::EmptyIpv4Hint);
                }
                if !param.value.len().is_multiple_of(4) {
                    return Err(SvcbParseError::InvalidIpv4HintLength {
                        length: param.value.len(),
                    });
                }
                record.ipv4_hint = param
                    .value
                    .chunks_exact(4)
                    .map(|chunk| Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]))
                    .collect();
            }
            KEY_ECH => {
                validate_ech_config_list(&param.value)?;
                record.ech = Some(param.value.clone());
            }
            KEY_IPV6HINT => {
                if param.value.is_empty() {
                    return Err(SvcbParseError::EmptyIpv6Hint);
                }
                if !param.value.len().is_multiple_of(16) {
                    return Err(SvcbParseError::InvalidIpv6HintLength {
                        length: param.value.len(),
                    });
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

    if record.no_default_alpn && record.alpn.is_empty() {
        return Err(SvcbParseError::NoDefaultAlpnWithoutAlpn);
    }
    for key in &record.mandatory {
        if params.binary_search_by_key(key, |param| param.key).is_err() {
            return Err(SvcbParseError::MissingMandatoryParam { key: *key });
        }
    }
    record.unsupported_mandatory = record
        .mandatory
        .iter()
        .copied()
        .filter(|key| !SUPPORTED_MANDATORY_KEYS.contains(key))
        .collect();
    Ok(record)
}

fn parse_mandatory(value: &[u8]) -> Result<Vec<u16>, SvcbParseError> {
    if value.is_empty() {
        return Err(SvcbParseError::EmptyMandatory);
    }
    if !value.len().is_multiple_of(2) {
        return Err(SvcbParseError::InvalidMandatoryLength {
            length: value.len(),
        });
    }
    let mut keys = Vec::with_capacity(value.len() / 2);
    for chunk in value.chunks_exact(2) {
        let key = u16::from_be_bytes([chunk[0], chunk[1]]);
        if key == KEY_MANDATORY {
            return Err(SvcbParseError::MandatoryKeyZero);
        }
        if let Some(previous) = keys.last().copied() {
            if key == previous {
                return Err(SvcbParseError::DuplicateMandatoryKey { key });
            }
            if key < previous {
                return Err(SvcbParseError::OutOfOrderMandatoryKey { previous, key });
            }
        }
        keys.push(key);
    }
    Ok(keys)
}

fn parse_alpn(value: &[u8]) -> Result<Vec<Vec<u8>>, SvcbParseError> {
    if value.is_empty() {
        return Err(SvcbParseError::EmptyAlpn);
    }
    let mut alpns = Vec::new();
    let mut offset = 0;
    while offset < value.len() {
        let len = usize::from(value[offset]);
        offset += 1;
        if len == 0 {
            return Err(SvcbParseError::EmptyAlpnId);
        }
        if offset + len > value.len() {
            return Err(SvcbParseError::TruncatedAlpnId {
                expected: len,
                actual: value.len() - offset,
            });
        }
        alpns.push(value[offset..offset + len].to_vec());
        offset += len;
    }
    Ok(alpns)
}

fn validate_ech_config_list(value: &[u8]) -> Result<(), SvcbParseError> {
    let Some(length) = value
        .get(..2)
        .map(|bytes| usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))
    else {
        return Err(SvcbParseError::InvalidEchConfigListLength {
            declared: None,
            actual: value.len(),
        });
    };
    let actual = value.len() - 2;
    if length != actual {
        return Err(SvcbParseError::InvalidEchConfigListLength {
            declared: Some(length),
            actual,
        });
    }
    if length == 0 {
        return Err(SvcbParseError::EmptyEchConfigList);
    }

    let mut offset = 2;
    while offset < value.len() {
        let remaining = value.len() - offset;
        if remaining < 4 {
            return Err(SvcbParseError::TruncatedEchConfigHeader {
                offset: offset - 2,
                actual: remaining,
            });
        }
        let version = u16::from_be_bytes([value[offset], value[offset + 1]]);
        let contents_len = usize::from(u16::from_be_bytes([value[offset + 2], value[offset + 3]]));
        let config_offset = offset - 2;
        offset += 4;
        let remaining = value.len() - offset;
        if contents_len > remaining {
            return Err(SvcbParseError::TruncatedEchConfig {
                offset: config_offset,
                expected: contents_len,
                actual: remaining,
            });
        }
        if version == 0xfe0d {
            validate_ech_config_contents(&value[offset..offset + contents_len])?;
        }
        offset += contents_len;
    }
    Ok(())
}

fn validate_ech_config_contents(value: &[u8]) -> Result<(), SvcbParseError> {
    let mut offset = 0;
    take_ech_bytes(value, &mut offset, 1, "missing config_id")?;
    take_ech_bytes(value, &mut offset, 2, "missing kem_id")?;

    let public_key_len = read_ech_u16(value, &mut offset, "missing public_key length")?;
    if public_key_len == 0 {
        return Err(SvcbParseError::InvalidEchConfigContents(
            "public_key is empty",
        ));
    }
    take_ech_bytes(value, &mut offset, public_key_len, "truncated public_key")?;

    let suites_len = read_ech_u16(value, &mut offset, "missing cipher suite list length")?;
    if suites_len == 0 || !suites_len.is_multiple_of(4) {
        return Err(SvcbParseError::InvalidEchConfigContents(
            "cipher suite list length is not a nonzero multiple of 4",
        ));
    }
    take_ech_bytes(
        value,
        &mut offset,
        suites_len,
        "truncated cipher suite list",
    )?;
    take_ech_bytes(value, &mut offset, 1, "missing maximum_name_length")?;

    let public_name_len = usize::from(
        *take_ech_bytes(value, &mut offset, 1, "missing public_name length")?
            .first()
            .expect("one byte was requested"),
    );
    if public_name_len == 0 {
        return Err(SvcbParseError::InvalidEchConfigContents(
            "public_name is empty",
        ));
    }
    take_ech_bytes(value, &mut offset, public_name_len, "truncated public_name")?;

    let extensions_len = read_ech_u16(value, &mut offset, "missing extensions length")?;
    let extensions = take_ech_bytes(value, &mut offset, extensions_len, "truncated extensions")?;
    let mut extension_offset = 0;
    while extension_offset < extensions.len() {
        take_ech_bytes(
            extensions,
            &mut extension_offset,
            2,
            "truncated extension type",
        )?;
        let data_len = read_ech_u16(
            extensions,
            &mut extension_offset,
            "truncated extension length",
        )?;
        take_ech_bytes(
            extensions,
            &mut extension_offset,
            data_len,
            "truncated extension data",
        )?;
    }
    if offset != value.len() {
        return Err(SvcbParseError::InvalidEchConfigContents(
            "trailing bytes after extensions",
        ));
    }
    Ok(())
}

fn read_ech_u16(
    value: &[u8],
    offset: &mut usize,
    reason: &'static str,
) -> Result<usize, SvcbParseError> {
    let bytes = take_ech_bytes(value, offset, 2, reason)?;
    Ok(usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))
}

fn take_ech_bytes<'a>(
    value: &'a [u8],
    offset: &mut usize,
    length: usize,
    reason: &'static str,
) -> Result<&'a [u8], SvcbParseError> {
    let end = offset
        .checked_add(length)
        .filter(|end| *end <= value.len())
        .ok_or(SvcbParseError::InvalidEchConfigContents(reason))?;
    let bytes = &value[*offset..end];
    *offset = end;
    Ok(bytes)
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
) -> Result<HttpsLookup, FetchError> {
    lookup_https_records_with_doh_tls_config(resolver, host, timeout, None).await
}

pub(crate) async fn lookup_https_records_with_doh_tls_config(
    resolver: HttpsRecordResolver<'_>,
    host: &str,
    timeout: Option<Duration>,
    doh_tls_config: Option<rustls::ClientConfig>,
) -> Result<HttpsLookup, FetchError> {
    if host.parse::<IpAddr>().is_ok() {
        return Ok(HttpsLookup {
            records: Vec::new(),
            fallback_target: host.to_string(),
        });
    }

    let budget = TimeoutBudget::new(timeout);
    let custom_server = match resolver {
        HttpsRecordResolver::Custom(server) => Some(crate::dns::custom::parse_dns_server(server)?),
        HttpsRecordResolver::System => None,
    };
    let original = canonical_host(host);
    let mut current = original.clone();
    let mut visited = std::collections::HashSet::new();
    let mut alias_ttl = None;

    for depth in 0..=MAX_ALIAS_CHAIN_DEPTH {
        if !visited.insert(current.clone()) {
            return Ok(HttpsLookup {
                records: Vec::new(),
                fallback_target: original,
            });
        }

        let mut records = match &custom_server {
            Some(server) => {
                let records = crate::dns::custom::query_type(
                    server,
                    &current,
                    DNS_TYPE_HTTPS,
                    "HTTPS",
                    budget,
                    doh_tls_config.clone(),
                )
                .await?;
                svcb_records_from_query(records)?
            }
            None => system::lookup_https_records(&current, budget).await?,
        };

        let aliases = records
            .iter()
            .filter(|record| record.is_alias_mode())
            .collect::<Vec<_>>();
        if aliases.is_empty() {
            for record in &mut records {
                if let Some(limit) = alias_ttl {
                    record.ttl = record.ttl.map(|ttl| ttl.min(limit));
                }
                if record.target == "." {
                    record.target = dns_name(&current);
                }
            }
            return Ok(HttpsLookup {
                records,
                fallback_target: current,
            });
        }
        if depth == MAX_ALIAS_CHAIN_DEPTH {
            return Ok(HttpsLookup {
                records: Vec::new(),
                fallback_target: original,
            });
        }

        // RFC 9460 section 2.4.2 requires ServiceMode records to be ignored
        // when AliasMode records are present. Multiple AliasMode records are
        // discouraged, but clients select one rather than rejecting the set.
        let alias = aliases[rand::random_range(0..aliases.len())];
        let target = canonical_host(&alias.target);
        if target.is_empty() || target == "." {
            return Err(FetchError::Runtime(
                "invalid HTTPS DNS AliasMode target".to_string(),
            ));
        }
        if let Some(ttl) = alias.ttl {
            alias_ttl = Some(alias_ttl.map_or(ttl, |limit: u32| limit.min(ttl)));
        }
        current = target;
    }

    unreachable!("alias depth is bounded by the loop")
}

fn canonical_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn dns_name(host: &str) -> String {
    format!("{}.", host.trim_end_matches('.'))
}

pub(super) fn svcb_records_from_query(
    records: Vec<crate::dns::custom::DnsQueryRecord>,
) -> Result<Vec<SvcbRecord>, FetchError> {
    records
        .into_iter()
        .filter(|record| record.typ == DNS_TYPE_HTTPS)
        .map(|record| {
            let raw = match record.data {
                DnsRecordData::Wire(raw) => raw,
                DnsRecordData::Text(text) => parse_generic_rdata(&text).ok_or_else(|| {
                    FetchError::Runtime("malformed HTTPS DNS record data".to_string())
                })?,
            };
            let mut parsed = parse_rdata(&raw).map_err(|err| {
                FetchError::Runtime(format!("malformed HTTPS DNS record data: {err}"))
            })?;
            parsed.ttl = record.ttl;
            Ok(parsed)
        })
        .collect()
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
        KEY_ALPN => match parse_alpn(value).and_then(|alpns| {
            alpns
                .into_iter()
                .map(|alpn| String::from_utf8(alpn).map_err(|_| SvcbParseError::EmptyAlpn))
                .collect::<Result<Vec<_>, _>>()
        }) {
            Ok(alpns) => format!("ALPN={}", alpns.join(",")),
            Err(_) => format!("ALPN=0x{}", hex_encode(value)),
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
        KEY_ECH => format!(
            "ECH={}",
            base64::engine::general_purpose::STANDARD.encode(value)
        ),
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
    use std::io::{Read, Write};
    use std::net::{TcpListener, UdpSocket};
    use std::thread;

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

    type AliasAnswers = Vec<(String, Vec<(u32, Vec<u8>)>)>;

    fn start_udp_alias_server(
        answers: AliasAnswers,
    ) -> (std::net::SocketAddr, thread::JoinHandle<()>) {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let addr = socket.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut raw = [0u8; 2048];
            for (expected_name, records) in answers {
                let (len, peer) = socket.recv_from(&mut raw).unwrap();
                let query = &raw[..len];
                let mut offset = 12;
                let mut labels = Vec::new();
                while query[offset] != 0 {
                    let label_len = usize::from(query[offset]);
                    offset += 1;
                    labels.push(std::str::from_utf8(&query[offset..offset + label_len]).unwrap());
                    offset += label_len;
                }
                offset += 1;
                assert_eq!(labels.join("."), expected_name);
                assert_eq!(
                    u16::from_be_bytes([query[offset], query[offset + 1]]),
                    DNS_TYPE_HTTPS
                );
                let question_end = offset + 4;

                let mut response = Vec::new();
                response.extend_from_slice(&query[..2]);
                response.extend_from_slice(&0x8180u16.to_be_bytes());
                response.extend_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&(records.len() as u16).to_be_bytes());
                response.extend_from_slice(&0u32.to_be_bytes());
                response.extend_from_slice(&query[12..question_end]);
                for (ttl, rdata) in records {
                    response.extend_from_slice(&[0xc0, 0x0c]);
                    response.extend_from_slice(&DNS_TYPE_HTTPS.to_be_bytes());
                    response.extend_from_slice(&wire::CLASS_IN.to_be_bytes());
                    response.extend_from_slice(&ttl.to_be_bytes());
                    response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                    response.extend_from_slice(&rdata);
                }
                socket.send_to(&response, peer).unwrap();
            }
        });
        (addr, handle)
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
        assert_eq!(got.alpn, [b"h3".to_vec()]);
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
                param(9, &[]),
            ],
        );

        let got = parse_rdata(&raw).unwrap();

        assert_eq!(got.mandatory, [1, 9]);
        assert_eq!(got.unsupported_mandatory, [9]);
        assert!(!got.is_usable());
    }

    #[test]
    fn rejects_malformed_records() {
        assert_eq!(parse_rdata(&[0, 1]), Err(SvcbParseError::ShortRdata));

        let bad_alpn = record(1, &[], vec![param(KEY_ALPN, &[3, b'h', b'3'])]);
        assert!(matches!(
            parse_rdata(&bad_alpn),
            Err(SvcbParseError::TruncatedAlpnId { .. })
        ));

        let bad_port = record(1, &[], vec![param(KEY_PORT, &[1])]);
        assert_eq!(
            parse_rdata(&bad_port),
            Err(SvcbParseError::InvalidPortLength { length: 1 })
        );
    }

    #[test]
    fn rejects_invalid_svcparams_with_detailed_errors() {
        let cases = [
            (
                "duplicate SvcParam",
                record(
                    1,
                    &[],
                    vec![
                        param(KEY_ALPN, &[2, b'h', b'3']),
                        param(KEY_ALPN, &[2, b'h', b'2']),
                    ],
                ),
                SvcbParseError::DuplicateParam { key: KEY_ALPN },
            ),
            (
                "descending SvcParams",
                record(
                    1,
                    &[],
                    vec![
                        param(KEY_PORT, &[1, 187]),
                        param(KEY_ALPN, &[2, b'h', b'3']),
                    ],
                ),
                SvcbParseError::OutOfOrderParam {
                    previous: KEY_PORT,
                    key: KEY_ALPN,
                },
            ),
            (
                "empty mandatory",
                record(1, &[], vec![param(KEY_MANDATORY, &[])]),
                SvcbParseError::EmptyMandatory,
            ),
            (
                "mandatory lists itself",
                record(1, &[], vec![param(KEY_MANDATORY, &[0, 0])]),
                SvcbParseError::MandatoryKeyZero,
            ),
            (
                "duplicate mandatory key",
                record(
                    1,
                    &[],
                    vec![
                        param(KEY_MANDATORY, &[0, 1, 0, 1]),
                        param(KEY_ALPN, &[2, b'h', b'3']),
                    ],
                ),
                SvcbParseError::DuplicateMandatoryKey { key: KEY_ALPN },
            ),
            (
                "descending mandatory keys",
                record(
                    1,
                    &[],
                    vec![
                        param(KEY_MANDATORY, &[0, 3, 0, 1]),
                        param(KEY_ALPN, &[2, b'h', b'3']),
                        param(KEY_PORT, &[1, 187]),
                    ],
                ),
                SvcbParseError::OutOfOrderMandatoryKey {
                    previous: KEY_PORT,
                    key: KEY_ALPN,
                },
            ),
            (
                "missing mandatory SvcParam",
                record(
                    1,
                    &[],
                    vec![
                        param(KEY_MANDATORY, &[0, 1, 0, 3]),
                        param(KEY_ALPN, &[2, b'h', b'3']),
                    ],
                ),
                SvcbParseError::MissingMandatoryParam { key: KEY_PORT },
            ),
            (
                "empty alpn",
                record(1, &[], vec![param(KEY_ALPN, &[])]),
                SvcbParseError::EmptyAlpn,
            ),
            (
                "no-default-alpn without alpn",
                record(1, &[], vec![param(KEY_NO_DEFAULT_ALPN, &[])]),
                SvcbParseError::NoDefaultAlpnWithoutAlpn,
            ),
            (
                "nonempty no-default-alpn",
                record(1, &[], vec![param(KEY_NO_DEFAULT_ALPN, &[1])]),
                SvcbParseError::NonEmptyNoDefaultAlpn,
            ),
            (
                "empty ipv4hint",
                record(1, &[], vec![param(KEY_IPV4HINT, &[])]),
                SvcbParseError::EmptyIpv4Hint,
            ),
            (
                "empty ech",
                record(1, &[], vec![param(KEY_ECH, &[])]),
                SvcbParseError::InvalidEchConfigListLength {
                    declared: None,
                    actual: 0,
                },
            ),
            (
                "empty ECHConfigList",
                record(1, &[], vec![param(KEY_ECH, &[0, 0])]),
                SvcbParseError::EmptyEchConfigList,
            ),
            (
                "truncated ECHConfig header",
                record(1, &[], vec![param(KEY_ECH, &[0, 3, 0xfe, 0x0d, 0])]),
                SvcbParseError::TruncatedEchConfigHeader {
                    offset: 0,
                    actual: 3,
                },
            ),
            (
                "truncated ECHConfig body",
                record(1, &[], vec![param(KEY_ECH, &[0, 5, 0xfe, 0x0d, 0, 2, 9])]),
                SvcbParseError::TruncatedEchConfig {
                    offset: 0,
                    expected: 2,
                    actual: 1,
                },
            ),
            (
                "empty ipv6hint",
                record(1, &[], vec![param(KEY_IPV6HINT, &[])]),
                SvcbParseError::EmptyIpv6Hint,
            ),
        ];

        for (label, raw, expected) in cases {
            assert_eq!(parse_rdata(&raw), Err(expected), "{label}");
        }
    }

    #[test]
    fn alias_mode_ignores_well_framed_svcparams() {
        let raw = record(
            0,
            &["alias", "example"],
            vec![param(KEY_NO_DEFAULT_ALPN, &[1])],
        );

        let parsed = parse_rdata(&raw).unwrap();

        assert!(parsed.is_alias_mode());
        assert_eq!(parsed.target, "alias.example.");
        assert!(!parsed.no_default_alpn);
    }

    #[test]
    fn accepts_framed_ech_config_list() {
        let contents = [
            0, // config_id
            0, 0x20, // kem_id
            0, 1, 7, // public_key
            0, 4, 0, 1, 0, 1, // cipher suites
            0, // maximum_name_length
            1, b'x', // public_name
            0, 0, // extensions
        ];
        let mut value = Vec::new();
        value.extend_from_slice(&((contents.len() + 4) as u16).to_be_bytes());
        value.extend_from_slice(&0xfe0d_u16.to_be_bytes());
        value.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        value.extend_from_slice(&contents);
        let raw = record(1, &[], vec![param(KEY_ECH, &value)]);

        assert_eq!(
            parse_rdata(&raw).unwrap().ech.as_deref(),
            Some(value.as_slice())
        );
    }

    #[test]
    fn accepts_opaque_alpn_protocol_ids() {
        let raw = record(1, &[], vec![param(KEY_ALPN, &[1, 0xff])]);

        assert_eq!(parse_rdata(&raw).unwrap().alpn, [vec![0xff]]);
    }

    #[test]
    fn accepts_repeated_alpn_protocol_ids() {
        let raw = record(
            1,
            &[],
            vec![param(KEY_ALPN, &[2, b'h', b'3', 2, b'h', b'3'])],
        );

        assert_eq!(
            parse_rdata(&raw).unwrap().alpn,
            [b"h3".to_vec(), b"h3".to_vec()]
        );
    }

    #[test]
    fn accepts_self_consistent_alpn_parameters() {
        let raw = record(
            1,
            &[],
            vec![
                param(KEY_ALPN, &[2, b'h', b'3']),
                param(KEY_NO_DEFAULT_ALPN, &[]),
            ],
        );

        let parsed = parse_rdata(&raw).unwrap();

        assert_eq!(parsed.alpn, [b"h3".to_vec()]);
        assert!(parsed.no_default_alpn);
    }

    #[test]
    fn malformed_https_record_rejects_the_entire_rrset() {
        let valid = record(1, &[], vec![param(KEY_ALPN, &[2, b'h', b'3'])]);
        let malformed = record(
            2,
            &[],
            vec![
                param(KEY_ALPN, &[2, b'h', b'3']),
                param(KEY_ALPN, &[2, b'h', b'2']),
            ],
        );
        let result = svcb_records_from_query(vec![
            crate::dns::custom::DnsQueryRecord {
                typ: DNS_TYPE_HTTPS,
                ttl: Some(60),
                data: DnsRecordData::Wire(valid),
            },
            crate::dns::custom::DnsQueryRecord {
                typ: DNS_TYPE_HTTPS,
                ttl: Some(60),
                data: DnsRecordData::Wire(malformed),
            },
        ]);

        let error = result.unwrap_err().to_string();
        assert!(error.contains("malformed HTTPS"), "{error}");
        assert!(error.contains("key 1 is repeated"), "{error}");
    }

    #[tokio::test]
    async fn custom_tcp_lookup_returns_https_records() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut len = [0u8; 2];
            stream.read_exact(&mut len).unwrap();
            let mut query = vec![0u8; usize::from(u16::from_be_bytes(len))];
            stream.read_exact(&mut query).unwrap();
            let question_end = query
                .iter()
                .enumerate()
                .skip(12)
                .find_map(|(index, byte)| (*byte == 0).then_some(index + 5))
                .unwrap();
            let rdata = record(
                1,
                &[],
                vec![
                    param(KEY_ALPN, &[2, b'h', b'3']),
                    param(KEY_PORT, &8443u16.to_be_bytes()),
                ],
            );
            let mut response = Vec::new();
            response.extend_from_slice(&query[..2]);
            response.extend_from_slice(&0x8180u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&0u32.to_be_bytes());
            response.extend_from_slice(&query[12..question_end]);
            response.extend_from_slice(&[0xc0, 0x0c]);
            response.extend_from_slice(&DNS_TYPE_HTTPS.to_be_bytes());
            response.extend_from_slice(&wire::CLASS_IN.to_be_bytes());
            response.extend_from_slice(&30u32.to_be_bytes());
            response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            response.extend_from_slice(&rdata);
            stream
                .write_all(&(response.len() as u16).to_be_bytes())
                .unwrap();
            stream.write_all(&response).unwrap();
        });

        let server = format!("tcp://{addr}");
        let records = lookup_https_records(
            HttpsRecordResolver::Custom(&server),
            "example.com",
            Some(Duration::from_secs(1)),
        )
        .await
        .unwrap();

        assert_eq!(records.records.len(), 1);
        assert_eq!(records.records[0].port, Some(8443));
        assert_eq!(records.records[0].ttl, Some(30));
        handle.join().unwrap();
    }

    #[tokio::test]
    async fn follows_alias_mode_and_returns_final_service_records() {
        let (addr, server) = start_udp_alias_server(vec![
            (
                "example.com".to_string(),
                vec![(20, record(0, &["svc", "example"], Vec::new()))],
            ),
            (
                "svc.example".to_string(),
                vec![(60, record(1, &[], vec![param(KEY_ALPN, &[2, b'h', b'3'])]))],
            ),
        ]);

        let lookup = lookup_https_records(
            HttpsRecordResolver::Custom(&addr.to_string()),
            "EXAMPLE.com.",
            Some(Duration::from_secs(1)),
        )
        .await
        .unwrap();

        assert_eq!(lookup.fallback_target, "svc.example");
        assert_eq!(lookup.records.len(), 1);
        assert_eq!(lookup.records[0].target, "svc.example.");
        assert_eq!(lookup.records[0].ttl, Some(20));
        assert!(!lookup.records[0].is_alias_mode());
        server.join().unwrap();
    }

    #[tokio::test]
    async fn alias_target_nodata_returns_the_effective_fallback_target() {
        let (addr, server) = start_udp_alias_server(vec![
            (
                "example.com".to_string(),
                vec![(60, record(0, &["fallback", "example"], Vec::new()))],
            ),
            ("fallback.example".to_string(), Vec::new()),
        ]);

        let lookup = lookup_https_records(
            HttpsRecordResolver::Custom(&addr.to_string()),
            "example.com",
            Some(Duration::from_secs(1)),
        )
        .await
        .unwrap();

        assert!(lookup.records.is_empty());
        assert_eq!(lookup.fallback_target, "fallback.example");
        server.join().unwrap();
    }

    #[tokio::test]
    async fn alias_queries_share_the_remaining_timeout() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut raw = [0u8; 2048];
            let (len, peer) = socket.recv_from(&mut raw).unwrap();
            let query = &raw[..len];
            let question_end = query[12..]
                .iter()
                .position(|byte| *byte == 0)
                .map(|offset| offset + 17)
                .unwrap();
            let alias = record(0, &["slow", "example"], Vec::new());
            let mut response = Vec::new();
            response.extend_from_slice(&query[..2]);
            response.extend_from_slice(&0x8180u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&0u32.to_be_bytes());
            response.extend_from_slice(&query[12..question_end]);
            response.extend_from_slice(&[0xc0, 0x0c]);
            response.extend_from_slice(&DNS_TYPE_HTTPS.to_be_bytes());
            response.extend_from_slice(&wire::CLASS_IN.to_be_bytes());
            response.extend_from_slice(&60u32.to_be_bytes());
            response.extend_from_slice(&(alias.len() as u16).to_be_bytes());
            response.extend_from_slice(&alias);
            socket.send_to(&response, peer).unwrap();

            let _ = socket.recv_from(&mut raw).unwrap();
            thread::sleep(Duration::from_millis(100));
        });
        let started = std::time::Instant::now();

        let err = lookup_https_records(
            HttpsRecordResolver::Custom(&addr.to_string()),
            "example.com",
            Some(Duration::from_millis(30)),
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_millis(90));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn alias_mode_loops_fall_back_to_the_original_name() {
        let (addr, server) = start_udp_alias_server(vec![
            (
                "a.example".to_string(),
                vec![(60, record(0, &["b", "example"], Vec::new()))],
            ),
            (
                "b.example".to_string(),
                vec![(60, record(0, &["A", "example"], Vec::new()))],
            ),
        ]);

        let lookup = lookup_https_records(
            HttpsRecordResolver::Custom(&addr.to_string()),
            "a.example",
            Some(Duration::from_secs(1)),
        )
        .await
        .unwrap();

        assert!(lookup.records.is_empty());
        assert_eq!(lookup.fallback_target, "a.example");
        server.join().unwrap();
    }

    #[tokio::test]
    async fn mixed_mode_rrset_ignores_service_records_and_follows_alias() {
        let (addr, server) = start_udp_alias_server(vec![
            (
                "example.com".to_string(),
                vec![
                    (60, record(1, &[], vec![param(KEY_ALPN, &[2, b'h', b'3'])])),
                    (60, record(0, &["alias", "example"], Vec::new())),
                ],
            ),
            (
                "alias.example".to_string(),
                vec![(30, record(1, &[], vec![param(KEY_ALPN, &[2, b'h', b'2'])]))],
            ),
        ]);

        let lookup = lookup_https_records(
            HttpsRecordResolver::Custom(&addr.to_string()),
            "example.com",
            Some(Duration::from_secs(1)),
        )
        .await
        .unwrap();

        assert_eq!(lookup.fallback_target, "alias.example");
        assert_eq!(lookup.records[0].alpn, [b"h2".to_vec()]);
        server.join().unwrap();
    }

    #[tokio::test]
    async fn multiple_alias_records_are_accepted() {
        let (addr, server) = start_udp_alias_server(vec![
            (
                "example.com".to_string(),
                vec![
                    (60, record(0, &["alias", "example"], Vec::new())),
                    (60, record(0, &["alias", "example"], Vec::new())),
                ],
            ),
            ("alias.example".to_string(), Vec::new()),
        ]);

        let lookup = lookup_https_records(
            HttpsRecordResolver::Custom(&addr.to_string()),
            "example.com",
            Some(Duration::from_secs(1)),
        )
        .await
        .unwrap();

        assert!(lookup.records.is_empty());
        assert_eq!(lookup.fallback_target, "alias.example");
        server.join().unwrap();
    }

    #[tokio::test]
    async fn alias_mode_depth_limit_falls_back_to_the_original_name() {
        let answers = (0..=MAX_ALIAS_CHAIN_DEPTH)
            .map(|index| {
                (
                    format!("n{index}.example"),
                    vec![(
                        60,
                        record(0, &[&format!("n{}", index + 1), "example"], Vec::new()),
                    )],
                )
            })
            .collect();
        let (addr, server) = start_udp_alias_server(answers);

        let lookup = lookup_https_records(
            HttpsRecordResolver::Custom(&addr.to_string()),
            "n0.example",
            Some(Duration::from_secs(1)),
        )
        .await
        .unwrap();

        assert!(lookup.records.is_empty());
        assert_eq!(lookup.fallback_target, "n0.example");
        server.join().unwrap();
    }

    #[tokio::test]
    async fn custom_tcp_nxdomain_is_a_completed_empty_lookup() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut len = [0u8; 2];
            stream.read_exact(&mut len).unwrap();
            let mut query = vec![0u8; usize::from(u16::from_be_bytes(len))];
            stream.read_exact(&mut query).unwrap();
            let question_end = query
                .iter()
                .enumerate()
                .skip(12)
                .find_map(|(index, byte)| (*byte == 0).then_some(index + 5))
                .unwrap();
            let mut response = Vec::new();
            response.extend_from_slice(&query[..2]);
            response.extend_from_slice(&0x8183u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&0u32.to_be_bytes());
            response.extend_from_slice(&query[12..question_end]);
            stream
                .write_all(&(response.len() as u16).to_be_bytes())
                .unwrap();
            stream.write_all(&response).unwrap();
        });

        let records = lookup_https_records(
            HttpsRecordResolver::Custom(&format!("tcp://{addr}")),
            "missing.example",
            Some(Duration::from_secs(1)),
        )
        .await
        .unwrap();

        assert!(records.records.is_empty());
        assert_eq!(records.fallback_target, "missing.example");
        handle.join().unwrap();
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

        assert!(records.records.is_empty());
        assert_eq!(records.fallback_target, "127.0.0.1");
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
