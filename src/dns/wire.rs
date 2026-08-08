use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::net::IpAddr;

pub(crate) const TYPE_A: u16 = 1;
pub(crate) const TYPE_NS: u16 = 2;
pub(crate) const TYPE_CNAME: u16 = 5;
pub(crate) const TYPE_SOA: u16 = 6;
pub(crate) const TYPE_MX: u16 = 15;
pub(crate) const TYPE_TXT: u16 = 16;
pub(crate) const TYPE_AAAA: u16 = 28;
pub(crate) const TYPE_SRV: u16 = 33;
pub(crate) const TYPE_RRSIG: u16 = 46;
pub(crate) const TYPE_SVCB: u16 = 64;
pub(crate) const TYPE_HTTPS: u16 = 65;
pub(crate) const TYPE_CAA: u16 = 257;
pub(crate) const TYPE_OPT: u16 = 41;
pub(crate) const CLASS_IN: u16 = 1;
pub(crate) const EDNS_UDP_PAYLOAD_SIZE: u16 = 1232;

const FLAG_RESPONSE: u16 = 0x8000;
const FLAG_OPCODE: u16 = 0x7800;
const FLAG_TRUNCATED: u16 = 0x0200;
const MAX_ANSWER_RECORDS: usize = 4096;
const MAX_CNAME_DEPTH: usize = 16;
const MAX_ENCODED_NAME_LEN: usize = 255;
const MAX_NAME_LABELS: usize = 127;
const MAX_NAME_POINTER_DEPTH: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WireError {
    Response(crate::dns::error::DnsErrorKind),
    Malformed(String),
    Other(String),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Response(kind) => kind.fmt(f),
            Self::Malformed(detail) => write!(f, "malformed DNS response: {detail}"),
            Self::Other(detail) => f.write_str(detail),
        }
    }
}

impl std::error::Error for WireError {}

impl WireError {
    fn other(message: String) -> Self {
        Self::Other(message)
    }

    fn malformed(message: impl Into<String>) -> Self {
        Self::Malformed(message.into())
    }

    pub(crate) fn kind(&self) -> crate::dns::error::DnsErrorKind {
        match self {
            Self::Response(kind) => *kind,
            Self::Malformed(_) => crate::dns::error::DnsErrorKind::Malformed,
            Self::Other(_) => crate::dns::error::DnsErrorKind::Other,
        }
    }

    pub(crate) fn is_truncated(&self) -> bool {
        self.kind() == crate::dns::error::DnsErrorKind::Truncated
    }

    fn into_response_error(self) -> Self {
        match self {
            Self::Other(detail) => Self::Malformed(detail),
            error => error,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ResourceRecord<'a> {
    canonical_name: CanonicalName,
    pub(crate) typ: u16,
    pub(crate) class: u16,
    pub(crate) ttl: u32,
    pub(crate) data_offset: usize,
    pub(crate) data: &'a [u8],
}

#[derive(Default)]
struct CnameOwner {
    cname_records: Vec<usize>,
    has_other_data: bool,
}

pub(crate) enum DecodedRdata<'a> {
    Address(IpAddr),
    Name(String),
    Text(String),
    Mx {
        preference: u16,
        exchange: String,
    },
    Soa {
        ns: String,
        mailbox: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Raw(&'a [u8]),
}

pub(crate) fn decode_rdata<'a>(
    packet: &'a [u8],
    typ: u16,
    offset: usize,
    len: usize,
) -> Result<DecodedRdata<'a>, WireError> {
    let end = offset
        .checked_add(len)
        .filter(|&end| end <= packet.len())
        .ok_or_else(|| WireError::other("short DNS resource".to_string()))?;
    let raw = &packet[offset..end];
    let mut reader = RdataReader {
        packet,
        pos: offset,
        end,
    };

    match typ {
        TYPE_A if len == 4 => Ok(DecodedRdata::Address(IpAddr::from([
            raw[0], raw[1], raw[2], raw[3],
        ]))),
        TYPE_A => Err(malformed_rdata(typ)),
        TYPE_AAAA if len == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(raw);
            Ok(DecodedRdata::Address(IpAddr::from(octets)))
        }
        TYPE_AAAA => Err(malformed_rdata(typ)),
        TYPE_CNAME | TYPE_NS => {
            let name = reader.read_name()?;
            reader.finish(typ)?;
            Ok(DecodedRdata::Name(name))
        }
        TYPE_TXT => Ok(DecodedRdata::Text(parse_txt_rdata(raw, typ)?)),
        TYPE_MX => {
            let preference = reader.read_u16()?;
            let exchange = reader.read_name()?;
            reader.finish(typ)?;
            Ok(DecodedRdata::Mx {
                preference,
                exchange,
            })
        }
        TYPE_SOA => {
            let ns = reader.read_name()?;
            let mailbox = reader.read_name()?;
            let serial = reader.read_u32()?;
            let refresh = reader.read_u32()?;
            let retry = reader.read_u32()?;
            let expire = reader.read_u32()?;
            let minimum = reader.read_u32()?;
            reader.finish(typ)?;
            Ok(DecodedRdata::Soa {
                ns,
                mailbox,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            })
        }
        TYPE_SRV => {
            let priority = reader.read_u16()?;
            let weight = reader.read_u16()?;
            let port = reader.read_u16()?;
            let target = reader.read_name()?;
            reader.finish(typ)?;
            Ok(DecodedRdata::Srv {
                priority,
                weight,
                port,
                target,
            })
        }
        TYPE_CAA if len >= 2 && usize::from(raw[1]) <= len - 2 => Ok(DecodedRdata::Raw(raw)),
        TYPE_CAA => Err(malformed_rdata(typ)),
        TYPE_SVCB | TYPE_HTTPS => crate::dns::svcb::parse_rdata(raw)
            .map(|_| DecodedRdata::Raw(raw))
            .map_err(|err| WireError::other(format!("malformed DNS RDATA for type {typ}: {err}"))),
        _ => Ok(DecodedRdata::Raw(raw)),
    }
}

struct RdataReader<'a> {
    packet: &'a [u8],
    pos: usize,
    end: usize,
}

impl RdataReader<'_> {
    fn read_u16(&mut self) -> Result<u16, WireError> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, WireError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_name(&mut self) -> Result<String, WireError> {
        let (name, next) = read_name_bounded(self.packet, self.pos, self.end)?;
        self.pos = next;
        Ok(name)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&[u8], WireError> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|&end| end <= self.end)
            .ok_or_else(|| WireError::other("short DNS RDATA".to_string()))?;
        let bytes = &self.packet[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }

    fn finish(&self, typ: u16) -> Result<(), WireError> {
        if self.pos == self.end {
            Ok(())
        } else {
            Err(malformed_rdata(typ))
        }
    }
}

pub(crate) fn malformed_rdata(typ: u16) -> WireError {
    WireError::malformed(format!("DNS RDATA for type {typ}"))
}

fn parse_txt_rdata(raw: &[u8], typ: u16) -> Result<String, WireError> {
    if raw.is_empty() {
        return Err(malformed_rdata(typ));
    }
    let mut parts = Vec::new();
    let mut offset = 0;
    while offset < raw.len() {
        let len = usize::from(raw[offset]);
        offset += 1;
        let end = offset
            .checked_add(len)
            .filter(|&end| end <= raw.len())
            .ok_or_else(|| malformed_rdata(typ))?;
        parts.push(String::from_utf8_lossy(&raw[offset..end]).into_owned());
        offset = end;
    }
    Ok(parts.join(" "))
}

pub(crate) fn build_query(id: u16, host: &str, dns_type: u16) -> Result<Vec<u8>, WireError> {
    let mut raw = Vec::with_capacity(512);
    raw.extend_from_slice(&id.to_be_bytes());
    raw.extend_from_slice(&0x0100u16.to_be_bytes());
    raw.extend_from_slice(&1u16.to_be_bytes());
    raw.extend_from_slice(&0u16.to_be_bytes());
    raw.extend_from_slice(&0u16.to_be_bytes());
    raw.extend_from_slice(&1u16.to_be_bytes());
    write_name(&mut raw, host)?;
    raw.extend_from_slice(&dns_type.to_be_bytes());
    raw.extend_from_slice(&CLASS_IN.to_be_bytes());
    write_opt_record(&mut raw);
    Ok(raw)
}

pub(crate) struct ResponseMatcher {
    id: u16,
    name: Option<CanonicalName>,
    typ: u16,
    class: u16,
}

impl ResponseMatcher {
    pub(crate) fn new(id: u16, name: &str, typ: u16, class: u16) -> Self {
        Self {
            id,
            name: parse_presentation_name(name).ok(),
            typ,
            class,
        }
    }

    pub(crate) fn matches(&self, raw: &[u8]) -> bool {
        if raw.len() < 12 || !read_u16(raw, 0).is_ok_and(|id| id == self.id) {
            return false;
        }
        let Ok(flags) = read_u16(raw, 2) else {
            return false;
        };
        if flags & FLAG_RESPONSE == 0 || flags & FLAG_OPCODE != 0 {
            return false;
        }
        let Ok(question_count) = read_u16(raw, 4) else {
            return false;
        };
        if question_count == 0 {
            // Some servers omit the question from an error response that they
            // could not parse. Parse all sections so an OPT-only extended
            // RCODE is also bound to this transaction.
            return parse_response(raw, self.id, ".", self.typ, self.class).is_err_and(|error| {
                !matches!(
                    error.kind(),
                    crate::dns::error::DnsErrorKind::Malformed
                        | crate::dns::error::DnsErrorKind::Other
                )
            });
        }
        if question_count != 1 {
            return false;
        }
        let Ok(question_name) = read_parsed_name_bounded(raw, 12, raw.len(), true) else {
            return false;
        };
        self.name
            .as_ref()
            .is_some_and(|expected| question_name.canonical == *expected)
            && read_u16(raw, question_name.next).is_ok_and(|typ| typ == self.typ)
            && read_u16(raw, question_name.next + 2).is_ok_and(|class| class == self.class)
    }
}

pub(crate) fn parse_response<'a>(
    raw: &'a [u8],
    expected_id: u16,
    expected_name: &str,
    expected_type: u16,
    expected_class: u16,
) -> Result<Vec<ResourceRecord<'a>>, WireError> {
    parse_response_inner(
        raw,
        Some(expected_id),
        expected_name,
        expected_type,
        expected_class,
    )
    .map_err(WireError::into_response_error)
}

#[cfg(test)]
pub(crate) fn parse_response_without_id<'a>(
    raw: &'a [u8],
    expected_name: &str,
    expected_type: u16,
    expected_class: u16,
) -> Result<Vec<ResourceRecord<'a>>, WireError> {
    parse_response_inner(raw, None, expected_name, expected_type, expected_class)
        .map_err(WireError::into_response_error)
}

#[cfg(target_os = "linux")]
pub(crate) fn parse_standalone_resource_record(
    raw: &[u8],
) -> Result<ResourceRecord<'_>, WireError> {
    let name = read_parsed_name_bounded(raw, 0, raw.len(), true)?;
    let offset = name.next;
    let typ = read_u16(raw, offset)?;
    let class = read_u16(raw, offset + 2)?;
    let ttl = read_u32(raw, offset + 4)?;
    let rdlen = usize::from(read_u16(raw, offset + 8)?);
    let data_offset = offset + 10;
    let end = data_offset
        .checked_add(rdlen)
        .filter(|end| *end == raw.len())
        .ok_or_else(|| WireError::other("malformed standalone DNS resource".to_string()))?;
    Ok(ResourceRecord {
        canonical_name: name.canonical,
        typ,
        class,
        ttl,
        data_offset,
        data: &raw[data_offset..end],
    })
}

fn parse_response_inner<'a>(
    raw: &'a [u8],
    expected_id: Option<u16>,
    expected_name: &str,
    expected_type: u16,
    expected_class: u16,
) -> Result<Vec<ResourceRecord<'a>>, WireError> {
    if raw.len() < 12 {
        return Err(WireError::malformed("short header"));
    }
    if expected_id.is_some_and(|expected_id| read_u16(raw, 0).is_ok_and(|id| id != expected_id)) {
        return Err(WireError::malformed("mismatched response ID"));
    }
    let flags = read_u16(raw, 2)?;
    if flags & FLAG_RESPONSE == 0 {
        return Err(WireError::malformed("message is not a response"));
    }
    if flags & FLAG_OPCODE != 0 {
        return Err(WireError::malformed("unexpected response opcode"));
    }
    if flags & FLAG_TRUNCATED != 0 {
        return Err(WireError::Response(
            crate::dns::error::DnsErrorKind::Truncated,
        ));
    }

    let question_count = usize::from(read_u16(raw, 4)?);
    let answer_count = usize::from(read_u16(raw, 6)?);
    let authority_count = usize::from(read_u16(raw, 8)?);
    let additional_count = usize::from(read_u16(raw, 10)?);
    if question_count > 1 {
        return Err(WireError::malformed("unexpected question count"));
    }
    let record_count = answer_count
        .checked_add(authority_count)
        .and_then(|count| count.checked_add(additional_count))
        .filter(|count| *count <= MAX_ANSWER_RECORDS)
        .ok_or_else(|| WireError::malformed("too many resource records"))?;

    let mut offset = 12;
    let expected_canonical = parse_presentation_name(expected_name)?;
    if question_count == 1 {
        let question_name = read_parsed_name_bounded(raw, offset, raw.len(), true)?;
        offset = question_name.next;
        let question_type = read_u16(raw, offset)?;
        let question_class = read_u16(raw, offset + 2)?;
        offset += 4;
        if question_name.canonical != expected_canonical
            || question_type != expected_type
            || question_class != expected_class
        {
            return Err(WireError::malformed("mismatched response question"));
        }
    }

    let mut records = Vec::with_capacity(answer_count);
    let mut extended_rcode = None;
    for index in 0..record_count {
        let name = read_parsed_name_bounded(raw, offset, raw.len(), true)?;
        offset = name.next;
        let typ = read_u16(raw, offset)?;
        let class = read_u16(raw, offset + 2)?;
        let ttl = read_u32(raw, offset + 4)?;
        let rdlen = usize::from(read_u16(raw, offset + 8)?);
        offset += 10;
        let end = offset
            .checked_add(rdlen)
            .filter(|end| *end <= raw.len())
            .ok_or_else(|| WireError::malformed("short resource record"))?;

        let in_answer = index < answer_count;
        let in_additional = index >= answer_count + authority_count;
        if typ == TYPE_OPT {
            if !in_additional || !name.canonical.0.is_empty() || extended_rcode.is_some() {
                return Err(WireError::malformed("invalid OPT record"));
            }
            extended_rcode = Some((ttl >> 24) as u8);
        } else if in_answer {
            records.push(ResourceRecord {
                canonical_name: name.canonical,
                typ,
                class,
                ttl,
                data_offset: offset,
                data: &raw[offset..end],
            });
        }
        offset = end;
    }
    if offset != raw.len() {
        return Err(WireError::malformed("trailing bytes"));
    }

    let rcode = (flags & 0x000f) | (u16::from(extended_rcode.unwrap_or(0)) << 4);
    if let Some(kind) = crate::dns::error::DnsErrorKind::from_rcode(rcode) {
        return Err(WireError::Response(kind));
    }
    if question_count == 0 {
        return Err(WireError::malformed(
            "successful response omitted the question",
        ));
    }

    let owners = records
        .iter()
        .map(|record| record.canonical_name.clone())
        .collect::<Vec<_>>();
    let types = records
        .iter()
        .map(|record| (record.class == expected_class).then_some(record.typ))
        .collect::<Vec<_>>();
    let reachable = reachable_answer_names(expected_canonical, &owners, &types, |index| {
        let cname = &records[index];
        let end = cname.data_offset + cname.data.len();
        let parsed = read_parsed_name_bounded(raw, cname.data_offset, end, true)?;
        if parsed.next != end {
            return Err(malformed_rdata(TYPE_CNAME));
        }
        Ok(parsed.canonical)
    })?;
    records.retain(|record| reachable.contains(&record.canonical_name));
    Ok(records)
}

#[cfg(test)]
pub(crate) fn read_name(packet: &[u8], offset: usize) -> Result<(String, usize), WireError> {
    read_name_bounded(packet, offset, packet.len())
}

fn read_name_bounded(
    packet: &[u8],
    offset: usize,
    end: usize,
) -> Result<(String, usize), WireError> {
    let name = read_parsed_name_bounded(packet, offset, end, true)?;
    Ok((name.presentation, name.next))
}

pub(crate) fn read_uncompressed_name(
    packet: &[u8],
    offset: usize,
    end: usize,
) -> Result<(String, usize), WireError> {
    let name = read_parsed_name_bounded(packet, offset, end, false)?;
    Ok((name.presentation, name.next))
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct CanonicalName(Vec<Vec<u8>>);

pub(crate) fn reachable_answer_names(
    expected: CanonicalName,
    owners: &[CanonicalName],
    types: &[Option<u16>],
    mut cname_target: impl FnMut(usize) -> Result<CanonicalName, WireError>,
) -> Result<HashSet<CanonicalName>, WireError> {
    assert_eq!(owners.len(), types.len());
    if owners.len() > MAX_ANSWER_RECORDS {
        return Err(WireError::other(
            "DNS response has too many answer records".to_string(),
        ));
    }

    // Index each owner once, then traverse only reachable CNAME owners. This
    // keeps reverse-ordered answers linear in the number of records.
    let mut cname_owners = HashMap::<CanonicalName, CnameOwner>::new();
    for (index, (owner_name, typ)) in owners.iter().zip(types).enumerate() {
        let Some(typ) = typ else {
            continue;
        };
        let owner = cname_owners.entry(owner_name.clone()).or_default();
        if *typ == TYPE_CNAME {
            owner.cname_records.push(index);
        } else if *typ != TYPE_RRSIG {
            owner.has_other_data = true;
        }
    }

    // Use canonical label bytes for authorization. Presentation strings can
    // map distinct invalid octets to the same text.
    let mut reachable = HashSet::from([expected.clone()]);
    let mut pending = VecDeque::from([expected]);
    let mut depth = 0;
    while let Some(owner_name) = pending.pop_front() {
        let Some(owner) = cname_owners.get(&owner_name) else {
            continue;
        };
        if owner.cname_records.is_empty() {
            continue;
        }
        if owner.has_other_data {
            return Err(WireError::other(
                "DNS CNAME owner has conflicting answer data".to_string(),
            ));
        }
        if depth == MAX_CNAME_DEPTH {
            return Err(WireError::other(
                "DNS CNAME chain exceeds depth limit".to_string(),
            ));
        }

        let mut target = None;
        for &index in &owner.cname_records {
            let parsed = cname_target(index)?;
            if target.as_ref().is_some_and(|prior| prior != &parsed) {
                return Err(WireError::other(
                    "DNS CNAME owner has conflicting targets".to_string(),
                ));
            }
            target = Some(parsed);
        }

        let target = target.expect("CNAME owner has at least one record");
        if !reachable.insert(target.clone()) {
            return Err(WireError::other(
                "DNS CNAME chain contains a cycle".to_string(),
            ));
        }
        pending.push_back(target);
        depth += 1;
    }
    Ok(reachable)
}

pub(crate) fn parse_presentation_name(name: &str) -> Result<CanonicalName, WireError> {
    if name == "." {
        return Ok(CanonicalName(Vec::new()));
    }
    if name.is_empty() {
        return Err(WireError::other("invalid DNS name".to_string()));
    }

    let bytes = name.as_bytes();
    let mut labels = Vec::new();
    let mut label = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        match bytes[offset] {
            b'.' => {
                if label.is_empty() {
                    return Err(WireError::other("invalid DNS name".to_string()));
                }
                labels.push(std::mem::take(&mut label));
                offset += 1;
                if offset == bytes.len() {
                    break;
                }
            }
            b'\\' => {
                offset += 1;
                if offset == bytes.len() {
                    return Err(WireError::other("invalid DNS name escape".to_string()));
                }
                if offset + 2 < bytes.len()
                    && bytes[offset..offset + 3].iter().all(u8::is_ascii_digit)
                {
                    let value = u16::from(bytes[offset] - b'0') * 100
                        + u16::from(bytes[offset + 1] - b'0') * 10
                        + u16::from(bytes[offset + 2] - b'0');
                    if value > u16::from(u8::MAX) {
                        return Err(WireError::other("invalid DNS name escape".to_string()));
                    }
                    label.push(value as u8);
                    offset += 3;
                } else {
                    label.push(bytes[offset]);
                    offset += 1;
                }
            }
            octet => {
                label.push(octet);
                offset += 1;
            }
        }
        if label.len() > 63 {
            return Err(WireError::other("invalid DNS name label".to_string()));
        }
    }
    if !label.is_empty() {
        labels.push(label);
    }
    if labels.is_empty()
        || labels.len() > MAX_NAME_LABELS
        || labels.iter().map(|label| label.len() + 1).sum::<usize>() + 1 > MAX_ENCODED_NAME_LEN
    {
        return Err(WireError::other("invalid DNS name".to_string()));
    }

    Ok(CanonicalName(
        labels
            .into_iter()
            .map(|label| label.into_iter().map(ascii_lowercase).collect())
            .collect(),
    ))
}

struct ParsedName {
    presentation: String,
    canonical: CanonicalName,
    next: usize,
}

fn read_parsed_name_bounded(
    packet: &[u8],
    offset: usize,
    end: usize,
    allow_compression: bool,
) -> Result<ParsedName, WireError> {
    if offset > end || end > packet.len() {
        return Err(WireError::other("short DNS name".to_string()));
    }
    let mut labels = Vec::new();
    let mut pos = offset;
    let mut next = offset;
    let mut jumped = false;
    let mut pointer_depth = 0usize;
    let mut expanded_len = 1usize; // Include the root terminator.

    loop {
        if pos >= packet.len() || (!jumped && pos >= end) {
            return Err(WireError::other("short DNS name".to_string()));
        }
        let len = packet[pos];
        if len & 0xc0 == 0xc0 {
            if !allow_compression {
                return Err(WireError::other(
                    "compressed DNS name is not allowed".to_string(),
                ));
            }
            if pos + 1 >= end {
                return Err(WireError::other("short DNS name pointer".to_string()));
            }
            if !jumped {
                next = pos + 2;
            }
            let pointer = usize::from(u16::from_be_bytes([len & 0x3f, packet[pos + 1]]));
            pos = pointer;
            jumped = true;
            pointer_depth += 1;
            if pointer_depth > MAX_NAME_POINTER_DEPTH {
                return Err(WireError::other(
                    "DNS name pointer depth exceeds limit".to_string(),
                ));
            }
            continue;
        }
        if len & 0xc0 != 0 {
            return Err(WireError::other("invalid DNS name label".to_string()));
        }
        pos += 1;
        if len == 0 {
            if !jumped {
                next = pos;
            }
            break;
        }
        let len = usize::from(len);
        if pos + len > end {
            return Err(WireError::other("short DNS name label".to_string()));
        }
        if labels.len() == MAX_NAME_LABELS {
            return Err(WireError::other(
                "DNS name exceeds label count limit".to_string(),
            ));
        }
        expanded_len += len + 1;
        if expanded_len > MAX_ENCODED_NAME_LEN {
            return Err(WireError::other(
                "DNS name exceeds expanded length limit".to_string(),
            ));
        }
        labels.push(packet[pos..pos + len].to_vec());
        pos += len;
        if !jumped {
            next = pos;
        }
    }

    let presentation = if labels.is_empty() {
        ".".to_string()
    } else {
        let labels = labels
            .iter()
            .map(|label| format_label(label))
            .collect::<Vec<_>>();
        format!("{}.", labels.join("."))
    };
    let canonical = CanonicalName(
        labels
            .into_iter()
            .map(|label| label.into_iter().map(ascii_lowercase).collect())
            .collect(),
    );
    Ok(ParsedName {
        presentation,
        canonical,
        next,
    })
}

fn ascii_lowercase(octet: u8) -> u8 {
    if octet.is_ascii_uppercase() {
        octet + (b'a' - b'A')
    } else {
        octet
    }
}

fn format_label(label: &[u8]) -> String {
    let mut output = String::new();
    for &octet in label {
        match octet {
            b'!'..=b'~' if octet != b'.' && octet != b'\\' => output.push(char::from(octet)),
            b'.' | b'\\' => {
                output.push('\\');
                output.push(char::from(octet));
            }
            _ => output.push_str(&format!("\\{octet:03}")),
        }
    }
    output
}

pub(crate) fn read_u16(raw: &[u8], offset: usize) -> Result<u16, WireError> {
    let bytes = raw
        .get(offset..offset + 2)
        .ok_or_else(|| WireError::other("short DNS message".to_string()))?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

pub(crate) fn read_u32(raw: &[u8], offset: usize) -> Result<u32, WireError> {
    let bytes = raw
        .get(offset..offset + 4)
        .ok_or_else(|| WireError::other("short DNS message".to_string()))?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(crate) fn write_name(raw: &mut Vec<u8>, host: &str) -> Result<(), WireError> {
    if host.is_empty() {
        return Err(WireError::other("invalid DNS name: empty name".to_string()));
    }
    if host == "." {
        raw.push(0);
        return Ok(());
    }
    let name = parse_presentation_name(host)
        .map_err(|_| WireError::other(format!("invalid DNS name: {host}")))?;
    for label in name.0 {
        raw.push(label.len() as u8);
        raw.extend_from_slice(&label);
    }
    raw.push(0);
    Ok(())
}

fn write_opt_record(raw: &mut Vec<u8>) {
    raw.push(0);
    raw.extend_from_slice(&TYPE_OPT.to_be_bytes());
    raw.extend_from_slice(&EDNS_UDP_PAYLOAD_SIZE.to_be_bytes());
    raw.extend_from_slice(&0u32.to_be_bytes());
    raw.extend_from_slice(&0u16.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_query_packet_as_response() {
        let query = build_query(0x1234, "example.com", TYPE_A).unwrap();
        let err = parse_response(&query, 0x1234, "example.com", TYPE_A, CLASS_IN).unwrap_err();
        assert_eq!(
            err.to_string(),
            "malformed DNS response: message is not a response"
        );
    }

    #[test]
    fn rejects_mismatched_response_question() {
        let mut response = build_query(0x1234, "other.example", TYPE_A).unwrap();
        response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        let err = parse_response(&response, 0x1234, "example.com", TYPE_A, CLASS_IN).unwrap_err();
        assert_eq!(
            err.to_string(),
            "malformed DNS response: mismatched response question"
        );
    }

    #[test]
    fn malformed_rdata_cannot_consume_adjacent_record() {
        let cases = [
            (TYPE_CNAME, vec![3, b'x']),
            (TYPE_NS, vec![3, b'x']),
            (TYPE_MX, vec![0, 10, 3, b'm']),
            (TYPE_SRV, vec![0, 1, 0, 2, 0, 3, 3, b's']),
            (TYPE_SOA, vec![1, b'n']),
            (TYPE_TXT, vec![3, b't']),
        ];

        for (typ, malformed) in cases {
            let query = build_query(0x1234, "example.com", typ).unwrap();
            let (_, question_end) = read_name(&query, 12).unwrap();
            let mut response = Vec::new();
            response.extend_from_slice(&0x1234u16.to_be_bytes());
            response.extend_from_slice(&0x8180u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&2u16.to_be_bytes());
            response.extend_from_slice(&[0, 0, 0, 0]);
            response.extend_from_slice(&query[12..question_end + 4]);
            let adjacent = match typ {
                TYPE_CNAME | TYPE_NS => vec![0],
                TYPE_MX => vec![0, 10, 0],
                TYPE_SRV => vec![0, 1, 0, 2, 0, 3, 0],
                TYPE_SOA => {
                    let mut data = vec![0, 0];
                    data.extend_from_slice(&[0; 20]);
                    data
                }
                TYPE_TXT => vec![0],
                _ => unreachable!(),
            };
            for data in [malformed, adjacent] {
                response.extend_from_slice(&[0xc0, 0x0c]);
                response.extend_from_slice(&typ.to_be_bytes());
                response.extend_from_slice(&CLASS_IN.to_be_bytes());
                response.extend_from_slice(&30u32.to_be_bytes());
                response.extend_from_slice(&(data.len() as u16).to_be_bytes());
                response.extend_from_slice(&data);
            }

            let records = parse_response_without_id(&response, "example.com", typ, CLASS_IN);
            if matches!(typ, TYPE_CNAME) {
                assert!(records.is_err(), "malformed {typ} RDATA was accepted");
                continue;
            }
            let records = records.unwrap();
            assert_eq!(records.len(), 2);
            assert!(
                decode_rdata(
                    &response,
                    records[0].typ,
                    records[0].data_offset,
                    records[0].data.len()
                )
                .is_err(),
                "malformed {typ} RDATA was accepted"
            );
            assert!(
                decode_rdata(
                    &response,
                    records[1].typ,
                    records[1].data_offset,
                    records[1].data.len()
                )
                .is_ok(),
                "adjacent {typ} RDATA was rejected"
            );
        }
    }

    #[test]
    fn bounded_rdata_decoder_rejects_extra_bytes_after_name() {
        let raw = [0, 0, 0xc0, 0x0c];

        assert!(decode_rdata(&raw, TYPE_CNAME, 0, raw.len()).is_err());
    }

    #[test]
    fn cname_with_trailing_rdata_cannot_authorize_address() {
        let response = response_with_answers(&[
            (encoded_name(b"example", b"com"), TYPE_CNAME, {
                let mut target = encoded_name(b"alias", b"example");
                target.push(0xff);
                target
            }),
            (
                encoded_name(b"alias", b"example"),
                TYPE_A,
                vec![192, 0, 2, 1],
            ),
        ]);

        let err = parse_response(&response, 0x1234, "example.com", TYPE_A, CLASS_IN).unwrap_err();
        assert!(err.to_string().contains("malformed DNS response"));
    }

    #[test]
    fn canonical_names_compare_label_bytes_without_lossy_utf8() {
        let response = response_with_answers(&[
            (
                encoded_name(b"example", b"com"),
                TYPE_CNAME,
                encoded_name(&[0xff], b"example"),
            ),
            (
                encoded_name(&[0xfe], b"example"),
                TYPE_A,
                vec![192, 0, 2, 1],
            ),
        ]);

        let records = parse_response(&response, 0x1234, "example.com", TYPE_A, CLASS_IN).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].typ, TYPE_CNAME);
        let (target, _) = read_name(&response, records[0].data_offset).unwrap();
        assert_eq!(target, r"\255.example.");
    }

    #[test]
    fn canonical_names_fold_ascii_case_only() {
        let response = response_with_answers(&[
            (
                encoded_name(b"EXAMPLE", b"COM"),
                TYPE_CNAME,
                encoded_name(b"Alias", b"Example"),
            ),
            (
                encoded_name(b"aLIAS", b"eXAMPLE"),
                TYPE_A,
                vec![192, 0, 2, 1],
            ),
        ]);

        let records = parse_response(&response, 0x1234, "example.com", TYPE_A, CLASS_IN).unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[1].typ, TYPE_A);
    }

    #[test]
    fn rejects_conflicting_cname_targets() {
        let response = response_with_answers(&[
            (
                encoded_name(b"example", b"com"),
                TYPE_CNAME,
                encoded_name(b"one", b"example"),
            ),
            (
                encoded_name(b"example", b"com"),
                TYPE_CNAME,
                encoded_name(b"two", b"example"),
            ),
            (encoded_name(b"one", b"example"), TYPE_A, vec![192, 0, 2, 1]),
        ]);

        let err = parse_response(&response, 0x1234, "example.com", TYPE_A, CLASS_IN).unwrap_err();
        assert!(err.to_string().contains("conflicting targets"));
    }

    #[test]
    fn rejects_cname_with_other_answer_data_at_owner() {
        let response = response_with_answers(&[
            (
                encoded_name(b"example", b"com"),
                TYPE_CNAME,
                encoded_name(b"alias", b"example"),
            ),
            (encoded_name(b"example", b"com"), TYPE_A, vec![192, 0, 2, 1]),
        ]);

        let err = parse_response(&response, 0x1234, "example.com", TYPE_A, CLASS_IN).unwrap_err();
        assert!(err.to_string().contains("conflicting answer data"));
    }

    #[test]
    fn rejects_cname_cycle_without_authorizing_unrelated_address() {
        let response = response_with_answers(&[
            (
                encoded_name(b"example", b"com"),
                TYPE_CNAME,
                encoded_name(b"alias", b"example"),
            ),
            (
                encoded_name(b"alias", b"example"),
                TYPE_CNAME,
                encoded_name(b"example", b"com"),
            ),
            (
                encoded_name(b"unrelated", b"example"),
                TYPE_A,
                vec![192, 0, 2, 1],
            ),
        ]);

        let err = parse_response(&response, 0x1234, "example.com", TYPE_A, CLASS_IN).unwrap_err();
        assert!(err.to_string().contains("contains a cycle"));
    }

    #[test]
    fn accepts_cname_chain_at_depth_limit() {
        let mut answers = cname_chain(MAX_CNAME_DEPTH);
        answers.push((chain_name(MAX_CNAME_DEPTH), TYPE_A, vec![192, 0, 2, 1]));
        let response = response_with_answers(&answers);

        let records = parse_response(&response, 0x1234, "example.com", TYPE_A, CLASS_IN).unwrap();

        assert_eq!(records.len(), MAX_CNAME_DEPTH + 1);
        assert_eq!(records.last().unwrap().typ, TYPE_A);
    }

    #[test]
    fn rejects_large_reverse_ordered_cname_chain_at_depth_limit() {
        let mut answers = cname_chain(MAX_ANSWER_RECORDS);
        answers.reverse();
        let response = response_with_answers(&answers);
        assert!(response.len() < 1024 * 1024);

        let err = parse_response(&response, 0x1234, "example.com", TYPE_A, CLASS_IN).unwrap_err();

        assert_eq!(
            err.to_string(),
            "malformed DNS response: DNS CNAME chain exceeds depth limit"
        );
    }

    #[test]
    fn rejects_excessive_answer_count_before_parsing_records() {
        let mut response = build_query(0x1234, "example.com", TYPE_A).unwrap();
        response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        response[6..8].copy_from_slice(&((MAX_ANSWER_RECORDS + 1) as u16).to_be_bytes());

        let err = parse_response(&response, 0x1234, "example.com", TYPE_A, CLASS_IN).unwrap_err();

        assert_eq!(
            err.to_string(),
            "malformed DNS response: too many resource records"
        );
    }

    fn cname_chain(depth: usize) -> Vec<(Vec<u8>, u16, Vec<u8>)> {
        (0..depth)
            .map(|index| (chain_name(index), TYPE_CNAME, chain_name(index + 1)))
            .collect()
    }

    fn chain_name(index: usize) -> Vec<u8> {
        if index == 0 {
            encoded_name(b"example", b"com")
        } else {
            encoded_name(format!("n{index}").as_bytes(), b"example")
        }
    }

    #[test]
    fn response_codes_are_structured_and_include_edns_extended_bits() {
        let cases: [(u16, crate::dns::error::DnsErrorKind); 7] = [
            (1, crate::dns::error::DnsErrorKind::FormErr),
            (2, crate::dns::error::DnsErrorKind::ServFail),
            (3, crate::dns::error::DnsErrorKind::NxDomain),
            (4, crate::dns::error::DnsErrorKind::NotImp),
            (5, crate::dns::error::DnsErrorKind::Refused),
            (16, crate::dns::error::DnsErrorKind::BadVers),
            (23, crate::dns::error::DnsErrorKind::OtherRcode(23)),
        ];

        for (rcode, expected) in cases {
            let query = build_query(0x1234, "example.com", TYPE_A).unwrap();
            let (_, question_end) = read_name(&query, 12).unwrap();
            let mut response = Vec::new();
            response.extend_from_slice(&0x1234u16.to_be_bytes());
            response.extend_from_slice(&(0x8180 | (rcode & 0x0f)).to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&query[12..question_end + 4]);
            response.push(0);
            response.extend_from_slice(&TYPE_OPT.to_be_bytes());
            response.extend_from_slice(&EDNS_UDP_PAYLOAD_SIZE.to_be_bytes());
            response.extend_from_slice(&(u32::from(rcode >> 4) << 24).to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());

            let error =
                parse_response(&response, 0x1234, "example.com", TYPE_A, CLASS_IN).unwrap_err();
            assert_eq!(error.kind(), expected, "RCODE {rcode}");
        }
    }

    #[test]
    fn error_response_can_omit_the_question() {
        let mut response = vec![0; 12];
        response[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
        response[2..4].copy_from_slice(&0x8181u16.to_be_bytes());

        let error = parse_response(&response, 0x1234, "example.com", TYPE_A, CLASS_IN).unwrap_err();
        assert_eq!(error.kind(), crate::dns::error::DnsErrorKind::FormErr);
        assert!(ResponseMatcher::new(0x1234, "example.com", TYPE_A, CLASS_IN).matches(&response));

        response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        response[10..12].copy_from_slice(&1u16.to_be_bytes());
        response.push(0);
        response.extend_from_slice(&TYPE_OPT.to_be_bytes());
        response.extend_from_slice(&EDNS_UDP_PAYLOAD_SIZE.to_be_bytes());
        response.extend_from_slice(&(1u32 << 24).to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        let error = parse_response(&response, 0x1234, "example.com", TYPE_A, CLASS_IN).unwrap_err();
        assert_eq!(error.kind(), crate::dns::error::DnsErrorKind::BadVers);
        assert!(ResponseMatcher::new(0x1234, "example.com", TYPE_A, CLASS_IN).matches(&response));
    }

    #[test]
    fn malformed_opt_records_are_rejected_before_rcode_classification() {
        for mutate in ["non-root owner", "duplicate"] {
            let query = build_query(0x1234, "example.com", TYPE_A).unwrap();
            let (_, question_end) = read_name(&query, 12).unwrap();
            let mut response = query[..question_end + 4].to_vec();
            response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            response[6..10].fill(0);
            response[10..12]
                .copy_from_slice(&(if mutate == "duplicate" { 2u16 } else { 1u16 }).to_be_bytes());
            let owner = if mutate == "non-root owner" {
                &[1, b'x', 0][..]
            } else {
                &[0][..]
            };
            for _ in 0..if mutate == "duplicate" { 2 } else { 1 } {
                response.extend_from_slice(owner);
                response.extend_from_slice(&TYPE_OPT.to_be_bytes());
                response.extend_from_slice(&EDNS_UDP_PAYLOAD_SIZE.to_be_bytes());
                response.extend_from_slice(&0u32.to_be_bytes());
                response.extend_from_slice(&0u16.to_be_bytes());
            }

            let error =
                parse_response(&response, 0x1234, "example.com", TYPE_A, CLASS_IN).unwrap_err();
            assert_eq!(error.kind(), crate::dns::error::DnsErrorKind::Malformed);
        }
    }

    fn response_with_answers(answers: &[(Vec<u8>, u16, Vec<u8>)]) -> Vec<u8> {
        let query = build_query(0x1234, "example.com", TYPE_A).unwrap();
        let (_, question_end) = read_name(&query, 12).unwrap();
        let mut response = Vec::new();
        response.extend_from_slice(&0x1234u16.to_be_bytes());
        response.extend_from_slice(&0x8180u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        response.extend_from_slice(&0u32.to_be_bytes());
        response.extend_from_slice(&query[12..question_end + 4]);
        for (owner, typ, data) in answers {
            response.extend_from_slice(owner);
            response.extend_from_slice(&typ.to_be_bytes());
            response.extend_from_slice(&CLASS_IN.to_be_bytes());
            response.extend_from_slice(&30u32.to_be_bytes());
            response.extend_from_slice(&(data.len() as u16).to_be_bytes());
            response.extend_from_slice(data);
        }
        response
    }

    fn encoded_name(first: &[u8], second: &[u8]) -> Vec<u8> {
        let mut name = Vec::new();
        for label in [first, second] {
            name.push(label.len() as u8);
            name.extend_from_slice(label);
        }
        name.push(0);
        name
    }

    fn name_with_label_lengths(lengths: &[usize]) -> String {
        lengths
            .iter()
            .map(|length| "a".repeat(*length))
            .collect::<Vec<_>>()
            .join(".")
    }

    fn encoded_labels(lengths: &[usize]) -> Vec<u8> {
        let mut raw = Vec::new();
        for &length in lengths {
            raw.push(length as u8);
            raw.extend(std::iter::repeat_n(b'a', length));
        }
        raw.push(0);
        raw
    }

    #[test]
    fn query_name_rejects_empty_name_and_accepts_root() {
        assert!(build_query(0x1234, "", TYPE_A).is_err());

        let mut response = build_query(0x1234, ".", TYPE_A).unwrap();
        response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        assert!(ResponseMatcher::new(0x1234, ".", TYPE_A, CLASS_IN).matches(&response));
        assert!(parse_response(&response, 0x1234, ".", TYPE_A, CLASS_IN).is_ok());
    }

    #[test]
    fn query_name_enforces_encoded_length_boundary() {
        let maximum = name_with_label_lengths(&[63, 63, 63, 61]);
        let too_long = name_with_label_lengths(&[63, 63, 63, 62]);

        assert!(build_query(0x1234, &maximum, TYPE_A).is_ok());
        let err = build_query(0x1234, &too_long, TYPE_A).unwrap_err();
        assert!(err.to_string().contains("invalid DNS name"));
    }

    #[test]
    fn query_name_rejects_too_many_labels() {
        let maximum = std::iter::repeat_n("a", MAX_NAME_LABELS)
            .collect::<Vec<_>>()
            .join(".");
        let too_many = format!("{maximum}.a");

        assert!(build_query(0x1234, &maximum, TYPE_A).is_ok());
        assert!(build_query(0x1234, &too_many, TYPE_A).is_err());
    }

    #[test]
    fn compressed_name_enforces_expanded_length_boundary() {
        let mut maximum = vec![0xc0, 0x02];
        maximum.extend_from_slice(&encoded_labels(&[63, 63, 63, 61]));
        let (name, next) = read_name(&maximum, 0).unwrap();
        assert_eq!(next, 2);
        assert_eq!(name.len(), 254);

        // Compression can replace the one-byte root terminator with a
        // two-byte pointer, so the compressed representation can use 256
        // octets while the expanded name remains at the 255-octet limit.
        let mut maximum_with_root_pointer = vec![0];
        maximum_with_root_pointer.extend_from_slice(&encoded_labels(&[63, 63, 63, 61])[..254]);
        maximum_with_root_pointer.extend_from_slice(&[0xc0, 0x00]);
        assert!(read_name(&maximum_with_root_pointer, 1).is_ok());

        let mut too_long = vec![0xc0, 0x02];
        too_long.extend_from_slice(&encoded_labels(&[63, 63, 63, 62]));
        let err = read_name(&too_long, 0).unwrap_err();
        assert!(err.to_string().contains("expanded length limit"));
    }

    #[test]
    fn parsed_name_enforces_label_count_limit() {
        let maximum = encoded_labels(&vec![1; MAX_NAME_LABELS]);
        assert!(read_name(&maximum, 0).is_ok());

        let too_many = encoded_labels(&vec![1; MAX_NAME_LABELS + 1]);
        let err = read_name(&too_many, 0).unwrap_err();
        assert!(err.to_string().contains("label count limit"));
    }

    #[test]
    fn escaped_query_name_matches_response_question() {
        let name = r"foo\.bar.\255.example.";
        let mut response = build_query(0x1234, name, TYPE_A).unwrap();
        response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());

        let matcher = ResponseMatcher::new(0x1234, name, TYPE_A, CLASS_IN);
        assert!(matcher.matches(&response));
        assert!(
            parse_response(&response, 0x1234, name, TYPE_A, CLASS_IN)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn presentation_name_round_trips_escaped_label_octets() {
        let encoded = [
            7, b'f', b'o', b'o', b'\\', b'b', b'a', b'r', 7, b'f', b'o', b'o', b'.', b'b', b'a',
            b'r', 0,
        ];
        let (presentation, next) = read_name(&encoded, 0).unwrap();
        assert_eq!(next, encoded.len());

        let mut round_trip = Vec::new();
        write_name(&mut round_trip, &presentation).unwrap();
        assert_eq!(round_trip, encoded);
    }

    #[test]
    fn compressed_name_enforces_pointer_depth_boundary() {
        let mut packet = vec![0];
        let mut starts = vec![0usize];
        for _ in 0..=MAX_NAME_POINTER_DEPTH {
            let target = *starts.last().unwrap() as u16;
            starts.push(packet.len());
            packet.extend_from_slice(&(0xc000 | target).to_be_bytes());
        }

        assert!(read_name(&packet, starts[MAX_NAME_POINTER_DEPTH]).is_ok());
        let err = read_name(&packet, starts[MAX_NAME_POINTER_DEPTH + 1]).unwrap_err();
        assert!(err.to_string().contains("pointer depth exceeds limit"));
    }

    #[test]
    fn build_query_advertises_edns0_udp_payload_size() {
        let query = build_query(0x1234, "example.com", TYPE_A).unwrap();

        assert_eq!(read_u16(&query, 4).unwrap(), 1);
        assert_eq!(read_u16(&query, 10).unwrap(), 1);

        let (_, question_end) = read_name(&query, 12).unwrap();
        let opt = question_end + 4;
        assert_eq!(query[opt], 0);
        assert_eq!(read_u16(&query, opt + 1).unwrap(), TYPE_OPT);
        assert_eq!(read_u16(&query, opt + 3).unwrap(), EDNS_UDP_PAYLOAD_SIZE);
        assert_eq!(read_u32(&query, opt + 5).unwrap(), 0);
        assert_eq!(read_u16(&query, opt + 9).unwrap(), 0);
        assert_eq!(opt + 11, query.len());
    }
}
