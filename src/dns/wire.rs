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
pub(crate) const TYPE_SVCB: u16 = 64;
pub(crate) const TYPE_HTTPS: u16 = 65;
pub(crate) const TYPE_CAA: u16 = 257;
pub(crate) const TYPE_OPT: u16 = 41;
pub(crate) const CLASS_IN: u16 = 1;
pub(crate) const EDNS_UDP_PAYLOAD_SIZE: u16 = 1232;

const TRUNCATED_RESPONSE: &str = "DNS response was truncated";
const FLAG_RESPONSE: u16 = 0x8000;
const FLAG_OPCODE: u16 = 0x7800;
const FLAG_TRUNCATED: u16 = 0x0200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WireError(String);

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WireError {}

impl WireError {
    pub(crate) fn is_truncated(&self) -> bool {
        self.0 == TRUNCATED_RESPONSE
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ResourceRecord<'a> {
    pub(crate) name: String,
    pub(crate) typ: u16,
    pub(crate) class: u16,
    pub(crate) ttl: u32,
    pub(crate) data_offset: usize,
    pub(crate) data: &'a [u8],
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
        .ok_or_else(|| WireError("short DNS resource".to_string()))?;
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
        TYPE_SVCB | TYPE_HTTPS if crate::dns::svcb::parse_rdata(raw).is_some() => {
            Ok(DecodedRdata::Raw(raw))
        }
        TYPE_SVCB | TYPE_HTTPS => Err(malformed_rdata(typ)),
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
            .ok_or_else(|| WireError("short DNS RDATA".to_string()))?;
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

fn malformed_rdata(typ: u16) -> WireError {
    WireError(format!("malformed DNS RDATA for type {typ}"))
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
}

#[cfg(test)]
pub(crate) fn parse_response_without_id<'a>(
    raw: &'a [u8],
    expected_name: &str,
    expected_type: u16,
    expected_class: u16,
) -> Result<Vec<ResourceRecord<'a>>, WireError> {
    parse_response_inner(raw, None, expected_name, expected_type, expected_class)
}

fn parse_response_inner<'a>(
    raw: &'a [u8],
    expected_id: Option<u16>,
    expected_name: &str,
    expected_type: u16,
    expected_class: u16,
) -> Result<Vec<ResourceRecord<'a>>, WireError> {
    if raw.len() < 12 {
        return Err(WireError("short DNS response".to_string()));
    }
    if expected_id.is_some_and(|expected_id| read_u16(raw, 0).is_ok_and(|id| id != expected_id)) {
        return Err(WireError("mismatched DNS response ID".to_string()));
    }
    let flags = read_u16(raw, 2)?;
    if flags & FLAG_RESPONSE == 0 {
        return Err(WireError("DNS message is not a response".to_string()));
    }
    if flags & FLAG_OPCODE != 0 {
        return Err(WireError("unexpected DNS response opcode".to_string()));
    }
    if flags & FLAG_TRUNCATED != 0 {
        return Err(WireError(TRUNCATED_RESPONSE.to_string()));
    }
    let rcode = i32::from(flags & 0x000f);
    if rcode != 0 {
        let name = rcode_name(rcode);
        if name.is_empty() {
            return Err(WireError("no such host".to_string()));
        }
        return Err(WireError(format!("no such host: {name}")));
    }

    let question_count = usize::from(read_u16(raw, 4)?);
    let answer_count = usize::from(read_u16(raw, 6)?);
    if question_count != 1 {
        return Err(WireError("unexpected DNS question count".to_string()));
    }
    let mut offset = 12;
    let (question_name, next) = read_name(raw, offset)?;
    offset = next;
    let question_type = read_u16(raw, offset)?;
    let question_class = read_u16(raw, offset + 2)?;
    offset += 4;
    if !names_equal(&question_name, expected_name)
        || question_type != expected_type
        || question_class != expected_class
    {
        return Err(WireError("mismatched DNS response question".to_string()));
    }

    let mut records = Vec::new();
    for _ in 0..answer_count {
        let (name, next) = read_name(raw, offset)?;
        offset = next;
        let typ = read_u16(raw, offset)?;
        let class = read_u16(raw, offset + 2)?;
        let ttl = read_u32(raw, offset + 4)?;
        let rdlen = usize::from(read_u16(raw, offset + 8)?);
        offset += 10;
        if offset + rdlen > raw.len() {
            return Err(WireError("short DNS resource".to_string()));
        }
        let data_offset = offset;
        offset += rdlen;
        records.push(ResourceRecord {
            name,
            typ,
            class,
            ttl,
            data_offset,
            data: &raw[data_offset..data_offset + rdlen],
        });
    }

    // Answer records are relevant only when their owner is the queried name or
    // is reachable from it through an IN-class CNAME chain. Records can appear
    // in any order, so expand the reachable set to a fixed point first.
    let mut reachable = vec![expected_name.to_string()];
    loop {
        let mut changed = false;
        for record in &records {
            if record.class != expected_class
                || record.typ != TYPE_CNAME
                || !reachable.iter().any(|name| names_equal(name, &record.name))
            {
                continue;
            }
            let (target, _) = read_name_bounded(
                raw,
                record.data_offset,
                record.data_offset + record.data.len(),
            )?;
            if !reachable.iter().any(|name| names_equal(name, &target)) {
                reachable.push(target);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    records.retain(|record| reachable.iter().any(|name| names_equal(name, &record.name)));
    Ok(records)
}

pub(crate) fn names_equal(left: &str, right: &str) -> bool {
    left.trim_end_matches('.')
        .eq_ignore_ascii_case(right.trim_end_matches('.'))
}

pub(crate) fn read_name(packet: &[u8], offset: usize) -> Result<(String, usize), WireError> {
    read_name_bounded(packet, offset, packet.len())
}

fn read_name_bounded(
    packet: &[u8],
    offset: usize,
    end: usize,
) -> Result<(String, usize), WireError> {
    if offset > end || end > packet.len() {
        return Err(WireError("short DNS name".to_string()));
    }
    let mut labels = Vec::new();
    let mut pos = offset;
    let mut next = offset;
    let mut jumped = false;
    let mut jumps = 0usize;

    loop {
        if pos >= packet.len() || (!jumped && pos >= end) {
            return Err(WireError("short DNS name".to_string()));
        }
        let len = packet[pos];
        if len & 0xc0 == 0xc0 {
            if pos + 1 >= end {
                return Err(WireError("short DNS name pointer".to_string()));
            }
            let pointer = usize::from(u16::from_be_bytes([len & 0x3f, packet[pos + 1]]));
            if !jumped {
                next = pos + 2;
            }
            pos = pointer;
            jumped = true;
            jumps += 1;
            if jumps > 128 {
                return Err(WireError("DNS name pointer loop".to_string()));
            }
            continue;
        }
        if len & 0xc0 != 0 {
            return Err(WireError("invalid DNS name label".to_string()));
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
            return Err(WireError("short DNS name label".to_string()));
        }
        labels.push(String::from_utf8_lossy(&packet[pos..pos + len]).into_owned());
        pos += len;
        if !jumped {
            next = pos;
        }
    }

    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        format!("{}.", labels.join("."))
    };
    Ok((name, next))
}

pub(crate) fn read_u16(raw: &[u8], offset: usize) -> Result<u16, WireError> {
    let bytes = raw
        .get(offset..offset + 2)
        .ok_or_else(|| WireError("short DNS message".to_string()))?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

pub(crate) fn read_u32(raw: &[u8], offset: usize) -> Result<u32, WireError> {
    let bytes = raw
        .get(offset..offset + 4)
        .ok_or_else(|| WireError("short DNS message".to_string()))?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn write_name(raw: &mut Vec<u8>, host: &str) -> Result<(), WireError> {
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        raw.push(0);
        return Ok(());
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(WireError(format!("invalid DNS name: {host}")));
        }
        raw.push(label.len() as u8);
        raw.extend_from_slice(label.as_bytes());
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

fn rcode_name(status: i32) -> &'static str {
    match status {
        1 => "FormatError",
        2 => "ServerFailure",
        3 => "NXDomain",
        4 => "NotImplemented",
        5 => "Refused",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_query_packet_as_response() {
        let query = build_query(0x1234, "example.com", TYPE_A).unwrap();
        let err = parse_response(&query, 0x1234, "example.com", TYPE_A, CLASS_IN).unwrap_err();
        assert_eq!(err.to_string(), "DNS message is not a response");
    }

    #[test]
    fn rejects_mismatched_response_question() {
        let mut response = build_query(0x1234, "other.example", TYPE_A).unwrap();
        response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        let err = parse_response(&response, 0x1234, "example.com", TYPE_A, CLASS_IN).unwrap_err();
        assert_eq!(err.to_string(), "mismatched DNS response question");
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
