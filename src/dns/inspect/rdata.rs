use std::net::IpAddr;

use crate::dns::wire;
use crate::error::FetchError;

use super::Record;

const DNS_TYPE_A: u16 = wire::TYPE_A;
const DNS_TYPE_NS: u16 = wire::TYPE_NS;
const DNS_TYPE_CNAME: u16 = wire::TYPE_CNAME;
const DNS_TYPE_SOA: u16 = wire::TYPE_SOA;
const DNS_TYPE_MX: u16 = wire::TYPE_MX;
const DNS_TYPE_TXT: u16 = wire::TYPE_TXT;
const DNS_TYPE_AAAA: u16 = wire::TYPE_AAAA;
const DNS_TYPE_SRV: u16 = wire::TYPE_SRV;
const DNS_TYPE_SVCB: u16 = wire::TYPE_SVCB;
const DNS_TYPE_HTTPS: u16 = wire::TYPE_HTTPS;
const DNS_TYPE_CAA: u16 = wire::TYPE_CAA;

pub(super) fn records_from_ip_addrs(addrs: impl IntoIterator<Item = IpAddr>) -> Vec<Record> {
    crate::dns::ordered_unique_ip_addrs(addrs)
        .into_iter()
        .map(|ip| {
            let typ = if ip.is_ipv4() { "A" } else { "AAAA" };
            Record {
                typ: typ.to_string(),
                value: ip.to_string(),
                ttl: 0,
                has_ttl: false,
            }
        })
        .collect()
}

pub(super) fn resource_value(
    packet: &[u8],
    typ: u16,
    offset: usize,
    len: usize,
) -> Result<Option<String>, FetchError> {
    let decoded = wire::decode_rdata(packet, typ, offset, len)
        .map_err(|err| FetchError::Message(err.to_string()))?;
    let value = match decoded {
        wire::DecodedRdata::Address(address) => address.to_string(),
        wire::DecodedRdata::Name(name) => name,
        wire::DecodedRdata::Text(text) => text,
        wire::DecodedRdata::Mx {
            preference,
            exchange,
        } => format!("{preference} {exchange}"),
        wire::DecodedRdata::Soa {
            ns,
            mailbox,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => format!(
            "{ns} {mailbox} serial={serial} refresh={refresh} retry={retry} expire={expire} minttl={minimum}"
        ),
        wire::DecodedRdata::Srv {
            priority,
            weight,
            port,
            target,
        } => format!("{priority} {weight} {port} {target}"),
        wire::DecodedRdata::Raw(raw) => match typ {
            DNS_TYPE_SVCB | DNS_TYPE_HTTPS => crate::dns::svcb::format_rdata(raw)
                .ok_or_else(|| FetchError::Message("malformed DNS RDATA".to_string()))?,
            DNS_TYPE_CAA => format_caa(raw),
            _ => return Ok(None),
        },
    };
    Ok(Some(value))
}

pub(super) fn type_label(typ: u16) -> String {
    match typ {
        DNS_TYPE_A => "A".to_string(),
        DNS_TYPE_AAAA => "AAAA".to_string(),
        DNS_TYPE_CNAME => "CNAME".to_string(),
        DNS_TYPE_TXT => "TXT".to_string(),
        DNS_TYPE_MX => "MX".to_string(),
        DNS_TYPE_NS => "NS".to_string(),
        DNS_TYPE_SOA => "SOA".to_string(),
        DNS_TYPE_SRV => "SRV".to_string(),
        DNS_TYPE_CAA => "CAA".to_string(),
        DNS_TYPE_SVCB => "SVCB".to_string(),
        DNS_TYPE_HTTPS => "HTTPS".to_string(),
        _ => format!("TYPE{typ}"),
    }
}

pub(super) fn normalize_doh_value(typ: u16, value: &str) -> String {
    let Some(raw) = crate::dns::svcb::parse_generic_rdata(value) else {
        return value.to_string();
    };
    match typ {
        DNS_TYPE_SVCB | DNS_TYPE_HTTPS => crate::dns::svcb::format_rdata(&raw)
            .unwrap_or_else(|| format!("0x{}", hex_encode(&raw))),
        DNS_TYPE_CAA => format_caa(&raw),
        _ => format!("0x{}", hex_encode(&raw)),
    }
}

pub(super) fn format_caa(raw: &[u8]) -> String {
    if raw.len() < 2 {
        return format!("0x{}", hex_encode(raw));
    }
    let tag_len = usize::from(raw[1]);
    if raw.len() < 2 + tag_len {
        return format!("0x{}", hex_encode(raw));
    }
    let flags = raw[0];
    let tag = String::from_utf8_lossy(&raw[2..2 + tag_len]);
    let value = String::from_utf8_lossy(&raw[2 + tag_len..]);
    format!("{flags} {tag} {value:?}")
}

fn hex_encode(raw: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(raw.len() * 2);
    for byte in raw {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
