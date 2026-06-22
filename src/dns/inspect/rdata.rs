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
    addrs
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
    let rdata = &packet[offset..offset + len];
    let value = match typ {
        DNS_TYPE_A if len == 4 => {
            IpAddr::from([rdata[0], rdata[1], rdata[2], rdata[3]]).to_string()
        }
        DNS_TYPE_AAAA if len == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rdata);
            IpAddr::from(octets).to_string()
        }
        DNS_TYPE_CNAME | DNS_TYPE_NS => {
            wire::read_name(packet, offset)
                .map_err(|err| FetchError::Message(err.to_string()))?
                .0
        }
        DNS_TYPE_TXT => parse_txt_rdata(rdata),
        DNS_TYPE_MX if len >= 3 => {
            let pref = wire::read_u16(packet, offset)
                .map_err(|err| FetchError::Message(err.to_string()))?;
            let name = wire::read_name(packet, offset + 2)
                .map_err(|err| FetchError::Message(err.to_string()))?
                .0;
            format!("{pref} {name}")
        }
        DNS_TYPE_SOA => parse_soa_rdata(packet, offset)?,
        DNS_TYPE_SRV if len >= 7 => {
            let priority = wire::read_u16(packet, offset)
                .map_err(|err| FetchError::Message(err.to_string()))?;
            let weight = wire::read_u16(packet, offset + 2)
                .map_err(|err| FetchError::Message(err.to_string()))?;
            let port = wire::read_u16(packet, offset + 4)
                .map_err(|err| FetchError::Message(err.to_string()))?;
            let target = wire::read_name(packet, offset + 6)
                .map_err(|err| FetchError::Message(err.to_string()))?
                .0;
            format!("{priority} {weight} {port} {target}")
        }
        DNS_TYPE_SVCB | DNS_TYPE_HTTPS => crate::dns::svcb::format_rdata(rdata)
            .unwrap_or_else(|| format!("0x{}", hex_encode(rdata))),
        DNS_TYPE_CAA => format_caa(rdata),
        _ => return Ok(None),
    };
    Ok(Some(value))
}

fn parse_txt_rdata(raw: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut offset = 0;
    while offset < raw.len() {
        let len = usize::from(raw[offset]);
        offset += 1;
        if offset + len > raw.len() {
            parts.push(String::from_utf8_lossy(&raw[offset - 1..]).into_owned());
            break;
        }
        parts.push(String::from_utf8_lossy(&raw[offset..offset + len]).into_owned());
        offset += len;
    }
    parts.join(" ")
}

fn parse_soa_rdata(packet: &[u8], offset: usize) -> Result<String, FetchError> {
    let (ns, mut next) =
        wire::read_name(packet, offset).map_err(|err| FetchError::Message(err.to_string()))?;
    let (mbox, next_after_mbox) =
        wire::read_name(packet, next).map_err(|err| FetchError::Message(err.to_string()))?;
    next = next_after_mbox;
    let serial =
        wire::read_u32(packet, next).map_err(|err| FetchError::Message(err.to_string()))?;
    let refresh =
        wire::read_u32(packet, next + 4).map_err(|err| FetchError::Message(err.to_string()))?;
    let retry =
        wire::read_u32(packet, next + 8).map_err(|err| FetchError::Message(err.to_string()))?;
    let expire =
        wire::read_u32(packet, next + 12).map_err(|err| FetchError::Message(err.to_string()))?;
    let min_ttl =
        wire::read_u32(packet, next + 16).map_err(|err| FetchError::Message(err.to_string()))?;
    Ok(format!(
        "{ns} {mbox} serial={serial} refresh={refresh} retry={retry} expire={expire} minttl={min_ttl}"
    ))
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
