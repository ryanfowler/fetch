use std::fmt;

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
pub(crate) const CLASS_IN: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WireError(String);

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WireError {}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ResourceRecord<'a> {
    pub(crate) typ: u16,
    pub(crate) class: u16,
    pub(crate) ttl: u32,
    pub(crate) data_offset: usize,
    pub(crate) data: &'a [u8],
}

pub(crate) fn build_query(id: u16, host: &str, dns_type: u16) -> Result<Vec<u8>, WireError> {
    let mut raw = Vec::with_capacity(512);
    raw.extend_from_slice(&id.to_be_bytes());
    raw.extend_from_slice(&0x0100u16.to_be_bytes());
    raw.extend_from_slice(&1u16.to_be_bytes());
    raw.extend_from_slice(&0u16.to_be_bytes());
    raw.extend_from_slice(&0u16.to_be_bytes());
    raw.extend_from_slice(&0u16.to_be_bytes());
    write_name(&mut raw, host)?;
    raw.extend_from_slice(&dns_type.to_be_bytes());
    raw.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(raw)
}

pub(crate) fn parse_response<'a>(
    raw: &'a [u8],
    expected_id: u16,
) -> Result<Vec<ResourceRecord<'a>>, WireError> {
    if raw.len() < 12 {
        return Err(WireError("short DNS response".to_string()));
    }
    let id = read_u16(raw, 0)?;
    if id != expected_id {
        return Err(WireError("mismatched DNS response ID".to_string()));
    }
    let flags = read_u16(raw, 2)?;
    let rcode = i32::from(flags & 0x000f);
    if rcode != 0 {
        let name = rcode_name(rcode);
        if name.is_empty() {
            return Err(WireError("no such host".to_string()));
        }
        return Err(WireError(format!("no such host: {name}")));
    }
    if flags & 0x0200 != 0 {
        return Err(WireError("DNS response was truncated".to_string()));
    }

    let question_count = usize::from(read_u16(raw, 4)?);
    let answer_count = usize::from(read_u16(raw, 6)?);
    let mut offset = 12;
    for _ in 0..question_count {
        let (_, next) = read_name(raw, offset)?;
        offset = next + 4;
        if offset > raw.len() {
            return Err(WireError("short DNS question".to_string()));
        }
    }

    let mut records = Vec::new();
    for _ in 0..answer_count {
        let (_, next) = read_name(raw, offset)?;
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
            typ,
            class,
            ttl,
            data_offset,
            data: &raw[data_offset..data_offset + rdlen],
        });
    }
    Ok(records)
}

pub(crate) fn read_name(packet: &[u8], offset: usize) -> Result<(String, usize), WireError> {
    let mut labels = Vec::new();
    let mut pos = offset;
    let mut next = offset;
    let mut jumped = false;
    let mut jumps = 0usize;

    loop {
        if pos >= packet.len() {
            return Err(WireError("short DNS name".to_string()));
        }
        let len = packet[pos];
        if len & 0xc0 == 0xc0 {
            if pos + 1 >= packet.len() {
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
        if pos + len > packet.len() {
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
