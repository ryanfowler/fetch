use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use crate::error::FetchError;

use super::der::DerReader;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OcspStatus {
    Good,
    Revoked,
    Unknown,
}

pub(super) fn parse_ocsp_status(raw: &[u8]) -> Option<OcspStatus> {
    if raw.is_empty() {
        return None;
    }
    let mut top = DerReader::new(raw);
    let response = top.read_tlv()?;
    if response.tag != 0x30 {
        return None;
    }

    let mut response = DerReader::new(response.value);
    let status = response.read_tlv()?;
    if status.tag != 0x0a || status.value != [0] {
        return None;
    }

    let response_bytes_explicit = response.read_tlv()?;
    if response_bytes_explicit.tag != 0xa0 {
        return None;
    }
    let mut explicit = DerReader::new(response_bytes_explicit.value);
    let response_bytes = explicit.read_tlv()?;
    if response_bytes.tag != 0x30 {
        return None;
    }

    let mut response_bytes = DerReader::new(response_bytes.value);
    let response_type = response_bytes.read_tlv()?;
    if response_type.tag != 0x06
        || response_type.value != [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01]
    {
        return None;
    }
    let basic_response = response_bytes.read_tlv()?;
    if basic_response.tag != 0x04 {
        return None;
    }
    parse_basic_ocsp_response_status(basic_response.value)
}

fn parse_basic_ocsp_response_status(raw: &[u8]) -> Option<OcspStatus> {
    let mut top = DerReader::new(raw);
    let basic = top.read_tlv()?;
    if basic.tag != 0x30 {
        return None;
    }

    let mut basic = DerReader::new(basic.value);
    let tbs_response = basic.read_tlv()?;
    if tbs_response.tag != 0x30 {
        return None;
    }
    if basic.read_tlv()?.tag != 0x30 {
        return None;
    }
    if basic.read_tlv()?.tag != 0x03 {
        return None;
    }

    let mut tbs = DerReader::new(tbs_response.value);
    if tbs.peek_tag() == Some(0xa0) {
        tbs.read_tlv()?;
    }
    tbs.read_tlv()?; // responderID
    tbs.read_tlv()?; // producedAt
    let responses = tbs.read_tlv()?;
    if responses.tag != 0x30 {
        return None;
    }
    let mut responses = DerReader::new(responses.value);
    let single = responses.read_tlv()?;
    if single.tag != 0x30 {
        return None;
    }

    let mut single = DerReader::new(single.value);
    single.read_tlv()?; // certID
    let status = single.read_tlv()?;
    match status.tag {
        0x80 | 0xa0 => Some(OcspStatus::Good),
        0x81 | 0xa1 => Some(OcspStatus::Revoked),
        0x82 | 0xa2 => Some(OcspStatus::Unknown),
        _ => None,
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct ParsedCert {
    pub(super) raw: Vec<u8>,
    pub(super) common_name: Option<String>,
    pub(super) organization: Option<String>,
    pub(super) dns_names: Vec<String>,
    pub(super) ip_addresses: Vec<IpAddr>,
    pub(super) not_after: Option<time::OffsetDateTime>,
    pub(super) issuer_der: Vec<u8>,
    pub(super) subject_der: Vec<u8>,
    pub(super) spki_der: Vec<u8>,
    pub(super) subject_key_id: Option<Vec<u8>>,
    pub(super) authority_key_id: Option<Vec<u8>>,
    pub(super) subject: String,
}

impl ParsedCert {
    pub(super) fn parse(raw: &[u8]) -> Option<Self> {
        let cert = CertDer::parse(raw)?;
        let tbs = cert.tbs_certificate()?;
        let mut fields = TbsFields::parse(tbs)?;
        parse_extensions(fields.extensions, &mut fields);
        Some(Self {
            raw: raw.to_vec(),
            common_name: fields.subject.common_name,
            organization: fields.subject.organization,
            dns_names: fields.dns_names,
            ip_addresses: fields.ip_addresses,
            not_after: fields.not_after,
            issuer_der: fields.issuer_der,
            subject_der: fields.subject_der,
            spki_der: fields.spki_der,
            subject_key_id: fields.subject_key_id,
            authority_key_id: fields.authority_key_id,
            subject: fields.subject.display,
        })
    }

    pub(super) fn display_name(&self) -> String {
        match (&self.common_name, &self.organization) {
            (Some(cn), Some(org)) if cn != org => format!("{cn}, {org}"),
            (Some(cn), _) => cn.clone(),
            (None, _) if !self.dns_names.is_empty() => self.dns_names[0].clone(),
            (None, Some(org)) => org.clone(),
            _ => self.subject.clone(),
        }
    }
}

pub(super) fn load_native_root_certs() -> Vec<ParsedCert> {
    // Native roots give us the full certificate metadata that rustls' webpki
    // trust anchors intentionally omit, including NotAfter for display.
    rustls_native_certs::load_native_certs()
        .certs
        .into_iter()
        .filter_map(|cert| ParsedCert::parse(cert.as_ref()))
        .collect()
}

pub(super) fn trusted_root_certs(
    ca_certs: &[ParsedCert],
    native_roots: &[ParsedCert],
) -> Vec<ParsedCert> {
    let mut roots = Vec::new();
    for cert in ca_certs.iter().chain(native_roots) {
        if !roots.iter().any(|existing: &ParsedCert| {
            (!existing.raw.is_empty() && existing.raw == cert.raw)
                || (!existing.subject_der.is_empty()
                    && existing.subject_der == cert.subject_der
                    && !existing.spki_der.is_empty()
                    && existing.spki_der == cert.spki_der)
        }) {
            roots.push(cert.clone());
        }
    }
    roots
}

pub(super) fn certificate_chain_for_display(
    mut peer_chain: Vec<ParsedCert>,
    trusted_roots: &[ParsedCert],
    verified: bool,
) -> Vec<ParsedCert> {
    if !verified || peer_chain.is_empty() {
        return peer_chain;
    }

    let Some(last) = peer_chain.last().cloned() else {
        return peer_chain;
    };

    if let Some(root) = trusted_roots
        .iter()
        .find(|root| same_trust_anchor_identity(&last, root))
    {
        if last.raw != root.raw
            && let Some(last) = peer_chain.last_mut()
        {
            *last = root.clone();
        }
        return peer_chain;
    }

    if let Some(root) = trusted_roots
        .iter()
        .find(|root| issued_by_trusted_root(&last, root))
        && !peer_chain.iter().any(|cert| cert.raw == root.raw)
    {
        peer_chain.push(root.clone());
    }

    peer_chain
}

fn same_trust_anchor_identity(cert: &ParsedCert, root: &ParsedCert) -> bool {
    !cert.subject_der.is_empty()
        && cert.subject_der == root.subject_der
        && !cert.spki_der.is_empty()
        && cert.spki_der == root.spki_der
}

fn issued_by_trusted_root(cert: &ParsedCert, root: &ParsedCert) -> bool {
    if cert.issuer_der.is_empty()
        || root.subject_der.is_empty()
        || cert.issuer_der != root.subject_der
    {
        return false;
    }

    match (&cert.authority_key_id, &root.subject_key_id) {
        (Some(authority), Some(subject)) => authority == subject,
        _ => true,
    }
}

pub(super) fn load_ca_certs(paths: &[String]) -> Result<Vec<ParsedCert>, FetchError> {
    let mut certs = Vec::new();
    for path in paths {
        let data = super::super::read_pem_file(path)?;
        let blocks = super::super::pem_certificates(&data).map_err(|err| {
            FetchError::Message(format!("invalid CA certificate '{path}': {err}"))
        })?;
        if blocks.is_empty() {
            return Err(format!("invalid CA certificate '{path}': no certificates found").into());
        }
        for block in blocks {
            let parsed = ParsedCert::parse(&block)
                .ok_or_else(|| FetchError::Message(format!("invalid CA certificate '{path}'")))?;
            certs.push(parsed);
        }
    }
    Ok(certs)
}

struct TbsFields<'a> {
    subject: NameFields,
    not_after: Option<time::OffsetDateTime>,
    dns_names: Vec<String>,
    ip_addresses: Vec<IpAddr>,
    issuer_der: Vec<u8>,
    subject_der: Vec<u8>,
    spki_der: Vec<u8>,
    subject_key_id: Option<Vec<u8>>,
    authority_key_id: Option<Vec<u8>>,
    extensions: Option<&'a [u8]>,
}

impl<'a> TbsFields<'a> {
    fn parse(tbs: &'a [u8]) -> Option<Self> {
        let mut reader = DerReader::new(tbs);
        if reader.peek_tag()? == 0xa0 {
            reader.read_tlv()?;
        }
        reader.read_tlv()?; // serial
        reader.read_tlv()?; // signature
        let issuer = reader.read_tlv()?;
        let validity = reader.read_tlv()?;
        let not_after = parse_validity(validity.value);
        let subject_tlv = reader.read_tlv()?;
        let subject = parse_name(subject_tlv.value);
        let spki = reader.read_tlv()?;

        let mut extensions = None;
        while !reader.is_empty() {
            let tlv = reader.read_tlv()?;
            if tlv.tag == 0xa3 {
                extensions = Some(tlv.value);
            }
        }

        Some(Self {
            subject,
            not_after,
            dns_names: Vec::new(),
            ip_addresses: Vec::new(),
            issuer_der: issuer.value.to_vec(),
            subject_der: subject_tlv.value.to_vec(),
            spki_der: spki.raw.to_vec(),
            subject_key_id: None,
            authority_key_id: None,
            extensions,
        })
    }
}

fn parse_validity(validity: &[u8]) -> Option<time::OffsetDateTime> {
    let mut reader = DerReader::new(validity);
    reader.read_tlv()?;
    let not_after = reader.read_tlv()?;
    parse_time(not_after.tag, not_after.value)
}

fn parse_time(tag: u8, value: &[u8]) -> Option<time::OffsetDateTime> {
    let text = std::str::from_utf8(value).ok()?;
    let (year, rest) = match tag {
        0x17 => {
            let yy: i32 = text.get(0..2)?.parse().ok()?;
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            (year, text.get(2..)?)
        }
        0x18 => {
            let year: i32 = text.get(0..4)?.parse().ok()?;
            (year, text.get(4..)?)
        }
        _ => return None,
    };
    let month: u8 = rest.get(0..2)?.parse().ok()?;
    let day: u8 = rest.get(2..4)?.parse().ok()?;
    let hour: u8 = rest.get(4..6)?.parse().ok()?;
    let minute: u8 = rest.get(6..8)?.parse().ok()?;
    let second: u8 = rest.get(8..10)?.parse().ok()?;
    let date =
        time::Date::from_calendar_date(year, time::Month::try_from(month).ok()?, day).ok()?;
    let time = time::Time::from_hms(hour, minute, second).ok()?;
    Some(time::OffsetDateTime::new_utc(date, time))
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
struct NameFields {
    common_name: Option<String>,
    organization: Option<String>,
    display: String,
}

fn parse_name(name: &[u8]) -> NameFields {
    let mut parts = Vec::new();
    let mut fields = NameFields::default();
    let mut reader = DerReader::new(name);
    while let Some(set) = reader.read_tlv() {
        let mut set_reader = DerReader::new(set.value);
        while let Some(attr) = set_reader.read_tlv() {
            if let Some((oid, value)) = parse_attribute(attr.value) {
                match oid.as_slice() {
                    [0x55, 0x04, 0x03] => {
                        fields.common_name = Some(value.clone());
                        parts.push(format!("CN={value}"));
                    }
                    [0x55, 0x04, 0x0a] => {
                        fields.organization = Some(value.clone());
                        parts.push(format!("O={value}"));
                    }
                    [0x55, 0x04, 0x06] => parts.push(format!("C={value}")),
                    _ => {}
                }
            }
        }
    }
    fields.display = parts.join(", ");
    fields
}

fn parse_attribute(attr: &[u8]) -> Option<(Vec<u8>, String)> {
    let mut reader = DerReader::new(attr);
    let oid = reader.read_tlv()?;
    let value = reader.read_tlv()?;
    Some((
        oid.value.to_vec(),
        parse_der_string(value.tag, value.value)?,
    ))
}

fn parse_der_string(tag: u8, value: &[u8]) -> Option<String> {
    match tag {
        0x0c | 0x13 | 0x16 => String::from_utf8(value.to_vec()).ok(),
        0x1e => {
            let mut units = Vec::new();
            for chunk in value.chunks_exact(2) {
                units.push(u16::from_be_bytes([chunk[0], chunk[1]]));
            }
            String::from_utf16(&units).ok()
        }
        _ => None,
    }
}

fn parse_extensions(extensions: Option<&[u8]>, fields: &mut TbsFields<'_>) {
    let Some(extensions) = extensions else {
        return;
    };
    let mut outer = DerReader::new(extensions);
    let Some(seq) = outer.read_tlv() else {
        return;
    };
    let mut reader = DerReader::new(seq.value);
    while let Some(extension) = reader.read_tlv() {
        let mut ext = DerReader::new(extension.value);
        let Some(oid) = ext.read_tlv() else {
            continue;
        };
        if ext.peek_tag() == Some(0x01) {
            ext.read_tlv();
        }
        let Some(value) = ext.read_tlv() else {
            continue;
        };
        match oid.value {
            [0x55, 0x1d, 0x11] => parse_subject_alt_name(value.value, fields),
            [0x55, 0x1d, 0x0e] => {
                fields.subject_key_id = parse_subject_key_identifier(value.value);
            }
            [0x55, 0x1d, 0x23] => {
                fields.authority_key_id = parse_authority_key_identifier(value.value);
            }
            _ => {}
        }
    }
}

fn parse_subject_key_identifier(octets: &[u8]) -> Option<Vec<u8>> {
    let mut reader = DerReader::new(octets);
    let key_id = reader.read_tlv()?;
    if key_id.tag == 0x04 {
        Some(key_id.value.to_vec())
    } else {
        None
    }
}

fn parse_authority_key_identifier(octets: &[u8]) -> Option<Vec<u8>> {
    let mut reader = DerReader::new(octets);
    let seq = reader.read_tlv()?;
    if seq.tag != 0x30 {
        return None;
    }
    let mut fields = DerReader::new(seq.value);
    while let Some(field) = fields.read_tlv() {
        if field.tag == 0x80 {
            return Some(field.value.to_vec());
        }
    }
    None
}

fn parse_subject_alt_name(octets: &[u8], fields: &mut TbsFields<'_>) {
    let mut octet_reader = DerReader::new(octets);
    let Some(seq) = octet_reader.read_tlv() else {
        return;
    };
    let mut names = DerReader::new(seq.value);
    while let Some(name) = names.read_tlv() {
        match name.tag {
            0x82 => {
                if let Ok(dns) = std::str::from_utf8(name.value) {
                    fields.dns_names.push(dns.to_string());
                }
            }
            0x87 => match name.value {
                [a, b, c, d] => fields.ip_addresses.push(IpAddr::from([*a, *b, *c, *d])),
                bytes if bytes.len() == 16 => {
                    let mut octets = [0_u8; 16];
                    octets.copy_from_slice(bytes);
                    fields.ip_addresses.push(IpAddr::from(octets));
                }
                _ => {}
            },
            _ => {}
        }
    }
}

struct CertDer<'a> {
    value: &'a [u8],
}

impl<'a> CertDer<'a> {
    fn parse(raw: &'a [u8]) -> Option<Self> {
        let mut reader = DerReader::new(raw);
        let cert = reader.read_tlv()?;
        if cert.tag == 0x30 {
            Some(Self { value: cert.value })
        } else {
            None
        }
    }

    fn tbs_certificate(&self) -> Option<&'a [u8]> {
        let mut reader = DerReader::new(self.value);
        let tbs = reader.read_tlv()?;
        if tbs.tag == 0x30 {
            Some(tbs.value)
        } else {
            None
        }
    }
}

#[derive(Debug, Default, Clone)]
pub(super) struct OcspCapture {
    response: Arc<Mutex<Vec<u8>>>,
}

impl OcspCapture {
    pub(super) fn set(&self, value: &[u8]) {
        if value.is_empty() {
            return;
        }
        *self.response.lock().expect("OCSP capture lock poisoned") = value.to_vec();
    }

    pub(super) fn get(&self) -> Vec<u8> {
        self.response
            .lock()
            .expect("OCSP capture lock poisoned")
            .clone()
    }
}
