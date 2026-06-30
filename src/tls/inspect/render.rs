use rustls::{ProtocolVersion, SupportedCipherSuite};

use crate::core::{Printer, Sequence};

use super::Inspection;
use super::cert::{OcspStatus, ParsedCert, parse_ocsp_status};

#[cfg(test)]
pub(super) fn render(inspection: &Inspection) -> String {
    render_with_color(inspection, false)
}

#[cfg(test)]
pub(super) fn render_with_color(inspection: &Inspection, use_color: bool) -> String {
    let mut out = Printer::new(use_color);
    render_to(inspection, &mut out);
    out.into_string().expect("TLS inspection output is UTF-8")
}

pub(super) fn render_to(inspection: &Inspection, out: &mut Printer) {
    out.write_info_prefix();
    out.write_styled(
        version_label(inspection.version),
        &[Sequence::Bold, Sequence::Yellow],
    );
    if let Some(cipher) = inspection.cipher_suite {
        out.push_str(": ");
        out.push_str(&cipher_suite_label(cipher));
    }
    out.push('\n');

    if let Some(alpn) = &inspection.alpn {
        out.write_info_prefix();
        out.push_str("ALPN: ");
        out.write_styled(alpn, &[Sequence::Italic]);
        out.push('\n');
    }

    render_ech_status(out, inspection.ech_status);

    if !inspection.chain.is_empty() {
        out.write_info_prefix();
        out.push_str("\n");
        render_cert_chain(out, &inspection.chain);
        render_sans(out, &inspection.chain[0]);
    }
    render_ocsp_status(out, &inspection.ocsp_response);
}

fn render_ech_status(out: &mut Printer, status: rustls::client::EchStatus) {
    let label = match status {
        rustls::client::EchStatus::NotOffered => return,
        rustls::client::EchStatus::Grease => "ECH: GREASE (anti-ossification)",
        rustls::client::EchStatus::Offered => "ECH: Offered (pending)",
        rustls::client::EchStatus::Accepted => "ECH: Accepted",
        rustls::client::EchStatus::Rejected => "ECH: Rejected",
    };
    out.write_info_prefix();
    out.push_str(label);
    out.push('\n');
}

fn render_cert_chain(out: &mut Printer, chain: &[ParsedCert]) {
    out.write_info_prefix();
    out.write_styled("Certificate chain", &[Sequence::Bold]);
    out.push_str(":\n");
    for (index, cert) in chain.iter().enumerate() {
        out.write_info_prefix();
        out.push_str(&"   ".repeat(index));
        out.write_styled("└─ ", &[Sequence::Dim]);
        out.write_styled(&cert.display_name(), &[Sequence::Bold]);
        let (expiry_text, expiry_color) = cert_expiry_info_and_color(cert.not_after);
        out.push_str(" (");
        out.write_styled(&expiry_text, &[expiry_color]);
        out.push_str(")\n");
    }
}

fn render_sans(out: &mut Printer, cert: &ParsedCert) {
    let mut sans = cert.dns_names.clone();
    sans.extend(cert.ip_addresses.iter().map(ToString::to_string));
    if sans.is_empty() {
        return;
    }
    out.write_info_prefix();
    out.push_str("\n");
    out.write_info_prefix();
    out.push_str("SANs: ");
    out.write_styled(&sans.join(", "), &[Sequence::Italic]);
    out.push('\n');
}

pub(super) fn render_ocsp_status(out: &mut Printer, raw_ocsp: &[u8]) {
    let Some(status) = parse_ocsp_status(raw_ocsp) else {
        return;
    };
    out.write_info_prefix();
    out.push_str("OCSP: ");
    out.write_styled(ocsp_status_label(status), &[ocsp_status_color(status)]);
    out.push_str(" (stapled)\n");
}

fn ocsp_status_label(status: OcspStatus) -> &'static str {
    match status {
        OcspStatus::Good => "good",
        OcspStatus::Revoked => "revoked",
        OcspStatus::Unknown => "unknown",
    }
}

fn ocsp_status_color(status: OcspStatus) -> Sequence {
    match status {
        OcspStatus::Good => Sequence::Green,
        OcspStatus::Revoked => Sequence::Red,
        OcspStatus::Unknown => Sequence::Yellow,
    }
}

#[cfg(test)]
pub(super) fn cert_expiry_info(not_after: Option<time::OffsetDateTime>) -> String {
    cert_expiry_info_and_color(not_after).0
}

fn cert_expiry_info_and_color(not_after: Option<time::OffsetDateTime>) -> (String, Sequence) {
    let Some(not_after) = not_after else {
        return ("expiry unknown".to_string(), Sequence::Yellow);
    };
    let now = time::OffsetDateTime::now_utc();
    if now > not_after {
        return ("expired".to_string(), Sequence::Red);
    }

    let remaining = not_after - now;
    let days = remaining.whole_days();
    let text = match days {
        0 => "expires in <1 day".to_string(),
        1 => "expires in 1 day".to_string(),
        days => format!("expires in {days} days"),
    };
    let color = match days {
        days if days < 7 => Sequence::Red,
        days if days < 30 => Sequence::Yellow,
        _ => Sequence::Green,
    };
    (text, color)
}

fn version_label(version: Option<ProtocolVersion>) -> &'static str {
    match version {
        Some(ProtocolVersion::TLSv1_3) => "TLS 1.3",
        Some(ProtocolVersion::TLSv1_2) => "TLS 1.2",
        Some(ProtocolVersion::TLSv1_1) => "TLS 1.1",
        Some(ProtocolVersion::TLSv1_0) => "TLS 1.0",
        _ => "TLS",
    }
}

fn cipher_suite_label(cipher: SupportedCipherSuite) -> String {
    format!("{:?}", cipher.suite())
}
