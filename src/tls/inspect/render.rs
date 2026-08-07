use std::fmt::Write as _;

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
    out.push_str(": ");
    match inspection.cipher_suite {
        super::CipherSuiteStatus::Negotiated(cipher) => {
            out.push_str(&cipher_suite_label(cipher));
        }
        super::CipherSuiteStatus::Unavailable => {
            out.push_str("cipher suite unavailable");
        }
        super::CipherSuiteStatus::UnavailableForHttp3 => {
            out.push_str("cipher suite unavailable for HTTP/3");
        }
    }
    out.push('\n');

    if let Some(alpn) = &inspection.alpn {
        out.write_info_prefix();
        out.push_str("ALPN: ");
        out.write_styled(&escape_untrusted_tls_text(alpn), &[Sequence::Italic]);
        out.push('\n');
    }

    render_ech_status(out, inspection.ech_status);

    if !inspection.chain.is_empty() {
        out.write_info_prefix();
        out.push_str("\n");
        render_cert_chain(out, &inspection.chain);
        render_sans(out, &inspection.chain[0]);
    }
    if inspection.trust_anchor_details_unavailable {
        out.write_info_prefix();
        out.push_str("Trust anchor: platform-selected, details unavailable\n");
    }
    render_ocsp_status(
        out,
        &inspection.ocsp_response,
        inspection.chain.first(),
        inspection.chain.get(1),
    );
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
    out.write_styled("Peer certificate chain", &[Sequence::Bold]);
    out.push_str(":\n");
    for (index, cert) in chain.iter().enumerate() {
        out.write_info_prefix();
        out.push_str(&"   ".repeat(index));
        out.write_styled("└─ ", &[Sequence::Dim]);
        out.write_styled(
            &escape_untrusted_tls_text(&cert.display_name()),
            &[Sequence::Bold],
        );
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
    out.write_styled(
        &escape_untrusted_tls_text(&sans.join(", ")),
        &[Sequence::Italic],
    );
    out.push('\n');
}

/// Escape remotely supplied TLS text before writing it to diagnostics.
///
/// Backslashes are also escaped so that the output cannot imitate an escape
/// added by this function.
fn escape_untrusted_tls_text(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\u{00}'..='\u{1f}' | '\u{7f}' => {
                write!(escaped, "\\x{:02x}", ch as u32).expect("writing to a String cannot fail");
            }
            '\u{80}'..='\u{9f}'
            | '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}' => {
                write!(escaped, "\\u{{{:x}}}", ch as u32).expect("writing to a String cannot fail");
            }
            _ => escaped.push(ch),
        }
    }
    escaped
}

pub(super) fn render_ocsp_status(
    out: &mut Printer,
    raw_ocsp: &[u8],
    leaf: Option<&ParsedCert>,
    issuer: Option<&ParsedCert>,
) {
    if raw_ocsp.is_empty() {
        return;
    }

    let status = leaf
        .zip(issuer)
        .and_then(|(leaf, issuer)| parse_ocsp_status(raw_ocsp, leaf, issuer));
    out.write_info_prefix();
    if let Some(status) = status {
        out.push_str("OCSP: ");
        out.push_str(ocsp_status_label(status));
        out.push_str(" (stapled, unverified)\n");
    } else {
        out.push_str("OCSP staple present (unverified)\n");
    }
}

fn ocsp_status_label(status: OcspStatus) -> &'static str {
    match status {
        OcspStatus::Good => "good",
        OcspStatus::Revoked => "revoked",
        OcspStatus::Unknown => "unknown",
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
