use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use crate::core::{self, Printer, Sequence};

use super::{INSPECT_TYPES, Inspection, InspectionOutput, Record, record_count};

pub(super) fn render_inspection_output_to(result: &InspectionOutput, out: &mut Printer) {
    match result {
        InspectionOutput::IpLiteral {
            host,
            ip,
            resolver,
            duration,
        } => render_ip_literal_to(out, host, *ip, resolver, *duration),
        InspectionOutput::Lookup(result) => render_to(result, out),
    }
}

fn render_ip_literal_to(
    out: &mut Printer,
    host: &str,
    ip: IpAddr,
    resolver: &str,
    duration: Duration,
) {
    write_dns_title(out, host, resolver);
    out.write_info_prefix();
    out.push_str("IP literal: ");
    out.write_styled(&ip.to_string(), &[Sequence::Green]);
    out.push_str(" (no DNS query needed)\n");
    out.write_info_prefix();
    out.push_str("Duration: ");
    out.write_styled(&format_duration(duration), &[Sequence::Dim]);
    out.push_str("\n");
}

#[cfg(test)]
pub(super) fn render(result: &Inspection) -> String {
    render_with_color(result, false)
}

#[cfg(test)]
pub(super) fn render_with_color(result: &Inspection, use_color: bool) -> String {
    let mut out = Printer::new(use_color);
    render_to(result, &mut out);
    out.into_string().expect("DNS inspection output is UTF-8")
}

fn render_to(result: &Inspection, out: &mut Printer) {
    write_dns_title(out, &result.host, &result.resolver);

    for query_type in INSPECT_TYPES {
        render_section(out, query_type.label, result.records.get(query_type.label));
    }
    render_other_sections(out, &result.records);

    out.write_info_prefix();
    out.push_str("Addresses: ");
    let address_count = result.records.get("A").map_or(0, Vec::len)
        + result.records.get("AAAA").map_or(0, Vec::len);
    out.write_styled(&address_count.to_string(), &[Sequence::Bold]);
    out.push_str("\n");
    out.write_info_prefix();
    out.push_str("Records: ");
    out.write_styled(&record_count(result).to_string(), &[Sequence::Bold]);
    out.push_str("\n");
    out.write_info_prefix();
    out.push_str("Duration: ");
    out.write_styled(&format_duration(result.duration), &[Sequence::Dim]);
    out.push_str("\n");
    render_warnings(out, &result.warnings);
}

fn render_warnings(out: &mut Printer, warnings: &[String]) {
    if !warnings.is_empty() {
        out.push('\n');
    }
    for warning in warnings {
        core::write_warning_msg_no_flush(out, warning);
    }
}

fn write_dns_title(out: &mut Printer, host: &str, resolver: &str) {
    out.write_info_prefix();
    out.write_styled("DNS lookup", &[Sequence::Bold, Sequence::Cyan]);
    out.push_str(": ");
    out.write_styled(host, &[Sequence::Bold]);
    out.push_str("\n");
    out.write_info_prefix();
    out.push_str("Resolver: ");
    out.write_styled(resolver, &[Sequence::Italic]);
    out.push_str("\n");
    out.write_info_prefix();
    out.push_str("\n");
}

fn render_other_sections(out: &mut Printer, records: &HashMap<String, Vec<Record>>) {
    let mut types: Vec<_> = records
        .keys()
        .filter(|key| {
            !INSPECT_TYPES
                .iter()
                .any(|query_type| query_type.label == *key)
        })
        .cloned()
        .collect();
    types.sort();
    for typ in types {
        render_section(out, &typ, records.get(&typ));
    }
}

fn render_section(out: &mut Printer, name: &str, records: Option<&Vec<Record>>) {
    let Some(records) = records else {
        return;
    };
    if records.is_empty() {
        return;
    }
    let mut records = records.clone();
    records.sort_by(|a, b| a.value.cmp(&b.value).then(a.ttl.cmp(&b.ttl)));

    out.write_info_prefix();
    out.write_styled(name, &[Sequence::Bold]);
    out.push_str("\n");
    for (idx, record) in records.iter().enumerate() {
        let marker = if idx == records.len() - 1 {
            "└─"
        } else {
            "├─"
        };
        out.write_info_prefix();
        out.push_str(&format!("{marker} "));
        out.write_styled(&record.value, &[Sequence::Green]);
        if record.has_ttl {
            out.push_str(" ");
            out.write_styled(
                &format!("(TTL {})", format_ttl(record.ttl)),
                &[Sequence::Dim],
            );
        }
        out.push('\n');
    }
    out.write_info_prefix();
    out.push('\n');
}

fn format_duration(duration: Duration) -> String {
    let nanos = duration.as_nanos();
    let rounded = if nanos < 1_000_000 {
        ((nanos + 500) / 1_000) * 1_000
    } else {
        ((nanos + 50_000) / 100_000) * 100_000
    };
    format_go_duration_nanos(rounded)
}

fn format_go_duration_nanos(nanos: u128) -> String {
    if nanos < 1_000 {
        return format!("{nanos}ns");
    }
    if nanos < 1_000_000 {
        return format_duration_unit(nanos, 1_000, "us");
    }
    if nanos < 1_000_000_000 {
        return format_duration_unit(nanos, 1_000_000, "ms");
    }
    format_duration_unit(nanos, 1_000_000_000, "s")
}

fn format_duration_unit(nanos: u128, unit_nanos: u128, suffix: &str) -> String {
    let whole = nanos / unit_nanos;
    let remainder = nanos % unit_nanos;
    if remainder == 0 {
        return format!("{whole}{suffix}");
    }
    let mut fraction = format!("{:09}", remainder * 1_000_000_000 / unit_nanos);
    while fraction.ends_with('0') {
        fraction.pop();
    }
    format!("{whole}.{fraction}{suffix}")
}

pub(super) fn format_ttl(ttl: u32) -> String {
    if ttl == 1 {
        return "1s".to_string();
    }
    if ttl < 60 {
        return format!("{ttl}s");
    }
    let hours = ttl / 3600;
    let minutes = (ttl % 3600) / 60;
    let seconds = ttl % 60;
    let mut out = String::new();
    if hours > 0 {
        out.push_str(&format!("{hours}h"));
    }
    if minutes > 0 {
        out.push_str(&format!("{minutes}m"));
    }
    if seconds > 0 {
        out.push_str(&format!("{seconds}s"));
    }
    out
}
