use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use futures_util::future::join_all;
use url::Url;

use crate::cli::Cli;
use crate::core::{self, Printer, Sequence};
use crate::dns::util::{dns_query_id, udp_dns_timeout};
use crate::dns::wire;
use crate::duration::{TimeoutBudget, duration_from_seconds};
use crate::error::{FetchError, write_error_with_color, write_warning_with_separator_with_color};

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
const DNS_CLASS_IN: u16 = wire::CLASS_IN;

const INSPECT_TYPES: &[QueryType] = &[
    QueryType {
        label: "A",
        dns_type: DNS_TYPE_A,
    },
    QueryType {
        label: "AAAA",
        dns_type: DNS_TYPE_AAAA,
    },
    QueryType {
        label: "CNAME",
        dns_type: DNS_TYPE_CNAME,
    },
    QueryType {
        label: "TXT",
        dns_type: DNS_TYPE_TXT,
    },
    QueryType {
        label: "MX",
        dns_type: DNS_TYPE_MX,
    },
    QueryType {
        label: "NS",
        dns_type: DNS_TYPE_NS,
    },
    QueryType {
        label: "SOA",
        dns_type: DNS_TYPE_SOA,
    },
    QueryType {
        label: "SRV",
        dns_type: DNS_TYPE_SRV,
    },
    QueryType {
        label: "CAA",
        dns_type: DNS_TYPE_CAA,
    },
    QueryType {
        label: "SVCB",
        dns_type: DNS_TYPE_SVCB,
    },
    QueryType {
        label: "HTTPS",
        dns_type: DNS_TYPE_HTTPS,
    },
];

#[derive(Clone, Copy)]
struct QueryType {
    label: &'static str,
    dns_type: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QueryErrorKind {
    Other,
    Truncated,
}

#[derive(Debug)]
struct QueryError {
    kind: QueryErrorKind,
    message: String,
}

impl QueryError {
    fn other(err: impl ToString) -> Self {
        Self {
            kind: QueryErrorKind::Other,
            message: err.to_string(),
        }
    }

    fn truncated(err: impl ToString) -> Self {
        Self {
            kind: QueryErrorKind::Truncated,
            message: err.to_string(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Record {
    typ: String,
    value: String,
    ttl: u32,
    has_ttl: bool,
}

#[derive(Debug)]
struct Inspection {
    host: String,
    resolver: String,
    records: HashMap<String, Vec<Record>>,
    warnings: Vec<String>,
    duration: Duration,
    exit_code: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ResolverTarget {
    Default { label: String },
    Udp { label: String, addr: String },
    Doh { label: String, url: Url },
}

pub async fn execute(cli: &Cli) -> Result<i32, FetchError> {
    let request_start = Instant::now();
    let url = crate::http::normalize_url(cli.url.as_deref().expect("URL checked by app"))?;
    let ignored = ignored_inspection_flags(cli);
    if !ignored.is_empty() {
        write_warning_with_separator_with_color(
            format!("--inspect-dns ignores: {}", ignored.join(", ")),
            cli.color.as_deref(),
        );
    }

    let request_timeout = inspection_request_timeout(cli)?;
    let connect_timeout = inspection_connect_timeout(cli, request_timeout, request_start)?;
    let mut printer = core::stdio().stderr_printer(cli.color.as_deref());
    let inspected = connect_timeout
        .run(inspect_to(
            &url,
            cli.dns_server.as_deref(),
            &mut printer,
            connect_timeout,
        ))
        .await;

    match inspected {
        Ok(code) => {
            printer.flush_to(&mut std::io::stderr())?;
            Ok(code)
        }
        Err(err) => {
            write_error_with_color(err, cli.color.as_deref());
            Ok(1)
        }
    }
}

fn inspection_request_timeout(cli: &Cli) -> Result<Option<Duration>, FetchError> {
    cli.timeout
        .map(|seconds| duration_from_seconds("timeout", seconds))
        .transpose()
}

fn inspection_connect_timeout(
    cli: &Cli,
    request_timeout: Option<Duration>,
    request_start: Instant,
) -> Result<TimeoutBudget, FetchError> {
    let connect_timeout = cli
        .connect_timeout
        .map(|seconds| duration_from_seconds("connect-timeout", seconds))
        .transpose()?;
    TimeoutBudget::for_connect(connect_timeout, request_timeout, request_start)
}

#[cfg(test)]
async fn inspect(url: &Url, dns_server: Option<&str>) -> Result<String, FetchError> {
    let (out, _) = inspect_with_code(url, dns_server).await?;
    Ok(out)
}

#[cfg(test)]
async fn inspect_with_code(
    url: &Url,
    dns_server: Option<&str>,
) -> Result<(String, i32), FetchError> {
    let mut out = Printer::new(false);
    let code = inspect_to(url, dns_server, &mut out, TimeoutBudget::new(None)).await?;
    Ok((
        out.into_string().expect("DNS inspection output is UTF-8"),
        code,
    ))
}

async fn inspect_to(
    url: &Url,
    dns_server: Option<&str>,
    out: &mut Printer,
    timeout: TimeoutBudget,
) -> Result<i32, FetchError> {
    let host = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| FetchError::Message("--inspect-dns requires a hostname".to_string()))?;
    let target = resolver_target(dns_server)?;
    let start = Instant::now();

    if let Ok(ip) = host.parse::<IpAddr>() {
        render_ip_literal_to(out, host, ip, target.label(), start.elapsed());
        return Ok(0);
    }

    let result = lookup(host, target, start, timeout).await?;
    render_to(&result, out);
    Ok(result.exit_code)
}

async fn lookup(
    host: &str,
    target: ResolverTarget,
    start: Instant,
    timeout: TimeoutBudget,
) -> Result<Inspection, FetchError> {
    let mut out = Inspection {
        host: host.to_string(),
        resolver: target.label().to_string(),
        records: HashMap::new(),
        warnings: Vec::new(),
        duration: Duration::ZERO,
        exit_code: 0,
    };

    if matches!(target, ResolverTarget::Default { .. }) {
        let records = timeout.run(lookup_default_resolver_records(host)).await?;
        out.duration = start.elapsed();
        for record in records {
            out.records
                .entry(record.typ.clone())
                .or_default()
                .push(record);
        }
        if record_count(&out) == 0 {
            return Err(format!("lookup {host}: no DNS records found").into());
        }
        return Ok(out);
    }

    let remaining_timeout = timeout.remaining()?;
    let udp_timeout = udp_dns_timeout(remaining_timeout);
    let doh_client = match &target {
        ResolverTarget::Doh { .. } => Some(
            crate::dns::doh::client(remaining_timeout)
                .map_err(|err| FetchError::Message(err.to_string()))?,
        ),
        _ => None,
    };
    let futures = INSPECT_TYPES.iter().copied().map(|query_type| {
        let client = doh_client.as_ref();
        let target = &target;
        async move {
            let result = match (target, client) {
                (ResolverTarget::Doh { url, .. }, Some(client)) => {
                    lookup_doh_records(client, url, host, query_type).await
                }
                (ResolverTarget::Udp { addr, .. }, _) => {
                    lookup_udp_records(addr, host, query_type, udp_timeout).await
                }
                (ResolverTarget::Default { .. }, _) => {
                    unreachable!("default resolver handled earlier")
                }
                (ResolverTarget::Doh { .. }, None) => {
                    unreachable!("DoH client initialized above")
                }
            };
            (query_type, result)
        }
    });
    let results = timeout
        .run(async { Ok::<_, FetchError>(join_all(futures).await) })
        .await?;

    let mut first_err = None;
    let mut truncated_types = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new();
    for (query_type, result) in results {
        match result {
            Ok(records) => {
                for record in records {
                    let key = format!("{}\0{}", record.typ, record.value);
                    let records = out.records.entry(record.typ.clone()).or_default();
                    if let Some(idx) = seen.get(&key).copied() {
                        if record.ttl < records[idx].ttl {
                            records[idx].ttl = record.ttl;
                        }
                        continue;
                    }
                    seen.insert(key, records.len());
                    records.push(record);
                }
            }
            Err(err) if err.kind == QueryErrorKind::Truncated => {
                truncated_types.push(query_type.label);
                if first_err.is_none() {
                    first_err = Some(err);
                }
            }
            Err(err) if first_err.is_none() => {
                first_err = Some(err);
            }
            Err(_) => {}
        }
    }
    out.duration = start.elapsed();

    if !truncated_types.is_empty() {
        out.warnings.push(truncated_warning(&truncated_types));
        out.exit_code = 1;
        return Ok(out);
    }
    if record_count(&out) > 0 {
        return Ok(out);
    }
    if let Some(err) = first_err {
        return Err(format!("lookup {host}: {}", err.message).into());
    }
    Err(format!("lookup {host}: no DNS records found").into())
}

async fn lookup_default_resolver_records(host: &str) -> Result<Vec<Record>, FetchError> {
    let addrs = tokio::net::lookup_host((host, 0)).await?;
    Ok(records_from_ip_addrs(addrs.map(|addr| addr.ip())))
}

fn records_from_ip_addrs(addrs: impl IntoIterator<Item = IpAddr>) -> Vec<Record> {
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

async fn lookup_doh_records(
    client: &reqwest::Client,
    server_url: &Url,
    host: &str,
    query_type: QueryType,
) -> Result<Vec<Record>, QueryError> {
    let records =
        crate::dns::doh::lookup_doh_records_with_client(client, server_url, host, query_type.label)
            .await
            .map_err(QueryError::other)?;
    Ok(records
        .into_iter()
        .map(|answer| {
            let typ = type_label(answer.answer_type);
            Record {
                typ: typ.to_string(),
                value: normalize_doh_value(answer.answer_type, &answer.data),
                ttl: answer.ttl.unwrap_or_default(),
                has_ttl: true,
            }
        })
        .collect())
}

async fn lookup_udp_records(
    server_addr: &str,
    host: &str,
    query_type: QueryType,
    timeout: Duration,
) -> Result<Vec<Record>, QueryError> {
    let id = dns_query_id();
    let raw = wire::build_query(id, host, query_type.dns_type).map_err(QueryError::other)?;
    let mut response = crate::dns::transport::query_udp(server_addr, &raw, timeout)
        .await
        .map_err(QueryError::other)?;
    let raw_records = match wire::parse_response(&response, id) {
        Ok(_) => wire::parse_response(&response, id).map_err(QueryError::other)?,
        Err(err) if err.is_truncated() => {
            response = crate::dns::transport::query_tcp(server_addr, &raw, timeout)
                .await
                .map_err(QueryError::truncated)?;
            wire::parse_response(&response, id).map_err(QueryError::truncated)?
        }
        Err(err) => return Err(QueryError::other(err)),
    };
    let mut records = Vec::new();
    for raw_record in raw_records {
        if raw_record.class != DNS_CLASS_IN {
            continue;
        }
        if let Some(value) = resource_value(
            &response,
            raw_record.typ,
            raw_record.data_offset,
            raw_record.data.len(),
        )
        .map_err(QueryError::other)?
        {
            records.push(Record {
                typ: type_label(raw_record.typ).to_string(),
                value,
                ttl: raw_record.ttl,
                has_ttl: true,
            });
        }
    }
    Ok(records)
}

fn resource_value(
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
        DNS_TYPE_SVCB | DNS_TYPE_HTTPS => {
            parse_svcb_rdata(rdata).unwrap_or_else(|| format!("0x{}", hex_encode(rdata)))
        }
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

fn resolver_target(dns_server: Option<&str>) -> Result<ResolverTarget, FetchError> {
    match dns_server {
        None => Ok(resolver_target_from_resolv_conf(
            None,
            std::fs::read_to_string("/etc/resolv.conf").ok().as_deref(),
        )),
        Some(server) if server.starts_with("http://") || server.starts_with("https://") => {
            let url = Url::parse(server).map_err(|_| {
                FetchError::Message(format!(
                    "invalid value '{server}' for option '--dns-server': unable to parse DoH URL"
                ))
            })?;
            Ok(ResolverTarget::Doh {
                label: url.to_string(),
                url,
            })
        }
        Some(server) => {
            let addr = crate::dns::resolver::normalize_udp_dns_server(server)
                .map_err(|err| FetchError::Message(err.to_string()))?;
            Ok(ResolverTarget::Udp {
                label: format!("udp {addr}"),
                addr,
            })
        }
    }
}

fn resolver_target_from_resolv_conf(
    explicit: Option<&str>,
    resolv_conf: Option<&str>,
) -> ResolverTarget {
    if let Some(server) = explicit {
        return ResolverTarget::Udp {
            label: format!("udp {server}"),
            addr: server.to_string(),
        };
    }

    if let Some(raw) = resolv_conf {
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() >= 2 && fields[0] == "nameserver" {
                let addr = if fields[1].contains(':') && !fields[1].starts_with('[') {
                    format!("[{}]:53", fields[1])
                } else {
                    format!("{}:53", fields[1])
                };
                return ResolverTarget::Udp {
                    label: format!("system ({addr})"),
                    addr,
                };
            }
        }
    }

    ResolverTarget::Default {
        label: "system resolver".to_string(),
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
fn render(result: &Inspection) -> String {
    render_with_color(result, false)
}

#[cfg(test)]
fn render_with_color(result: &Inspection, use_color: bool) -> String {
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

fn record_count(result: &Inspection) -> usize {
    result.records.values().map(Vec::len).sum()
}

fn truncated_warning(types: &[&'static str]) -> String {
    if types.len() == 1 {
        return format!(
            "DNS response for {} was truncated over UDP after EDNS(0), and TCP fallback failed; results are incomplete",
            types[0]
        );
    }
    format!(
        "DNS responses for {} were truncated over UDP after EDNS(0), and TCP fallback failed; results are incomplete",
        types.join(", ")
    )
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

fn format_ttl(ttl: u32) -> String {
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

fn type_label(typ: u16) -> String {
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

fn normalize_doh_value(typ: u16, value: &str) -> String {
    let Some(raw) = parse_generic_rdata(value) else {
        return value.to_string();
    };
    match typ {
        DNS_TYPE_SVCB | DNS_TYPE_HTTPS => {
            parse_svcb_rdata(&raw).unwrap_or_else(|| format!("0x{}", hex_encode(&raw)))
        }
        DNS_TYPE_CAA => format_caa(&raw),
        _ => format!("0x{}", hex_encode(&raw)),
    }
}

fn parse_generic_rdata(value: &str) -> Option<Vec<u8>> {
    let fields: Vec<_> = value.split_whitespace().collect();
    if fields.len() < 3 || fields[0] != r"\#" {
        return None;
    }
    let want_len = fields[1].parse::<usize>().ok()?;
    let raw = hex_decode(&fields[2..].join(""))?;
    (raw.len() == want_len).then_some(raw)
}

fn parse_svcb_rdata(raw: &[u8]) -> Option<String> {
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
        1 => {
            let mut alpns = Vec::new();
            let mut offset = 0;
            while offset < value.len() {
                let len = usize::from(value[offset]);
                offset += 1;
                if offset + len > value.len() {
                    return format!("ALPN=0x{}", hex_encode(value));
                }
                alpns.push(String::from_utf8_lossy(&value[offset..offset + len]).into_owned());
                offset += len;
            }
            format!("ALPN={}", alpns.join(","))
        }
        2 => "NoDefaultALPN".to_string(),
        3 if value.len() == 2 => {
            let port = u16::from_be_bytes([value[0], value[1]]);
            format!("Port={port}")
        }
        3 => format!("Port=0x{}", hex_encode(value)),
        4 if value.len().is_multiple_of(4) => {
            let ips = value
                .chunks_exact(4)
                .map(|chunk| IpAddr::from([chunk[0], chunk[1], chunk[2], chunk[3]]).to_string())
                .collect::<Vec<_>>();
            format!("IPv4Hint={}", ips.join(","))
        }
        4 => format!("IPv4Hint=0x{}", hex_encode(value)),
        6 if value.len().is_multiple_of(16) => {
            let ips = value
                .chunks_exact(16)
                .map(|chunk| {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(chunk);
                    IpAddr::from(octets).to_string()
                })
                .collect::<Vec<_>>();
            format!("IPv6Hint={}", ips.join(","))
        }
        6 => format!("IPv6Hint=0x{}", hex_encode(value)),
        7 => format!("DOHPath={:?}", String::from_utf8_lossy(value)),
        _ => format!("key{key}=0x{}", hex_encode(value)),
    }
}

fn format_caa(raw: &[u8]) -> String {
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

fn ignored_inspection_flags(cli: &Cli) -> Vec<&'static str> {
    let mut ignored = Vec::new();
    if cli.data.is_some() || cli.json.is_some() || cli.xml.is_some() {
        ignored.push("--data/--json/--xml");
    }
    if !cli.form.is_empty() {
        ignored.push("--form");
    }
    if !cli.multipart.is_empty() {
        ignored.push("--multipart");
    }
    if cli.grpc {
        ignored.push("--grpc");
    }
    if cli.grpc_describe.is_some() {
        ignored.push("--grpc-describe");
    }
    if cli.grpc_list {
        ignored.push("--grpc-list");
    }
    if cli.output.is_some() {
        ignored.push("--output");
    }
    if cli.remote_name {
        ignored.push("--remote-name");
    }
    if cli.remote_header_name {
        ignored.push("--remote-header-name");
    }
    if cli.copy {
        ignored.push("--copy");
    }
    if cli.method.is_some() {
        ignored.push("--method");
    }
    if !cli.headers.is_empty() {
        ignored.push("--header");
    }
    if !cli.query.is_empty() {
        ignored.push("--query");
    }
    if cli.edit {
        ignored.push("--edit");
    }
    if cli.session.is_some() {
        ignored.push("--session");
    }
    if cli.retry() > 0 {
        ignored.push("--retry");
    }
    if !cli.ranges.is_empty() {
        ignored.push("--range");
    }
    if cli.timing {
        ignored.push("--timing");
    }
    if cli.proxy.is_some() {
        ignored.push("--proxy");
    }
    if cli.discard {
        ignored.push("--discard");
    }
    if cli.unix.is_some() {
        ignored.push("--unix");
    }
    if cli.inspect_tls {
        ignored.push("--inspect-tls");
    }
    if cli.bearer.is_some() {
        ignored.push("--bearer");
    }
    if cli.basic.is_some() {
        ignored.push("--basic");
    }
    if cli.digest.is_some() {
        ignored.push("--digest");
    }
    if cli.aws_sigv4.is_some() {
        ignored.push("--aws-sigv4");
    }
    if !cli.ca_cert.is_empty() {
        ignored.push("--ca-cert");
    }
    if cli.cert.is_some() {
        ignored.push("--cert");
    }
    if cli.key.is_some() {
        ignored.push("--key");
    }
    if cli.tls.is_some() || cli.min_tls.is_some() {
        ignored.push("--tls");
    }
    if cli.max_tls.is_some() {
        ignored.push("--max-tls");
    }
    if cli.insecure {
        ignored.push("--insecure");
    }
    if cli.format.is_some() {
        ignored.push("--format");
    }
    if cli.dry_run {
        ignored.push("--dry-run");
    }
    ignored
}

impl ResolverTarget {
    fn label(&self) -> &str {
        match self {
            Self::Default { label } | Self::Udp { label, .. } | Self::Doh { label, .. } => label,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream as StdTcpStream, UdpSocket as StdUdpSocket};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;

    async fn start_test_server<F>(handler: F) -> (Url, tokio::task::JoinHandle<()>)
    where
        F: Fn(http::Request<String>) -> http::Response<String> + Send + Sync + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = Arc::new(handler);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let handler = handler.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0; 4096];
                    let Ok(n) = stream
                        .readable()
                        .await
                        .and_then(|_| stream.try_read(&mut buf))
                    else {
                        return;
                    };
                    let request = String::from_utf8_lossy(&buf[..n]);
                    let first_line = request.lines().next().unwrap_or_default();
                    let path = first_line.split_whitespace().nth(1).unwrap_or("/");
                    let req = http::Request::builder()
                        .uri(path)
                        .body(request.into_owned())
                        .unwrap();
                    let response = handler(req);
                    let (parts, body) = response.into_parts();
                    let status = parts.status.as_u16();
                    let reason = parts.status.canonical_reason().unwrap_or("");
                    let raw = format!(
                        "HTTP/1.1 {status} {reason}\r\ncontent-length: {}\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.writable().await;
                    let _ = stream.try_write(raw.as_bytes());
                });
            }
        });
        (
            Url::parse(&format!("http://{addr}/dns-query")).unwrap(),
            task,
        )
    }

    #[tokio::test]
    async fn test_inspect_doh_shows_a_and_aaaa_ttls() {
        let (server_url, task) = start_test_server(|request| {
            match request
                .uri()
                .query()
                .unwrap_or_default()
                .split('&')
                .find_map(|part| part.strip_prefix("type="))
                .unwrap_or_default()
            {
                "A" => http::Response::new(
                    r#"{"Status":0,"Answer":[{"type":5,"data":"alias.example.com.","TTL":120},{"type":1,"data":"192.0.2.1","TTL":60}]}"#
                        .to_string(),
                ),
                "AAAA" => http::Response::new(
                    r#"{"Status":0,"Answer":[{"type":28,"data":"2001:db8::1","TTL":300}]}"#
                        .to_string(),
                ),
                "TXT" => http::Response::new(
                    r#"{"Status":0,"Answer":[{"type":16,"data":"v=spf1 -all","TTL":180}]}"#
                        .to_string(),
                ),
                _ => http::Response::new(r#"{"Status":0}"#.to_string()),
            }
        })
        .await;

        let out = inspect(
            &Url::parse("https://example.com").unwrap(),
            Some(server_url.as_str()),
        )
        .await
        .unwrap();

        let wants = vec![
            "DNS lookup: example.com".to_string(),
            format!("Resolver: {server_url}"),
            "A\n".to_string(),
            "└─ 192.0.2.1 (TTL 1m)".to_string(),
            "AAAA\n".to_string(),
            "└─ 2001:db8::1 (TTL 5m)".to_string(),
            "CNAME\n".to_string(),
            "alias.example.com. (TTL 2m)".to_string(),
            "TXT\n".to_string(),
            "v=spf1 -all (TTL 3m)".to_string(),
            "Addresses: 2".to_string(),
        ];
        for want in wants {
            assert!(out.contains(&want), "output missing {want:?}:\n{out}");
        }
        task.abort();
    }

    #[tokio::test]
    async fn test_inspect_ip_literal_skips_lookup() {
        let out = inspect(&Url::parse("http://127.0.0.1").unwrap(), None)
            .await
            .unwrap();

        assert!(out.contains("IP literal: 127.0.0.1 (no DNS query needed)"));
        assert!(out.contains("* Duration:"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_lookup_queries_record_types_concurrently() {
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let seen_active = active.clone();
        let seen_max = max_active.clone();
        let (server_url, task) = start_test_server(move |request| {
            let now = seen_active.fetch_add(1, Ordering::SeqCst) + 1;
            seen_max.fetch_max(now, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(25));
            seen_active.fetch_sub(1, Ordering::SeqCst);

            match request
                .uri()
                .query()
                .unwrap_or_default()
                .split('&')
                .find_map(|part| part.strip_prefix("type="))
                .unwrap_or_default()
            {
                "A" => http::Response::new(
                    r#"{"Status":0,"Answer":[{"type":1,"data":"192.0.2.1","TTL":60}]}"#.to_string(),
                ),
                _ => http::Response::new(r#"{"Status":0}"#.to_string()),
            }
        })
        .await;

        lookup(
            "example.com",
            ResolverTarget::Doh {
                label: server_url.to_string(),
                url: server_url,
            },
            Instant::now(),
            TimeoutBudget::new(None),
        )
        .await
        .unwrap();

        assert!(max_active.load(Ordering::SeqCst) >= 2);
        task.abort();
    }

    #[tokio::test]
    async fn test_lookup_collapses_duplicate_cnames_with_lowest_ttl() {
        let (server_url, task) = start_test_server(|request| {
            match request
                .uri()
                .query()
                .unwrap_or_default()
                .split('&')
                .find_map(|part| part.strip_prefix("type="))
                .unwrap_or_default()
            {
                "A" => http::Response::new(
                    r#"{"Status":0,"Answer":[{"type":5,"data":"alias.example.com.","TTL":120},{"type":1,"data":"192.0.2.1","TTL":60}]}"#
                        .to_string(),
                ),
                "AAAA" => http::Response::new(
                    r#"{"Status":0,"Answer":[{"type":5,"data":"alias.example.com.","TTL":119}]}"#
                        .to_string(),
                ),
                _ => http::Response::new(r#"{"Status":0}"#.to_string()),
            }
        })
        .await;

        let result = lookup(
            "example.com",
            ResolverTarget::Doh {
                label: server_url.to_string(),
                url: server_url,
            },
            Instant::now(),
            TimeoutBudget::new(None),
        )
        .await
        .unwrap();

        let cnames = &result.records["CNAME"];
        assert_eq!(cnames.len(), 1);
        assert_eq!(cnames[0].ttl, 119);
        task.abort();
    }

    #[tokio::test]
    async fn test_lookup_udp_records_returns_ttl() {
        let (addr, stop) = start_udp_server();

        let records = lookup_udp_records(
            &addr,
            "example.com",
            QueryType {
                label: "A",
                dns_type: DNS_TYPE_A,
            },
            Duration::from_secs(1),
        )
        .await
        .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].value, "192.0.2.10");
        assert_eq!(records[0].ttl, 42);
        stop();
    }

    #[tokio::test]
    async fn test_inspect_udp_truncated_response_uses_tcp_fallback() {
        let (addr, stop) = start_truncated_udp_tcp_server(DNS_TYPE_TXT);

        let (out, code) = inspect_with_code(
            &Url::parse("https://example.com").unwrap(),
            Some(addr.as_str()),
        )
        .await
        .unwrap();

        assert_eq!(code, 0);
        assert!(out.contains("TXT\n"));
        assert!(out.contains("v=spf1 -all (TTL 2m)"));
        assert!(!out.contains("warning:"));
        stop();
    }

    #[tokio::test]
    async fn test_inspect_udp_truncated_response_warns_and_exits_nonzero() {
        let (addr, stop) = start_truncated_udp_server(DNS_TYPE_TXT);

        let (out, code) = inspect_with_code(
            &Url::parse("https://example.com").unwrap(),
            Some(addr.as_str()),
        )
        .await
        .unwrap();

        assert_eq!(code, 1);
        assert!(out.contains("A\n"));
        assert!(out.contains("192.0.2.10 (TTL 42s)"));
        assert!(out.contains(
            "\n\nwarning: DNS response for TXT was truncated over UDP after EDNS(0), and TCP fallback failed; results are incomplete\n"
        ));
        assert!(out.ends_with(
            "warning: DNS response for TXT was truncated over UDP after EDNS(0), and TCP fallback failed; results are incomplete\n"
        ));
        stop();
    }

    #[tokio::test]
    async fn test_lookup_uses_default_resolver_when_no_system_dns_server_discovered() {
        let target = resolver_target_from_resolv_conf(None, Some("# no nameservers\n"));
        assert_eq!(
            target,
            ResolverTarget::Default {
                label: "system resolver".to_string()
            }
        );
        let records = records_from_ip_addrs([
            "192.0.2.44".parse().unwrap(),
            "2001:db8::44".parse().unwrap(),
        ]);
        assert_eq!(records[0].typ, "A");
        assert_eq!(records[0].value, "192.0.2.44");
        assert!(!records[0].has_ttl);
        assert_eq!(records[1].typ, "AAAA");
        assert_eq!(records[1].value, "2001:db8::44");
        assert!(!records[1].has_ttl);
    }

    #[test]
    fn test_resolver_target_does_not_default_to_loopback() {
        let target = resolver_target_from_resolv_conf(None, Some("# no nameservers\n"));

        assert!(matches!(target, ResolverTarget::Default { .. }));
        assert!(!target.label().contains("127.0.0.1"));
    }

    #[test]
    fn test_render_shows_unavailable_ttl_per_record() {
        let out = render(&Inspection {
            host: "example.com".to_string(),
            resolver: "system".to_string(),
            records: HashMap::from([(
                "A".to_string(),
                vec![Record {
                    typ: "A".to_string(),
                    value: "192.0.2.1".to_string(),
                    ttl: 60,
                    has_ttl: true,
                }],
            )]),
            warnings: Vec::new(),
            duration: Duration::ZERO,
            exit_code: 0,
        });

        assert!(out.contains("└─ 192.0.2.1 (TTL 1m)"));
    }

    #[test]
    fn test_render_colors_dns_output_like_go() {
        let out = render_with_color(
            &Inspection {
                host: "example.com".to_string(),
                resolver: "system".to_string(),
                records: HashMap::from([(
                    "A".to_string(),
                    vec![Record {
                        typ: "A".to_string(),
                        value: "192.0.2.1".to_string(),
                        ttl: 60,
                        has_ttl: true,
                    }],
                )]),
                warnings: Vec::new(),
                duration: Duration::ZERO,
                exit_code: 0,
            },
            true,
        );

        assert!(out.starts_with("\x1b[2m* \x1b[0m\x1b[1m\x1b[36mDNS lookup\x1b[0m"));
        assert!(out.contains("\x1b[3msystem\x1b[0m"));
        assert!(out.contains("\x1b[2m* \x1b[0m\x1b[1mA\x1b[0m"));
        assert!(out.contains("\x1b[2m* \x1b[0m└─ \x1b[32m192.0.2.1\x1b[0m"));
        assert!(out.contains("\x1b[2m* \x1b[0mAddresses: \x1b[1m1\x1b[0m"));
        assert!(out.contains("\x1b[2m* \x1b[0mRecords: \x1b[1m1\x1b[0m"));
        assert!(out.contains("\x1b[2m* \x1b[0mDuration: \x1b[2m0ns\x1b[0m"));
        assert!(out.contains("\x1b[32m192.0.2.1\x1b[0m"));
        assert!(out.contains("\x1b[2m(TTL 1m)\x1b[0m"));
    }

    #[test]
    fn test_render_sorts_records_within_type() {
        let out = render(&Inspection {
            host: "example.com".to_string(),
            resolver: "system".to_string(),
            records: HashMap::from([(
                "A".to_string(),
                vec![
                    Record {
                        typ: "A".to_string(),
                        value: "192.0.2.20".to_string(),
                        ttl: 60,
                        has_ttl: true,
                    },
                    Record {
                        typ: "A".to_string(),
                        value: "192.0.2.10".to_string(),
                        ttl: 60,
                        has_ttl: true,
                    },
                ],
            )]),
            warnings: Vec::new(),
            duration: Duration::ZERO,
            exit_code: 0,
        });

        let first = out.find("192.0.2.10").unwrap();
        let second = out.find("192.0.2.20").unwrap();
        assert!(first < second, "records not sorted within type:\n{out}");
    }

    #[test]
    fn test_format_ttl_trims_zero_units() {
        for (ttl, want) in [
            (1, "1s"),
            (60, "1m"),
            (300, "5m"),
            (3600, "1h"),
            (3660, "1h1m"),
        ] {
            assert_eq!(format_ttl(ttl), want);
        }
    }

    #[test]
    fn test_format_caa() {
        let mut raw = vec![0, 5];
        raw.extend_from_slice(b"issueletsencrypt.org");

        assert_eq!(format_caa(&raw), r#"0 issue "letsencrypt.org""#);
    }

    #[test]
    fn test_normalize_doh_https_generic_rdata() {
        let got = normalize_doh_value(
            DNS_TYPE_HTTPS,
            r"\# 24 000100000100030268330003000201bb00040004c0000201",
        );

        for want in ["1 .", "ALPN=h3", "Port=443", "IPv4Hint=192.0.2.1"] {
            assert!(
                got.contains(want),
                "decoded HTTPS value missing {want:?}: {got:?}"
            );
        }
    }

    #[test]
    fn test_normalize_doh_caa_generic_rdata() {
        let got = normalize_doh_value(
            DNS_TYPE_CAA,
            r"\# 22 000569737375656c657473656e63727970742e6f7267",
        );

        assert_eq!(got, r#"0 issue "letsencrypt.org""#);
    }

    #[tokio::test]
    async fn test_inspect_doh_failure() {
        let (server_url, task) =
            start_test_server(|_| http::Response::new(r#"{"Status":3}"#.to_string())).await;

        let err = inspect(
            &Url::parse("https://missing.example").unwrap(),
            Some(server_url.as_str()),
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("NXDomain"));
        task.abort();
    }

    #[test]
    fn inspect_dns_ignored_flags_match_go_order() {
        let cli = Cli::try_parse_from([
            "fetch",
            "https://example.com",
            "--inspect-dns",
            "-d",
            "body",
            "--grpc",
            "--output",
            "out.txt",
            "--copy",
            "--timing",
            "--proxy",
            "http://proxy.test",
            "--bearer",
            "token",
            "--insecure",
            "--format",
            "off",
        ])
        .unwrap();

        assert_eq!(
            ignored_inspection_flags(&cli),
            [
                "--data/--json/--xml",
                "--grpc",
                "--output",
                "--copy",
                "--timing",
                "--proxy",
                "--bearer",
                "--insecure",
                "--format",
            ]
        );
    }

    fn start_udp_server() -> (String, impl FnOnce()) {
        let socket = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let addr = socket.local_addr().unwrap().to_string();
        let done = Arc::new(Mutex::new(false));
        let thread_done = done.clone();
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 512];
            loop {
                if *thread_done.lock().unwrap() {
                    return;
                }
                let Ok((n, peer)) = socket.recv_from(&mut buf) else {
                    continue;
                };
                if n < 12 {
                    continue;
                }
                let query_type = read_question_type(&buf[..n]).unwrap_or_default();
                let mut response = Vec::new();
                response.extend_from_slice(&buf[0..2]);
                response.extend_from_slice(&0x8180u16.to_be_bytes());
                response.extend_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&(u16::from(query_type == DNS_TYPE_A)).to_be_bytes());
                response.extend_from_slice(&0u16.to_be_bytes());
                response.extend_from_slice(&0u16.to_be_bytes());
                let question_name_end = question_end(&buf[..n]).unwrap_or(12);
                let question_end = (question_name_end + 4).min(n);
                response.extend_from_slice(&buf[12..question_end]);
                if query_type == DNS_TYPE_A {
                    response.extend_from_slice(&[0xc0, 0x0c]);
                    response.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
                    response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
                    response.extend_from_slice(&42u32.to_be_bytes());
                    response.extend_from_slice(&4u16.to_be_bytes());
                    response.extend_from_slice(&[192, 0, 2, 10]);
                }
                let _ = socket.send_to(&response, peer);
            }
        });

        (addr, move || {
            *done.lock().unwrap() = true;
            let _ = StdUdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .send_to(&[0], "127.0.0.1:9");
            handle.join().unwrap();
        })
    }

    fn start_truncated_udp_server(truncated_type: u16) -> (String, impl FnOnce()) {
        let socket = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let addr = socket.local_addr().unwrap().to_string();
        let done = Arc::new(Mutex::new(false));
        let thread_done = done.clone();
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 512];
            loop {
                if *thread_done.lock().unwrap() {
                    return;
                }
                let Ok((n, peer)) = socket.recv_from(&mut buf) else {
                    continue;
                };
                if n < 12 {
                    continue;
                }
                let query_type = read_question_type(&buf[..n]).unwrap_or_default();
                let mut response = Vec::new();
                response.extend_from_slice(&buf[0..2]);
                let flags = if query_type == truncated_type {
                    0x8380u16
                } else {
                    0x8180u16
                };
                response.extend_from_slice(&flags.to_be_bytes());
                response.extend_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&(u16::from(query_type == DNS_TYPE_A)).to_be_bytes());
                response.extend_from_slice(&0u16.to_be_bytes());
                response.extend_from_slice(&0u16.to_be_bytes());
                let question_name_end = question_end(&buf[..n]).unwrap_or(12);
                let question_end = (question_name_end + 4).min(n);
                response.extend_from_slice(&buf[12..question_end]);
                if query_type == DNS_TYPE_A {
                    response.extend_from_slice(&[0xc0, 0x0c]);
                    response.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
                    response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
                    response.extend_from_slice(&42u32.to_be_bytes());
                    response.extend_from_slice(&4u16.to_be_bytes());
                    response.extend_from_slice(&[192, 0, 2, 10]);
                }
                let _ = socket.send_to(&response, peer);
            }
        });

        (addr, move || {
            *done.lock().unwrap() = true;
            let _ = StdUdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .send_to(&[0], "127.0.0.1:9");
            handle.join().unwrap();
        })
    }

    fn start_truncated_udp_tcp_server(truncated_type: u16) -> (String, impl FnOnce()) {
        let udp_socket = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        udp_socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let addr = udp_socket.local_addr().unwrap();
        let tcp_listener = TcpListener::bind(addr).unwrap();
        tcp_listener.set_nonblocking(true).unwrap();
        let done = Arc::new(Mutex::new(false));

        let udp_done = done.clone();
        let udp_handle = thread::spawn(move || {
            let mut buf = [0u8; 512];
            loop {
                if *udp_done.lock().unwrap() {
                    return;
                }
                let Ok((n, peer)) = udp_socket.recv_from(&mut buf) else {
                    continue;
                };
                if n < 12 {
                    continue;
                }
                let query = &buf[..n];
                let query_type = read_question_type(query).unwrap_or_default();
                let flags = if query_type == truncated_type {
                    0x8380u16
                } else {
                    0x8180u16
                };
                let mut response = inspect_response_header(query, flags, query_type == DNS_TYPE_A);
                if query_type == DNS_TYPE_A {
                    write_raw_answer(&mut response, DNS_TYPE_A, 42, &[192, 0, 2, 10]);
                }
                let _ = udp_socket.send_to(&response, peer);
            }
        });

        let tcp_done = done.clone();
        let tcp_handle = thread::spawn(move || {
            loop {
                if *tcp_done.lock().unwrap() {
                    return;
                }
                match tcp_listener.accept() {
                    Ok((mut stream, _)) => {
                        let Some(query) = read_tcp_query(&mut stream) else {
                            continue;
                        };
                        let query_type = read_question_type(&query).unwrap_or_default();
                        let mut response =
                            inspect_response_header(&query, 0x8180, query_type == truncated_type);
                        if query_type == truncated_type && query_type == DNS_TYPE_TXT {
                            write_txt_answer(&mut response, 120, "v=spf1 -all");
                        }
                        let mut framed = Vec::with_capacity(response.len() + 2);
                        framed.extend_from_slice(&(response.len() as u16).to_be_bytes());
                        framed.extend_from_slice(&response);
                        let _ = stream.write_all(&framed);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => {}
                }
            }
        });

        (addr.to_string(), move || {
            *done.lock().unwrap() = true;
            let _ = StdUdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .send_to(&[0], addr);
            let _ = StdTcpStream::connect(addr);
            udp_handle.join().unwrap();
            tcp_handle.join().unwrap();
        })
    }

    fn inspect_response_header(query: &[u8], flags: u16, has_answer: bool) -> Vec<u8> {
        let question_name_end = question_end(query).unwrap_or(12);
        let question_end = (question_name_end + 4).min(query.len());
        let mut response = Vec::new();
        response.extend_from_slice(&query[0..2]);
        response.extend_from_slice(&flags.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&(u16::from(has_answer)).to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&query[12..question_end]);
        response
    }

    fn write_raw_answer(response: &mut Vec<u8>, dns_type: u16, ttl: u32, data: &[u8]) {
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&dns_type.to_be_bytes());
        response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        response.extend_from_slice(&ttl.to_be_bytes());
        response.extend_from_slice(&(data.len() as u16).to_be_bytes());
        response.extend_from_slice(data);
    }

    fn write_txt_answer(response: &mut Vec<u8>, ttl: u32, value: &str) {
        let mut data = vec![value.len() as u8];
        data.extend_from_slice(value.as_bytes());
        write_raw_answer(response, DNS_TYPE_TXT, ttl, &data);
    }

    fn read_tcp_query(stream: &mut StdTcpStream) -> Option<Vec<u8>> {
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).ok()?;
        let len = usize::from(u16::from_be_bytes(len_buf));
        let mut query = vec![0u8; len];
        stream.read_exact(&mut query).ok()?;
        Some(query)
    }

    fn read_question_type(raw: &[u8]) -> Option<u16> {
        let end = question_end(raw)?;
        Some(u16::from_be_bytes([raw[end], raw[end + 1]]))
    }

    fn question_end(raw: &[u8]) -> Option<usize> {
        let mut offset = 12;
        loop {
            let len = *raw.get(offset)?;
            offset += 1;
            if len == 0 {
                return Some(offset);
            }
            offset += usize::from(len);
        }
    }
}
