use std::collections::HashMap;
use std::io::IsTerminal;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use futures_util::future::join_all;
use reqwest::header::{ACCEPT, USER_AGENT};
use serde::Deserialize;
use tokio::net::UdpSocket;
use url::Url;

use crate::cli::Cli;
use crate::core::{self, Printer, Sequence};
use crate::dns::util::{dns_query_id, udp_dns_timeout};
use crate::error::{FetchError, write_error_with_color, write_warning_with_color};

const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_NS: u16 = 2;
const DNS_TYPE_CNAME: u16 = 5;
const DNS_TYPE_SOA: u16 = 6;
const DNS_TYPE_MX: u16 = 15;
const DNS_TYPE_TXT: u16 = 16;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_TYPE_SRV: u16 = 33;
const DNS_TYPE_SVCB: u16 = 64;
const DNS_TYPE_HTTPS: u16 = 65;
const DNS_TYPE_CAA: u16 = 257;
const DNS_CLASS_IN: u16 = 1;

const INSPECT_TYPES: &[QueryType] = &[
    QueryType {
        label: "A",
        doh_type: "A",
        dns_type: DNS_TYPE_A,
    },
    QueryType {
        label: "AAAA",
        doh_type: "AAAA",
        dns_type: DNS_TYPE_AAAA,
    },
    QueryType {
        label: "CNAME",
        doh_type: "CNAME",
        dns_type: DNS_TYPE_CNAME,
    },
    QueryType {
        label: "TXT",
        doh_type: "TXT",
        dns_type: DNS_TYPE_TXT,
    },
    QueryType {
        label: "MX",
        doh_type: "MX",
        dns_type: DNS_TYPE_MX,
    },
    QueryType {
        label: "NS",
        doh_type: "NS",
        dns_type: DNS_TYPE_NS,
    },
    QueryType {
        label: "SOA",
        doh_type: "SOA",
        dns_type: DNS_TYPE_SOA,
    },
    QueryType {
        label: "SRV",
        doh_type: "SRV",
        dns_type: DNS_TYPE_SRV,
    },
    QueryType {
        label: "CAA",
        doh_type: "CAA",
        dns_type: DNS_TYPE_CAA,
    },
    QueryType {
        label: "SVCB",
        doh_type: "SVCB",
        dns_type: DNS_TYPE_SVCB,
    },
    QueryType {
        label: "HTTPS",
        doh_type: "HTTPS",
        dns_type: DNS_TYPE_HTTPS,
    },
];

#[derive(Clone, Copy)]
struct QueryType {
    label: &'static str,
    doh_type: &'static str,
    dns_type: u16,
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
    duration: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ResolverTarget {
    Default { label: String },
    Udp { label: String, addr: String },
    Doh { label: String, url: Url },
}

pub async fn execute(cli: &Cli) -> Result<i32, FetchError> {
    let url = crate::http::normalize_url(cli.url.as_deref().expect("URL checked by app"))?;
    let ignored = ignored_inspection_flags(cli);
    if !ignored.is_empty() {
        write_warning_with_color(
            format!("--inspect-dns ignores: {}", ignored.join(", ")),
            cli.color.as_deref(),
        );
    }

    let timeout = cli
        .timeout
        .map(|seconds| crate::http::duration_from_seconds("timeout", seconds))
        .transpose()?;
    let use_color = core::color_enabled(cli.color.as_deref(), std::io::stderr().is_terminal());
    let inspected = if let Some(timeout) = timeout {
        match tokio::time::timeout(
            timeout,
            inspect_with_color(&url, cli.dns_server.as_deref(), use_color, Some(timeout)),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(FetchError::Message(format!(
                "request timed out after {}",
                format_timeout(timeout)
            ))),
        }
    } else {
        inspect_with_color(&url, cli.dns_server.as_deref(), use_color, None).await
    };

    match inspected {
        Ok(output) => {
            eprint!("{output}");
            Ok(0)
        }
        Err(err) => {
            write_error_with_color(err, cli.color.as_deref());
            Ok(1)
        }
    }
}

#[cfg(test)]
async fn inspect(url: &Url, dns_server: Option<&str>) -> Result<String, FetchError> {
    inspect_with_color(url, dns_server, false, None).await
}

async fn inspect_with_color(
    url: &Url,
    dns_server: Option<&str>,
    use_color: bool,
    timeout: Option<Duration>,
) -> Result<String, FetchError> {
    let host = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| FetchError::Message("--inspect-dns requires a hostname".to_string()))?;
    let target = resolver_target(dns_server)?;
    let start = Instant::now();

    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(render_ip_literal_with_color(
            host,
            ip,
            target.label(),
            start.elapsed(),
            use_color,
        ));
    }

    let result = lookup(host, target, start, timeout).await?;
    Ok(render_with_color(&result, use_color))
}

async fn lookup(
    host: &str,
    target: ResolverTarget,
    start: Instant,
    timeout: Option<Duration>,
) -> Result<Inspection, FetchError> {
    let mut out = Inspection {
        host: host.to_string(),
        resolver: target.label().to_string(),
        records: HashMap::new(),
        duration: Duration::ZERO,
    };

    if matches!(target, ResolverTarget::Default { .. }) {
        let records = lookup_default_resolver_records(host).await?;
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

    let udp_timeout = udp_dns_timeout(timeout);
    let futures = INSPECT_TYPES.iter().copied().map(|query_type| {
        let target = target.clone();
        async move {
            match target {
                ResolverTarget::Doh { url, .. } => lookup_doh_records(&url, host, query_type).await,
                ResolverTarget::Udp { addr, .. } => {
                    lookup_udp_records(&addr, host, query_type, udp_timeout).await
                }
                ResolverTarget::Default { .. } => unreachable!("default resolver handled earlier"),
            }
        }
    });
    let results = join_all(futures).await;

    let mut first_err = None;
    let mut seen: HashMap<String, usize> = HashMap::new();
    for result in results {
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
            Err(err) if first_err.is_none() => {
                first_err = Some(err);
            }
            Err(_) => {}
        }
    }
    out.duration = start.elapsed();

    if record_count(&out) > 0 {
        return Ok(out);
    }
    if let Some(err) = first_err {
        return Err(format!("lookup {host}: {err}").into());
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
    server_url: &Url,
    host: &str,
    query_type: QueryType,
) -> Result<Vec<Record>, FetchError> {
    let mut url = server_url.clone();
    let mut pairs: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(key, _)| key != "name" && key != "type")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    pairs.push(("name".to_string(), host.to_string()));
    pairs.push(("type".to_string(), query_type.doh_type.to_string()));
    url.query_pairs_mut().clear().extend_pairs(pairs);

    let response = reqwest::Client::builder()
        .use_rustls_tls()
        .build()?
        .get(url)
        .header(ACCEPT, "application/dns-json")
        .header(USER_AGENT, crate::core::user_agent())
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        let body = response.bytes().await.unwrap_or_default();
        if body.is_empty() {
            return Err(format!("http response code: {}", status.as_u16()).into());
        }
        return Err(format!("{}: {}", status.as_u16(), String::from_utf8_lossy(&body)).into());
    }

    let body = response.json::<DohResponse>().await?;
    if body.status != 0 {
        let name = rcode_name(body.status);
        if name.is_empty() {
            return Err("no DNS records found".into());
        }
        return Err(format!("no DNS records found: {name}").into());
    }

    Ok(body
        .answer
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
) -> Result<Vec<Record>, FetchError> {
    let id = dns_query_id();
    let raw = build_dns_query(id, host, query_type.dns_type)?;
    let socket = UdpSocket::bind(if server_addr.starts_with('[') {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    })
    .await?;
    socket.connect(server_addr).await?;
    socket.send(&raw).await?;

    let mut buf = vec![0u8; 4096];
    let n = match tokio::time::timeout(timeout, socket.recv(&mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(err)) => return Err(err.into()),
        Err(_) => return Err("DNS lookup timed out".into()),
    };
    parse_dns_response(&buf[..n], id)
}

fn build_dns_query(id: u16, host: &str, dns_type: u16) -> Result<Vec<u8>, FetchError> {
    let mut raw = Vec::with_capacity(512);
    raw.extend_from_slice(&id.to_be_bytes());
    raw.extend_from_slice(&0x0100u16.to_be_bytes());
    raw.extend_from_slice(&1u16.to_be_bytes());
    raw.extend_from_slice(&0u16.to_be_bytes());
    raw.extend_from_slice(&0u16.to_be_bytes());
    raw.extend_from_slice(&0u16.to_be_bytes());
    write_dns_name(&mut raw, host)?;
    raw.extend_from_slice(&dns_type.to_be_bytes());
    raw.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    Ok(raw)
}

fn write_dns_name(raw: &mut Vec<u8>, host: &str) -> Result<(), FetchError> {
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        raw.push(0);
        return Ok(());
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("invalid DNS name: {host}").into());
        }
        raw.push(label.len() as u8);
        raw.extend_from_slice(label.as_bytes());
    }
    raw.push(0);
    Ok(())
}

fn parse_dns_response(raw: &[u8], expected_id: u16) -> Result<Vec<Record>, FetchError> {
    if raw.len() < 12 {
        return Err("short DNS response".into());
    }
    let id = read_u16(raw, 0)?;
    if id != expected_id {
        return Err("mismatched DNS response ID".into());
    }
    let flags = read_u16(raw, 2)?;
    let rcode = i32::from(flags & 0x000f);
    if rcode != 0 {
        return Err(format!("no DNS records found: {}", rcode_name(rcode)).into());
    }
    if flags & 0x0200 != 0 {
        return Err("DNS response was truncated".into());
    }

    let question_count = usize::from(read_u16(raw, 4)?);
    let answer_count = usize::from(read_u16(raw, 6)?);
    let mut offset = 12;
    for _ in 0..question_count {
        let (_, next) = read_dns_name(raw, offset)?;
        offset = next + 4;
        if offset > raw.len() {
            return Err("short DNS question".into());
        }
    }

    let mut records = Vec::new();
    for _ in 0..answer_count {
        let (_, next) = read_dns_name(raw, offset)?;
        offset = next;
        let typ = read_u16(raw, offset)?;
        let class = read_u16(raw, offset + 2)?;
        let ttl = read_u32(raw, offset + 4)?;
        let rdlen = usize::from(read_u16(raw, offset + 8)?);
        offset += 10;
        if offset + rdlen > raw.len() {
            return Err("short DNS resource".into());
        }
        let data_offset = offset;
        offset += rdlen;
        if class != DNS_CLASS_IN {
            continue;
        }
        if let Some(value) = resource_value(raw, typ, data_offset, rdlen)? {
            records.push(Record {
                typ: type_label(typ).to_string(),
                value,
                ttl,
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
        DNS_TYPE_CNAME | DNS_TYPE_NS => read_dns_name(packet, offset)?.0,
        DNS_TYPE_TXT => parse_txt_rdata(rdata),
        DNS_TYPE_MX if len >= 3 => {
            let pref = read_u16(packet, offset)?;
            let name = read_dns_name(packet, offset + 2)?.0;
            format!("{pref} {name}")
        }
        DNS_TYPE_SOA => parse_soa_rdata(packet, offset)?,
        DNS_TYPE_SRV if len >= 7 => {
            let priority = read_u16(packet, offset)?;
            let weight = read_u16(packet, offset + 2)?;
            let port = read_u16(packet, offset + 4)?;
            let target = read_dns_name(packet, offset + 6)?.0;
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
    let (ns, mut next) = read_dns_name(packet, offset)?;
    let (mbox, next_after_mbox) = read_dns_name(packet, next)?;
    next = next_after_mbox;
    let serial = read_u32(packet, next)?;
    let refresh = read_u32(packet, next + 4)?;
    let retry = read_u32(packet, next + 8)?;
    let expire = read_u32(packet, next + 12)?;
    let min_ttl = read_u32(packet, next + 16)?;
    Ok(format!(
        "{ns} {mbox} serial={serial} refresh={refresh} retry={retry} expire={expire} minttl={min_ttl}"
    ))
}

fn read_dns_name(packet: &[u8], offset: usize) -> Result<(String, usize), FetchError> {
    let mut labels = Vec::new();
    let mut pos = offset;
    let mut next = offset;
    let mut jumped = false;
    let mut jumps = 0usize;

    loop {
        if pos >= packet.len() {
            return Err("short DNS name".into());
        }
        let len = packet[pos];
        if len & 0xc0 == 0xc0 {
            if pos + 1 >= packet.len() {
                return Err("short DNS name pointer".into());
            }
            let pointer = usize::from(u16::from_be_bytes([len & 0x3f, packet[pos + 1]]));
            if !jumped {
                next = pos + 2;
            }
            pos = pointer;
            jumped = true;
            jumps += 1;
            if jumps > 128 {
                return Err("DNS name pointer loop".into());
            }
            continue;
        }
        if len & 0xc0 != 0 {
            return Err("invalid DNS name label".into());
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
            return Err("short DNS name label".into());
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
            let addr = normalize_udp_dns_server(server)?;
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

fn normalize_udp_dns_server(server: &str) -> Result<String, FetchError> {
    if server.contains("://") {
        return Err(format!(
            "invalid value '{server}' for option '--dns-server': must be in the format <IP[:PORT]>"
        )
        .into());
    }
    if server.parse::<SocketAddr>().is_ok() {
        return Ok(server.to_string());
    }
    if let Ok(ip) = server.parse::<IpAddr>() {
        return Ok(match ip {
            IpAddr::V4(_) => format!("{ip}:53"),
            IpAddr::V6(_) => format!("[{ip}]:53"),
        });
    }
    Err(format!(
        "invalid value '{server}' for option '--dns-server': must be in the format <IP[:PORT]>"
    )
    .into())
}

fn render_ip_literal_with_color(
    host: &str,
    ip: IpAddr,
    resolver: &str,
    duration: Duration,
    use_color: bool,
) -> String {
    let mut printer = Printer::new(use_color);
    write_dns_title(&mut printer, host, resolver);
    printer.write_info_prefix();
    printer.push_str("  IP literal: ");
    printer.write_styled(&ip.to_string(), &[Sequence::Green]);
    printer.push_str(" (no DNS query needed)\n");
    printer.write_info_prefix();
    printer.push_str("  Duration: ");
    printer.write_styled(&format_duration(duration), &[Sequence::Dim]);
    printer.push_str("\n");
    printer
        .into_string()
        .expect("DNS inspection output is UTF-8")
}

#[cfg(test)]
fn render(result: &Inspection) -> String {
    render_with_color(result, false)
}

fn render_with_color(result: &Inspection, use_color: bool) -> String {
    let mut out = Printer::new(use_color);
    write_dns_title(&mut out, &result.host, &result.resolver);

    for query_type in INSPECT_TYPES {
        render_section(
            &mut out,
            query_type.label,
            result.records.get(query_type.label),
        );
    }
    render_other_sections(&mut out, &result.records);

    out.write_info_prefix();
    out.push_str("  Addresses: ");
    let address_count = result.records.get("A").map_or(0, Vec::len)
        + result.records.get("AAAA").map_or(0, Vec::len);
    out.write_styled(&address_count.to_string(), &[Sequence::Bold]);
    out.push_str("\n");
    out.write_info_prefix();
    out.push_str("  Records: ");
    out.write_styled(&record_count(result).to_string(), &[Sequence::Bold]);
    out.push_str("\n");
    out.write_info_prefix();
    out.push_str("  Duration: ");
    out.write_styled(&format_duration(result.duration), &[Sequence::Dim]);
    out.push_str("\n");
    out.into_string().expect("DNS inspection output is UTF-8")
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
    out.write_styled(&format!("  {name}"), &[Sequence::Bold]);
    out.push_str("\n");
    for (idx, record) in records.iter().enumerate() {
        let marker = if idx == records.len() - 1 {
            "└─"
        } else {
            "├─"
        };
        out.write_info_prefix();
        out.push_str(&format!("  {marker} "));
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

fn format_duration(duration: Duration) -> String {
    let nanos = duration.as_nanos();
    let rounded = if nanos < 1_000_000 {
        ((nanos + 500) / 1_000) * 1_000
    } else {
        ((nanos + 50_000) / 100_000) * 100_000
    };
    format_go_duration_nanos(rounded)
}

fn format_timeout(timeout: Duration) -> String {
    let seconds = timeout.as_secs_f64();
    if timeout.subsec_nanos() == 0 {
        format!("{}s", timeout.as_secs())
    } else {
        format!("{seconds:.3}s")
            .trim_end_matches('0')
            .trim_end_matches('.')
            .to_string()
    }
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

fn read_u16(raw: &[u8], offset: usize) -> Result<u16, FetchError> {
    let bytes = raw
        .get(offset..offset + 2)
        .ok_or_else(|| FetchError::Message("short DNS message".to_string()))?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(raw: &[u8], offset: usize) -> Result<u32, FetchError> {
    let bytes = raw
        .get(offset..offset + 4)
        .ok_or_else(|| FetchError::Message("short DNS message".to_string()))?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
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

#[derive(Debug, Deserialize)]
struct DohResponse {
    #[serde(rename = "Status")]
    status: i32,
    #[serde(rename = "Answer", default)]
    answer: Vec<DohAnswer>,
}

#[derive(Debug, Deserialize)]
struct DohAnswer {
    #[serde(rename = "type")]
    answer_type: u16,
    data: String,
    #[serde(rename = "TTL")]
    ttl: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::net::UdpSocket as StdUdpSocket;
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
            None,
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
            None,
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
                doh_type: "A",
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
            duration: Duration::ZERO,
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
                duration: Duration::ZERO,
            },
            true,
        );

        assert!(out.starts_with("\x1b[2m* \x1b[0m\x1b[1m\x1b[36mDNS lookup\x1b[0m"));
        assert!(out.contains("\x1b[3msystem\x1b[0m"));
        assert!(out.contains("\x1b[1m  A\x1b[0m"));
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
            duration: Duration::ZERO,
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
