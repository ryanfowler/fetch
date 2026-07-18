use std::net::{Ipv4Addr, UdpSocket};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::thread;
use std::time::Duration;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_HTTPS: u16 = 65;

pub(crate) fn start_udp_dns_server(host: &'static str, ip: Ipv4Addr) -> String {
    start_udp_dns_server_with_hosts(vec![(host, ip)])
}

pub(crate) fn start_udp_dns_server_with_https(
    host: &'static str,
    ip: Ipv4Addr,
    https_port: u16,
) -> String {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind udp dns server");
    let addr = socket.local_addr().unwrap().to_string();
    thread::spawn(move || {
        let mut buf = [0_u8; 512];
        while let Ok((n, peer)) = socket.recv_from(&mut buf) {
            let Some((name, qtype, question_end)) = parse_dns_question(&buf[..n]) else {
                continue;
            };
            let answer = if name == host && qtype == TYPE_A {
                Some((TYPE_A, ip.octets().to_vec()))
            } else if name == host && qtype == TYPE_HTTPS {
                Some((TYPE_HTTPS, https_rdata(https_port, ip)))
            } else {
                None
            };
            let response = dns_response(&buf[..n], question_end, answer);
            let _ = socket.send_to(&response, peer);
        }
    });
    addr
}

pub(crate) fn start_udp_dns_server_with_toggleable_https(
    host: &'static str,
    ip: Ipv4Addr,
    https_port: u16,
) -> (String, Arc<AtomicBool>) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind udp dns server");
    let addr = socket.local_addr().unwrap().to_string();
    let advertise_https = Arc::new(AtomicBool::new(true));
    let advertise_for_thread = advertise_https.clone();
    thread::spawn(move || {
        let mut buf = [0_u8; 512];
        while let Ok((n, peer)) = socket.recv_from(&mut buf) {
            let Some((name, qtype, question_end)) = parse_dns_question(&buf[..n]) else {
                continue;
            };
            let answer = if name == host && qtype == TYPE_A {
                Some((TYPE_A, ip.octets().to_vec()))
            } else if name == host
                && qtype == TYPE_HTTPS
                && advertise_for_thread.load(Ordering::SeqCst)
            {
                Some((TYPE_HTTPS, https_rdata(https_port, ip)))
            } else {
                None
            };
            let response = dns_response(&buf[..n], question_end, answer);
            let _ = socket.send_to(&response, peer);
        }
    });
    (addr, advertise_https)
}

pub(crate) fn start_udp_dns_server_with_https_target_dropping_target(
    host: &'static str,
    ip: Ipv4Addr,
    https_target: &'static str,
    https_port: u16,
) -> String {
    let (addr, _) = start_udp_dns_server_with_https_targets_dropping_targets(
        host,
        ip,
        vec![https_target],
        https_port,
    );
    addr
}

pub(crate) fn start_udp_dns_server_with_https_targets_dropping_targets(
    host: &'static str,
    ip: Ipv4Addr,
    https_targets: Vec<&'static str>,
    https_port: u16,
) -> (String, Arc<AtomicUsize>) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind udp dns server");
    let addr = socket.local_addr().unwrap().to_string();
    let dropped_target_a_queries = Arc::new(AtomicUsize::new(0));
    let query_count = dropped_target_a_queries.clone();
    thread::spawn(move || {
        let mut buf = [0_u8; 512];
        while let Ok((n, peer)) = socket.recv_from(&mut buf) {
            let Some((name, qtype, question_end)) = parse_dns_question(&buf[..n]) else {
                continue;
            };
            if https_targets
                .iter()
                .any(|target| name.eq_ignore_ascii_case(target))
                && qtype == TYPE_A
            {
                query_count.fetch_add(1, Ordering::SeqCst);
                continue;
            }
            let response = if name == host && qtype == TYPE_A {
                dns_response(
                    &buf[..n],
                    question_end,
                    Some((TYPE_A, ip.octets().to_vec())),
                )
            } else if name == host && qtype == TYPE_HTTPS {
                dns_response_many(
                    &buf[..n],
                    question_end,
                    https_targets
                        .iter()
                        .map(|target| (TYPE_HTTPS, https_target_rdata(https_port, target)))
                        .collect(),
                )
            } else {
                dns_response(&buf[..n], question_end, None)
            };
            let _ = socket.send_to(&response, peer);
        }
    });
    (addr, dropped_target_a_queries)
}

pub(crate) fn start_udp_dns_server_with_delayed_https_and_resolution(
    host: &'static str,
    ip: Ipv4Addr,
    delay: Duration,
) -> (String, Arc<AtomicBool>) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind udp dns server");
    let addr = socket.local_addr().unwrap().to_string();
    let https_pending = Arc::new(AtomicUsize::new(0));
    let ordinary_pending = Arc::new(AtomicUsize::new(0));
    let overlapped = Arc::new(AtomicBool::new(false));
    let https_for_thread = https_pending.clone();
    let ordinary_for_thread = ordinary_pending.clone();
    let overlapped_for_thread = overlapped.clone();
    thread::spawn(move || {
        let mut buf = [0_u8; 512];
        while let Ok((n, peer)) = socket.recv_from(&mut buf) {
            let Some((name, qtype, question_end)) = parse_dns_question(&buf[..n]) else {
                continue;
            };
            let answer =
                (name == host && qtype == TYPE_A).then_some((TYPE_A, ip.octets().to_vec()));
            let response = dns_response(&buf[..n], question_end, answer);
            let pending = if name == host && qtype == TYPE_HTTPS {
                https_for_thread.fetch_add(1, Ordering::SeqCst);
                if ordinary_for_thread.load(Ordering::SeqCst) > 0 {
                    overlapped_for_thread.store(true, Ordering::SeqCst);
                }
                Some(https_for_thread.clone())
            } else if name == host && matches!(qtype, TYPE_A | TYPE_AAAA) {
                ordinary_for_thread.fetch_add(1, Ordering::SeqCst);
                if https_for_thread.load(Ordering::SeqCst) > 0 {
                    overlapped_for_thread.store(true, Ordering::SeqCst);
                }
                Some(ordinary_for_thread.clone())
            } else {
                None
            };
            if let Some(pending) = pending {
                let socket = socket.try_clone().expect("clone udp dns server socket");
                thread::spawn(move || {
                    thread::sleep(delay);
                    pending.fetch_sub(1, Ordering::SeqCst);
                    let _ = socket.send_to(&response, peer);
                });
            } else {
                let _ = socket.send_to(&response, peer);
            }
        }
    });
    (addr, overlapped)
}

pub(crate) fn start_udp_dns_server_dropping_https(host: &'static str, ip: Ipv4Addr) -> String {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind udp dns server");
    let addr = socket.local_addr().unwrap().to_string();
    thread::spawn(move || {
        let mut buf = [0_u8; 512];
        while let Ok((n, peer)) = socket.recv_from(&mut buf) {
            let Some((name, qtype, question_end)) = parse_dns_question(&buf[..n]) else {
                continue;
            };
            if name == host && qtype == TYPE_HTTPS {
                continue;
            }
            let answer = if name == host && qtype == TYPE_A {
                Some((TYPE_A, ip.octets().to_vec()))
            } else {
                None
            };
            let resp = dns_response(&buf[..n], question_end, answer);
            let _ = socket.send_to(&resp, peer);
        }
    });
    addr
}

pub(crate) fn start_udp_dns_server_with_delayed_resolution(
    host: &'static str,
    ip: Ipv4Addr,
    delay: Duration,
) -> String {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind udp dns server");
    let addr = socket.local_addr().unwrap().to_string();
    thread::spawn(move || {
        let mut buf = [0_u8; 512];
        while let Ok((n, peer)) = socket.recv_from(&mut buf) {
            let Some((name, qtype, question_end)) = parse_dns_question(&buf[..n]) else {
                continue;
            };
            let answer =
                (name == host && qtype == TYPE_A).then_some((TYPE_A, ip.octets().to_vec()));
            let response = dns_response(&buf[..n], question_end, answer);
            if name == host && matches!(qtype, TYPE_A | TYPE_AAAA) {
                let socket = socket.try_clone().expect("clone udp dns server socket");
                thread::spawn(move || {
                    thread::sleep(delay);
                    let _ = socket.send_to(&response, peer);
                });
            } else {
                let _ = socket.send_to(&response, peer);
            }
        }
    });
    addr
}

pub(crate) fn start_udp_dns_server_with_delayed_aaaa(
    host: &'static str,
    ip: Ipv4Addr,
    delay: Duration,
) -> String {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind udp dns server");
    let addr = socket.local_addr().unwrap().to_string();
    thread::spawn(move || {
        let mut buf = [0_u8; 512];
        while let Ok((n, peer)) = socket.recv_from(&mut buf) {
            let Some((name, qtype, question_end)) = parse_dns_question(&buf[..n]) else {
                continue;
            };
            if name == host && qtype == TYPE_AAAA {
                let resp = dns_response(&buf[..n], question_end, None);
                let socket = socket.try_clone().expect("clone udp dns server socket");
                thread::spawn(move || {
                    thread::sleep(delay);
                    let _ = socket.send_to(&resp, peer);
                });
                continue;
            }
            let answer = if name == host && qtype == TYPE_A {
                Some((TYPE_A, ip.octets().to_vec()))
            } else {
                None
            };
            let resp = dns_response(&buf[..n], question_end, answer);
            let _ = socket.send_to(&resp, peer);
        }
    });
    addr
}

pub(crate) fn start_udp_dns_server_with_hosts(records: Vec<(&'static str, Ipv4Addr)>) -> String {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind udp dns server");
    let addr = socket.local_addr().unwrap().to_string();
    thread::spawn(move || {
        let mut buf = [0_u8; 512];
        while let Ok((n, peer)) = socket.recv_from(&mut buf) {
            let Some((name, qtype, question_end)) = parse_dns_question(&buf[..n]) else {
                continue;
            };
            let answer = records
                .iter()
                .find_map(|(host, ip)| (name == *host && qtype == TYPE_A).then_some(*ip))
                .map(|ip| (TYPE_A, ip.octets().to_vec()));
            let resp = dns_response(&buf[..n], question_end, answer);
            let _ = socket.send_to(&resp, peer);
        }
    });
    addr
}

pub(crate) fn start_unresponsive_udp_dns_server() -> String {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind udp dns server");
    let addr = socket.local_addr().unwrap().to_string();
    thread::spawn(move || {
        let mut buf = [0_u8; 512];
        while socket.recv_from(&mut buf).is_ok() {}
    });
    addr
}

pub(crate) fn parse_dns_question(raw: &[u8]) -> Option<(String, u16, usize)> {
    if raw.len() < 12 {
        return None;
    }
    let mut off = 12;
    let mut labels = Vec::new();
    loop {
        let len = *raw.get(off)? as usize;
        off += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 || off + len > raw.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&raw[off..off + len]).into_owned());
        off += len;
    }
    if off + 4 > raw.len() {
        return None;
    }
    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        format!("{}.", labels.join("."))
    };
    let qtype = u16::from_be_bytes([raw[off], raw[off + 1]]);
    Some((name, qtype, off + 4))
}

fn dns_response(query: &[u8], question_end: usize, answer: Option<(u16, Vec<u8>)>) -> Vec<u8> {
    dns_response_many(query, question_end, answer.into_iter().collect())
}

fn dns_response_many(query: &[u8], question_end: usize, answers: Vec<(u16, Vec<u8>)>) -> Vec<u8> {
    let mut resp = Vec::new();
    resp.extend_from_slice(&query[..2]);
    resp.extend_from_slice(&[0x81, 0x80]);
    resp.extend_from_slice(&1_u16.to_be_bytes());
    resp.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    resp.extend_from_slice(&0_u16.to_be_bytes());
    resp.extend_from_slice(&0_u16.to_be_bytes());
    resp.extend_from_slice(&query[12..question_end]);
    for (typ, data) in answers {
        resp.extend_from_slice(&[0xc0, 0x0c]);
        resp.extend_from_slice(&typ.to_be_bytes());
        resp.extend_from_slice(&1_u16.to_be_bytes());
        resp.extend_from_slice(&30_u32.to_be_bytes());
        resp.extend_from_slice(&(data.len() as u16).to_be_bytes());
        resp.extend_from_slice(&data);
    }
    resp
}

fn https_rdata(port: u16, ipv4_hint: Ipv4Addr) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&1_u16.to_be_bytes());
    write_dns_name(&mut out, ".");
    write_svc_param(&mut out, 1, &[2, b'h', b'3']);
    write_svc_param(&mut out, 3, &port.to_be_bytes());
    write_svc_param(&mut out, 4, &ipv4_hint.octets());
    out
}

fn https_target_rdata(port: u16, target: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&1_u16.to_be_bytes());
    write_dns_name(&mut out, target);
    write_svc_param(&mut out, 1, &[2, b'h', b'3']);
    write_svc_param(&mut out, 3, &port.to_be_bytes());
    out
}

fn write_dns_name(out: &mut Vec<u8>, name: &str) {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        out.push(0);
        return;
    }
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

fn write_svc_param(out: &mut Vec<u8>, key: u16, value: &[u8]) {
    out.extend_from_slice(&key.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}
