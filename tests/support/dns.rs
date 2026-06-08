use std::net::{Ipv4Addr, UdpSocket};
use std::thread;

pub(crate) fn start_udp_dns_server(host: &'static str, ip: Ipv4Addr) -> String {
    start_udp_dns_server_with_hosts(vec![(host, ip)])
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
            let mut resp = Vec::new();
            resp.extend_from_slice(&buf[..2]);
            resp.extend_from_slice(&[0x81, 0x80]);
            resp.extend_from_slice(&1_u16.to_be_bytes());
            let answer = records
                .iter()
                .find_map(|(host, ip)| (name == *host && qtype == 1).then_some(*ip));
            resp.extend_from_slice(&(if answer.is_some() { 1_u16 } else { 0_u16 }).to_be_bytes());
            resp.extend_from_slice(&0_u16.to_be_bytes());
            resp.extend_from_slice(&0_u16.to_be_bytes());
            resp.extend_from_slice(&buf[12..question_end]);
            if let Some(ip) = answer {
                resp.extend_from_slice(&[0xc0, 0x0c]);
                resp.extend_from_slice(&1_u16.to_be_bytes());
                resp.extend_from_slice(&1_u16.to_be_bytes());
                resp.extend_from_slice(&30_u32.to_be_bytes());
                resp.extend_from_slice(&4_u16.to_be_bytes());
                resp.extend_from_slice(&ip.octets());
            }
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
