#[cfg(target_os = "macos")]
use std::ffi::CString;
#[cfg(not(all(unix, not(target_os = "macos"))))]
use std::time::Duration;
#[cfg(target_os = "macos")]
use std::time::Instant;

#[cfg(any(target_os = "macos", test))]
use crate::dns::wire;
use crate::duration::TimeoutBudget;
use crate::error::FetchError;

use super::SvcbRecord;
#[cfg(any(target_os = "macos", windows, test))]
use super::parse_rdata;

#[cfg(all(unix, not(target_os = "macos")))]
pub(super) async fn lookup_https_records(
    host: &str,
    timeout: TimeoutBudget,
) -> Result<Vec<SvcbRecord>, FetchError> {
    let Some(server_addr) = resolv_conf_nameserver() else {
        return Ok(Vec::new());
    };
    match super::lookup_udp_https_records(server_addr, host, timeout).await {
        Ok(records) => Ok(records),
        Err(_) => Ok(Vec::new()),
    }
}

#[cfg(not(all(unix, not(target_os = "macos"))))]
pub(super) async fn lookup_https_records(
    host: &str,
    timeout: TimeoutBudget,
) -> Result<Vec<SvcbRecord>, FetchError> {
    let host = host.to_string();
    let blocking_timeout = timeout.remaining()?;
    let lookup =
        tokio::task::spawn_blocking(move || lookup_https_records_blocking(&host, blocking_timeout));

    timeout
        .run(async {
            lookup
                .await
                .map_err(|err| FetchError::Runtime(format!("system DNS task failed: {err}")))?
        })
        .await
}

#[cfg(target_os = "macos")]
fn lookup_https_records_blocking(
    host: &str,
    timeout: Option<Duration>,
) -> Result<Vec<SvcbRecord>, FetchError> {
    use std::os::raw::{c_char, c_int, c_uint, c_void};

    type DNSServiceRef = *mut c_void;
    type DNSServiceErrorType = c_int;
    type DNSServiceFlags = c_uint;

    const K_DNS_SERVICE_ERR_NO_ERROR: DNSServiceErrorType = 0;
    const K_DNS_SERVICE_FLAGS_MORE_COMING: DNSServiceFlags = 1;

    type DNSServiceQueryRecordReply = unsafe extern "C" fn(
        DNSServiceRef,
        DNSServiceFlags,
        c_uint,
        DNSServiceErrorType,
        *const c_char,
        u16,
        u16,
        u16,
        *const c_void,
        u32,
        *mut c_void,
    );

    #[link(name = "System")]
    unsafe extern "C" {
        fn DNSServiceQueryRecord(
            sd_ref: *mut DNSServiceRef,
            flags: DNSServiceFlags,
            interface_index: c_uint,
            fullname: *const c_char,
            rrtype: u16,
            rrclass: u16,
            callback: DNSServiceQueryRecordReply,
            context: *mut c_void,
        ) -> DNSServiceErrorType;
        fn DNSServiceProcessResult(sd_ref: DNSServiceRef) -> DNSServiceErrorType;
        fn DNSServiceRefDeallocate(sd_ref: DNSServiceRef);
        fn DNSServiceRefSockFD(sd_ref: DNSServiceRef) -> c_int;
    }

    struct DnsServiceRefGuard(DNSServiceRef);

    impl Drop for DnsServiceRefGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    DNSServiceRefDeallocate(self.0);
                }
            }
        }
    }

    struct QueryState {
        records: Vec<SvcbRecord>,
        error: Option<String>,
        finished: bool,
    }

    unsafe extern "C" fn query_record_callback(
        _sd_ref: DNSServiceRef,
        flags: DNSServiceFlags,
        _interface_index: c_uint,
        error_code: DNSServiceErrorType,
        _fullname: *const c_char,
        rrtype: u16,
        rrclass: u16,
        rdlen: u16,
        rdata: *const c_void,
        ttl: u32,
        context: *mut c_void,
    ) {
        if context.is_null() {
            return;
        }
        let state = unsafe { &mut *(context.cast::<QueryState>()) };
        if error_code != K_DNS_SERVICE_ERR_NO_ERROR {
            state.error = Some(format!("system HTTPS record lookup failed: {error_code}"));
            state.finished = true;
            return;
        }
        if rrtype == wire::TYPE_HTTPS && rrclass == wire::CLASS_IN && !rdata.is_null() {
            let raw = unsafe { std::slice::from_raw_parts(rdata.cast::<u8>(), usize::from(rdlen)) };
            if let Some(mut record) = parse_rdata(raw) {
                record.ttl = Some(ttl);
                state.records.push(record);
            }
        }
        if flags & K_DNS_SERVICE_FLAGS_MORE_COMING == 0 {
            state.finished = true;
        }
    }

    let host = CString::new(host)
        .map_err(|_| FetchError::Message("DNS host contains an interior NUL byte".to_string()))?;
    let mut sd_ref = std::ptr::null_mut();
    let mut state = QueryState {
        records: Vec::new(),
        error: None,
        finished: false,
    };

    let status = unsafe {
        DNSServiceQueryRecord(
            &mut sd_ref,
            0,
            0,
            host.as_ptr(),
            wire::TYPE_HTTPS,
            wire::CLASS_IN,
            query_record_callback,
            (&mut state as *mut QueryState).cast(),
        )
    };
    if status != K_DNS_SERVICE_ERR_NO_ERROR {
        return Ok(Vec::new());
    }
    let _guard = DnsServiceRefGuard(sd_ref);
    let fd = unsafe { DNSServiceRefSockFD(sd_ref) };
    if fd < 0 {
        return Ok(Vec::new());
    }

    let deadline = timeout.and_then(|timeout| Instant::now().checked_add(timeout));
    loop {
        if state.finished {
            break;
        }
        let Some(timeout_ms) = poll_timeout_ms(deadline) else {
            return Ok(Vec::new());
        };
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
        if ready == 0 {
            return Ok(Vec::new());
        }
        if ready < 0 {
            return Err(FetchError::Runtime(format!(
                "system DNS poll failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let status = unsafe { DNSServiceProcessResult(sd_ref) };
        if status != K_DNS_SERVICE_ERR_NO_ERROR {
            return Ok(Vec::new());
        }
    }

    if let Some(error) = state.error {
        return Err(FetchError::Runtime(error));
    }
    Ok(state.records)
}

#[cfg(target_os = "macos")]
fn poll_timeout_ms(deadline: Option<Instant>) -> Option<libc::c_int> {
    let Some(deadline) = deadline else {
        return Some(-1);
    };
    let remaining = deadline.checked_duration_since(Instant::now())?;
    let millis = remaining.as_millis().clamp(1, i32::MAX as u128);
    Some(millis as libc::c_int)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn resolv_conf_nameserver() -> Option<std::net::SocketAddr> {
    let resolv_conf = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    for line in resolv_conf.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 2 || fields[0] != "nameserver" {
            continue;
        }
        if let Ok(ip) = fields[1].parse::<std::net::IpAddr>() {
            return Some(std::net::SocketAddr::new(ip, 53));
        }
    }
    None
}

#[cfg(windows)]
fn lookup_https_records_blocking(
    host: &str,
    _timeout: Option<Duration>,
) -> Result<Vec<SvcbRecord>, FetchError> {
    use windows_sys::Win32::NetworkManagement::Dns::{
        DNS_QUERY_STANDARD, DNS_RECORDA, DNS_TYPE_HTTPS, DnsFree, DnsFreeRecordList, DnsQuery_W,
    };

    struct DnsRecordListGuard(*mut DNS_RECORDA);

    impl Drop for DnsRecordListGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    DnsFree(self.0.cast(), DnsFreeRecordList);
                }
            }
        }
    }

    let mut wide = host.encode_utf16().collect::<Vec<_>>();
    wide.push(0);
    let mut records = std::ptr::null_mut();
    let status = unsafe {
        DnsQuery_W(
            wide.as_ptr(),
            DNS_TYPE_HTTPS,
            DNS_QUERY_STANDARD,
            std::ptr::null_mut(),
            &mut records,
            std::ptr::null_mut(),
        )
    };
    if status != 0 || records.is_null() {
        return Ok(Vec::new());
    }
    let _guard = DnsRecordListGuard(records);

    let mut parsed = Vec::new();
    let mut current = records;
    while !current.is_null() {
        let dns_record = unsafe { &*current };
        if dns_record.wType == DNS_TYPE_HTTPS {
            if let Some(raw) = windows_svcb_rdata(dns_record) {
                if let Some(mut parsed_record) = parse_rdata(&raw) {
                    parsed_record.ttl = Some(dns_record.dwTtl);
                    parsed.push(parsed_record);
                }
            }
        }
        current = dns_record.pNext;
    }
    Ok(parsed)
}

#[cfg(windows)]
fn windows_svcb_rdata(
    record: &windows_sys::Win32::NetworkManagement::Dns::DNS_RECORDA,
) -> Option<Vec<u8>> {
    let svcb = unsafe { record.Data.Svcb };
    let mut out = Vec::new();
    out.extend_from_slice(&svcb.wSvcPriority.to_be_bytes());
    let target = pstr_to_string(svcb.pszTargetName)?;
    write_dns_name(&mut out, &target)?;

    if !svcb.pSvcParams.is_null() {
        for index in 0..usize::from(svcb.cSvcParams) {
            let param = unsafe { &*svcb.pSvcParams.add(index) };
            let value = windows_svcb_param_value(param)?;
            out.extend_from_slice(&param.wSvcParamKey.to_be_bytes());
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
            out.extend_from_slice(&value);
        }
    }
    Some(out)
}

#[cfg(windows)]
fn pstr_to_string(value: windows_sys::core::PSTR) -> Option<String> {
    if value.is_null() {
        return Some(".".to_string());
    }
    Some(
        unsafe { std::ffi::CStr::from_ptr(value.cast()) }
            .to_string_lossy()
            .into_owned(),
    )
}

#[cfg(windows)]
fn windows_svcb_param_value(
    param: &windows_sys::Win32::NetworkManagement::Dns::DNS_SVCB_PARAM,
) -> Option<Vec<u8>> {
    use windows_sys::Win32::NetworkManagement::Dns::{
        DnsSvcbParamAlpn, DnsSvcbParamIpv4Hint, DnsSvcbParamIpv6Hint, DnsSvcbParamMandatory,
        DnsSvcbParamNoDefaultAlpn, DnsSvcbParamPort,
    };

    match i32::from(param.wSvcParamKey) {
        DnsSvcbParamMandatory => {
            let mandatory = unsafe { param.Anonymous.pMandatory.as_ref()? };
            let keys = unsafe {
                std::slice::from_raw_parts(
                    mandatory.rgwMandatoryKeys.as_ptr(),
                    usize::from(mandatory.cMandatoryKeys),
                )
            };
            let mut value = Vec::with_capacity(keys.len() * 2);
            for key in keys {
                value.extend_from_slice(&key.to_be_bytes());
            }
            Some(value)
        }
        DnsSvcbParamAlpn => {
            let alpn = unsafe { param.Anonymous.pAlpn.as_ref()? };
            let ids =
                unsafe { std::slice::from_raw_parts(alpn.rgIds.as_ptr(), usize::from(alpn.cIds)) };
            let mut value = Vec::new();
            for id in ids {
                let bytes = unsafe { std::slice::from_raw_parts(id.pbId, usize::from(id.cBytes)) };
                value.push(id.cBytes);
                value.extend_from_slice(bytes);
            }
            Some(value)
        }
        DnsSvcbParamNoDefaultAlpn => Some(Vec::new()),
        DnsSvcbParamPort => Some(unsafe { param.Anonymous.wPort }.to_be_bytes().to_vec()),
        DnsSvcbParamIpv4Hint => {
            let hints = unsafe { param.Anonymous.pIpv4Hints.as_ref()? };
            let ips = unsafe {
                std::slice::from_raw_parts(hints.rgIps.as_ptr(), usize::from(hints.cIps))
            };
            let mut value = Vec::with_capacity(ips.len() * 4);
            for ip in ips {
                value.extend_from_slice(&ip.to_ne_bytes());
            }
            Some(value)
        }
        DnsSvcbParamIpv6Hint => {
            let hints = unsafe { param.Anonymous.pIpv6Hints.as_ref()? };
            let ips = unsafe {
                std::slice::from_raw_parts(hints.rgIps.as_ptr(), usize::from(hints.cIps))
            };
            let mut value = Vec::with_capacity(ips.len() * 16);
            for ip in ips {
                value.extend_from_slice(unsafe { &ip.IP6Byte });
            }
            Some(value)
        }
        _ => {
            let unknown = unsafe { param.Anonymous.pUnknown.as_ref()? };
            Some(
                unsafe {
                    std::slice::from_raw_parts(
                        unknown.pbSvcParamValue.as_ptr(),
                        usize::from(unknown.cBytes),
                    )
                }
                .to_vec(),
            )
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn lookup_https_records_blocking(
    _host: &str,
    _timeout: Option<Duration>,
) -> Result<Vec<SvcbRecord>, FetchError> {
    Ok(Vec::new())
}

#[cfg(test)]
fn records_from_wire_response(raw: &[u8]) -> Result<Vec<SvcbRecord>, FetchError> {
    let records =
        wire::parse_response_without_id(raw, "example.com", wire::TYPE_HTTPS, wire::CLASS_IN)
            .map_err(|err| FetchError::Runtime(err.to_string()))?;
    Ok(records
        .into_iter()
        .filter(|record| record.class == wire::CLASS_IN && record.typ == wire::TYPE_HTTPS)
        .filter_map(|record| {
            parse_rdata(record.data).map(|mut parsed| {
                parsed.ttl = Some(record.ttl);
                parsed
            })
        })
        .collect())
}

#[cfg(any(windows, test))]
fn write_dns_name(out: &mut Vec<u8>, name: &str) -> Option<()> {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        out.push(0);
        return Some(());
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns_response_without_matching_query_id(
        answer_owner: &str,
        answer_rdata: Vec<u8>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0x1234_u16.to_be_bytes());
        out.extend_from_slice(&0x8180_u16.to_be_bytes());
        out.extend_from_slice(&1_u16.to_be_bytes());
        out.extend_from_slice(&1_u16.to_be_bytes());
        out.extend_from_slice(&0_u16.to_be_bytes());
        out.extend_from_slice(&0_u16.to_be_bytes());
        write_dns_name(&mut out, "example.com.").unwrap();
        out.extend_from_slice(&wire::TYPE_HTTPS.to_be_bytes());
        out.extend_from_slice(&wire::CLASS_IN.to_be_bytes());
        write_dns_name(&mut out, answer_owner).unwrap();
        out.extend_from_slice(&wire::TYPE_HTTPS.to_be_bytes());
        out.extend_from_slice(&wire::CLASS_IN.to_be_bytes());
        out.extend_from_slice(&30_u32.to_be_bytes());
        out.extend_from_slice(&(answer_rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&answer_rdata);
        out
    }

    fn https_rdata() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&1_u16.to_be_bytes());
        write_dns_name(&mut out, ".").unwrap();
        out.extend_from_slice(&1_u16.to_be_bytes());
        out.extend_from_slice(&3_u16.to_be_bytes());
        out.extend_from_slice(&[2, b'h', b'3']);
        out
    }

    #[test]
    fn parses_system_wire_response_without_generated_query_id() {
        let raw = dns_response_without_matching_query_id("example.com.", https_rdata());

        let records = records_from_wire_response(&raw).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].priority, 1);
        assert_eq!(records[0].target, ".");
        assert_eq!(records[0].alpn, ["h3"]);
    }

    #[test]
    fn rejects_unrelated_https_answer_owner() {
        let raw = dns_response_without_matching_query_id("unrelated.example.", https_rdata());

        let records = records_from_wire_response(&raw).unwrap();

        assert!(records.is_empty());
    }
}
