#[cfg(target_os = "macos")]
use std::ffi::CString;
#[cfg(all(unix, not(target_os = "macos")))]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(not(all(unix, not(target_os = "macos"))))]
use std::time::Duration;
#[cfg(target_os = "macos")]
use std::time::Instant;

#[cfg(any(unix, windows, test))]
use crate::dns::wire;
use crate::duration::TimeoutBudget;
use crate::error::FetchError;

use super::SvcbRecord;
#[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
use super::parse_rdata;

#[cfg(all(unix, not(target_os = "macos")))]
pub(super) async fn lookup_https_records(
    host: &str,
    timeout: TimeoutBudget,
) -> Result<Vec<SvcbRecord>, FetchError> {
    #[cfg(target_os = "linux")]
    {
        let service = lookup_with_systemd_resolved(host, timeout).await;
        return route_system_lookup(service, lookup_with_resolv_conf(host, timeout)).await;
    }
    #[cfg(not(target_os = "linux"))]
    lookup_with_resolv_conf(host, timeout).await
}

#[cfg(all(unix, not(target_os = "macos")))]
#[derive(Debug)]
enum SystemServiceOutcome {
    Records(Vec<SvcbRecord>),
    Unavailable,
    Error(FetchError),
}

#[cfg(all(unix, not(target_os = "macos")))]
async fn route_system_lookup<F>(
    service: SystemServiceOutcome,
    fallback: F,
) -> Result<Vec<SvcbRecord>, FetchError>
where
    F: Future<Output = Result<Vec<SvcbRecord>, FetchError>>,
{
    match service {
        SystemServiceOutcome::Records(records) => Ok(records),
        SystemServiceOutcome::Unavailable => fallback.await,
        SystemServiceOutcome::Error(err) => Err(err),
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
use std::future::Future;

#[cfg(target_os = "linux")]
async fn lookup_with_systemd_resolved(host: &str, timeout: TimeoutBudget) -> SystemServiceOutcome {
    use std::process::Stdio;

    let timeout = crate::dns::util::dns_transaction_budget(timeout);

    let Some(program) = [
        "/usr/bin/resolvectl",
        "/bin/resolvectl",
        "/usr/local/bin/resolvectl",
        "/run/current-system/sw/bin/resolvectl",
    ]
    .into_iter()
    .find(|path| std::path::Path::new(path).is_file()) else {
        return SystemServiceOutcome::Unavailable;
    };

    let mut command = tokio::process::Command::new(program);
    command
        .args(["--raw=packet", "--type=TYPE65", "query", host])
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => return SystemServiceOutcome::Unavailable,
    };
    let stdout = child.stdout.take().expect("resolvectl stdout is piped");
    let stderr = child.stderr.take().expect("resolvectl stderr is piped");
    const MAX_SERVICE_OUTPUT: u64 = 1024 * 1024;
    let result = timeout
        .run(async {
            use tokio::io::AsyncReadExt;

            let read_stdout = async {
                let mut bytes = Vec::new();
                stdout
                    .take(MAX_SERVICE_OUTPUT + 1)
                    .read_to_end(&mut bytes)
                    .await?;
                Ok::<_, std::io::Error>(bytes)
            };
            let read_stderr = async {
                let mut bytes = Vec::new();
                stderr
                    .take(MAX_SERVICE_OUTPUT + 1)
                    .read_to_end(&mut bytes)
                    .await?;
                Ok::<_, std::io::Error>(bytes)
            };
            let (stdout, stderr, status) = tokio::try_join!(read_stdout, read_stderr, child.wait())
                .map_err(|err| {
                    FetchError::Runtime(format!("system resolver service failed: {err}"))
                })?;
            Ok((stdout, stderr, status))
        })
        .await;
    let (stdout, stderr, status) = match result {
        Ok(result) => result,
        Err(err) => return SystemServiceOutcome::Error(err),
    };
    if stdout.len() as u64 > MAX_SERVICE_OUTPUT || stderr.len() as u64 > MAX_SERVICE_OUTPUT {
        return SystemServiceOutcome::Error(FetchError::Runtime(
            "system resolver service output is too large".to_string(),
        ));
    }

    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr);
        return match classify_resolvectl_failure(&stderr) {
            ResolvectlFailure::Unavailable => SystemServiceOutcome::Unavailable,
            ResolvectlFailure::NegativeAnswer => SystemServiceOutcome::Records(Vec::new()),
            ResolvectlFailure::Error => SystemServiceOutcome::Error(FetchError::Runtime(format!(
                "system resolver service lookup failed ({status})"
            ))),
        };
    }

    match records_from_resolvectl_packets(host, &stdout) {
        Ok(records) => SystemServiceOutcome::Records(records),
        Err(err) => SystemServiceOutcome::Error(err),
    }
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Debug, PartialEq, Eq)]
enum ResolvectlFailure {
    Unavailable,
    NegativeAnswer,
    Error,
}

#[cfg(any(test, target_os = "linux"))]
fn classify_resolvectl_failure(stderr: &str) -> ResolvectlFailure {
    let stderr = stderr.to_ascii_lowercase();
    if [
        "unknown option",
        "unrecognized option",
        "failed to connect to bus",
        "could not connect",
        "sd_bus_open_system",
        "failed to get global data",
        "service unknown",
        "unit dbus-org.freedesktop.resolve1.service not found",
        "unknown rr type",
    ]
    .iter()
    .any(|message| stderr.contains(message))
    {
        ResolvectlFailure::Unavailable
    } else if stderr.contains("not found")
        || stderr.contains("does not have any rr of the requested type")
    {
        ResolvectlFailure::NegativeAnswer
    } else {
        ResolvectlFailure::Error
    }
}

#[cfg(target_os = "linux")]
fn records_from_resolvectl_packets(
    _host: &str,
    packets: &[u8],
) -> Result<Vec<SvcbRecord>, FetchError> {
    let mut offset = 0;
    let mut records = Vec::new();
    while offset < packets.len() {
        if records.len() >= 4096 {
            return Err(FetchError::Runtime(
                "too many records from system resolver".to_string(),
            ));
        }
        let length_bytes: [u8; 8] = packets
            .get(offset..offset + 8)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| FetchError::Runtime("malformed system resolver output".to_string()))?;
        offset += 8;
        let length = usize::try_from(u64::from_le_bytes(length_bytes))
            .map_err(|_| FetchError::Runtime("oversized system resolver record".to_string()))?;
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= packets.len())
            .ok_or_else(|| FetchError::Runtime("malformed system resolver output".to_string()))?;
        let resource = wire::parse_standalone_resource_record(&packets[offset..end])
            .map_err(|err| FetchError::Runtime(err.to_string()))?;
        offset = end;
        if resource.typ != wire::TYPE_HTTPS || resource.class != wire::CLASS_IN {
            continue;
        }
        let mut record = parse_rdata(resource.data).map_err(|err| {
            FetchError::Runtime(format!("malformed HTTPS DNS record data: {err}"))
        })?;
        record.ttl = Some(resource.ttl);
        records.push(record);
    }
    Ok(records)
}

#[cfg(all(unix, not(target_os = "macos")))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvConf {
    nameservers: Vec<std::net::SocketAddr>,
    timeout: std::time::Duration,
    attempts: usize,
    rotate: bool,
}

#[cfg(all(unix, not(target_os = "macos")))]
impl Default for ResolvConf {
    fn default() -> Self {
        Self {
            nameservers: Vec::new(),
            timeout: std::time::Duration::from_secs(5),
            attempts: 2,
            rotate: false,
        }
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
static RESOLVER_ROTATION: AtomicUsize = AtomicUsize::new(0);

#[cfg(all(unix, not(target_os = "macos")))]
async fn lookup_with_resolv_conf(
    host: &str,
    budget: TimeoutBudget,
) -> Result<Vec<SvcbRecord>, FetchError> {
    let contents = match tokio::fs::read_to_string("/etc/resolv.conf").await {
        Ok(contents) => contents,
        Err(_) => return Ok(Vec::new()),
    };
    lookup_with_resolv_conf_config(host, budget, &parse_resolv_conf(&contents)).await
}

#[cfg(all(unix, not(target_os = "macos")))]
async fn lookup_with_resolv_conf_config(
    host: &str,
    budget: TimeoutBudget,
    config: &ResolvConf,
) -> Result<Vec<SvcbRecord>, FetchError> {
    if config.nameservers.is_empty() || config.attempts == 0 {
        return Ok(Vec::new());
    }
    let start = if config.rotate {
        RESOLVER_ROTATION.fetch_add(1, Ordering::Relaxed) % config.nameservers.len()
    } else {
        0
    };
    let mut last_error = None;
    for _ in 0..config.attempts {
        for index in 0..config.nameservers.len() {
            let server = config.nameservers[(start + index) % config.nameservers.len()];
            let remaining = budget.remaining()?;
            let query_timeout = remaining.map_or(config.timeout, |value| value.min(config.timeout));
            if query_timeout.is_zero() {
                return Err(FetchError::Runtime("DNS lookup timed out".to_string()));
            }
            match crate::dns::resolver::query_udp_type(
                &server,
                host,
                wire::TYPE_HTTPS,
                TimeoutBudget::new(Some(query_timeout)),
            )
            .await
            {
                Ok(records) => {
                    let records = records
                        .into_iter()
                        .map(|record| crate::dns::custom::DnsQueryRecord {
                            typ: record.typ,
                            ttl: Some(record.ttl),
                            data: crate::dns::custom::DnsRecordData::Wire(record.data),
                        })
                        .collect();
                    return super::svcb_records_from_query(records);
                }
                Err(err) if err.is_nxdomain() => return Ok(Vec::new()),
                Err(err) => last_error = Some(err),
            }
        }
    }
    Err(FetchError::Runtime(format!(
        "lookup {host}: {}",
        last_error.map_or_else(|| "DNS lookup failed".to_string(), |err| err.to_string())
    )))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn parse_resolv_conf(contents: &str) -> ResolvConf {
    let mut config = ResolvConf::default();
    for line in contents.lines() {
        let line = line.split(['#', ';']).next().unwrap_or_default().trim();
        let mut fields = line.split_whitespace();
        match fields.next() {
            Some("nameserver") => {
                if let Some(ip) = fields.next().and_then(|value| value.parse().ok()) {
                    config.nameservers.push(std::net::SocketAddr::new(ip, 53));
                }
            }
            Some("options") => {
                for option in fields {
                    if option == "rotate" {
                        config.rotate = true;
                    } else if let Some(value) = option.strip_prefix("timeout:") {
                        if let Ok(seconds) = value.parse::<u64>() {
                            config.timeout = std::time::Duration::from_secs(seconds.clamp(1, 30));
                        }
                    } else if let Some(value) = option.strip_prefix("attempts:")
                        && let Ok(attempts) = value.parse::<usize>()
                    {
                        config.attempts = attempts.min(5);
                    }
                }
            }
            _ => {}
        }
    }
    config
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
            match parse_rdata(raw) {
                Ok(mut record) => {
                    record.ttl = Some(ttl);
                    state.records.push(record);
                }
                Err(err) => {
                    state.error = Some(format!("malformed HTTPS DNS record data: {err}"));
                }
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
            let raw = windows_svcb_rdata(dns_record).ok_or_else(|| {
                FetchError::Runtime(
                    "malformed HTTPS DNS record data from system resolver".to_string(),
                )
            })?;
            let mut parsed_record = parse_rdata(&raw).map_err(|err| {
                FetchError::Runtime(format!("malformed HTTPS DNS record data: {err}"))
            })?;
            parsed_record.ttl = Some(dns_record.dwTtl);
            parsed.push(parsed_record);
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
    wire::write_name(&mut out, &target).ok()?;

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
fn records_from_wire_response_for_host(
    host: &str,
    raw: &[u8],
) -> Result<Vec<SvcbRecord>, FetchError> {
    let records = wire::parse_response_without_id(raw, host, wire::TYPE_HTTPS, wire::CLASS_IN)
        .map_err(|err| FetchError::Runtime(err.to_string()))?;
    records
        .into_iter()
        .filter(|record| record.class == wire::CLASS_IN && record.typ == wire::TYPE_HTTPS)
        .map(|record| {
            let mut parsed = parse_rdata(record.data).map_err(|err| {
                FetchError::Runtime(format!("malformed HTTPS DNS record data: {err}"))
            })?;
            parsed.ttl = Some(record.ttl);
            Ok(parsed)
        })
        .collect()
}

#[cfg(test)]
fn write_dns_name(out: &mut Vec<u8>, name: &str) -> Option<()> {
    wire::write_name(out, name).ok()
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

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn parses_all_nameservers_and_resolver_options() {
        let config = parse_resolv_conf(
            "nameserver not-an-address\n\
             nameserver 192.0.2.1\n\
             nameserver 2001:db8::1 # vpn\n\
             options timeout:9 attempts:4 rotate\n",
        );

        assert_eq!(
            config.nameservers,
            [
                "192.0.2.1:53".parse().unwrap(),
                "[2001:db8::1]:53".parse().unwrap()
            ]
        );
        assert_eq!(config.timeout, std::time::Duration::from_secs(9));
        assert_eq!(config.attempts, 4);
        assert!(config.rotate);
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[tokio::test]
    async fn resolv_conf_lookup_fails_over_to_second_nameserver() {
        let unavailable = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let unavailable_addr = unavailable.local_addr().unwrap();
        drop(unavailable);
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut request = [0_u8; 512];
            let (length, peer) = server.recv_from(&mut request).await.unwrap();
            let mut response = request[..length].to_vec();
            response[2] = 0x81;
            response[3] = 0x80;
            server.send_to(&response, peer).await.unwrap();
        });
        let config = ResolvConf {
            nameservers: vec![unavailable_addr, server_addr],
            timeout: std::time::Duration::from_millis(30),
            attempts: 1,
            rotate: false,
        };

        let records = lookup_with_resolv_conf_config(
            "example.com",
            TimeoutBudget::new(Some(std::time::Duration::from_secs(1))),
            &config,
        )
        .await
        .unwrap();

        assert!(records.is_empty());
        task.await.unwrap();
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[tokio::test]
    async fn service_backend_prevents_fallback_routing() {
        use std::sync::{Arc, atomic::AtomicBool};

        let fallback_ran = Arc::new(AtomicBool::new(false));
        let marker = Arc::clone(&fallback_ran);
        let records = route_system_lookup(SystemServiceOutcome::Records(Vec::new()), async move {
            marker.store(true, Ordering::Relaxed);
            Ok(Vec::new())
        })
        .await
        .unwrap();

        assert!(records.is_empty());
        assert!(!fallback_ran.load(Ordering::Relaxed));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[tokio::test]
    async fn unavailable_service_uses_resolver_file_fallback() {
        use std::sync::{Arc, atomic::AtomicBool};

        let fallback_ran = Arc::new(AtomicBool::new(false));
        let marker = Arc::clone(&fallback_ran);
        route_system_lookup(SystemServiceOutcome::Unavailable, async move {
            marker.store(true, Ordering::Relaxed);
            Ok(Vec::new())
        })
        .await
        .unwrap();

        assert!(fallback_ran.load(Ordering::Relaxed));
    }

    #[test]
    fn classifies_resolvectl_failures_without_bypassing_service_policy() {
        assert_eq!(
            classify_resolvectl_failure("example.com: resolve call failed: example.com not found"),
            ResolvectlFailure::NegativeAnswer
        );
        assert_eq!(
            classify_resolvectl_failure("example.com does not have any RR of the requested type"),
            ResolvectlFailure::NegativeAnswer
        );
        assert_eq!(
            classify_resolvectl_failure(
                "example.com: resolve call failed: DNSSEC validation failed"
            ),
            ResolvectlFailure::Error
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolvectl_records_accept_canonical_owner_after_cname() {
        let mut resource = Vec::new();
        write_dns_name(&mut resource, "canonical.example").unwrap();
        resource.extend_from_slice(&wire::TYPE_HTTPS.to_be_bytes());
        resource.extend_from_slice(&wire::CLASS_IN.to_be_bytes());
        resource.extend_from_slice(&30_u32.to_be_bytes());
        let rdata = https_rdata();
        resource.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        resource.extend_from_slice(&rdata);
        let mut framed = (resource.len() as u64).to_le_bytes().to_vec();
        framed.extend_from_slice(&resource);

        let records = records_from_resolvectl_packets("alias.example", &framed).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].ttl, Some(30));
    }

    #[test]
    fn parses_system_wire_response_without_generated_query_id() {
        let raw = dns_response_without_matching_query_id("example.com.", https_rdata());

        let records = records_from_wire_response_for_host("example.com", &raw).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].priority, 1);
        assert_eq!(records[0].target, ".");
        assert_eq!(records[0].alpn, [b"h3".to_vec()]);
    }

    #[test]
    fn rejects_unrelated_https_answer_owner() {
        let raw = dns_response_without_matching_query_id("unrelated.example.", https_rdata());

        let records = records_from_wire_response_for_host("example.com", &raw).unwrap();

        assert!(records.is_empty());
    }
}
