use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::HeaderMap;
use http::header::HeaderName;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::dns::svcb::SvcbRecord;
use crate::fileutil::FileLock;

const CACHE_VERSION: u32 = 1;
const MAX_CANDIDATES_PER_ORIGIN: usize = 4;
const MAX_SHARDS: usize = 1024;
const MAX_RETENTION_SECS: u64 = 7 * 24 * 60 * 60;
const DEFAULT_ALT_SVC_MA_SECS: u64 = 24 * 60 * 60;
const GLOBAL_PRUNE_INTERVAL_SECS: u64 = 24 * 60 * 60;
const LOCK_WAIT_TIMEOUT: Duration = Duration::from_millis(200);

const SOURCE_HTTPS: &str = "https";
const SOURCE_ALT_SVC: &str = "alt-svc";
const SYSTEM_RESOLVER_KEY: &str = "system";
const ALT_SVC: HeaderName = HeaderName::from_static("alt-svc");

#[derive(Clone, Debug)]
pub(crate) struct Http3Cache {
    dir: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Http3CacheCandidate {
    pub(crate) alt_host: String,
    pub(crate) alt_port: u16,
    pub(crate) priority: Option<u16>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ShardFile {
    version: u32,
    origin: String,
    resolver_key: String,
    candidates: Vec<StoredCandidate>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct StoredCandidate {
    source: String,
    alt_host: String,
    alt_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
    expires_at: u64,
    learned_at: u64,
    last_used_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CacheKey {
    origin: String,
    resolver_key: String,
}

#[derive(Debug)]
struct AltSvcUpdate {
    clear: bool,
    candidates: Vec<StoredCandidate>,
    remove: Vec<(String, u16)>,
}

#[derive(Debug)]
struct ShardSummary {
    path: PathBuf,
    expired: bool,
    last_used_at: u64,
}

impl Http3Cache {
    pub(crate) fn new() -> Self {
        Self {
            dir: http3_cache_dir().ok(),
        }
    }

    pub(crate) fn is_enabled(&self) -> bool {
        self.dir.is_some()
    }

    #[cfg(test)]
    fn with_dir(dir: PathBuf) -> Self {
        Self { dir: Some(dir) }
    }

    pub(crate) fn candidates(
        &self,
        url: &Url,
        dns_server: Option<&str>,
    ) -> Vec<Http3CacheCandidate> {
        let Some((key, path)) = self.key_and_path(url, dns_server) else {
            return Vec::new();
        };
        let now = now_secs();
        let Some(mut shard) = self.read_valid_shard(&path, &key) else {
            return Vec::new();
        };
        prune_expired_candidates(&mut shard.candidates, now);
        if shard.candidates.is_empty() {
            self.update_shard(&path, &key, |_, _| {});
            return Vec::new();
        }
        let candidates = shard
            .candidates
            .into_iter()
            .map(|candidate| Http3CacheCandidate {
                alt_host: candidate.alt_host,
                alt_port: candidate.alt_port,
                priority: candidate.priority,
            })
            .collect::<Vec<_>>();
        self.update_shard(&path, &key, |shard, now| {
            prune_expired_candidates(&mut shard.candidates, now);
            for stored in &mut shard.candidates {
                if candidates
                    .iter()
                    .any(|candidate| candidate.matches_stored(stored))
                {
                    stored.last_used_at = now;
                }
            }
        });
        self.maybe_prune_global(now);
        candidates
    }

    pub(crate) fn remove_candidates(
        &self,
        url: &Url,
        dns_server: Option<&str>,
        candidates: &[Http3CacheCandidate],
    ) {
        if candidates.is_empty() {
            return;
        }
        let Some((key, path)) = self.key_and_path(url, dns_server) else {
            return;
        };
        self.update_shard(&path, &key, |shard, now| {
            prune_expired_candidates(&mut shard.candidates, now);
            shard.candidates.retain(|stored| {
                !candidates
                    .iter()
                    .any(|candidate| candidate.matches_stored(stored))
            });
        });
    }

    pub(crate) fn store_https_records(
        &self,
        url: &Url,
        dns_server: Option<&str>,
        records: &[SvcbRecord],
    ) {
        let Some((key, path)) = self.key_and_path(url, dns_server) else {
            return;
        };
        let Some(origin_host) = normalized_host(url) else {
            return;
        };
        let Some(origin_port) = url.port_or_known_default() else {
            return;
        };
        let mut candidates = records
            .iter()
            .filter(|record| !record.is_alias_mode())
            .filter(|record| record.is_usable())
            .filter(|record| record.advertises_alpn("h3"))
            .filter_map(|record| {
                let ttl = record.ttl?;
                if ttl == 0 {
                    return None;
                }
                let alt_host = normalized_svcb_target(&origin_host, &record.target)?;
                Some((
                    record.priority,
                    alt_host,
                    record.port.unwrap_or(origin_port),
                    ttl,
                ))
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|(priority, _, _, _)| *priority);
        if candidates.is_empty() {
            return;
        }

        self.update_shard(&path, &key, |shard, now| {
            prune_expired_candidates(&mut shard.candidates, now);
            for (priority, alt_host, alt_port, ttl) in &candidates {
                let ttl = u64::from(*ttl).min(MAX_RETENTION_SECS);
                let candidate = StoredCandidate {
                    source: SOURCE_HTTPS.to_string(),
                    alt_host: alt_host.clone(),
                    alt_port: *alt_port,
                    priority: Some(*priority),
                    expires_at: now.saturating_add(ttl),
                    learned_at: now,
                    last_used_at: now,
                };
                upsert_candidate(&mut shard.candidates, candidate);
            }
            prune_candidate_count(&mut shard.candidates);
        });
    }

    pub(crate) fn store_alt_svc(&self, url: &Url, dns_server: Option<&str>, headers: &HeaderMap) {
        let Some((key, path)) = self.key_and_path(url, dns_server) else {
            return;
        };
        let Some(update) = parse_alt_svc_headers(url, headers, now_secs()) else {
            return;
        };
        self.update_shard(&path, &key, |shard, now| {
            prune_expired_candidates(&mut shard.candidates, now);
            if update.clear {
                shard
                    .candidates
                    .retain(|candidate| candidate.source != SOURCE_ALT_SVC);
            }
            for (alt_host, alt_port) in &update.remove {
                shard.candidates.retain(|candidate| {
                    !(candidate.source == SOURCE_ALT_SVC
                        && candidate.alt_host.eq_ignore_ascii_case(alt_host)
                        && candidate.alt_port == *alt_port)
                });
            }
            for candidate in update.candidates.clone() {
                upsert_candidate(&mut shard.candidates, candidate);
            }
            prune_candidate_count(&mut shard.candidates);
        });
    }

    fn key_and_path(&self, url: &Url, dns_server: Option<&str>) -> Option<(CacheKey, PathBuf)> {
        let dir = self.dir.as_ref()?;
        let key = cache_key(url, dns_server)?;
        let hash = sha256_hex(format!("{}\n{}", key.origin, key.resolver_key).as_bytes());
        let path = dir.join(&hash[..2]).join(format!("{hash}.json"));
        Some((key, path))
    }

    fn read_valid_shard(&self, path: &Path, key: &CacheKey) -> Option<ShardFile> {
        let data = fs::read(path).ok()?;
        let shard = serde_json::from_slice::<ShardFile>(&data).ok()?;
        if shard.version != CACHE_VERSION
            || shard.origin != key.origin
            || shard.resolver_key != key.resolver_key
        {
            return None;
        }
        Some(shard)
    }

    fn update_shard(&self, path: &Path, key: &CacheKey, update: impl FnOnce(&mut ShardFile, u64)) {
        let Some(parent) = path.parent() else {
            return;
        };
        if create_cache_dir(parent).is_err() {
            return;
        }
        let lock_path = shard_lock_path(path);
        let Ok(_lock) = FileLock::acquire_with_timeout(
            &lock_path,
            LOCK_WAIT_TIMEOUT,
            || {},
            |timeout| std::io::Error::new(std::io::ErrorKind::TimedOut, format!("{timeout:?}")),
        ) else {
            return;
        };
        let now = now_secs();
        let mut shard = self
            .read_valid_shard(path, key)
            .unwrap_or_else(|| ShardFile {
                version: CACHE_VERSION,
                origin: key.origin.clone(),
                resolver_key: key.resolver_key.clone(),
                candidates: Vec::new(),
            });
        update(&mut shard, now);
        prune_expired_candidates(&mut shard.candidates, now);
        prune_candidate_count(&mut shard.candidates);
        if shard.candidates.is_empty() {
            let _ = fs::remove_file(path);
            return;
        }
        let _ = write_shard(path, &shard);
    }

    fn maybe_prune_global(&self, now: u64) {
        let Some(dir) = &self.dir else {
            return;
        };
        if create_cache_dir(dir).is_err() {
            return;
        }
        let marker = dir.join(".last-prune");
        let should_prune = fs::read_to_string(&marker)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .is_none_or(|last| now.saturating_sub(last) >= GLOBAL_PRUNE_INTERVAL_SECS);
        if !should_prune {
            return;
        }
        prune_global(dir, now);
        let _ = fs::write(marker, now.to_string());
    }
}

impl Http3CacheCandidate {
    fn matches_stored(&self, stored: &StoredCandidate) -> bool {
        self.alt_host.eq_ignore_ascii_case(&stored.alt_host) && self.alt_port == stored.alt_port
    }
}

fn http3_cache_dir() -> std::io::Result<PathBuf> {
    if let Some(dir) = std::env::var_os("FETCH_INTERNAL_HTTP3_CACHE_DIR") {
        let dir = PathBuf::from(dir);
        create_cache_dir(&dir)?;
        return Ok(dir);
    }
    let base = default_cache_dir()?;
    let dir = base.join("fetch").join("http3");
    create_cache_dir(&dir)?;
    Ok(dir)
}

fn default_cache_dir() -> std::io::Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        if let Some(dir) = std::env::var_os("LOCALAPPDATA") {
            return Ok(PathBuf::from(dir));
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME") {
            return Ok(PathBuf::from(home).join("Library").join("Caches"));
        }
    }

    if let Some(dir) = std::env::var_os("XDG_CACHE_HOME") {
        return Ok(PathBuf::from(dir));
    }
    if let Some(home) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(home).join(".cache"));
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "unable to determine user cache directory",
    ))
}

#[cfg(unix)]
fn create_cache_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700).create(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn create_cache_dir(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)
}

fn cache_key(url: &Url, dns_server: Option<&str>) -> Option<CacheKey> {
    if url.scheme() != "https" {
        return None;
    }
    let host = normalized_host(url)?;
    if host.parse::<IpAddr>().is_ok() {
        return None;
    }
    let port = url.port_or_known_default()?;
    Some(CacheKey {
        origin: format!("https://{host}:{port}"),
        resolver_key: resolver_key(dns_server),
    })
}

fn resolver_key(dns_server: Option<&str>) -> String {
    dns_server
        .map(|server| format!("dns-server:{server}"))
        .unwrap_or_else(|| SYSTEM_RESOLVER_KEY.to_string())
}

fn normalized_host(url: &Url) -> Option<String> {
    Some(url.host_str()?.trim_end_matches('.').to_ascii_lowercase())
}

fn normalized_svcb_target(origin_host: &str, target: &str) -> Option<String> {
    let target = if target == "." {
        origin_host.to_string()
    } else {
        target.trim_end_matches('.').to_ascii_lowercase()
    };
    (!target.is_empty()).then_some(target)
}

fn parse_alt_svc_headers(url: &Url, headers: &HeaderMap, now: u64) -> Option<AltSvcUpdate> {
    let origin_host = normalized_host(url)?;
    let mut update = AltSvcUpdate {
        clear: false,
        candidates: Vec::new(),
        remove: Vec::new(),
    };
    for value in headers.get_all(ALT_SVC).iter() {
        let Ok(value) = value.to_str() else {
            continue;
        };
        if value.trim().eq_ignore_ascii_case("clear") {
            update.clear = true;
            continue;
        }
        for item in split_quoted(value, ',') {
            let Some(candidate) = parse_alt_svc_item(&item, &origin_host, now) else {
                continue;
            };
            if candidate.expires_at <= now {
                update
                    .remove
                    .push((candidate.alt_host.clone(), candidate.alt_port));
            } else {
                update.candidates.push(candidate);
            }
        }
    }
    (update.clear || !update.candidates.is_empty() || !update.remove.is_empty()).then_some(update)
}

fn parse_alt_svc_item(item: &str, origin_host: &str, now: u64) -> Option<StoredCandidate> {
    let parts = split_quoted(item, ';');
    let first = parts.first()?.trim();
    let (protocol, authority) = first.split_once('=')?;
    if !protocol.trim().eq_ignore_ascii_case("h3") {
        return None;
    }
    let authority = unquote(authority.trim())?;
    let (alt_host, alt_port) = parse_alt_authority(authority, origin_host)?;
    let mut ma = DEFAULT_ALT_SVC_MA_SECS;
    for part in parts.iter().skip(1) {
        let Some((name, value)) = part.split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("ma")
            && let Ok(parsed) = unquote(value.trim()).unwrap_or(value.trim()).parse::<u64>()
        {
            ma = parsed;
        }
    }
    let ma = ma.min(MAX_RETENTION_SECS);
    Some(StoredCandidate {
        source: SOURCE_ALT_SVC.to_string(),
        alt_host,
        alt_port,
        priority: None,
        expires_at: now.saturating_add(ma),
        learned_at: now,
        last_used_at: now,
    })
}

fn parse_alt_authority(authority: &str, origin_host: &str) -> Option<(String, u16)> {
    if let Some(port) = authority.strip_prefix(':') {
        let port = port.parse::<u16>().ok()?;
        return Some((origin_host.to_string(), port));
    }
    let url = Url::parse(&format!("https://{authority}/")).ok()?;
    let host = normalized_host(&url)?;
    let port = url.port()?;
    Some((host, port))
}

fn split_quoted(value: &str, separator: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for ch in value.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if quoted && ch == '\\' {
            escaped = true;
            current.push(ch);
            continue;
        }
        if ch == '"' {
            quoted = !quoted;
            current.push(ch);
            continue;
        }
        if !quoted && ch == separator {
            out.push(current.trim().to_string());
            current.clear();
            continue;
        }
        current.push(ch);
    }
    out.push(current.trim().to_string());
    out
}

fn unquote(value: &str) -> Option<&str> {
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        return Some(&value[1..value.len() - 1]);
    }
    if value.starts_with('"') || value.ends_with('"') {
        return None;
    }
    Some(value)
}

fn upsert_candidate(candidates: &mut Vec<StoredCandidate>, candidate: StoredCandidate) {
    if let Some(existing) = candidates.iter_mut().find(|existing| {
        existing.source == candidate.source
            && existing.alt_host.eq_ignore_ascii_case(&candidate.alt_host)
            && existing.alt_port == candidate.alt_port
    }) {
        *existing = candidate;
    } else {
        candidates.push(candidate);
    }
}

fn prune_expired_candidates(candidates: &mut Vec<StoredCandidate>, now: u64) {
    candidates.retain(|candidate| candidate.expires_at > now);
}

fn prune_candidate_count(candidates: &mut Vec<StoredCandidate>) {
    candidates.sort_by(|a, b| {
        a.priority
            .unwrap_or(u16::MAX)
            .cmp(&b.priority.unwrap_or(u16::MAX))
            .then(b.last_used_at.cmp(&a.last_used_at))
            .then(b.expires_at.cmp(&a.expires_at))
    });
    candidates.truncate(MAX_CANDIDATES_PER_ORIGIN);
}

fn write_shard(path: &Path, shard: &ShardFile) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    create_cache_dir(parent)?;
    let tmp = parent.join(format!(
        ".http3-{}-{}.tmp",
        std::process::id(),
        now_secs_nanos()
    ));
    let data = serde_json::to_vec_pretty(shard)?;
    let mut file = create_temp_file(&tmp)?;
    file.write_all(&data)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);
    if let Err(err) = crate::fileutil::atomic_replace_file(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    Ok(())
}

#[cfg(unix)]
fn create_temp_file(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_temp_file(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

fn shard_lock_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| "http3.json".into());
    path.with_file_name(format!(".{name}.lock"))
}

fn prune_global(dir: &Path, now: u64) {
    let mut summaries = Vec::new();
    collect_shard_summaries(dir, now, &mut summaries);
    for summary in summaries.iter().filter(|summary| summary.expired) {
        let _ = fs::remove_file(&summary.path);
    }
    summaries.retain(|summary| !summary.expired);
    if summaries.len() <= MAX_SHARDS {
        return;
    }
    summaries.sort_by_key(|summary| summary.last_used_at);
    for summary in summaries.iter().take(summaries.len() - MAX_SHARDS) {
        let _ = fs::remove_file(&summary.path);
    }
}

fn collect_shard_summaries(dir: &Path, now: u64, out: &mut Vec<ShardSummary>) {
    // The cache layout is exactly <root>/<two hex digits>/<full hash>.json. Do not
    // recurse: besides being unnecessary, recursion could follow a corrupted
    // cache's directory symlinks outside the cache root.
    let Ok(metadata) = fs::symlink_metadata(dir) else {
        return;
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for shard_dir in entries.flatten() {
        let Ok(file_type) = shard_dir.file_type() else {
            continue;
        };
        if file_type.is_symlink() || !file_type.is_dir() || !is_hex_name(&shard_dir.file_name(), 2)
        {
            continue;
        }
        let Ok(files) = fs::read_dir(shard_dir.path()) else {
            continue;
        };
        for entry in files.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if file_type.is_symlink()
                || !file_type.is_file()
                || !is_shard_file_name(&entry.file_name(), &shard_dir.file_name())
            {
                continue;
            }
            let Some(mut shard) = fs::read(&path)
                .ok()
                .and_then(|data| serde_json::from_slice::<ShardFile>(&data).ok())
            else {
                continue;
            };
            prune_expired_candidates(&mut shard.candidates, now);
            let expired = shard.candidates.is_empty();
            let last_used_at = shard
                .candidates
                .iter()
                .map(|candidate| candidate.last_used_at)
                .max()
                .unwrap_or(0);
            out.push(ShardSummary {
                path,
                expired,
                last_used_at,
            });
        }
    }
}

fn is_hex_name(name: &std::ffi::OsStr, len: usize) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    name.len() == len && name.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_shard_file_name(name: &std::ffi::OsStr, prefix: &std::ffi::OsStr) -> bool {
    let (Some(name), Some(prefix)) = (name.to_str(), prefix.to_str()) else {
        return false;
    };
    let Some(hash) = name.strip_suffix(".json") else {
        return false;
    };
    hash.len() == 64
        && hash.starts_with(prefix)
        && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(hex_char(byte >> 4));
        out.push(hex_char(byte & 0x0f));
    }
    out
}

fn hex_char(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'a' + (nibble - 10)) as char,
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn now_secs_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;
    use tempfile::TempDir;

    fn test_url() -> Url {
        Url::parse("https://Example.com:8443/path").unwrap()
    }

    fn record(target: &str, port: Option<u16>, ttl: Option<u32>) -> SvcbRecord {
        SvcbRecord {
            priority: 1,
            target: target.to_string(),
            alpn: vec!["h3".to_string()],
            no_default_alpn: false,
            port,
            ipv4_hint: Vec::new(),
            ech: None,
            ipv6_hint: Vec::new(),
            mandatory: Vec::new(),
            unsupported_mandatory: Vec::new(),
            ttl,
        }
    }

    #[test]
    fn cache_key_normalizes_origin_and_scopes_resolver() {
        let key = cache_key(&test_url(), Some("127.0.0.1:53")).unwrap();
        assert_eq!(key.origin, "https://example.com:8443");
        assert_eq!(key.resolver_key, "dns-server:127.0.0.1:53");

        let key = cache_key(&test_url(), None).unwrap();
        assert_eq!(key.resolver_key, "system");
    }

    #[test]
    fn stores_https_records_per_origin_shard() {
        let dir = TempDir::new().unwrap();
        let cache = Http3Cache::with_dir(dir.path().to_path_buf());
        cache.store_https_records(&test_url(), None, &[record(".", Some(9443), Some(60))]);

        let got = cache.candidates(&test_url(), None);
        assert_eq!(
            got,
            vec![Http3CacheCandidate {
                alt_host: "example.com".to_string(),
                alt_port: 9443,
                priority: Some(1),
            }]
        );
        assert!(
            cache
                .candidates(&test_url(), Some("127.0.0.1:53"))
                .is_empty()
        );
    }

    #[test]
    fn ignores_https_records_without_ttl() {
        let dir = TempDir::new().unwrap();
        let cache = Http3Cache::with_dir(dir.path().to_path_buf());
        cache.store_https_records(&test_url(), None, &[record(".", Some(9443), None)]);

        assert!(cache.candidates(&test_url(), None).is_empty());
    }

    #[test]
    fn removes_failed_candidates() {
        let dir = TempDir::new().unwrap();
        let cache = Http3Cache::with_dir(dir.path().to_path_buf());
        cache.store_https_records(&test_url(), None, &[record(".", Some(9443), Some(60))]);
        let candidates = cache.candidates(&test_url(), None);

        cache.remove_candidates(&test_url(), None, &candidates);

        assert!(cache.candidates(&test_url(), None).is_empty());
    }

    #[test]
    fn parses_alt_svc_h3_candidates_and_clear() {
        let url = test_url();
        let mut headers = HeaderMap::new();
        headers.insert(
            ALT_SVC,
            HeaderValue::from_static(r#"h3=":443"; ma=60, h2=":443", h3="alt.example:9443""#),
        );
        let update = parse_alt_svc_headers(&url, &headers, 100).unwrap();

        assert!(!update.clear);
        assert_eq!(update.candidates.len(), 2);
        assert_eq!(update.candidates[0].alt_host, "example.com");
        assert_eq!(update.candidates[0].alt_port, 443);
        assert_eq!(update.candidates[0].expires_at, 160);
        assert_eq!(update.candidates[1].alt_host, "alt.example");
        assert_eq!(update.candidates[1].alt_port, 9443);

        let mut headers = HeaderMap::new();
        headers.insert(ALT_SVC, HeaderValue::from_static("clear"));
        assert!(parse_alt_svc_headers(&url, &headers, 100).unwrap().clear);
    }

    #[test]
    fn alt_svc_ma_zero_removes_matching_candidate() {
        let url = test_url();
        let mut headers = HeaderMap::new();
        headers.insert(ALT_SVC, HeaderValue::from_static(r#"h3=":443"; ma=0"#));
        let update = parse_alt_svc_headers(&url, &headers, 100).unwrap();

        assert!(update.candidates.is_empty());
        assert_eq!(update.remove, vec![("example.com".to_string(), 443)]);
    }

    #[cfg(unix)]
    #[test]
    fn global_pruning_skips_directory_and_file_symlinks_and_cycles() {
        use std::os::unix::fs::symlink;

        let cache_dir = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let expired = ShardFile {
            version: CACHE_VERSION,
            origin: "https://outside.example".to_string(),
            resolver_key: SYSTEM_RESOLVER_KEY.to_string(),
            candidates: Vec::new(),
        };
        let outside_file = outside.path().join(format!("ab{}.json", "0".repeat(62)));
        fs::write(&outside_file, serde_json::to_vec(&expired).unwrap()).unwrap();

        // A valid-looking shard directory must not be followed outside the root.
        symlink(outside.path(), cache_dir.path().join("ab")).unwrap();

        // Nor may a valid-looking shard file itself be a symlink.
        let file_symlink_dir = cache_dir.path().join("cd");
        fs::create_dir(&file_symlink_dir).unwrap();
        symlink(
            &outside_file,
            file_symlink_dir.join(format!("cd{}.json", "0".repeat(62))),
        )
        .unwrap();

        // A cycle under a real shard directory must not be traversed.
        let cycle_dir = cache_dir.path().join("ef");
        fs::create_dir(&cycle_dir).unwrap();
        symlink(cache_dir.path(), cycle_dir.join("cycle")).unwrap();

        prune_global(cache_dir.path(), now_secs());

        assert!(outside_file.exists());
    }

    #[test]
    fn caps_candidates_per_origin() {
        let dir = TempDir::new().unwrap();
        let cache = Http3Cache::with_dir(dir.path().to_path_buf());
        let records = (0..8)
            .map(|idx| {
                let mut record = record(&format!("alt{idx}.example."), Some(9443), Some(60));
                record.priority = idx + 1;
                record
            })
            .collect::<Vec<_>>();

        cache.store_https_records(&test_url(), None, &records);

        let got = cache.candidates(&test_url(), None);
        assert_eq!(got.len(), MAX_CANDIDATES_PER_ORIGIN);
        assert_eq!(got[0].priority, Some(1));
        assert_eq!(got[3].priority, Some(4));
    }
}
