use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use cookie::{Cookie as RawCookie, SameSite};
use cookie_store::{CookieDomain, CookieExpiration};
use reqwest::header::HeaderValue;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use url::Url;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error(
        "invalid session name '{0}': session names may only contain letters, numbers, hyphens, and underscores"
    )]
    InvalidName(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Url(#[from] url::ParseError),
}

#[derive(Clone)]
pub struct LoadedSession {
    pub session: Session,
    pub warning: Option<String>,
}

#[derive(Clone)]
pub struct Session {
    name: String,
    path: PathBuf,
    store: Arc<PersistentCookieStore>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionCookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub host_only: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub secure: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub http_only: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub same_site: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionFile {
    cookies: Vec<SessionCookie>,
}

#[derive(Debug, Default)]
pub struct PersistentCookieStore {
    store: RwLock<cookie_store::CookieStore>,
}

impl Session {
    pub fn load(name: &str) -> Result<LoadedSession, SessionError> {
        if !is_valid_name(name) {
            return Err(SessionError::InvalidName(name.to_string()));
        }

        let dir = sessions_dir()?;
        let path = dir.join(format!("{name}.json"));
        let store = Arc::new(PersistentCookieStore::default());
        let session = Session {
            name: name.to_string(),
            path,
            store,
        };

        let data = match std::fs::read(&session.path) {
            Ok(data) => data,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(LoadedSession {
                    session,
                    warning: None,
                });
            }
            Err(err) => return Err(err.into()),
        };

        let file: SessionFile = match serde_json::from_slice(&data) {
            Ok(file) => file,
            Err(err) => {
                return Ok(LoadedSession {
                    session,
                    warning: Some(err.to_string()),
                });
            }
        };

        session.store.load_cookies(file.cookies)?;
        Ok(LoadedSession {
            session,
            warning: None,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn cookie_provider(&self) -> Arc<PersistentCookieStore> {
        Arc::clone(&self.store)
    }

    pub fn save(&self) -> Result<(), SessionError> {
        let file = SessionFile {
            cookies: self.store.session_cookies(),
        };
        let mut data = serde_json::to_vec_pretty(&file)?;
        data.push(b'\n');
        atomic_write(&self.path, &data)?;
        Ok(())
    }

    #[cfg(test)]
    fn cookies(&self) -> Vec<SessionCookie> {
        self.store.session_cookies()
    }
}

impl PersistentCookieStore {
    fn load_cookies(&self, cookies: Vec<SessionCookie>) -> Result<(), SessionError> {
        let mut store = self.store.write().expect("session cookie store lock");
        for cookie in cookies {
            if cookie_is_expired(&cookie) {
                continue;
            }
            let Some(url) = cookie_origin_url(&cookie)? else {
                continue;
            };
            let mut raw = raw_cookie_from_session(cookie);
            if apply_go_public_suffix_policy(&mut raw, &url) {
                let _ = store.insert_raw(&raw, &url);
            }
        }
        Ok(())
    }

    fn session_cookies(&self) -> Vec<SessionCookie> {
        let store = self.store.read().expect("session cookie store lock");
        let mut cookies = store
            .iter_any()
            .filter(|cookie| !cookie.is_expired())
            .filter_map(SessionCookie::from_store_cookie)
            .collect::<Vec<_>>();
        cookies.sort_by(|a, b| (&a.domain, &a.path, &a.name).cmp(&(&b.domain, &b.path, &b.name)));
        cookies
    }
}

impl reqwest::cookie::CookieStore for PersistentCookieStore {
    fn set_cookies(&self, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>, url: &Url) {
        let cookies = cookie_headers.filter_map(|value| {
            let raw = std::str::from_utf8(value.as_bytes()).ok()?;
            let mut cookie = RawCookie::parse(raw).ok()?.into_owned();
            if !apply_go_public_suffix_policy(&mut cookie, url) {
                return None;
            }
            Some(cookie)
        });
        self.store
            .write()
            .expect("session cookie store lock")
            .store_response_cookies(cookies, url);
    }

    fn cookies(&self, url: &Url) -> Option<HeaderValue> {
        let value = self
            .store
            .read()
            .expect("session cookie store lock")
            .get_request_values(url)
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");

        if value.is_empty() {
            return None;
        }
        HeaderValue::from_maybe_shared(Bytes::from(value)).ok()
    }
}

impl SessionCookie {
    fn from_store_cookie(cookie: &cookie_store::Cookie<'static>) -> Option<Self> {
        let (domain, host_only) = match &cookie.domain {
            CookieDomain::HostOnly(domain) => (domain.clone(), true),
            CookieDomain::Suffix(domain) => (domain.clone(), false),
            CookieDomain::NotPresent | CookieDomain::Empty => return None,
        };

        let expires = match cookie.expires {
            CookieExpiration::AtUtc(expires) => format_rfc3339(expires).ok(),
            CookieExpiration::SessionEnd => None,
        };
        let same_site = match cookie.same_site() {
            Some(SameSite::Lax) => "lax",
            Some(SameSite::Strict) => "strict",
            Some(SameSite::None) => "none",
            _ => "",
        }
        .to_string();

        Some(Self {
            name: cookie.name().to_string(),
            value: cookie.value().to_string(),
            domain,
            host_only,
            path: String::from(&cookie.path),
            expires,
            secure: cookie.secure().unwrap_or(false),
            http_only: cookie.http_only().unwrap_or(false),
            same_site,
        })
    }
}

pub fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

pub fn sessions_dir() -> Result<PathBuf, SessionError> {
    #[cfg(test)]
    if let Some(dir) = test_sessions_dir() {
        std::fs::create_dir_all(&dir)?;
        return Ok(dir);
    }

    if let Some(dir) = std::env::var_os("FETCH_INTERNAL_SESSIONS_DIR") {
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir)?;
        return Ok(dir);
    }

    let base = default_cache_dir()?;
    let dir = base.join("fetch").join("sessions");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

#[cfg(test)]
static TEST_SESSIONS_DIR: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

#[cfg(test)]
fn test_sessions_dir() -> Option<PathBuf> {
    TEST_SESSIONS_DIR
        .lock()
        .expect("session test dir lock")
        .clone()
}

fn default_cache_dir() -> Result<PathBuf, SessionError> {
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
    )
    .into())
}

fn raw_cookie_from_session(cookie: SessionCookie) -> RawCookie<'static> {
    let mut builder = RawCookie::build((cookie.name, cookie.value));
    if !cookie.path.is_empty() {
        builder = builder.path(cookie.path);
    }
    if !cookie.host_only && !cookie.domain.is_empty() {
        builder = builder.domain(cookie.domain);
    }
    if let Some(expires) = cookie.expires.and_then(|value| parse_rfc3339(&value).ok()) {
        builder = builder.expires(expires);
    }
    if cookie.secure {
        builder = builder.secure(true);
    }
    if cookie.http_only {
        builder = builder.http_only(true);
    }
    builder = match cookie.same_site.as_str() {
        "lax" => builder.same_site(SameSite::Lax),
        "strict" => builder.same_site(SameSite::Strict),
        "none" => builder.same_site(SameSite::None),
        _ => builder,
    };
    builder.build()
}

fn cookie_origin_url(cookie: &SessionCookie) -> Result<Option<Url>, SessionError> {
    if cookie.domain.is_empty() {
        return Ok(None);
    }
    let scheme = if cookie.secure { "https" } else { "http" };
    let path = if cookie.path.is_empty() {
        "/"
    } else {
        &cookie.path
    };
    Ok(Some(Url::parse(&format!(
        "{scheme}://{}{}",
        cookie.domain, path
    ))?))
}

fn cookie_is_expired(cookie: &SessionCookie) -> bool {
    cookie
        .expires
        .as_deref()
        .and_then(|expires| parse_rfc3339(expires).ok())
        .is_some_and(|expires| expires <= OffsetDateTime::now_utc())
}

fn apply_go_public_suffix_policy(cookie: &mut RawCookie<'static>, url: &Url) -> bool {
    let Some(domain) = cookie.domain() else {
        return true;
    };
    let Some(domain) = normalize_cookie_domain_for_public_suffix(domain) else {
        return true;
    };
    if !is_public_suffix_domain(&domain) {
        return true;
    }
    if canonical_url_host(url).as_deref() == Some(domain.as_str()) {
        cookie.unset_domain();
        return true;
    }
    false
}

fn normalize_cookie_domain_for_public_suffix(domain: &str) -> Option<String> {
    let domain = domain.trim_start_matches('.').trim_end_matches('.');
    if domain.is_empty() || domain.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    Some(domain.to_ascii_lowercase())
}

fn canonical_url_host(url: &Url) -> Option<String> {
    Some(url.host_str()?.trim_end_matches('.').to_ascii_lowercase())
}

fn is_public_suffix_domain(domain: &str) -> bool {
    psl::suffix(domain.as_bytes()).is_some_and(|suffix| {
        suffix
            .trim()
            .as_bytes()
            .eq_ignore_ascii_case(domain.as_bytes())
    })
}

fn parse_rfc3339(value: &str) -> Result<OffsetDateTime, time::error::Parse> {
    OffsetDateTime::parse(value, &Rfc3339)
}

fn format_rfc3339(value: OffsetDateTime) -> Result<String, time::error::Format> {
    value.format(&Rfc3339)
}

fn atomic_write(path: &Path, data: &[u8]) -> Result<(), SessionError> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp = dir.join(format!(".session-{}-{nanos}.tmp", std::process::id()));
    std::fs::write(&tmp, data)?;
    if let Err(err) = crate::fileutil::atomic_replace_file(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err.into());
    }
    Ok(())
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::cookie::CookieStore;
    use std::sync::{Mutex, MutexGuard};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn lock_env() -> MutexGuard<'static, ()> {
        ENV_LOCK.lock().expect("session test env lock")
    }

    fn set_sessions_dir(dir: &Path) {
        *TEST_SESSIONS_DIR.lock().expect("session test dir lock") = Some(dir.to_path_buf());
    }

    #[test]
    fn test_is_valid_name() {
        for name in [
            "default",
            "api-prod",
            "my_session",
            "Session1",
            "a",
            "a-b_c-123",
        ] {
            assert!(is_valid_name(name), "{name}");
        }
        for name in [
            "",
            "../etc/passwd",
            "session name",
            "session/name",
            "session.name",
            "session\0name",
            ".hidden",
        ] {
            assert!(!is_valid_name(name), "{name:?}");
        }
    }

    #[test]
    fn test_load_save_round_trip() {
        let _guard = lock_env();
        let dir = tempfile::tempdir().unwrap();
        set_sessions_dir(dir.path());
        let loaded = Session::load("test").unwrap();
        assert_eq!(loaded.session.name(), "test");
        assert!(loaded.session.cookies().is_empty());

        let url = Url::parse("https://example.com/").unwrap();
        loaded.store().set_cookies(
            &mut [
                HeaderValue::from_static(
                    "session_id=abc123; Path=/; Secure; HttpOnly; SameSite=Lax",
                ),
                HeaderValue::from_static("theme=dark; Path=/"),
            ]
            .iter(),
            &url,
        );
        loaded.session.save().unwrap();

        let reloaded = Session::load("test").unwrap();
        let cookies = reloaded.session.cookies();
        assert_eq!(cookies.len(), 2);
        assert!(cookies.iter().any(|cookie| cookie.name == "session_id"
            && cookie.value == "abc123"
            && cookie.secure
            && cookie.http_only));
        assert!(
            cookies
                .iter()
                .any(|cookie| cookie.name == "theme" && cookie.value == "dark")
        );
    }

    #[test]
    fn test_expired_cookies_filtered() {
        let _guard = lock_env();
        let dir = tempfile::tempdir().unwrap();
        set_sessions_dir(dir.path());
        let session = Session::load("expiry-test").unwrap().session;
        let url = Url::parse("http://example.com/").unwrap();
        session.store.set_cookies(
            &mut [
                HeaderValue::from_static("valid=yes; Path=/; Max-Age=3600"),
                HeaderValue::from_static("expired=no; Path=/; Max-Age=0"),
                HeaderValue::from_static("no-expiry=session; Path=/"),
            ]
            .iter(),
            &url,
        );
        session.save().unwrap();

        let reloaded = Session::load("expiry-test").unwrap();
        let cookies = reloaded.session.cookies();
        assert_eq!(cookies.len(), 2);
        assert!(!cookies.iter().any(|cookie| cookie.name == "expired"));
    }

    #[test]
    fn test_session_store_rejects_foreign_domain_cookie() {
        let store = PersistentCookieStore::default();
        let origin = Url::parse("https://example.com/").unwrap();
        store.set_cookies(
            &mut [HeaderValue::from_static("token=secret; Domain=evil.com")].iter(),
            &origin,
        );

        assert!(store.cookies(&origin).is_none());
        assert!(store.session_cookies().is_empty());
    }

    #[test]
    fn test_session_store_rejects_top_level_public_suffix_cookie() {
        let store = PersistentCookieStore::default();
        let origin = Url::parse("https://example.com/").unwrap();
        store.set_cookies(
            &mut [HeaderValue::from_static("token=secret; Domain=com")].iter(),
            &origin,
        );

        assert!(store.cookies(&origin).is_none());
        assert!(store.session_cookies().is_empty());
    }

    #[test]
    fn test_session_store_rejects_multi_label_public_suffix_cookie_like_go() {
        let store = PersistentCookieStore::default();
        let origin = Url::parse("https://user.github.io/").unwrap();
        store.set_cookies(
            &mut [HeaderValue::from_static("token=secret; Domain=github.io")].iter(),
            &origin,
        );

        assert!(store.cookies(&origin).is_none());
        assert!(store.session_cookies().is_empty());
    }

    #[test]
    fn test_session_store_public_suffix_matching_host_becomes_host_only_like_go() {
        let store = PersistentCookieStore::default();
        let origin = Url::parse("https://github.io/").unwrap();
        let subdomain = Url::parse("https://user.github.io/").unwrap();
        store.set_cookies(
            &mut [HeaderValue::from_static("token=secret; Domain=github.io")].iter(),
            &origin,
        );

        let cookies = store.session_cookies();
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].domain, "github.io");
        assert!(cookies[0].host_only);
        assert!(
            store
                .cookies(&origin)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("token=secret")
        );
        assert!(store.cookies(&subdomain).is_none());
    }

    #[test]
    fn test_session_load_converts_public_suffix_cookie_matching_host_to_host_only_like_go() {
        let _guard = lock_env();
        let dir = tempfile::tempdir().unwrap();
        set_sessions_dir(dir.path());
        let path = dir.path().join("public-suffix-host.json");
        std::fs::write(
            path,
            r#"{
  "cookies": [
    {
      "name": "token",
      "value": "secret",
      "domain": "github.io",
      "path": "/"
    }
  ]
}
"#,
        )
        .unwrap();

        let loaded = Session::load("public-suffix-host").unwrap().session;
        let origin = Url::parse("http://github.io/").unwrap();
        let subdomain = Url::parse("http://user.github.io/").unwrap();

        assert!(
            loaded
                .store
                .cookies(&origin)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("token=secret")
        );
        assert!(loaded.store.cookies(&subdomain).is_none());
        let cookies = loaded.cookies();
        assert_eq!(cookies.len(), 1);
        assert!(cookies[0].host_only);
    }

    #[test]
    fn test_session_reload_preserves_host_only_cookies() {
        let _guard = lock_env();
        let dir = tempfile::tempdir().unwrap();
        set_sessions_dir(dir.path());
        let session = Session::load("host-only-test").unwrap().session;
        let origin = Url::parse("https://example.com/").unwrap();
        let subdomain = Url::parse("https://api.example.com/").unwrap();
        session.store.set_cookies(
            &mut [
                HeaderValue::from_static("host=only"),
                HeaderValue::from_static("domain=wide; Domain=example.com"),
            ]
            .iter(),
            &origin,
        );
        session.save().unwrap();

        let reloaded = Session::load("host-only-test").unwrap().session;
        let origin_cookies = reloaded.store.cookies(&origin).unwrap();
        assert!(origin_cookies.to_str().unwrap().contains("host=only"));
        assert!(origin_cookies.to_str().unwrap().contains("domain=wide"));

        let subdomain_cookies = reloaded.store.cookies(&subdomain).unwrap();
        let subdomain_cookies = subdomain_cookies.to_str().unwrap();
        assert!(!subdomain_cookies.contains("host=only"));
        assert!(subdomain_cookies.contains("domain=wide"));
    }

    #[test]
    fn test_session_store_deletes_existing_cookie() {
        let store = PersistentCookieStore::default();
        let origin = Url::parse("https://example.com/app/login").unwrap();
        store.set_cookies(
            &mut [HeaderValue::from_static("token=live")].iter(),
            &origin,
        );
        assert_eq!(store.session_cookies().len(), 1);

        store.set_cookies(
            &mut [HeaderValue::from_static("token=; Max-Age=0")].iter(),
            &origin,
        );
        assert!(store.session_cookies().is_empty());
    }

    #[test]
    fn test_corrupted_session_file_returns_warning_and_empty_session() {
        let _guard = lock_env();
        let dir = tempfile::tempdir().unwrap();
        set_sessions_dir(dir.path());
        std::fs::write(dir.path().join("corrupt.json"), "not json").unwrap();

        let loaded = Session::load("corrupt").unwrap();

        assert!(loaded.warning.is_some());
        assert!(loaded.session.cookies().is_empty());
    }

    impl LoadedSession {
        fn store(&self) -> Arc<PersistentCookieStore> {
            self.session.cookie_provider()
        }
    }
}
