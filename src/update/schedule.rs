use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::install::current_exe;
use super::lock::acquire_update_lock;
use super::unique_suffix;
use crate::error::FetchError;

pub(crate) fn maybe_spawn_auto_update(value: &str, config_path: Option<&Path>) {
    let Some(interval) = parse_auto_update_interval(value) else {
        return;
    };
    if should_attempt_update(interval).is_ok_and(|ok| !ok) {
        return;
    }

    let Ok(path) = current_exe() else {
        return;
    };
    let mut command = Command::new(path);
    command
        .args(auto_update_command_args(config_path))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if std::env::var_os("FETCH_INTERNAL_SYNC_AUTO_UPDATE").is_some() {
        let _ = command.status();
    } else {
        let _ = command.spawn();
    }
}

fn auto_update_command_args(config_path: Option<&Path>) -> Vec<OsString> {
    let mut args = Vec::new();
    if let Some(path) = config_path {
        push_arg(&mut args, "--config");
        args.push(path.as_os_str().to_os_string());
    }
    push_arg(&mut args, "--update");
    push_arg(&mut args, "--timeout=300");
    push_arg(&mut args, "--silent");
    args
}

fn push_arg(args: &mut Vec<OsString>, value: impl Into<OsString>) {
    args.push(value.into());
}

fn parse_auto_update_interval(value: &str) -> Option<Duration> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    match value {
        "false" | "FALSE" | "False" | "f" | "F" | "0" | "off" | "no" | "never" => return None,
        "true" | "TRUE" | "True" | "t" | "T" | "1" | "on" | "yes" => {
            return Some(Duration::from_secs(24 * 60 * 60));
        }
        "0s" | "0sec" | "0secs" | "0m" => return Some(Duration::ZERO),
        _ => {}
    }

    crate::duration::parse_duration_interval(value)
}

#[derive(Debug, Serialize, Deserialize)]
struct Metadata {
    last_attempt_at: String,
}

pub(super) fn record_last_attempt_time(dir: &Path) {
    let _ = update_last_attempt_time(dir, SystemTime::now());
}

fn should_attempt_update(interval: Duration) -> Result<bool, FetchError> {
    let dir = cache_dir()?;
    should_attempt_update_in(&dir, interval)
}

fn should_attempt_update_in(dir: &Path, interval: Duration) -> Result<bool, FetchError> {
    let Some(_lock) = acquire_update_lock(dir, false, true, None)? else {
        return Ok(false);
    };
    let path = dir.join("metadata.json");
    let data = match std::fs::read(&path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(err) => return Err(err.into()),
    };

    let metadata: Metadata = match serde_json::from_slice(&data) {
        Ok(metadata) => metadata,
        Err(_) => return Ok(true),
    };
    let last_attempt_at = match OffsetDateTime::parse(&metadata.last_attempt_at, &Rfc3339) {
        Ok(value) => value,
        Err(_) => return Ok(true),
    };
    let now = OffsetDateTime::now_utc();
    let elapsed = (now - last_attempt_at).try_into().unwrap_or(Duration::ZERO);
    Ok(elapsed > interval)
}

pub(super) fn cache_dir() -> Result<PathBuf, FetchError> {
    let base = user_cache_dir().ok_or_else(|| {
        FetchError::Message("unable to determine user cache directory".to_string())
    })?;
    let dir = base.join("fetch");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn user_cache_dir() -> Option<PathBuf> {
    if cfg!(target_os = "windows") {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join("Library").join("Caches"))
    } else if let Some(cache) = std::env::var_os("XDG_CACHE_HOME") {
        Some(PathBuf::from(cache))
    } else {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache"))
    }
}

fn update_last_attempt_time(dir: &Path, now: SystemTime) -> Result<(), FetchError> {
    let timestamp = OffsetDateTime::from(now)
        .to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(|err| FetchError::Message(err.to_string()))?;
    let data = serde_json::to_vec(&Metadata {
        last_attempt_at: timestamp,
    })
    .map_err(|err| FetchError::Message(err.to_string()))?;

    std::fs::create_dir_all(dir)?;
    let path = dir.join("metadata.json");
    let tmp = dir.join(format!(".metadata-{}.tmp", unique_suffix()));
    std::fs::write(&tmp, data)?;
    if let Err(err) = crate::fileutil::atomic_replace_file(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn auto_update_command_args_preserve_explicit_config_only() {
        let args = auto_update_command_args(Some(Path::new("custom config.ini")));
        let args = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(
            args,
            vec![
                "--config",
                "custom config.ini",
                "--update",
                "--timeout=300",
                "--silent",
            ]
        );
    }

    #[test]
    fn auto_update_zero_interval_is_due() {
        assert!(parse_auto_update_interval("0s").is_some());
        assert!(parse_auto_update_interval("0sec").is_some());
        assert_eq!(parse_auto_update_interval("0"), None);
    }

    #[test]
    fn update_last_attempt_time_overwrites_existing_metadata() {
        let dir = tempfile::tempdir().unwrap();

        update_last_attempt_time(dir.path(), UNIX_EPOCH + Duration::from_secs(100)).unwrap();
        update_last_attempt_time(dir.path(), UNIX_EPOCH + Duration::from_secs(200)).unwrap();

        let data = std::fs::read_to_string(dir.path().join("metadata.json")).unwrap();
        assert_eq!(data, r#"{"last_attempt_at":"1970-01-01T00:03:20Z"}"#);
    }

    #[test]
    fn auto_update_interval_parses_go_bool_and_duration_values() {
        assert_eq!(
            parse_auto_update_interval("true"),
            Some(Duration::from_secs(24 * 60 * 60))
        );
        assert_eq!(
            parse_auto_update_interval("1h30m"),
            Some(Duration::from_secs(90 * 60))
        );
        assert_eq!(
            parse_auto_update_interval("1.5h"),
            Some(Duration::from_secs(90 * 60))
        );
        assert_eq!(
            parse_auto_update_interval("+30m"),
            Some(Duration::from_secs(30 * 60))
        );
        assert_eq!(
            parse_auto_update_interval("1d"),
            Some(Duration::from_secs(24 * 60 * 60))
        );
        assert_eq!(
            parse_auto_update_interval("250ms"),
            Some(Duration::from_millis(250))
        );
        assert_eq!(parse_auto_update_interval("false"), None);
        assert_eq!(parse_auto_update_interval("-1h"), None);
        assert_eq!(parse_auto_update_interval("garbage"), None);
    }

    #[cfg(unix)]
    #[test]
    fn should_attempt_update_returns_false_when_lock_is_held() {
        let dir = tempfile::tempdir().unwrap();
        let _held = acquire_update_lock(dir.path(), true, true, None)
            .unwrap()
            .unwrap();

        assert!(!should_attempt_update_in(dir.path(), Duration::ZERO).unwrap());
    }

    #[test]
    fn should_attempt_update_uses_metadata_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        update_last_attempt_time(dir.path(), SystemTime::now()).unwrap();

        assert!(!should_attempt_update_in(dir.path(), Duration::from_secs(60)).unwrap());
        assert!(should_attempt_update_in(dir.path(), Duration::ZERO).unwrap());
    }
}
