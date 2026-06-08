use std::path::Path;
use std::time::Duration;

use crate::duration::format_go_duration;
use crate::error::{FetchError, write_warning_with_separator_with_color};
use crate::fileutil::FileLock;

pub(super) const UPDATE_LOCK_WAIT_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) fn acquire_update_lock(
    dir: &Path,
    block: bool,
    silent: bool,
    color: Option<&str>,
) -> Result<Option<FileLock>, FetchError> {
    acquire_update_lock_with_timeout(dir, block, silent, color, UPDATE_LOCK_WAIT_TIMEOUT)
}

pub(super) fn acquire_update_lock_with_timeout(
    dir: &Path,
    block: bool,
    silent: bool,
    color: Option<&str>,
    timeout: Duration,
) -> Result<Option<FileLock>, FetchError> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(".update-lock");
    if !block {
        return FileLock::try_acquire(path).map_err(FetchError::from);
    }

    FileLock::acquire_with_timeout(
        path,
        timeout,
        || {
            if !silent {
                write_warning_with_separator_with_color("waiting on lock to begin updating", color);
            }
        },
        update_lock_timeout_error,
    )
    .map(Some)
}

pub(super) fn update_lock_wait_timeout(request_timeout: Option<Duration>) -> Duration {
    request_timeout
        .map(|timeout| timeout.min(UPDATE_LOCK_WAIT_TIMEOUT))
        .unwrap_or(UPDATE_LOCK_WAIT_TIMEOUT)
}

fn update_lock_timeout_error(timeout: Duration) -> FetchError {
    FetchError::Runtime(format!(
        "timed out waiting for update lock after {}",
        format_go_duration(timeout)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[cfg(unix)]
    #[test]
    fn update_lock_nonblocking_returns_none_when_held() {
        let dir = tempfile::tempdir().unwrap();
        let _held = acquire_update_lock(dir.path(), true, true, None)
            .unwrap()
            .unwrap();

        assert!(
            acquire_update_lock(dir.path(), false, true, None)
                .unwrap()
                .is_none()
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn update_lock_timeout_returns_when_held() {
        let dir = tempfile::tempdir().unwrap();
        let _held = acquire_update_lock(dir.path(), true, true, None)
            .unwrap()
            .unwrap();

        let started_at = Instant::now();
        let result = acquire_update_lock_with_timeout(
            dir.path(),
            true,
            true,
            None,
            Duration::from_millis(10),
        );
        let elapsed = started_at.elapsed();

        match result {
            Err(err) => {
                assert_eq!(
                    err.to_string(),
                    "timed out waiting for update lock after 10ms"
                );
            }
            Ok(_) => panic!("expected held update lock to time out"),
        }
        assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
    }

    #[test]
    fn update_lock_wait_timeout_uses_shorter_request_timeout() {
        assert_eq!(
            update_lock_wait_timeout(Some(Duration::from_millis(250))),
            Duration::from_millis(250)
        );
        assert_eq!(
            update_lock_wait_timeout(Some(Duration::from_secs(120))),
            UPDATE_LOCK_WAIT_TIMEOUT
        );
        assert_eq!(update_lock_wait_timeout(None), UPDATE_LOCK_WAIT_TIMEOUT);
    }
}
