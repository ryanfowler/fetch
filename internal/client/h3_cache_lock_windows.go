//go:build windows

package client

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

// lockH3CacheFile takes an exclusive lock on the file name in dir, and
// creates the file if necessary. Windows releases the lock when the process
// exits, so a crash cannot leave a stale lock. The file is never removed.
func lockH3CacheFile(dir, name string) (*h3CacheLock, error) {
	path := filepath.Join(dir, name)
	// Windows has no O_NOFOLLOW. Refuse a link that someone with write access
	// to the cache directory planted, so that fetch does not create or lock
	// a file outside the cache.
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return nil, os.ErrInvalid
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	const allBytes = ^uint32(0)
	handle := windows.Handle(file.Fd())
	deadline := time.Now().Add(h3CacheLockWait)
	for {
		var ol windows.Overlapped
		flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK | windows.LOCKFILE_FAIL_IMMEDIATELY)
		err := windows.LockFileEx(handle, flags, 0, allBytes, allBytes, &ol)
		if err == nil {
			return &h3CacheLock{release: func() {
				var ol windows.Overlapped
				_ = windows.UnlockFileEx(handle, 0, allBytes, allBytes, &ol)
				_ = file.Close()
			}}, nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			_ = file.Close()
			return nil, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			_ = file.Close()
			return nil, os.ErrDeadlineExceeded
		}
		time.Sleep(min(5*time.Millisecond, remaining))
	}
}
