package fileutil

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"
)

// FileLock is an exclusive lock that LockFile took.
type FileLock struct {
	file *os.File
	path string
}

// LockFile takes an exclusive operating-system lock on the file at path,
// and creates the file if necessary. It waits up to timeout, or until ctx
// ends, for another holder. The operating system releases the lock when its
// process exits, so a crash does not leave a stale lock.
//
// Unlock removes the file. After it takes the lock, LockFile checks that
// path still names the locked file, so that a holder that removed the file
// meanwhile cannot make two processes hold the lock.
func LockFile(ctx context.Context, path string, timeout time.Duration) (*FileLock, error) {
	deadline := time.Now().Add(timeout)
	for {
		lock, err := tryLockPath(path)
		if lock != nil || (err != nil && !retryableOpenError(err)) {
			return lock, err
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("timed out waiting for lock %q", path)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

// tryLockPath makes one attempt to lock path. It returns a nil lock and a
// nil error when another process holds the lock, or when path changed
// during the attempt.
func tryLockPath(path string) (*FileLock, error) {
	file, err := openLockFile(path)
	if err != nil {
		return nil, err
	}
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		if err == nil {
			err = fmt.Errorf("lock %q is not a regular file", path)
		}
		return nil, err
	}
	locked, err := tryLockFile(file)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock %q: %w", path, err)
	}
	if !locked {
		_ = file.Close()
		return nil, nil
	}
	same, err := sameFile(file, path)
	if err == nil && same {
		return &FileLock{file: file, path: path}, nil
	}
	// The previous holder removed the file after this open.
	unlockFile(file)
	_ = file.Close()
	return nil, err
}

// Unlock releases the lock and removes its file. It is safe to call on nil.
func (l *FileLock) Unlock() {
	if l == nil || l.file == nil {
		return
	}
	releaseLockFile(l.file, l.path)
	l.file = nil
}

// sameFile reports whether path still names the open file.
func sameFile(file *os.File, path string) (bool, error) {
	opened, err := file.Stat()
	if err != nil {
		return false, err
	}
	current, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return os.SameFile(opened, current), nil
}
