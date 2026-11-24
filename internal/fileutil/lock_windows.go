//go:build windows

package fileutil

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

const lockAllBytes = ^uint32(0)

// openLockFile opens or creates the lock file. Windows has no O_NOFOLLOW,
// so it refuses a path that exists and is not a regular file, such as a
// planted symlink.
func openLockFile(path string) (*os.File, error) {
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return nil, fmt.Errorf("lock %q is not a regular file", path)
	}
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
}

// retryableOpenError reports whether an open error can go away by itself:
// a file that another process deletes, or that a scanner holds open.
func retryableOpenError(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}

func tryLockFile(file *os.File) (bool, error) {
	var ol windows.Overlapped
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK | windows.LOCKFILE_FAIL_IMMEDIATELY)
	err := windows.LockFileEx(windows.Handle(file.Fd()), flags, 0, lockAllBytes, lockAllBytes, &ol)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return false, nil
	}
	return false, err
}

func unlockFile(file *os.File) {
	var ol windows.Overlapped
	_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, lockAllBytes, lockAllBytes, &ol)
}

// releaseLockFile unlocks and closes the file before it removes it: Windows
// cannot remove an open file. Go opens files without FILE_SHARE_DELETE, so
// the removal fails while another process has the file open, and it cannot
// remove the file that another process has just locked.
func releaseLockFile(file *os.File, path string) {
	unlockFile(file)
	_ = file.Close()
	_ = os.Remove(path)
}
