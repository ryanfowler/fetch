//go:build unix

package fileutil

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// openLockFile opens or creates the lock file. It does not follow a
// symlink, so a planted link cannot make it create a file elsewhere.
func openLockFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW, 0o600)
}

// retryableOpenError reports whether an open error can go away by itself.
func retryableOpenError(error) bool { return false }

func tryLockFile(file *os.File) (bool, error) {
	for {
		err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, unix.EWOULDBLOCK):
			return false, nil
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.ENOLCK) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOSYS):
			return false, fmt.Errorf("the file system does not support file locks: %w", err)
		default:
			return false, err
		}
	}
}

func unlockFile(file *os.File) {
	_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
}

// releaseLockFile removes the file while it holds the lock, so that a
// process that waits for it sees that the file is gone.
func releaseLockFile(file *os.File, path string) {
	_ = os.Remove(path)
	unlockFile(file)
	_ = file.Close()
}
