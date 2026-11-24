//go:build !unix && !windows

package fileutil

import (
	"errors"
	"os"
)

func openLockFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
}

func retryableOpenError(error) bool { return false }

// This platform has no file locks.
func tryLockFile(*os.File) (bool, error) { return false, errors.ErrUnsupported }

func unlockFile(*os.File) {}

func releaseLockFile(file *os.File, path string) {
	_ = file.Close()
	_ = os.Remove(path)
}
