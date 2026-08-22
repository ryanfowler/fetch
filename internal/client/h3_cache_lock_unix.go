//go:build !windows

package client

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func lockH3CacheFile(dir, name string) (*h3CacheLock, error) {
	dirFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(h3CacheLockWait)
	for {
		fd, openErr := unix.Openat(dirFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
		if openErr == nil {
			file := os.NewFile(uintptr(fd), name)
			if file == nil {
				_ = unix.Close(fd)
				_ = unix.Close(dirFD)
				return nil, os.ErrInvalid
			}
			return &h3CacheLock{release: func() {
				_ = file.Close()
				_ = unix.Unlinkat(dirFD, name, 0)
				_ = unix.Close(dirFD)
			}}, nil
		}
		if !errors.Is(openErr, unix.EEXIST) {
			_ = unix.Close(dirFD)
			return nil, openErr
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			_ = unix.Close(dirFD)
			return nil, os.ErrDeadlineExceeded
		}
		delay := 5 * time.Millisecond
		if remaining < delay {
			delay = remaining
		}
		time.Sleep(delay)
	}
}
