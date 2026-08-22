//go:build !windows

package client

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func removeH3CacheFile(dir, name string) error {
	dirFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(dirFD)
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	info, statErr := os.NewFile(uintptr(fd), name).Stat()
	_ = unix.Close(fd)
	if statErr != nil {
		return statErr
	}
	if !info.Mode().IsRegular() {
		return os.ErrInvalid
	}
	return unix.Unlinkat(dirFD, name, 0)
}
