//go:build !windows

package client

import (
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// readH3CacheFile opens the cache directory and shard relative to directory
// descriptors. O_NOFOLLOW prevents a shard symlink from being read even when
// it is swapped after directory validation.
func readH3CacheFile(dir, name string, maxBytes int64) ([]byte, os.FileInfo, error) {
	dirFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	defer unix.Close(dirFD)

	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), filepath.Join(dir, name))
	if file == nil {
		_ = unix.Close(fd)
		return nil, nil, os.ErrInvalid
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxBytes {
		if err == nil {
			err = os.ErrInvalid
		}
		return nil, nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || int64(len(data)) > maxBytes {
		if err == nil {
			err = os.ErrInvalid
		}
		return nil, nil, err
	}
	return data, info, nil
}
