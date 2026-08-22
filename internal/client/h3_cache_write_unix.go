//go:build !windows

package client

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// writeH3CacheFile writes a shard relative to an opened cache directory. The
// directory descriptor remains stable if its pathname is replaced while the
// write is in progress.
func writeH3CacheFile(dir, name string, data []byte) error {
	dirFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(dirFD)

	var tempName string
	tempFD := -1
	for attempt := 0; attempt < 16; attempt++ {
		tempName = fmt.Sprintf(".h3-cache-%d-%d-%d", os.Getpid(), time.Now().UnixNano(), attempt)
		tempFD, err = unix.Openat(dirFD, tempName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EEXIST) {
			return err
		}
	}
	if tempFD < 0 {
		return os.ErrExist
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = unix.Unlinkat(dirFD, tempName, 0)
		}
	}()
	for len(data) > 0 {
		written, writeErr := unix.Write(tempFD, data)
		if writeErr != nil {
			_ = unix.Close(tempFD)
			return writeErr
		}
		data = data[written:]
	}
	if err := unix.Fsync(tempFD); err != nil {
		_ = unix.Close(tempFD)
		return err
	}
	if err := unix.Close(tempFD); err != nil {
		return err
	}

	// Refuse a symlink or non-regular destination. Renameat does not follow
	// the final destination, but this check prevents silently replacing a
	// cache entry that an attacker changed into a link.
	targetFD, targetErr := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if targetErr == nil {
		file := os.NewFile(uintptr(targetFD), filepath.Join(dir, name))
		if file == nil {
			_ = unix.Close(targetFD)
			return os.ErrInvalid
		}
		info, statErr := file.Stat()
		_ = file.Close()
		if statErr != nil {
			return statErr
		}
		if !info.Mode().IsRegular() {
			return errors.New("HTTP/3 cache shard is not a regular file")
		}
	} else if !errors.Is(targetErr, unix.ENOENT) {
		return targetErr
	}
	if err := unix.Renameat(dirFD, tempName, dirFD, name); err != nil {
		return err
	}
	cleanup = false
	_ = unix.Fsync(dirFD)
	return nil
}
