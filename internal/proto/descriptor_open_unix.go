//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || zos

package proto

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// openDescriptorSetFile opens and validates a descriptor through one handle.
// O_NONBLOCK is important here: opening a FIFO for reading without it can
// wait forever before fstat gets a chance to reject the file.
func openDescriptorSetFile(path string) (*os.File, os.FileInfo, error) {
	var (
		fd  int
		err error
	)
	for {
		fd, err = unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		return nil, nil, err
	}

	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, nil, errors.New("failed to create descriptor set file")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, errDescriptorSetNotRegular
	}
	return file, info, nil
}
