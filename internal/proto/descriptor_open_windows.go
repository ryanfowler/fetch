//go:build windows

package proto

import (
	"os"

	"golang.org/x/sys/windows"
)

// openDescriptorSetFile opens and validates a descriptor through one handle.
// FILE_FLAG_OVERLAPPED is the Windows asynchronous-I/O equivalent of the
// Unix nonblocking open, preventing a pipe/device replacement from making the
// open path wait synchronously.
func openDescriptorSetFile(path string) (*os.File, os.FileInfo, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|windows.O_FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return nil, nil, err
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
