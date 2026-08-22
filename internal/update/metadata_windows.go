//go:build windows

package update

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// openUpdateMetadata opens the reparse point itself instead of following it.
// The descriptor is stat'ed by readMetadata before any bytes are consumed.
func openUpdateMetadata(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(
		name,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		_ = windows.CloseHandle(h)
		return nil, errors.New("unable to open update metadata")
	}
	return f, nil
}
