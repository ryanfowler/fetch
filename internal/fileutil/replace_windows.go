//go:build windows

package fileutil

import (
	"os"

	"golang.org/x/sys/windows"
)

const (
	moveFileReplaceExisting = 0x1
	moveFileWriteThrough    = 0x8
)

// AtomicReplaceFile atomically replaces targetPath with tempPath.
// tempPath and targetPath must be on the same filesystem.
func AtomicReplaceFile(tempPath, targetPath string) error {
	src, err := windows.UTF16PtrFromString(tempPath)
	if err != nil {
		return &os.PathError{Op: "replace", Path: tempPath, Err: err}
	}
	dst, err := windows.UTF16PtrFromString(targetPath)
	if err != nil {
		return &os.PathError{Op: "replace", Path: targetPath, Err: err}
	}

	if err := windows.MoveFileEx(src, dst, moveFileReplaceExisting|moveFileWriteThrough); err != nil {
		return &os.PathError{Op: "replace", Path: targetPath, Err: err}
	}

	return nil
}
