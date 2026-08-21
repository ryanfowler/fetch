//go:build windows

package fileutil

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

const (
	moveFileReplaceExisting = 0x1
	moveFileWriteThrough    = 0x8
)

var (
	ErrSymlinkTarget = errors.New("refusing to replace a symlink target")
	errTargetChanged = errors.New("output target changed during commit")
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

// AtomicReplaceFileNoSymlink atomically replaces targetPath but refuses a
// symlink that was present when the commit was attempted.
func AtomicReplaceFileNoSymlink(tempPath, targetPath string) error {
	// Serialize fileutil commits so concurrent fetches cannot invalidate each
	// other's identity check. The final replacement does not follow a symlink.
	noSymlinkCommitMu.Lock()
	defer noSymlinkCommitMu.Unlock()

	info, err := os.Lstat(targetPath)
	if os.IsNotExist(err) {
		if err := AtomicWriteNewFile(tempPath, targetPath); err == nil {
			return nil
		} else if !os.IsExist(err) {
			return err
		}
		info, err = os.Lstat(targetPath)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return ErrSymlinkTarget
	}
	if !info.Mode().IsRegular() {
		return errors.New("output target is not a regular file")
	}
	latest, err := os.Lstat(targetPath)
	if err != nil {
		return err
	}
	if !os.SameFile(info, latest) {
		return errTargetChanged
	}
	return AtomicReplaceFile(tempPath, targetPath)
}

// AtomicWriteNewFile atomically installs tempPath at targetPath only if targetPath
// does not already exist. tempPath and targetPath must be on the same filesystem.
func AtomicWriteNewFile(tempPath, targetPath string) error {
	src, err := windows.UTF16PtrFromString(tempPath)
	if err != nil {
		return &os.PathError{Op: "write", Path: tempPath, Err: err}
	}
	dst, err := windows.UTF16PtrFromString(targetPath)
	if err != nil {
		return &os.PathError{Op: "write", Path: targetPath, Err: err}
	}

	if err := windows.MoveFileEx(src, dst, moveFileWriteThrough); err != nil {
		return &os.PathError{Op: "write", Path: targetPath, Err: err}
	}

	return nil
}
