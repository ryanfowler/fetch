//go:build unix

package fileutil

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// linkUnsupported reports whether a link error means that the file system
// has no hard links.
func linkUnsupported(err error) bool {
	return errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENOTSUP) ||
		errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOSYS)
}

// renameNoReplaceFunc is renameNoReplace. Tests replace it to exercise the
// fallback for file systems without a no-replace rename.
var renameNoReplaceFunc = renameNoReplace

// renameNoReplaceUnsupported reports whether a renameNoReplace error means
// that the platform or the file system does not support it.
func renameNoReplaceUnsupported(err error) bool {
	return errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP)
}

// writeNewFileWithoutLink installs tempPath at targetPath, which must not
// exist, without a hard link. It consumes tempPath on success.
func writeNewFileWithoutLink(tempPath, targetPath string) error {
	err := renameNoReplaceFunc(tempPath, targetPath)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.EEXIST) || !renameNoReplaceUnsupported(err):
		// os.IsExist reports an existing target, as for a failed link.
		return &os.LinkError{Op: "rename", Old: tempPath, New: targetPath, Err: err}
	}
	return writeNewFileWithPlaceholder(tempPath, targetPath)
}

// writeNewFileWithPlaceholder is the last fallback, for a file system that
// has neither hard links nor a no-replace rename. It reserves targetPath
// with an exclusive create, which fails if targetPath exists, also as a
// symlink, and then renames tempPath over its own empty file.
//
// This is weaker than a link:
//   - The empty file is visible until the rename. If the process dies in
//     between, the empty file stays, and later no-clobber writes fail.
//   - Another process can replace the placeholder just before the rename.
//     The identity check below makes that window very short, but it cannot
//     close it, because a rename cannot be conditional.
func writeNewFileWithPlaceholder(tempPath, targetPath string) error {
	placeholder, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	reserved, err := placeholder.Stat()
	if closeErr := placeholder.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		removeIfSame(targetPath, reserved)
		return err
	}
	if current, err := os.Lstat(targetPath); err != nil || !os.SameFile(current, reserved) {
		// Another process replaced the placeholder. Do not replace its file.
		return &os.LinkError{Op: "rename", Old: tempPath, New: targetPath, Err: os.ErrExist}
	}
	if err := os.Rename(tempPath, targetPath); err != nil {
		removeIfSame(targetPath, reserved)
		return err
	}
	return nil
}

// removeIfSame removes path only if it is still the file described by info,
// so that cleanup cannot remove a file that another process created.
func removeIfSame(path string, info os.FileInfo) {
	if info == nil {
		return
	}
	if current, err := os.Lstat(path); err == nil && os.SameFile(current, info) {
		_ = os.Remove(path)
	}
}
