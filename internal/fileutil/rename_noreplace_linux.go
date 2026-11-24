//go:build linux

package fileutil

import "golang.org/x/sys/unix"

// renameNoReplace renames oldPath to newPath only if newPath does not exist.
func renameNoReplace(oldPath, newPath string) error {
	return unix.Renameat2(unix.AT_FDCWD, oldPath, unix.AT_FDCWD, newPath, unix.RENAME_NOREPLACE)
}
