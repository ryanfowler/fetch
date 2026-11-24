//go:build darwin

package fileutil

import "golang.org/x/sys/unix"

// renameNoReplace renames oldPath to newPath only if newPath does not exist.
func renameNoReplace(oldPath, newPath string) error {
	return unix.RenamexNp(oldPath, newPath, unix.RENAME_EXCL)
}
