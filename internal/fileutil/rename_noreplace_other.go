//go:build unix && !linux && !darwin

package fileutil

import "golang.org/x/sys/unix"

// renameNoReplace is not available on this platform.
func renameNoReplace(string, string) error {
	return unix.ENOSYS
}
