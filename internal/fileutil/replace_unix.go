//go:build !windows

package fileutil

import "os"

// AtomicReplaceFile atomically replaces targetPath with tempPath.
// tempPath and targetPath must be on the same filesystem.
func AtomicReplaceFile(tempPath, targetPath string) error {
	return os.Rename(tempPath, targetPath)
}
