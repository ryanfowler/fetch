//go:build !windows

package fileutil

import "os"

// AtomicReplaceFile atomically replaces targetPath with tempPath.
// tempPath and targetPath must be on the same filesystem.
func AtomicReplaceFile(tempPath, targetPath string) error {
	return os.Rename(tempPath, targetPath)
}

// AtomicWriteNewFile atomically installs tempPath at targetPath only if targetPath
// does not already exist. tempPath and targetPath must be on the same filesystem.
func AtomicWriteNewFile(tempPath, targetPath string) error {
	if err := os.Link(tempPath, targetPath); err != nil {
		return err
	}
	_ = os.Remove(tempPath)
	return nil
}
