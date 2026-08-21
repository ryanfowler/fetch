//go:build !windows

package fileutil

import "os"

// SyncDir flushes directory metadata when the platform supports opening a
// directory for synchronization. Callers may treat failures as best effort.
func SyncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
