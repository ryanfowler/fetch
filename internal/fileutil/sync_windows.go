//go:build windows

package fileutil

// SyncDir is not required for the Windows replacement path. The staged file
// is flushed by the replacement API itself.
func SyncDir(string) error { return nil }
