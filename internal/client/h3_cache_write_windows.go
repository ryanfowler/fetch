//go:build windows

package client

import (
	"os"
	"path/filepath"

	"github.com/ryanfowler/fetch/internal/fileutil"
)

func writeH3CacheFile(dir, name string, data []byte) error {
	if err := ensureH3CacheDir(dir); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".h3-cache-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := ensureH3CacheDir(dir); err != nil {
		return err
	}
	return fileutil.AtomicReplaceFileNoSymlink(tempPath, filepath.Join(dir, name))
}
