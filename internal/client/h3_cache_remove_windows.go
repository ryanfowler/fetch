//go:build windows

package client

import (
	"errors"
	"os"
	"path/filepath"
)

func removeH3CacheFile(dir, name string) error {
	path := filepath.Join(dir, name)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		if err != nil {
			return err
		}
		return os.ErrInvalid
	}
	return os.Remove(path)
}
