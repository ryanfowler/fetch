//go:build windows

package client

import (
	"io"
	"os"
	"path/filepath"
)

// Windows uses the platform file API here. Lstat rejects ordinary symlink
// shards before opening them; the cache directory is revalidated before every
// atomic write. The cache is best effort if a reparse-point race is detected.
func readH3CacheFile(dir, name string, maxBytes int64) ([]byte, os.FileInfo, error) {
	path := filepath.Join(dir, name)
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > maxBytes {
		if err == nil {
			err = os.ErrInvalid
		}
		return nil, nil, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxBytes {
		if err == nil {
			err = os.ErrInvalid
		}
		return nil, nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || int64(len(data)) > maxBytes {
		if err == nil {
			err = os.ErrInvalid
		}
		return nil, nil, err
	}
	return data, info, nil
}
