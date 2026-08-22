//go:build windows

package client

import (
	"os"
	"path/filepath"
	"time"
)

func lockH3CacheFile(dir, name string) (*h3CacheLock, error) {
	deadline := time.Now().Add(h3CacheLockWait)
	path := filepath.Join(dir, name)
	for {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			return &h3CacheLock{release: func() {
				_ = file.Close()
				_ = os.Remove(path)
			}}, nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, os.ErrDeadlineExceeded
		}
		delay := 5 * time.Millisecond
		if remaining < delay {
			delay = remaining
		}
		time.Sleep(delay)
	}
}
