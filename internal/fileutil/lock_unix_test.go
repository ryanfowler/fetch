//go:build unix

package fileutil

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLockFileRefusesASymlink(t *testing.T) {
	// A planted link must not make the lock create a file elsewhere.
	dir := t.TempDir()
	outside := filepath.Join(dir, "outside")
	path := filepath.Join(dir, "lock")
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if lock, err := LockFile(context.Background(), path, 100*time.Millisecond); err == nil {
		lock.Unlock()
		t.Fatal("LockFile() locked through a symlink")
	}
	if _, err := os.Lstat(outside); !os.IsNotExist(err) {
		t.Fatalf("LockFile() created the symlink target: %v", err)
	}
}

func TestLockFileRefusesAFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	// Open a FIFO for reading and writing, so that the open does not block.
	if lock, err := LockFile(context.Background(), path, 100*time.Millisecond); err == nil {
		lock.Unlock()
		t.Fatal("LockFile() locked a FIFO")
	}
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("FIFO was removed or changed: %v", err)
	}
}
