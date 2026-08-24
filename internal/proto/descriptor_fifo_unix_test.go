//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly || solaris

package proto

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLoadDescriptorSetFileRejectsReplacedFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "descriptor.pipe")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	if err := unix.Unlink(path); err != nil {
		t.Fatalf("unix.Unlink() error = %v", err)
	}
	if err := unix.Mkfifo(path, 0600); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENOSYS) {
			t.Skipf("FIFO unavailable: %v", err)
		}
		t.Fatalf("unix.Mkfifo() error = %v", err)
	}

	started := time.Now()
	_, err := LoadDescriptorSetFile(path)
	if err == nil {
		t.Fatal("LoadDescriptorSetFile() unexpectedly accepted FIFO")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("LoadDescriptorSetFile() blocked on FIFO for %s", elapsed)
	}
}
