//go:build linux

package body

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNewFileFromOpenFileClosesOnSeekError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "body.txt")
	if err := os.WriteFile(path, []byte("body"), 0o600); err != nil {
		t.Fatal(err)
	}

	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = unix.Close(fd)
		t.Fatal("os.NewFile returned nil")
	}

	if _, err := NewFileFromOpenFile(f, "text/plain"); err == nil {
		t.Fatal("NewFileFromOpenFile() succeeded with an unseekable file")
	}
	if err := f.Close(); err == nil {
		t.Fatal("unseekable file was not closed")
	}
}

func TestNewFileFromOpenFileClosesAfterStatError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "body.txt")
	if err := os.WriteFile(path, []byte("body"), 0o600); err != nil {
		t.Fatal(err)
	}

	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = unix.Close(fd)
		t.Fatal("os.NewFile returned nil")
	}
	// Keep the os.File wrapper live while invalidating its underlying
	// descriptor. This gives us a deterministic f.Stat error without relying
	// on a filesystem that can fail fstat on an otherwise valid descriptor.
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}

	if _, err := NewFileFromOpenFile(f, "text/plain"); !errors.Is(err, unix.EBADF) {
		t.Fatalf("NewFileFromOpenFile() error = %v, want an invalid-descriptor error", err)
	}
	if _, err := f.Stat(); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("file after Stat error = %v, want a closed-file error", err)
	}
}
