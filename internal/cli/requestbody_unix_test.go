//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly || solaris || aix

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestRequestBodyRejectsFIFOWithoutOpeningIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "body.pipe")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}

	reader, _, err := RequestBody("@" + path)
	if reader != nil {
		t.Fatal("RequestBody returned a reader for a FIFO")
	}
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("RequestBody error = %v, want regular-file validation error", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("FIFO disappeared during validation: %v", err)
	}
}
