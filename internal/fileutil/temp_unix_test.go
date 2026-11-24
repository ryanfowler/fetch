//go:build unix

package fileutil

import (
	"syscall"
	"testing"
)

// TestCreateTempExactUmaskMode sets a known umask, so it must not run in
// parallel with other tests.
func TestCreateTempExactUmaskMode(t *testing.T) {
	old := syscall.Umask(0o027)
	t.Cleanup(func() { syscall.Umask(old) })

	f, err := CreateTemp(t.TempDir(), "x")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Fatalf("mode = %04o, want 0640", got)
	}
}
