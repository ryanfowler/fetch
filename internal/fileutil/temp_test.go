package fileutil

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCreateTempUsesUmaskMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no Unix permission bits")
	}
	dir := t.TempDir()

	f, err := CreateTemp(dir, ".prefix-")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if !strings.HasPrefix(filepath.Base(f.Name()), ".prefix-") {
		t.Fatalf("name %q does not start with the prefix", f.Name())
	}
	if filepath.Dir(f.Name()) != dir {
		t.Fatalf("file %q is not in %q", f.Name(), dir)
	}

	// A file opened with mode 0666 gets the umask applied by the kernel.
	ref := filepath.Join(dir, "reference")
	if err := os.WriteFile(ref, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	want, err := os.Stat(ref)
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode().Perm() != want.Mode().Perm() {
		t.Fatalf("mode = %04o, want %04o", got.Mode().Perm(), want.Mode().Perm())
	}
}

func TestCreateTempMakesUniqueFiles(t *testing.T) {
	dir := t.TempDir()
	seen := make(map[string]bool)
	for range 50 {
		f, err := CreateTemp(dir, "x")
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		if seen[f.Name()] {
			t.Fatalf("duplicate name %q", f.Name())
		}
		seen[f.Name()] = true
	}
}

func TestCreateTempSkipsExistingNames(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if runtime.GOOS != "windows" {
		if err := os.Symlink(outside, filepath.Join(dir, "x1")); err != nil {
			t.Fatal(err)
		}
	} else if err := os.WriteFile(filepath.Join(dir, "x1"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "x2"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	names := []string{"1", "2", "3"}
	old := tempSuffix
	t.Cleanup(func() { tempSuffix = old })
	tempSuffix = func() string {
		name := names[0]
		names = names[1:]
		return name
	}

	f, err := CreateTemp(dir, "x")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if f.Name() != filepath.Join(dir, "x3") {
		t.Fatalf("name = %q, want x3", f.Name())
	}
	if _, err := os.Lstat(outside); !os.IsNotExist(err) {
		t.Fatalf("the symlink target was created: %v", err)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "x2")); string(data) != "keep" {
		t.Fatalf("an existing file was changed: %q", data)
	}
}

func TestCreateTempGivesUp(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "xsame"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := tempSuffix
	t.Cleanup(func() { tempSuffix = old })
	tempSuffix = func() string { return "same" }

	if _, err := CreateTemp(dir, "x"); !errors.Is(err, os.ErrExist) {
		t.Fatalf("err = %v, want os.ErrExist", err)
	}
}

func TestCreateTempRejectsSeparator(t *testing.T) {
	if _, err := CreateTemp(t.TempDir(), "../x"); err == nil {
		t.Fatal("CreateTemp accepted a prefix with a path separator")
	}
}
