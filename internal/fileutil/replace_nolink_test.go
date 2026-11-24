//go:build unix

package fileutil

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// testWriteWithoutLink checks writeNewFileWithoutLink for a new and for an
// existing target.
func testWriteWithoutLink(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	temp := filepath.Join(dir, "temp")
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(temp, []byte("new"), 0o640); err != nil {
		t.Fatal(err)
	}
	tempInfo, err := os.Stat(temp)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeNewFileWithoutLink(temp, target); err != nil {
		t.Fatalf("writeNewFileWithoutLink() error = %v", err)
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "new" {
		t.Fatalf("target = %q, %v; want new", data, err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != tempInfo.Mode().Perm() {
		t.Fatalf("target mode = %v, want the temporary file's mode %v", info.Mode(), tempInfo.Mode())
	}
	if _, err := os.Stat(temp); !os.IsNotExist(err) {
		t.Fatalf("temporary file still exists: %v", err)
	}

	// An existing target is not replaced, and the error satisfies
	// os.IsExist, as for a failed link.
	if err := os.WriteFile(temp, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeNewFileWithoutLink(temp, target); !os.IsExist(err) {
		t.Fatalf("writeNewFileWithoutLink() over an existing file: error = %v, want os.IsExist", err)
	}
	if data, _ := os.ReadFile(target); string(data) != "new" {
		t.Fatalf("existing target was replaced: %q", data)
	}

	// A symlink at the target is not followed or replaced.
	link := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), link); err != nil {
		t.Fatal(err)
	}
	if err := writeNewFileWithoutLink(temp, link); !os.IsExist(err) {
		t.Fatalf("writeNewFileWithoutLink() over a symlink: error = %v, want os.IsExist", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "elsewhere")); !os.IsNotExist(err) {
		t.Fatal("symlink target was created")
	}
}

func TestWriteNewFileWithoutLink(t *testing.T) {
	testWriteWithoutLink(t)
}

func TestWriteNewFileWithoutLinkOrNoReplaceRename(t *testing.T) {
	previous := renameNoReplaceFunc
	renameNoReplaceFunc = func(string, string) error { return unix.ENOSYS }
	t.Cleanup(func() { renameNoReplaceFunc = previous })
	testWriteWithoutLink(t)
}

func TestLinkUnsupported(t *testing.T) {
	for _, errno := range []unix.Errno{unix.EPERM, unix.ENOTSUP, unix.EOPNOTSUPP, unix.ENOSYS} {
		err := &os.LinkError{Op: "link", Err: errno}
		if !linkUnsupported(err) {
			t.Errorf("linkUnsupported(%v) = false", errno)
		}
	}
	if linkUnsupported(&os.LinkError{Op: "link", Err: unix.EEXIST}) {
		t.Error("linkUnsupported(EEXIST) = true")
	}
}

func TestAtomicWriteNewFileFallsBackWhenLinkIsUnsupported(t *testing.T) {
	previous := linkFunc
	linkFunc = func(oldName, newName string) error {
		return &os.LinkError{Op: "link", Old: oldName, New: newName, Err: unix.EPERM}
	}
	t.Cleanup(func() { linkFunc = previous })

	dir := t.TempDir()
	temp := filepath.Join(dir, "temp")
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(temp, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWriteNewFile(temp, target); err != nil {
		t.Fatalf("AtomicWriteNewFile() error = %v", err)
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "data" {
		t.Fatalf("target = %q, %v; want data", data, err)
	}
}

func TestPlaceholderIsRemovedWhenRenameFails(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	err := writeNewFileWithPlaceholder(filepath.Join(dir, "missing"), target)
	if err == nil {
		t.Fatal("writeNewFileWithPlaceholder() succeeded without a temporary file")
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("placeholder was not removed: %v", err)
	}
}

func TestRemoveIfSameKeepsAnotherFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Another process replaces the file with a rename, so the new file has
	// another inode.
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(other, path); err != nil {
		t.Fatal(err)
	}
	removeIfSame(path, info)
	if data, err := os.ReadFile(path); err != nil || string(data) != "other" {
		t.Fatalf("removeIfSame removed another file: %q, %v", data, err)
	}
}
