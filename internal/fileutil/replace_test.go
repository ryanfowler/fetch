package fileutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicReplaceFile_ReplacesExistingFile(t *testing.T) {
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "target.txt")
	tempPath := filepath.Join(dir, "temp.txt")

	if err := os.WriteFile(targetPath, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tempPath, []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := AtomicReplaceFile(tempPath, targetPath); err != nil {
		t.Fatalf("AtomicReplaceFile returned error: %v", err)
	}

	data, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("reading target file: %v", err)
	}
	if string(data) != "new" {
		t.Fatalf("target file = %q, want %q", data, "new")
	}
	if _, err := os.Stat(tempPath); !os.IsNotExist(err) {
		t.Fatalf("temp file should be gone, stat err = %v", err)
	}
}

func TestAtomicWriteNewFile_CreatesNewFile(t *testing.T) {
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "target.txt")
	tempPath := filepath.Join(dir, "temp.txt")

	if err := os.WriteFile(tempPath, []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := AtomicWriteNewFile(tempPath, targetPath); err != nil {
		t.Fatalf("AtomicWriteNewFile returned error: %v", err)
	}

	data, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("reading target file: %v", err)
	}
	if string(data) != "new" {
		t.Fatalf("target file = %q, want %q", data, "new")
	}
	if _, err := os.Stat(tempPath); !os.IsNotExist(err) {
		t.Fatalf("temp file should be gone, stat err = %v", err)
	}
}

func TestAtomicWriteNewFile_DoesNotReplaceExistingFile(t *testing.T) {
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "target.txt")
	tempPath := filepath.Join(dir, "temp.txt")

	if err := os.WriteFile(targetPath, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tempPath, []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := AtomicWriteNewFile(tempPath, targetPath); err == nil {
		t.Fatal("AtomicWriteNewFile succeeded for an existing target")
	}

	data, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("reading target file: %v", err)
	}
	if string(data) != "old" {
		t.Fatalf("target file = %q, want %q", data, "old")
	}
	if _, err := os.Stat(tempPath); err != nil {
		t.Fatalf("temp file should remain after failed install, stat err = %v", err)
	}
}
