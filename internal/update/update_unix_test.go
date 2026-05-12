//go:build unix

package update

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/gzip"
)

func TestUnpackArtifact_PathTraversal(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantErr  bool
	}{
		{
			name:     "normal file",
			filename: "fetch",
			wantErr:  false,
		},
		{
			name:     "path traversal with ..",
			filename: "../escape.txt",
			wantErr:  true,
		},
		{
			name:     "deep path traversal",
			filename: "../../etc/passwd",
			wantErr:  true,
		},
		{
			name:     "absolute path",
			filename: "/etc/passwd",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a tar.gz archive with the test filename.
			archive := createTarGz(t, tt.filename, []byte("content"))

			// Create a temp directory for extraction.
			dir := t.TempDir()

			err := unpackArtifact(dir, bytes.NewReader(archive))
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for filename %q, got nil", tt.filename)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				// Verify file was created in the correct location.
				if _, err := os.Stat(filepath.Join(dir, tt.filename)); err != nil {
					t.Errorf("expected file to exist: %v", err)
				}
			}
		})
	}
}

func TestCanReplaceFile_ReadOnlyFileWritableDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fetch")

	if err := os.WriteFile(path, []byte("binary"), 0755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(path, 0555); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	if !canReplaceFile(path) {
		t.Fatalf("canReplaceFile(%q) = false, want true", path)
	}
}

func TestUnpackArtifact_ExplicitDirectoryEntry(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	if err := tw.WriteHeader(&tar.Header{
		Name:     "bin/",
		Typeflag: tar.TypeDir,
		Mode:     0755,
	}); err != nil {
		t.Fatal(err)
	}

	content := []byte("content")
	if err := tw.WriteHeader(&tar.Header{
		Name: "bin/fetch",
		Mode: 0755,
		Size: int64(len(content)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := unpackArtifact(dir, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("unpackArtifact: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "bin", "fetch")); err != nil {
		t.Fatalf("expected file to exist: %v", err)
	}
}

func TestUnpackArtifact_TruncatesExistingRegularFile(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for _, content := range [][]byte{[]byte("longer content"), []byte("short")} {
		if err := tw.WriteHeader(&tar.Header{
			Name: "fetch",
			Mode: 0755,
			Size: int64(len(content)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := unpackArtifact(dir, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("unpackArtifact: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "fetch"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "short" {
		t.Fatalf("extracted content = %q, want %q", got, "short")
	}
}

func createTarGz(t *testing.T, filename string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	hdr := &tar.Header{
		Name: filename,
		Mode: 0644,
		Size: int64(len(content)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
