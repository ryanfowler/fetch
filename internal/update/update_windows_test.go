//go:build windows

package update

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestUnpackArtifact_PathTraversal(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantErr  bool
	}{
		{
			name:     "normal file",
			filename: "fetch.exe",
			wantErr:  false,
		},
		{
			name:     "path traversal with ..",
			filename: "../escape.txt",
			wantErr:  true,
		},
		{
			name:     "deep path traversal",
			filename: "../../Windows/System32/malicious.dll",
			wantErr:  true,
		},
		{
			name:     "absolute path",
			filename: "C:/Windows/System32/malicious.dll",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a zip archive with the test filename.
			archive := createZip(t, tt.filename, []byte("content"))

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

func createZip(t *testing.T, filename string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	fw, err := zw.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
