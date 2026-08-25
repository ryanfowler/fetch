//go:build unix

package update

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/gzip"
	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/fileutil"
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

func TestUnpackArtifact_AllowsOptionalLeadingDot(t *testing.T) {
	dir := t.TempDir()
	archive := createTarGz(t, "./fetch", []byte("candidate"))
	if err := unpackArtifact(dir, bytes.NewReader(archive)); err != nil {
		t.Fatalf("unpackArtifact: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "fetch"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "candidate" {
		t.Fatalf("extracted content = %q, want candidate", got)
	}
}

func TestUnpackArtifact_RejectsSpecialEntries(t *testing.T) {
	for _, test := range []struct {
		name string
		kind byte
	}{
		{name: "fetch", kind: tar.TypeSymlink},
		{name: "fetch", kind: tar.TypeLink},
	} {
		t.Run(string(test.kind), func(t *testing.T) {
			var buf bytes.Buffer
			gw := gzip.NewWriter(&buf)
			tw := tar.NewWriter(gw)
			if err := tw.WriteHeader(&tar.Header{Name: test.name, Typeflag: test.kind, Linkname: "outside"}); err != nil {
				t.Fatal(err)
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := gw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := unpackArtifact(t.TempDir(), bytes.NewReader(buf.Bytes())); err == nil {
				t.Fatal("special archive entry was accepted")
			}
		})
	}
}

func TestUnpackArtifact_RejectsOversizedEntry(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{Name: "fetch", Typeflag: tar.TypeReg, Size: core.MaxUpdaterUnpackedDataBytes + 1}); err != nil {
		t.Fatal(err)
	}
	// Closing reports the deliberately incomplete entry. The header is still
	// enough for the extractor to reject its declared size before reading it.
	_ = tw.Close()
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := unpackArtifact(t.TempDir(), bytes.NewReader(buf.Bytes())); err == nil {
		t.Fatal("oversized entry was accepted")
	}
}

func TestSelfReplaceIsAtomicAndRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "fetch")
	candidate := filepath.Join(t.TempDir(), "fetch")
	if err := os.WriteFile(target, []byte("old"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(candidate, []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := selfReplace(target, candidate); err != nil {
		t.Fatalf("selfReplace: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("target = %q, want new", got)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Fatalf("target mode = %o, want 0755", info.Mode().Perm())
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := selfReplace(link, candidate); !errors.Is(err, fileutil.ErrSymlinkTarget) {
		t.Fatalf("selfReplace symlink error = %v, want %v", err, fileutil.ErrSymlinkTarget)
	}
}

func TestValidateReplacementDirectory_ActionableError(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0775); err != nil {
		t.Fatal(err)
	}

	err := validateReplacementDirectory(filepath.Join(dir, "fetch"))
	if err == nil {
		t.Fatal("validateReplacementDirectory accepted a group-writable directory")
	}
	message := err.Error()
	for _, want := range []string{"writable by group or others", "0775", dir, "chmod go-w", "private directory"} {
		if !strings.Contains(message, want) {
			t.Errorf("error = %q, want it to contain %q", message, want)
		}
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

func TestUnpackArtifact_RejectsNestedDirectoryAndPayload(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{Name: "bin/", Typeflag: tar.TypeDir, Mode: 0755}); err != nil {
		t.Fatal(err)
	}
	content := []byte("content")
	if err := tw.WriteHeader(&tar.Header{Name: "bin/fetch", Mode: 0755, Size: int64(len(content))}); err != nil {
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
	if err := unpackArtifact(dir, bytes.NewReader(buf.Bytes())); err == nil {
		t.Fatal("unpackArtifact accepted a nested executable")
	}
	if _, err := os.Stat(filepath.Join(dir, "bin", "fetch")); !os.IsNotExist(err) {
		t.Fatalf("nested payload exists after rejection, stat error = %v", err)
	}
}

func TestUnpackArtifact_RejectsDuplicateExecutable(t *testing.T) {
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
	if err := unpackArtifact(dir, bytes.NewReader(buf.Bytes())); err == nil {
		t.Fatal("unpackArtifact accepted duplicate executable entries")
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
