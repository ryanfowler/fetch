package fetch

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "simple filename",
			input:    "file.txt",
			expected: "file.txt",
			wantErr:  false,
		},
		{
			name:     "path traversal with ../ prefix",
			input:    "../file.txt",
			expected: "file.txt",
			wantErr:  false,
		},
		{
			name:     "path traversal with multiple ../ prefixes",
			input:    "../../../tmp/file.txt",
			expected: "file.txt",
			wantErr:  false,
		},
		{
			name:     "absolute path",
			input:    "/tmp/file.txt",
			expected: "file.txt",
			wantErr:  false,
		},
		{
			name:     "nested path",
			input:    "dir/subdir/file.txt",
			expected: "file.txt",
			wantErr:  false,
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "single dot",
			input:    ".",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "double dot",
			input:    "..",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "hidden file",
			input:    ".hidden",
			expected: ".hidden",
			wantErr:  false,
		},
		{
			name:     "path with trailing slash",
			input:    "dir/",
			expected: "dir",
			wantErr:  false,
		},
		{
			name:     "windows separator",
			input:    `dir\\file.txt`,
			expected: "file.txt",
			wantErr:  false,
		},
		{
			name:     "control character",
			input:    "file\x00.txt",
			expected: "file_.txt",
			wantErr:  false,
		},
		{
			name:     "trailing dot and space",
			input:    "file. ",
			expected: "file",
			wantErr:  false,
		},
		{
			name:    "windows device name",
			input:   "CON.txt",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := sanitizeFilename(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("sanitizeFilename(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("sanitizeFilename(%q) unexpected error: %v", tt.input, err)
				return
			}
			if result != tt.expected {
				t.Errorf("sanitizeFilename(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGetOutputValue_DirectOutputRequiresClobber(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.txt")

	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}

	name, err := getOutputValue(&Request{Output: path}, nil)
	if err == nil {
		t.Fatal("getOutputValue succeeded for an existing output file without clobber")
	}
	if name != "" {
		t.Fatalf("getOutputValue filename = %q, want empty string", name)
	}
	if _, ok := err.(errFileExists); !ok {
		t.Fatalf("getOutputValue error = %T, want errFileExists", err)
	}

	name, err = getOutputValue(&Request{Output: path, Clobber: true}, nil)
	if err != nil {
		t.Fatalf("getOutputValue with clobber returned error: %v", err)
	}
	if name != path {
		t.Fatalf("getOutputValue filename = %q, want %q", name, path)
	}
}

func TestGetOutputValue_DirectStdoutSkipsFileCheck(t *testing.T) {
	dir := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldwd); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	})

	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("-", []byte("existing stdout sentinel"), 0644); err != nil {
		t.Fatal(err)
	}

	name, err := getOutputValue(&Request{Output: "-"}, nil)
	if err != nil {
		t.Fatalf("getOutputValue returned error: %v", err)
	}
	if name != "-" {
		t.Fatalf("getOutputValue filename = %q, want %q", name, "-")
	}
}

func TestWriteOutputToFile_OverwritesExistingFileWithClobber(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "download.txt")

	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}

	printer := core.TestPrinter(false)
	err := writeOutputToFile(path, bytes.NewReader([]byte("new")), int64(len("new")), printer, core.VSilent, true)
	if err != nil {
		t.Fatalf("writeOutputToFile returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}
	if string(data) != "new" {
		t.Fatalf("output file = %q, want %q", data, "new")
	}
}

func TestContentDispositionFilenamePrefersRFC5987(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Disposition", `attachment; filename="plain.txt"; filename*=UTF-8''%E2%82%AC.txt`)
	name, ok := getContentDispositionFilenameDetails(h)
	if !ok || name != "€.txt" {
		t.Fatalf("filename = %q, valid = %v, want €.txt and true", name, ok)
	}
}

func TestContentDispositionFilenameSkipsMalformedParameter(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Disposition", `attachment; filename="plain.txt"; filename*=bad%zz`)
	name, ok := getContentDispositionFilenameDetails(h)
	if !ok || name != "plain.txt" {
		t.Fatalf("filename = %q, valid = %v, want plain.txt and true", name, ok)
	}

	h.Set("Content-Disposition", `attachment; filename="a"bad"; filename*=UTF-8''good.txt`)
	name, ok = getContentDispositionFilenameDetails(h)
	if ok {
		t.Fatalf("malformed quoted parameter produced filename %q", name)
	}
}

func TestSanitizeFilenameBoundsUTF8(t *testing.T) {
	name, err := sanitizeFilename(strings.Repeat("界", 100))
	if err != nil {
		t.Fatal(err)
	}
	if len(name) > maxOutputFilenameBytes || !utf8.ValidString(name) {
		t.Fatalf("sanitized filename has invalid size or encoding: bytes=%d", len(name))
	}
}

func TestWriteOutputToFileRejectsSymlinkWithClobber(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	outside := filepath.Join(dir, "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, target); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	err := writeOutputToFile(target, bytes.NewReader([]byte("new")), 3, core.TestPrinter(false), core.VSilent, true)
	if err == nil {
		t.Fatal("writeOutputToFile succeeded through a symlink")
	}
	got, readErr := os.ReadFile(outside)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "outside" {
		t.Fatalf("outside target changed to %q", got)
	}
}

func TestWriteOutputToFileCleansTemporaryFileAfterReadError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	body := &errorReader{}
	if err := writeOutputToFile(target, body, 0, core.TestPrinter(false), core.VSilent, false); err == nil {
		t.Fatal("writeOutputToFile succeeded for a failing reader")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary output files remain: %v", entries)
	}
}

type errorReader struct{}

func (*errorReader) Read([]byte) (int, error) { return 0, errors.New("body failed") }

func TestWriteOutputToFile_DoesNotOverwriteExistingFileWithoutClobber(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "download.txt")

	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}

	printer := core.TestPrinter(false)
	err := writeOutputToFile(path, bytes.NewReader([]byte("new")), int64(len("new")), printer, core.VSilent, false)
	if err == nil {
		t.Fatal("writeOutputToFile succeeded for an existing output file without clobber")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}
	if string(data) != "old" {
		t.Fatalf("output file = %q, want %q", data, "old")
	}
}
