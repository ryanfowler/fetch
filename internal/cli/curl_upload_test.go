package cli

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestFromCurlUploadAddsFileName(t *testing.T) {
	dir := t.TempDir()
	odd := filepath.Join(dir, "a b&c+d.txt")
	plain := filepath.Join(dir, "f.json")
	for _, name := range []string{odd, plain} {
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// These results match curl 8.23.
	tests := []struct {
		file, url, want string
	}{
		{odd, "http://example.com/", "http://example.com/a%20b%26c%2Bd.txt"},
		{odd, "http://example.com", "http://example.com/a%20b%26c%2Bd.txt"},
		{plain, "http://example.com/dir/", "http://example.com/dir/f.json"},
		{plain, "http://example.com/a%20dir/", "http://example.com/a%20dir/f.json"},
		{plain, "http://example.com/dir/?", "http://example.com/dir/f.json"},
		{plain, "http://example.com/dir/#frag", "http://example.com/dir/f.json#frag"},
		{plain, "http://example.com/dir/?q=1", "http://example.com/dir/?q=1"},
		{plain, "http://example.com/name", "http://example.com/name"},
		{plain, "http://example.com/a%2F", "http://example.com/a%2F"},
		{"-", "http://example.com/", "http://example.com/"},
		{"-", "http://example.com/dir/?q=1", "http://example.com/dir/?q=1"},
	}
	for _, tt := range tests {
		app, err := Parse([]string{"--from-curl", "curl -T '" + tt.file + "' '" + tt.url + "'"})
		if err != nil {
			t.Fatalf("Parse(%q, %q) error = %v", tt.file, tt.url, err)
		}
		// Close the upload file so that Windows can remove the directory.
		// Do not close standard input.
		if f, ok := app.Data.(*os.File); ok && f != os.Stdin {
			f.Close()
		}
		if got := app.URL.String(); got != tt.want {
			t.Errorf("-T %q %q: URL = %q, want %q", filepath.Base(tt.file), tt.url, got, tt.want)
		}
		want, err := url.Parse(tt.want)
		if err != nil {
			t.Fatal(err)
		}
		if got := app.URL.RequestURI(); got != want.RequestURI() {
			t.Errorf("-T %q %q: request URI = %q, want %q", filepath.Base(tt.file), tt.url, got, want.RequestURI())
		}
	}
}

func TestAddUploadFileNameSplitsOnBackslash(t *testing.T) {
	// curl takes the text after the last "/" or "\" on every OS.
	for file, want := range map[string]string{
		`back\slash.txt`: "/dir/slash.txt",
		`a\b\c.txt`:      "/dir/c.txt",
		`a/b\c.txt`:      "/dir/c.txt",
		`dir/`:           "/dir/",
	} {
		u, err := url.Parse("http://example.com/dir/")
		if err != nil {
			t.Fatal(err)
		}
		addUploadFileName(u, file)
		if got := u.EscapedPath(); got != want {
			t.Errorf("addUploadFileName(%q) path = %q, want %q", file, got, want)
		}
	}
}
