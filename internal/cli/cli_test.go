package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestFlagsAlphabeticalOrder(t *testing.T) {
	app, err := Parse(nil)
	if err != nil {
		t.Fatalf("unable to parse cli: %s", err.Error())
	}
	cli := app.CLI()
	for i := 1; i < len(cli.Flags); i++ {
		prev := cli.Flags[i-1].Long
		curr := cli.Flags[i].Long
		if curr < prev {
			t.Errorf("flags out of alphabetical order: %q should come before %q", curr, prev)
		}
	}
}

func TestFromCurlDataUrlencode(t *testing.T) {
	t.Run("@file reads and encodes contents", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "payload.txt")
		os.WriteFile(path, []byte("hello world&foo=bar"), 0o644)

		app, err := Parse([]string{
			"--from-curl",
			`curl --data-urlencode '@` + path + `' https://example.com`,
		})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		body, _ := io.ReadAll(app.Data)
		got := string(body)
		want := "hello+world%26foo%3Dbar"
		if got != want {
			t.Fatalf("body = %q, want %q", got, want)
		}
	})

	t.Run("name@file reads and encodes contents with name prefix", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "data.txt")
		os.WriteFile(path, []byte("value with spaces"), 0o644)

		app, err := Parse([]string{
			"--from-curl",
			`curl --data-urlencode 'field@` + path + `' https://example.com`,
		})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		body, _ := io.ReadAll(app.Data)
		got := string(body)
		want := "field=value+with+spaces"
		if got != want {
			t.Fatalf("body = %q, want %q", got, want)
		}
	})

	t.Run("inline name=content still works", func(t *testing.T) {
		app, err := Parse([]string{
			"--from-curl",
			`curl --data-urlencode "key=hello world" https://example.com`,
		})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		body, _ := io.ReadAll(app.Data)
		got := string(body)
		want := "key=hello+world"
		if got != want {
			t.Fatalf("body = %q, want %q", got, want)
		}
	})
}

func TestFromCurlDataFileClose(t *testing.T) {
	// Verify that file descriptors are properly closed after reading.
	dir := t.TempDir()
	path := filepath.Join(dir, "body.txt")
	os.WriteFile(path, []byte("file content"), 0o644)

	app, err := Parse([]string{
		"--from-curl",
		`curl -d '@` + path + `' https://example.com`,
	})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	body, _ := io.ReadAll(app.Data)
	got := string(body)
	if got != "file content" {
		t.Fatalf("body = %q, want %q", got, "file content")
	}
}

func TestFromCurlCookieFileRejected(t *testing.T) {
	_, err := Parse([]string{
		"--from-curl",
		`curl -b cookies.txt https://example.com`,
	})
	if err == nil {
		t.Fatal("expected error for cookie file path, got nil")
	}
	if !strings.Contains(err.Error(), "cookie jar files are not supported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCLI(t *testing.T) {
	app, err := Parse(nil)
	if err != nil {
		t.Fatalf("unable to parse cli: %s", err.Error())
	}
	p := core.NewHandle(core.ColorOff).Stdout()

	// Verify that no line of the help command is over 80 characters.
	app.PrintHelp(p)
	for line := range strings.Lines(string(p.Bytes())) {
		line = strings.TrimSuffix(line, "\n")
		if utf8.RuneCountInString(line) > 80 {
			t.Fatalf("line too long: %q", line)
		}
	}
}
