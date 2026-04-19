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

func TestLongFlagExplicitEmptyValue(t *testing.T) {
	t.Run("does not consume following URL", func(t *testing.T) {
		app, err := Parse([]string{"--output=", "example.com"})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if app.Output != "" {
			t.Fatalf("Output = %q, want empty string", app.Output)
		}
		if app.URL == nil {
			t.Fatal("expected URL to be parsed")
		}
		if app.URL.Host != "example.com" {
			t.Fatalf("URL host = %q, want %q", app.URL.Host, "example.com")
		}
	})

	t.Run("passes empty value to flag", func(t *testing.T) {
		app, err := Parse([]string{"--form=", "example.com"})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if len(app.Form) != 1 {
			t.Fatalf("len(Form) = %d, want 1", len(app.Form))
		}
		if app.Form[0].Key != "" || app.Form[0].Val != "" {
			t.Fatalf("Form[0] = %#v, want empty key/value", app.Form[0])
		}
		if app.URL == nil {
			t.Fatal("expected URL to be parsed")
		}
		if app.URL.Host != "example.com" {
			t.Fatalf("URL host = %q, want %q", app.URL.Host, "example.com")
		}
	})
}

func TestGRPCDiscoveryFlags(t *testing.T) {
	t.Run("grpc list parses", func(t *testing.T) {
		app, err := Parse([]string{"--grpc-list", "localhost:50051"})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if !app.GRPCList {
			t.Fatal("expected GRPCList to be set")
		}
		if app.URL == nil {
			t.Fatal("expected URL to be parsed")
		}
	})

	t.Run("proto desc accepts grpc describe without url", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "service.pb")
		os.WriteFile(path, []byte("placeholder"), 0o644)

		app, err := Parse([]string{"--grpc-describe", "pkg.Service", "--proto-desc", path})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if app.GRPCDescribe != "pkg.Service" {
			t.Fatalf("GRPCDescribe = %q, want %q", app.GRPCDescribe, "pkg.Service")
		}
		if app.URL != nil {
			t.Fatal("expected URL to be optional for offline discovery")
		}
	})

	t.Run("proto desc requires grpc mode", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "service.pb")
		os.WriteFile(path, []byte("placeholder"), 0o644)

		_, err := Parse([]string{"--proto-desc", path})
		if err == nil {
			t.Fatal("expected error for proto-desc without grpc mode")
		}
		if !strings.Contains(err.Error(), "requires one of '--grpc', '--grpc-list', '--grpc-describe'") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("grpc discovery rejects request body flags", func(t *testing.T) {
		_, err := Parse([]string{"--grpc-list", "--data", "hello", "localhost:50051"})
		if err == nil {
			t.Fatal("expected error for grpc-list with data")
		}
		if !strings.Contains(err.Error(), "cannot be used together") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
