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

func TestFromCurlGetData(t *testing.T) {
	t.Run("-d @file expands contents into query", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "payload.txt")
		os.WriteFile(path, []byte("q=search&limit=10"), 0o644)

		app, err := Parse([]string{
			"--from-curl",
			`curl -G -d '@` + path + `' https://example.com`,
		})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if app.Data != nil {
			t.Fatal("expected no request body for curl -G")
		}
		if app.URL.RawQuery != "q=search&limit=10" {
			t.Fatalf("RawQuery = %q, want %q", app.URL.RawQuery, "q=search&limit=10")
		}
	})

	t.Run("--data-urlencode name@file expands and encodes contents into query", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "data.txt")
		os.WriteFile(path, []byte("value with spaces&x=1"), 0o644)

		app, err := Parse([]string{
			"--from-curl",
			`curl -G --data-urlencode 'field@` + path + `' https://example.com?existing=1`,
		})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if app.Data != nil {
			t.Fatal("expected no request body for curl -G")
		}
		want := "existing=1&field=value+with+spaces%26x%3D1"
		if app.URL.RawQuery != want {
			t.Fatalf("RawQuery = %q, want %q", app.URL.RawQuery, want)
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

func TestFromCurlMultipartFileValidation(t *testing.T) {
	t.Run("accepts existing file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "payload.txt")
		if err := os.WriteFile(path, []byte("file content"), 0o644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		app, err := Parse([]string{
			"--from-curl",
			`curl -F 'file=@` + path + `' https://example.com`,
		})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if len(app.Multipart) != 1 {
			t.Fatalf("len(Multipart) = %d, want 1", len(app.Multipart))
		}
		if app.Multipart[0].Key != "file" || app.Multipart[0].Val != "@"+path {
			t.Fatalf("Multipart[0] = %#v, want file=@%s", app.Multipart[0], path)
		}
	})

	t.Run("rejects missing file during parse", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing.txt")
		_, err := Parse([]string{
			"--from-curl",
			`curl -F 'file=@` + path + `' https://example.com`,
		})
		if err == nil {
			t.Fatal("expected missing file error, got nil")
		}
		if !strings.Contains(err.Error(), "file does not exist: '"+path+"'") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("rejects directory during parse", func(t *testing.T) {
		path := t.TempDir()
		_, err := Parse([]string{
			"--from-curl",
			`curl -F 'file=@` + path + `' https://example.com`,
		})
		if err == nil {
			t.Fatal("expected directory error, got nil")
		}
		if !strings.Contains(err.Error(), "file is a directory: '"+path+"'") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
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

func TestRangeFlag(t *testing.T) {
	t.Run("accepts unsigned byte ranges", func(t *testing.T) {
		tests := []struct {
			name string
			arg  string
			want []string
		}{
			{name: "suffix", arg: "-1023", want: []string{"-1023"}},
			{name: "open ended", arg: "1023-", want: []string{"1023-"}},
			{name: "bounded", arg: "0-1023", want: []string{"0-1023"}},
			{name: "trimmed", arg: " 5 - 10 ", want: []string{"5-10"}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				app, err := Parse([]string{"--range", tt.arg})
				if err != nil {
					t.Fatalf("Parse() error = %v", err)
				}
				if len(app.Range) != len(tt.want) {
					t.Fatalf("Range = %v, want %v", app.Range, tt.want)
				}
				for i := range tt.want {
					if app.Range[i] != tt.want[i] {
						t.Fatalf("Range = %v, want %v", app.Range, tt.want)
					}
				}
			})
		}
	})

	t.Run("rejects signed or malformed byte ranges", func(t *testing.T) {
		tests := []string{
			"bad",
			"-",
			"5--1",
			"+5-10",
			"5-+10",
			"--1",
			"-+1",
		}

		for _, arg := range tests {
			t.Run(arg, func(t *testing.T) {
				_, err := Parse([]string{"--range", arg})
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), "invalid") {
					t.Fatalf("unexpected error: %v", err)
				}
			})
		}
	})

	t.Run("validates ranges from curl commands", func(t *testing.T) {
		app, err := Parse([]string{"--from-curl", "curl -r 0-1023 https://example.com/file"})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if len(app.Range) != 1 || app.Range[0] != "0-1023" {
			t.Fatalf("Range = %v, want [0-1023]", app.Range)
		}

		_, err = Parse([]string{"--from-curl", "curl -r 5--1 https://example.com/file"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "invalid range end") {
			t.Fatalf("unexpected error: %v", err)
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

func TestDigestFlag(t *testing.T) {
	t.Run("digest auth parsing", func(t *testing.T) {
		app, err := Parse([]string{"--digest", "user:pass", "http://example.com"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if app.Digest == nil {
			t.Fatal("expected Digest to be set")
		}
		if app.Digest.Key != "user" || app.Digest.Val != "pass" {
			t.Fatalf("unexpected digest credentials: %q:%q", app.Digest.Key, app.Digest.Val)
		}
	})

	t.Run("digest auth invalid format", func(t *testing.T) {
		_, err := Parse([]string{"--digest", "nocolon", "http://example.com"})
		if err == nil {
			t.Fatal("expected error for invalid digest format")
		}
		if !strings.Contains(err.Error(), "format must be") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("digest conflicts with basic", func(t *testing.T) {
		_, err := Parse([]string{"--digest", "user:pass", "--basic", "user:pass", "http://example.com"})
		if err == nil {
			t.Fatal("expected error for conflicting auth flags")
		}
		if !strings.Contains(err.Error(), "cannot be used together") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
