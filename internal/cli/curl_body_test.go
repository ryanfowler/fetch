package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/body"
)

func readImportedBody(t *testing.T, command string) string {
	t.Helper()
	app, err := Parse([]string{"--from-curl", "curl " + command + " https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := app.Data.(io.Closer); ok {
		defer closer.Close()
	}
	data, err := io.ReadAll(app.Data)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestFromCurlBodyOptionSemantics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payload.bin")
	payload := "a\r\nb\x00c\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ command, want string }{
		{"-d '@" + path + "'", "abc"},
		{"--data '@" + path + "'", "abc"},
		{"--data-ascii '@" + path + "'", "abc"},
		{"--data-binary '@" + path + "'", payload},
		{"--json '@" + path + "'", payload},
		{"--data '@" + path + "' --data suffix", "abc&suffix"},
		{"--data '@" + path + "' --data-binary '@" + path + "'", "abc&" + payload},
		{"--json '@" + path + "' --json suffix", payload + "suffix"},
		{`--json '{"a":' --json '1}'`, `{"a":1}`},
		{`--json first --data second --json third`, "first&secondthird"},
		{`--data first --json second --data third`, "firstsecond&third"},
		{`--data '' --data second`, "second"},
		{`--data first --data '' --data third`, "first&&third"},
		{`--json '' --json second`, "second"},
		{"--data 'a\r\nb'", "a\r\nb"},
		{`--data-raw '@not-a-file'`, "@not-a-file"},
		{`--data-urlencode 'email=user@example.com'`, "email=user%40example.com"},
		{`--data-urlencode 'hello world'`, "hello+world"},
		{`--data-urlencode 'key=hello world'`, "key=hello+world"},
		{`--data-urlencode '=hello world'`, "hello+world"},
		{"--data-urlencode '@" + path + "'", "a%0D%0Ab%00c%0A"},
		{"--data-urlencode 'field@" + path + "'", "field=a%0D%0Ab%00c%0A"},
	} {
		t.Run(tt.command, func(t *testing.T) {
			if got := readImportedBody(t, tt.command); got != tt.want {
				t.Fatalf("body = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFromCurlTextFileBodyRemainsReplayable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "body.txt")
	if err := os.WriteFile(path, []byte("a\r\nb\x00c\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	app, err := Parse([]string{"--from-curl", "curl --data '@" + path + "' https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	source, ok := app.Data.(*body.Body)
	if !ok || !source.Replayable() {
		t.Fatalf("body = %T, want replayable transformed source", app.Data)
	}
	defer source.Close()
	preview, err := source.Preview(2)
	if err != nil || string(preview.Data) != "ab" || !preview.Truncated {
		t.Fatalf("preview = %+v, error = %v", preview, err)
	}
	for range 2 {
		rc, err := source.Replay()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil || string(data) != "abc" {
			t.Fatalf("replay = %q, error = %v", data, err)
		}
	}
	data, err := io.ReadAll(source)
	if err != nil || string(data) != "abc" {
		t.Fatalf("body after preview/replay = %q, error = %v", data, err)
	}
}

func TestFromCurlStdinBodyOptionSemantics(t *testing.T) {
	for _, tt := range []struct{ command, want string }{
		{"-d @-", "abc"},
		{"--data-ascii @-", "abc"},
		{"--data-binary @-", "a\r\nb\x00c\n"},
		{"--json @-", "a\r\nb\x00c\n"},
		{"--data @- --data suffix", "abc&suffix"},
		{"--json @- --json suffix", "a\r\nb\x00c\nsuffix"},
		{"--json @- --json @-", "a\r\nb\x00c\n"},
		{"--data @- --data @-", "abc&"},
	} {
		t.Run(tt.command, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "stdin")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if _, err := io.Copy(f, strings.NewReader("a\r\nb\x00c\n")); err != nil {
				t.Fatal(err)
			}
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			original := os.Stdin
			os.Stdin = f
			defer func() { os.Stdin = original }()
			if got := readImportedBody(t, tt.command); got != tt.want {
				t.Fatalf("body = %q, want %q", got, tt.want)
			}
		})
	}
}
