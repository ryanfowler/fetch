package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFromCurlRejectsConflictingOptions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upload.txt")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		command string
		want    string
	}{
		// The body would be a=1, with a multipart Content-Type.
		{command: "curl -d a=1 -F b=2 https://example.com", want: "-F/--form"},
		// The form would be dropped, and a=1 sent in the query.
		{command: "curl -d a=1 -G -F b=2 https://example.com", want: "-F/--form"},
		{command: "curl -G -F b=2 https://example.com", want: "-G/--get"},
		{command: "curl -T " + path + " -F b=2 https://example.com", want: "-T/--upload-file"},
		{command: "curl -o out.txt -O https://example.com/file", want: "-O/--remote-name"},
	} {
		t.Run(test.command, func(t *testing.T) {
			_, err := Parse([]string{"--from-curl", test.command})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Parse() error = %v, want a conflict naming %s", err, test.want)
			}
		})
	}
}

func TestFromCurlAllowsCombinationsThatCurlAccepts(t *testing.T) {
	for _, command := range []string{
		"curl -d a=1 -d b=2 https://example.com",
		"curl -F a=1 -F b=2 https://example.com",
		"curl --json '{}' -d x https://example.com",
		"curl -d a=1 -G https://example.com",
		"curl -u user:pass -H 'X-Test: 1' https://example.com",
		"curl --digest -u user:pass https://example.com",
		"curl -O -J https://example.com/file",
		// curl ignores -J without -O.
		"curl -J https://example.com/file",
		"curl -o out.txt -J https://example.com/file",
	} {
		if _, err := Parse([]string{"--from-curl", command}); err != nil {
			t.Errorf("%s: Parse() error = %v", command, err)
		}
	}
}

func TestFromCurlUsesOneAuthorizationLikeCurl(t *testing.T) {
	// curl sends Bearer instead of Basic credentials.
	app, err := Parse([]string{"--from-curl", "curl -u a:b --oauth2-bearer tok https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if app.Basic != nil || app.Bearer != "tok" {
		t.Fatalf("Basic set = %t, Bearer = %q; want only the bearer token", app.Basic != nil, app.Bearer)
	}
	// curl signs with AWS and ignores the bearer token.
	app, err = Parse([]string{"--from-curl", "curl --aws-sigv4 aws:amz:us-east-1:s3 --oauth2-bearer tok https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if app.Bearer != "" || app.AWSSigv4 == nil {
		t.Fatalf("Bearer = %q, AWS set = %t; want only AWS signing", app.Bearer, app.AWSSigv4 != nil)
	}
	if app.OptionWasExplicit("bearer") {
		t.Fatal("bearer is recorded as an explicit option")
	}
}
