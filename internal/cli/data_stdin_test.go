package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRecordsDataFromStdin(t *testing.T) {
	file := filepath.Join(t.TempDir(), "body.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		args []string
		want bool
	}{
		{[]string{"-d", "@-", "ws://example.com"}, true},
		{[]string{"-j", "@-", "ws://example.com"}, true},
		{[]string{"-x", "@-", "https://example.com"}, true},
		{[]string{"-d", "inline", "ws://example.com"}, false},
		{[]string{"-d", "@" + file, "ws://example.com"}, false},
		{[]string{"-d", "@-", "-d", "inline", "ws://example.com"}, false},
		{[]string{"--from-curl", "curl -d @- ws://example.com"}, true},
		{[]string{"--from-curl", "curl --data-binary @- ws://example.com"}, true},
		{[]string{"--from-curl", "curl -T - https://example.com/"}, true},
		{[]string{"--from-curl", "curl -T '" + file + "' https://example.com/"}, false},
	}
	for _, tt := range tests {
		app, err := Parse(tt.args)
		if err != nil {
			t.Fatalf("Parse(%q) error = %v", tt.args, err)
		}
		if f, ok := app.Data.(*os.File); ok && f != os.Stdin {
			f.Close()
		}
		if app.DataFromStdin != tt.want {
			t.Errorf("Parse(%q): DataFromStdin = %t, want %t", tt.args, app.DataFromStdin, tt.want)
		}
	}
}

func TestParseRejectsInteractiveWebSocketWithStdinBody(t *testing.T) {
	_, err := Parse([]string{"--ws-interactive", "on", "-d", "@-", "ws://example.com"})
	if err == nil || !strings.Contains(err.Error(), "initial message from stdin") {
		t.Fatalf("Parse() error = %v, want the stdin conflict", err)
	}
	if _, err := Parse([]string{"--ws-interactive", "off", "-d", "@-", "ws://example.com"}); err != nil {
		t.Fatalf("Parse() with off error = %v", err)
	}
}
