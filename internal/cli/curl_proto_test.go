package cli

import (
	"slices"
	"strings"
	"testing"
)

func TestFromCurlProtoRestrictsRequestAndRedirects(t *testing.T) {
	tests := []struct {
		command   string
		wantErr   string
		redirects []string
	}{
		{command: "curl --proto -all,https http://example.com", wantErr: "protocol 'http' not allowed"},
		{command: "curl --proto =https -L https://example.com", redirects: []string{"https"}},
		{command: "curl --proto -all,https -L https://example.com", redirects: []string{"https"}},
		{command: "curl --proto =http http://example.com", redirects: []string{"http"}},
		{command: "curl --proto -all https://example.com", wantErr: "protocol 'https' not allowed"},
		{command: "curl --proto =wss wss://example.com", redirects: []string{}},
		{command: "curl --proto =https wss://example.com", wantErr: "protocol 'wss' not allowed"},
		{command: "curl --proto =,https https://example.com", wantErr: "unrecognized protocol"},
		{command: "curl --proto all https://example.com"},
	}
	for _, test := range tests {
		t.Run(test.command, func(t *testing.T) {
			app, err := Parse([]string{"--from-curl", test.command})
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("Parse() error = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if !slices.Equal(app.RedirectSchemes, test.redirects) {
				t.Fatalf("RedirectSchemes = %v, want %v", app.RedirectSchemes, test.redirects)
			}
		})
	}
}
