package cli

import (
	"slices"
	"testing"
)

func TestFromCurlHeaderReplacesConvenienceHeader(t *testing.T) {
	tests := []struct {
		command string
		want    []string
	}{
		{`curl -b a=1 -b b=2 https://example.com`, []string{"Cookie: a=1; b=2"}},
		{`curl -H 'cookie: y=2' -b x=1 https://example.com`, []string{"cookie: y=2"}},
		{`curl -A agent -H 'User-Agent: custom' https://example.com`, []string{"User-Agent: custom"}},
		{`curl -e https://r.example -H 'Referer: https://h.example' https://example.com`, []string{"Referer: https://h.example"}},
		{`curl -A agent -e https://r.example https://example.com`, []string{"User-Agent: agent", "Referer: https://r.example"}},
	}
	for _, tt := range tests {
		app, err := Parse([]string{"--from-curl", tt.command})
		if err != nil {
			t.Fatalf("Parse(%q) error = %v", tt.command, err)
		}
		var got []string
		for _, h := range app.Cfg.Headers {
			got = append(got, h.Key+": "+h.Val)
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("%s: headers = %q, want %q", tt.command, got, tt.want)
		}
	}
}
