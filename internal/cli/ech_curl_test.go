package cli

import (
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestFromCurlECHTranslation(t *testing.T) {
	for _, test := range []struct {
		value string
		want  core.ECHMode
	}{
		{"hard", core.ECHOn},
		{"true", core.ECHOn},
		{"auto", core.ECHAuto},
		{"false", core.ECHOff},
	} {
		app, err := Parse([]string{"--from-curl", "curl --ech " + test.value + " https://example.com"})
		if err != nil {
			t.Fatalf("Parse(%q): %v", test.value, err)
		}
		if app.Cfg.ECH != test.want {
			t.Errorf("ECH for %q = %v, want %v", test.value, app.Cfg.ECH, test.want)
		}
	}
}
