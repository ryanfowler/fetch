package cli

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ryanfowler/fetch/internal/core"
)

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
