package format

import (
	"io"
	"strings"

	"github.com/ryanfowler/fetch/internal/core"
)

var indentSpaces = strings.Repeat(" ", 2*core.MaxFormatterNestingDepth)

// spaces is a run of spaces that writeSpaces writes in slices.
var spaces = strings.Repeat(" ", 256)

// writeSpaces writes n spaces with one write per 256 spaces. It stops at the
// first write error, such as the output limit of a bounded printer.
func writeSpaces(w io.StringWriter, n int) {
	for n > 0 {
		chunk := min(n, len(spaces))
		if _, err := w.WriteString(spaces[:chunk]); err != nil {
			return
		}
		n -= chunk
	}
}

// writeIndent writes the provided number of indents to the Printer.
func writeIndent(w io.StringWriter, indent int) {
	if indent <= 0 {
		return
	}
	if indent > core.MaxFormatterNestingDepth {
		indent = core.MaxFormatterNestingDepth
	}
	_, _ = w.WriteString(indentSpaces[:2*indent])
}
