package format

import (
	"io"
	"strings"

	"github.com/ryanfowler/fetch/internal/core"
)

var indentSpaces = strings.Repeat(" ", 2*core.MaxFormatterNestingDepth)

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
