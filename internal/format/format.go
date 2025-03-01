package format

import "io"

// writeIndent writes the provided number of indents to the Printer.
func writeIndent(w io.StringWriter, indent int) {
	for range indent {
		w.WriteString("  ")
	}
}
