package format

import "io"

type Writer interface {
	io.Writer
	io.StringWriter
}

func writeIndent(w Writer, indent int) {
	for range indent {
		w.WriteString("  ")
	}
}
