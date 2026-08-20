package core

import "strings"

// WarningWriter is the shared warning path for operations that may emit
// warnings alongside streamed output. It suppresses nonessential warnings in
// silent mode and guarantees one trailing newline per warning.
type WarningWriter struct {
	p      *Printer
	silent bool
}

// NewWarningWriter creates a warning writer for p.
func NewWarningWriter(p *Printer, silent bool) *WarningWriter {
	return &WarningWriter{p: p, silent: silent}
}

// Write emits a terminal-safe warning unless silent mode is enabled.
func (w *WarningWriter) Write(msg string) error {
	if w == nil || w.silent || w.p == nil {
		return nil
	}
	msg = strings.TrimRight(msg, "\r\n")
	if msg == "" {
		return nil
	}
	return writeWarningMsg(w.p, msg)
}

// BeforeBody separates diagnostics from body output when both are written to
// the same presentation stream.
func (w *WarningWriter) BeforeBody() error {
	if w == nil || w.silent || w.p == nil {
		return nil
	}
	w.p.WriteString("\n")
	return w.p.Flush()
}

// AfterBody terminates a body line before a following warning or diagnostic.
func (w *WarningWriter) AfterBody() error {
	if w == nil || w.silent || w.p == nil {
		return nil
	}
	w.p.WriteString("\n")
	return w.p.Flush()
}
