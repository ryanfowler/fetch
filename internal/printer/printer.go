package printer

import (
	"bytes"
	"io"
	"os"

	"github.com/ryanfowler/fetch/internal/core"
)

// Sequence represents an ANSI escape sequence.
type Sequence string

const (
	escape = "\x1b"
	reset  = "0"

	Bold      Sequence = "1"
	Dim       Sequence = "2"
	Italic    Sequence = "3"
	Underline Sequence = "4"

	Black   Sequence = "30"
	Red     Sequence = "31"
	Green   Sequence = "32"
	Yellow  Sequence = "33"
	Blue    Sequence = "34"
	Magenta Sequence = "35"
	Cyan    Sequence = "36"
	White   Sequence = "37"
	Default Sequence = "39"
)

// PrinterTo represents the interface for printing to a Printer.
type PrinterTo interface {
	PrintTo(*Printer)
}

// Handle represents a handle for stderr and stdout Printers.
type Handle struct {
	stderr *Printer
	stdout *Printer
}

// NewHandle returns a new Handle given the provided color configuration.
func NewHandle(c core.Color) *Handle {
	return &Handle{
		stderr: newPrinter(os.Stderr, core.IsStderrTerm, c),
		stdout: newPrinter(os.Stdout, core.IsStdoutTerm, c),
	}
}

// Stderr returns the Printer for stderr.
func (h *Handle) Stderr() *Printer {
	return h.stderr
}

// Stdout returns the Printer for stdout.
func (h *Handle) Stdout() *Printer {
	return h.stdout
}

// Printer allows for writing data with optional ANSI escape sequences based on
// the color settings for a target.
type Printer struct {
	file     *os.File
	buf      bytes.Buffer
	useColor bool
}

func newPrinter(file *os.File, isTerm bool, c core.Color) *Printer {
	var useColor bool
	switch c {
	case core.ColorOn:
		useColor = true
	case core.ColorOff:
		useColor = false
	default:
		// By default, set color settings based on whether the file is
		// a terminal.
		useColor = isTerm
	}
	return &Printer{file: file, useColor: useColor}
}

// Set writes the provided Sequence.
func (p *Printer) Set(s Sequence) {
	if p.useColor {
		p.buf.WriteString(escape)
		p.buf.WriteByte('[')
		p.buf.WriteString(string(s))
		p.buf.WriteByte('m')
	}
}

// Reset resets any active escape sequences.
func (p *Printer) Reset() {
	p.Set(reset)
}

// Flush writes any buffered data to the underlying file.
func (p *Printer) Flush() error {
	_, err := p.file.Write(p.buf.Bytes())
	p.buf.Reset()
	return err
}

// Bytes returns the current contents of the buffer.
func (p *Printer) Bytes() []byte {
	return p.buf.Bytes()
}

// Read reads from the buffer.
func (p *Printer) Read(b []byte) (int, error) {
	return p.buf.Read(b)
}

// WriteTo writes the buffered data to the provided io.Writer.
func (p *Printer) WriteTo(w io.Writer) (int64, error) {
	return p.buf.WriteTo(w)
}

// Write writes the provided data to the buffer.
func (p *Printer) Write(b []byte) (int, error) {
	return p.buf.Write(b)
}

// WriteString writes the provided string to the buffer.
func (p *Printer) WriteString(s string) (int, error) {
	return p.buf.WriteString(s)
}

// WriteRune writes the provided rune to the buffer.
func (p *Printer) WriteRune(r rune) (int, error) {
	return p.buf.WriteRune(r)
}
