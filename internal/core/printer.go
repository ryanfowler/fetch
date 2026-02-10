package core

import (
	"bytes"
	"io"
	"os"
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
func NewHandle(c Color) *Handle {
	return &Handle{
		stderr: newPrinter(os.Stderr, IsStderrTerm, c),
		stdout: newPrinter(os.Stdout, IsStdoutTerm, c),
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

func newPrinter(file *os.File, isTerm bool, c Color) *Printer {
	var useColor bool
	switch c {
	case ColorOn:
		useColor = true
	case ColorOff:
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

// Discard clears the buffer without writing to the underlying file.
func (p *Printer) Discard() {
	p.buf.Reset()
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

// WriteRequestPrefix writes a dim "> " prefix for request lines.
func (p *Printer) WriteRequestPrefix() {
	p.Set(Dim)
	p.buf.WriteString("> ")
	p.Reset()
}

// WriteResponsePrefix writes a dim "< " prefix for response lines.
func (p *Printer) WriteResponsePrefix() {
	p.Set(Dim)
	p.buf.WriteString("< ")
	p.Reset()
}

// WriteInfoPrefix writes a dim "* " prefix for informational lines.
func (p *Printer) WriteInfoPrefix() {
	p.Set(Dim)
	p.buf.WriteString("* ")
	p.Reset()
}

// WriteErrorMsg writes the provided error to the printer.
func WriteErrorMsg(p *Printer, err error) {
	WriteErrorMsgNoFlush(p, err)
	p.Flush()
}

// WriteErrorMsgNoFlush writes the provided error msg to the printer, but does
// not flush the printer.
func WriteErrorMsgNoFlush(p *Printer, err error) {
	p.Set(Red)
	p.Set(Bold)
	p.WriteString("error")
	p.Reset()
	p.WriteString(": ")

	if pt, ok := err.(PrinterTo); ok {
		pt.PrintTo(p)
	} else {
		p.WriteString(err.Error())
	}
	p.WriteString("\n")
}

// WriteWarningMsg writes the provided warning msg to the printer.
func WriteWarningMsg(p *Printer, msg string) {
	p.Set(Bold)
	p.Set(Yellow)
	p.WriteString("warning")
	p.Reset()
	p.WriteString(": ")

	p.WriteString(msg)
	p.WriteString("\n")
	p.Flush()
}

// WriteInfoMsg writes the provided info msg to the printer.
func WriteInfoMsg(p *Printer, msg string) {
	p.Set(Bold)
	p.Set(Green)
	p.WriteString("info")
	p.Reset()
	p.WriteString(": ")

	p.WriteString(msg)
	p.WriteString("\n")
	p.Flush()
}
