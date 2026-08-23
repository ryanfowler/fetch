package core

import (
	"bytes"
	"io"
	"os"
	"strings"
	"sync"
	"unicode/utf8"
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

// NewWriter returns a printer with the same color policy as p and a different
// output writer. It is useful for streaming formatters that must write through
// an intermediate sink, such as a pager, without buffering the response.
func (p *Printer) NewWriter(w io.Writer) *Printer {
	return &Printer{file: w, useColor: p.useColor}
}

// NewBoundedWriter returns a printer that accepts at most max bytes in total.
// Writes after the limit are discarded and Err reports the limit error. It is
// useful for formatters that must materialize output before appending it
// atomically to another printer.
func (p *Printer) NewBoundedWriter(w io.Writer, max int64, subsystem string) *Printer {
	return &Printer{
		file:      w,
		useColor:  p.useColor,
		maxBytes:  max,
		bounded:   true,
		limitName: subsystem,
	}
}

// Printer allows for writing data with optional ANSI escape sequences based on
// the color settings for a target.
type Printer struct {
	file       io.Writer
	buf        bytes.Buffer
	useColor   bool
	maxBytes   int64
	bounded    bool
	limitError error
	limitName  string
	accepted   int64
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

// TestPrinter returns a Printer suitable for testing. All output, including
// flushed data, is captured and accessible via Bytes.
func TestPrinter(useColor bool) *Printer {
	return &Printer{file: &lockedBuffer{}, useColor: useColor}
}

// lockedBuffer is a goroutine-safe bytes.Buffer used as the flush target in
// test printers so that Bytes can return the combined buffered + flushed data.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (p *Printer) reserve(n int) bool {
	if p.limitError != nil {
		return false
	}
	if !p.bounded {
		return true
	}
	if n < 0 || int64(n) > p.maxBytes-p.accepted {
		p.limitError = LimitError{Subsystem: p.limitName, Limit: p.maxBytes}
		return false
	}
	p.accepted += int64(n)
	return true
}

// Err returns the first limit error recorded by a bounded printer.
func (p *Printer) Err() error {
	return p.limitError
}

func (lb *lockedBuffer) Write(p []byte) (int, error) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	return lb.buf.Write(p)
}

// Set writes the provided Sequence.
func (p *Printer) Set(s Sequence) {
	if !p.useColor || !p.reserve(len(string(s))+3) {
		return
	}
	p.buf.WriteString(escape)
	p.buf.WriteByte('[')
	p.buf.WriteString(string(s))
	p.buf.WriteByte('m')
}

// Reset resets any active escape sequences.
func (p *Printer) Reset() {
	p.Set(reset)
}

// Flush writes any buffered data to the underlying file.
func (p *Printer) Flush() error {
	data := p.buf.Bytes()
	n, err := p.file.Write(data)
	p.buf.Reset()
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}

// Discard clears the buffer without writing to the underlying file. A bounded
// printer also starts a new bounded transaction.
func (p *Printer) Discard() {
	p.buf.Reset()
	if p.bounded {
		p.accepted = 0
		p.limitError = nil
	}
}

// Bytes returns the current contents of the buffer. For test printers created
// with TestPrinter, this also includes previously flushed data.
func (p *Printer) Bytes() []byte {
	if lb, ok := p.file.(*lockedBuffer); ok {
		lb.mu.Lock()
		flushed := lb.buf.Bytes()
		lb.mu.Unlock()
		if len(flushed) > 0 {
			return append(flushed, p.buf.Bytes()...)
		}
	}
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
	if !p.reserve(len(b)) {
		return 0, p.limitError
	}
	return p.buf.Write(b)
}

// WriteString writes the provided string to the buffer.
func (p *Printer) WriteString(s string) (int, error) {
	if !p.reserve(len(s)) {
		return 0, p.limitError
	}
	return p.buf.WriteString(s)
}

// WriteRune writes the provided rune to the buffer.
func (p *Printer) WriteRune(r rune) (int, error) {
	n := utf8.RuneLen(r)
	if n < 0 {
		n = utf8.RuneLen(utf8.RuneError)
	}
	if !p.reserve(n) {
		return 0, p.limitError
	}
	return p.buf.WriteRune(r)
}

// WriteRequestPrefix writes a dim "> " prefix for request lines.
func (p *Printer) WriteRequestPrefix() {
	p.Set(Dim)
	p.WriteString("> ")
	p.Reset()
}

// WriteResponsePrefix writes a dim "< " prefix for response lines.
func (p *Printer) WriteResponsePrefix() {
	p.Set(Dim)
	p.WriteString("< ")
	p.Reset()
}

// WriteInfoPrefix writes a dim "* " prefix for informational lines.
func (p *Printer) WriteInfoPrefix() {
	p.Set(Dim)
	p.WriteString("* ")
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
		p.WriteString(TerminalSafeText(err.Error()))
	}
	p.WriteString("\n")
}

// WriteWarningMsg writes the provided warning msg to the printer.
func WriteWarningMsg(p *Printer, msg string) {
	_ = NewWarningWriter(p, false).Write(msg)
}

// WriteWarningMsgIf writes a warning unless silent mode is enabled.
func WriteWarningMsgIf(p *Printer, msg string, silent bool) {
	_ = NewWarningWriter(p, silent).Write(msg)
}

func writeWarningMsg(p *Printer, msg string) error {
	msg = strings.TrimRight(msg, "\r\n")
	p.Set(Bold)
	p.Set(Yellow)
	p.WriteString("warning")
	p.Reset()
	p.WriteString(": ")

	p.WriteString(TerminalSafeText(msg))
	p.WriteString("\n")
	return p.Flush()
}

// WriteInfoMsg writes the provided info msg to the printer.
func WriteInfoMsg(p *Printer, msg string) {
	p.Set(Bold)
	p.Set(Green)
	p.WriteString("info")
	p.Reset()
	p.WriteString(": ")

	p.WriteString(TerminalSafeText(msg))
	p.WriteString("\n")
	p.Flush()
}
