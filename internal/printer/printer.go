package printer

import (
	"bytes"
	"io"

	"github.com/ryanfowler/fetch/internal/vars"
)

const escape = "\x1b"

type Sequence string

const (
	Bold      = "1m"
	Dim       = "2m"
	Italic    = "3m"
	Underline = "4m"

	Black   = "30m"
	Red     = "31m"
	Green   = "32m"
	Yellow  = "33m"
	Blue    = "34m"
	Magenta = "35m"
	Cyan    = "36m"
	White   = "37m"
	Default = "39m"
)

type Color int

const (
	ColorAuto Color = iota
	ColorAlways
	ColorNever
)

type Handle struct {
	stderr *Printer
	stdout *Printer
}

func NewHandle(c Color) *Handle {
	return &Handle{
		stderr: newPrinter(vars.IsStderrTerm, c),
		stdout: newPrinter(vars.IsStdoutTerm, c),
	}
}

func (h *Handle) Stderr() *Printer {
	return h.stderr
}

func (h *Handle) Stdout() *Printer {
	return h.stdout
}

type Printer struct {
	buf      bytes.Buffer
	useColor bool
}

func newPrinter(isTerm bool, c Color) *Printer {
	var useColor bool
	switch c {
	case ColorAuto:
		useColor = isTerm
	case ColorAlways:
		useColor = true
	case ColorNever:
		useColor = false
	}
	return &Printer{useColor: useColor}
}

func (p *Printer) Set(s Sequence) {
	if p.useColor {
		p.buf.WriteString(escape)
		p.buf.WriteByte('[')
		p.buf.WriteString(string(s))
	}
}

func (p *Printer) Reset() {
	if p.useColor {
		p.buf.WriteString(escape)
		p.buf.WriteString("[0m")
	}
}

func (p *Printer) Flush(w io.Writer) {
	w.Write(p.buf.Bytes())
	p.buf.Reset()
}

func (p *Printer) Bytes() []byte {
	return p.buf.Bytes()
}

func (p *Printer) Read(b []byte) (int, error) {
	return p.buf.Read(b)
}

func (p *Printer) WriteTo(w io.Writer) (int64, error) {
	return p.buf.WriteTo(w)
}

func (p *Printer) Write(b []byte) (int, error) {
	return p.buf.Write(b)
}

func (p *Printer) WriteString(s string) (int, error) {
	return p.buf.WriteString(s)
}

func (p *Printer) WriteRune(r rune) (int, error) {
	return p.buf.WriteRune(r)
}
