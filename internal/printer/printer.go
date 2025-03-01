package printer

import (
	"bytes"
	"io"
	"os"

	"github.com/ryanfowler/fetch/internal/core"
)

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

type PrinterTo interface {
	PrintTo(*Printer)
}

type Handle struct {
	stderr *Printer
	stdout *Printer
}

func NewHandle(c core.Color) *Handle {
	return &Handle{
		stderr: newPrinter(os.Stderr, core.IsStderrTerm, c),
		stdout: newPrinter(os.Stdout, core.IsStdoutTerm, c),
	}
}

func (h *Handle) Stderr() *Printer {
	return h.stderr
}

func (h *Handle) Stdout() *Printer {
	return h.stdout
}

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
		useColor = isTerm
	}
	return &Printer{file: file, useColor: useColor}
}

func (p *Printer) Set(s Sequence) {
	if p.useColor {
		p.buf.WriteString(escape)
		p.buf.WriteByte('[')
		p.buf.WriteString(string(s))
		p.buf.WriteByte('m')
	}
}

func (p *Printer) Reset() {
	p.Set(reset)
}

func (p *Printer) Flush() error {
	_, err := p.file.Write(p.buf.Bytes())
	p.buf.Reset()
	return err
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
