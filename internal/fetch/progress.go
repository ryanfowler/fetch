package fetch

import (
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/progress"
)

// progressBar wraps a progress.Bar with fetch-specific close behavior
// (native progress emission and download summary).
type progressBar struct {
	bar     *progress.Bar
	printer *core.Printer
}

func newProgressBar(r io.Reader, p *core.Printer, totalBytes int64) *progressBar {
	var onRender func(int64)
	if core.IsStdoutTerm {
		onRender = func(pct int64) {
			emitProgress(1, int(pct), p)
		}
	}
	return &progressBar{
		bar:     progress.NewBar(r, p, totalBytes, onRender),
		printer: p,
	}
}

func (pb *progressBar) Read(p []byte) (int, error) {
	return pb.bar.Read(p)
}

func (pb *progressBar) Close(path string, err error) {
	bytesRead, elapsed := pb.bar.Stop()

	p := pb.printer

	// Clear native progress state.
	if core.IsStdoutTerm {
		emitProgress(0, 0, p)
	}

	if err != nil {
		// An error will be printed after this.
		p.WriteString("\n\n")
	} else {
		// Replace the progress bar with a summary.
		writeFinalProgress(p, bytesRead, elapsed, 32, path)
	}
	p.Flush()
}

// progressSpinner wraps a progress.Spinner with fetch-specific close behavior
// (native progress emission and download summary).
type progressSpinner struct {
	spinner *progress.Spinner
	printer *core.Printer
}

func newProgressSpinner(r io.Reader, p *core.Printer) *progressSpinner {
	var onStart func()
	if core.IsStdoutTerm {
		onStart = func() {
			emitProgress(3, 0, p)
		}
	}
	return &progressSpinner{
		spinner: progress.NewSpinner(r, p, onStart),
		printer: p,
	}
}

func (ps *progressSpinner) Read(p []byte) (int, error) {
	return ps.spinner.Read(p)
}

func (ps *progressSpinner) Close(path string, err error) {
	bytesRead, elapsed := ps.spinner.Stop()

	p := ps.printer

	// Clear native progress state.
	if core.IsStdoutTerm {
		emitProgress(0, 0, p)
	}

	if err != nil {
		p.WriteString("\n\n")
	} else {
		// Replace the progress spinner with a summary.
		writeFinalProgress(p, bytesRead, elapsed, 20, path)
	}
	p.Flush()
}

type progressStatic struct {
	r         io.Reader
	printer   *core.Printer
	bytesRead int64
	start     time.Time
}

func newProgressStatic(r io.Reader, p *core.Printer) *progressStatic {
	return &progressStatic{
		r:       r,
		printer: p,
		start:   time.Now(),
	}
}

func (ps *progressStatic) Read(p []byte) (int, error) {
	n, err := ps.r.Read(p)
	ps.bytesRead += int64(n)
	return n, err
}

func (ps *progressStatic) Close(path string, err error) {
	if err != nil {
		return
	}

	dur := time.Since(ps.start)
	writeFinalProgress(ps.printer, ps.bytesRead, dur, -1, path)
	ps.printer.Flush()
}

func formatDuration(d time.Duration) string {
	switch {
	case d < time.Second:
		return fmt.Sprintf("%.1fms", float64(d)/float64(time.Millisecond))
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", float64(d)/float64(time.Second))
	case d < time.Hour:
		return fmt.Sprintf("%.1fm", float64(d)/float64(time.Minute))
	default:
		return fmt.Sprintf("%.1fh", float64(d)/float64(time.Hour))
	}
}

func writeFinalProgress(p *core.Printer, bytesRead int64, dur time.Duration, toClear int, path string) {
	if toClear >= 0 {
		p.WriteString("\r")
	}

	p.WriteString("Downloaded ")
	p.Set(core.Bold)
	p.WriteString(progress.FormatSize(bytesRead))
	p.Reset()
	p.WriteString(" in ")
	p.Set(core.Italic)
	p.WriteString(formatDuration(dur))
	p.Reset()

	p.WriteString(" to '")
	p.Set(core.Dim)
	p.WriteString(path)
	p.Reset()
	p.WriteString("'")

	for range toClear - len(path) {
		p.WriteString(" ")
	}
	p.WriteString("\n")

}

func emitProgress(state, percent int, p *core.Printer) {
	if percent < 0 {
		percent = 0
	} else if percent > 100 {
		percent = 100
	}

	p.WriteString("\x1b]9;4;")
	p.WriteString(strconv.Itoa(state))
	p.WriteString(";")
	p.WriteString(strconv.Itoa(percent))
	p.WriteString("\x1b\\")
}
