package fetch

import (
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

// uploadReadCloser combines a progress io.Reader with the original body's
// io.Closer to satisfy io.ReadCloser for req.Body.
type uploadReadCloser struct {
	io.Reader
	closer io.Closer
}

func (u *uploadReadCloser) Close() error {
	return u.closer.Close()
}

// uploadProgressBar wraps an io.Reader to display an upload progress bar on
// stderr. When uploading is complete, the Close method MUST be called.
type uploadProgressBar struct {
	r          io.Reader
	printer    *core.Printer
	bytesRead  int64
	totalBytes int64
	chRead     chan int64
	start      time.Time
	wg         sync.WaitGroup
}

func newUploadProgressBar(r io.Reader, p *core.Printer, totalBytes int64) *uploadProgressBar {
	pb := &uploadProgressBar{
		r:          r,
		printer:    p,
		totalBytes: totalBytes,
		chRead:     make(chan int64, 1),
		start:      time.Now(),
	}
	pb.wg.Add(1)
	go pb.renderLoop()
	return pb
}

func (pb *uploadProgressBar) Read(p []byte) (int, error) {
	n, err := pb.r.Read(p)
	if n > 0 {
		pb.chRead <- int64(n)
	}
	return n, err
}

func (pb *uploadProgressBar) Close(err error) {
	close(pb.chRead)
	pb.wg.Wait()

	p := pb.printer

	if core.IsStdoutTerm {
		emitProgress(0, 0, p)
	}

	if err != nil {
		p.WriteString("\n\n")
	} else {
		writeUploadFinalProgress(p, pb.bytesRead, time.Since(pb.start), 32)
	}
	p.Flush()
}

func (pb *uploadProgressBar) renderLoop() {
	defer pb.wg.Done()

	lastUpdateTime := pb.start
	var chTimeout <-chan time.Time
	for {
		select {
		case <-chTimeout:
			chTimeout = nil
		case n, ok := <-pb.chRead:
			if !ok {
				pb.render()
				return
			}
			pb.bytesRead += n

			if chTimeout != nil {
				continue
			}

			now := time.Now()
			dur := lastUpdateTime.Add(100 * time.Millisecond).Sub(now)
			if dur > 0 {
				chTimeout = time.After(dur)
				continue
			}
			lastUpdateTime = now
		}

		pb.render()
	}
}

func (pb *uploadProgressBar) render() {
	const barWidth = 30
	percentage := pb.bytesRead * 100 / pb.totalBytes
	completedWidth := min(barWidth*percentage/100, barWidth)

	p := pb.printer

	if core.IsStdoutTerm {
		emitProgress(1, int(percentage), p)
	}

	p.WriteString("\r")

	p.Set(core.Bold)
	p.WriteString("[")
	p.Set(core.Green)
	for range completedWidth {
		p.WriteString("=")
	}
	p.Reset()
	for range barWidth - completedWidth {
		p.WriteString(" ")
	}
	p.Set(core.Bold)
	p.WriteString("] ")

	pctStr := strconv.FormatInt(percentage, 10)
	for i := len(pctStr); i < 3; i++ {
		p.WriteString(" ")
	}
	p.WriteString(pctStr)
	p.WriteString("%")
	p.Reset()

	p.WriteString(" (")
	size := formatSize(pb.bytesRead)
	for range 7 - len(size) {
		p.WriteString(" ")
	}
	p.WriteString(size)
	p.WriteString(" / ")
	p.WriteString(formatSize(pb.totalBytes))
	p.WriteString(")")
	p.Flush()
}

// uploadProgressSpinner wraps an io.Reader to display an upload progress
// spinner on stderr. When uploading is complete, the Close method MUST be
// called.
type uploadProgressSpinner struct {
	r         io.Reader
	printer   *core.Printer
	bytesRead int64
	chRead    chan int64
	position  int64
	wg        sync.WaitGroup
	start     time.Time
}

func newUploadProgressSpinner(r io.Reader, p *core.Printer) *uploadProgressSpinner {
	ps := &uploadProgressSpinner{
		r:       r,
		printer: p,
		chRead:  make(chan int64, 1),
		start:   time.Now(),
	}
	ps.wg.Add(1)
	go ps.renderLoop()
	return ps
}

func (ps *uploadProgressSpinner) Read(p []byte) (int, error) {
	n, err := ps.r.Read(p)
	if n > 0 {
		ps.chRead <- int64(n)
	}
	return n, err
}

func (ps *uploadProgressSpinner) Close(err error) {
	close(ps.chRead)
	ps.wg.Wait()

	p := ps.printer

	if core.IsStdoutTerm {
		emitProgress(0, 0, p)
	}

	if err != nil {
		p.WriteString("\n\n")
	} else {
		writeUploadFinalProgress(p, ps.bytesRead, time.Since(ps.start), 20)
	}
	p.Flush()
}

func (ps *uploadProgressSpinner) renderLoop() {
	defer ps.wg.Done()

	if core.IsStdoutTerm {
		emitProgress(3, 0, ps.printer)
	}

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ps.render()
			ps.position++
		case n, ok := <-ps.chRead:
			if !ok {
				ps.render()
				return
			}
			ps.bytesRead += n
		}
	}
}

func (ps *uploadProgressSpinner) render() {
	const width = 20

	var value string
	var offset int
	position := ps.position % (width * 2)
	if position < width {
		value = "=>"
		offset = int(position)
	} else {
		value = "<="
		offset = int(width*2 - position - 1)
	}

	p := ps.printer
	p.WriteString("\r")
	p.Set(core.Bold)
	p.WriteString("[")
	for range offset {
		p.WriteString(" ")
	}
	p.Set(core.Green)
	p.WriteString(value)
	p.Reset()
	for range width - offset - 1 {
		p.WriteString(" ")
	}
	p.Set(core.Bold)
	p.WriteString("]")
	p.Reset()

	p.WriteString(" ")
	size := formatSize(ps.bytesRead)
	for range 7 - len(size) {
		p.WriteString(" ")
	}
	p.WriteString(size)

	p.Flush()
}

// uploadProgressStatic wraps an io.Reader to display upload progress on
// non-terminal stderr.
type uploadProgressStatic struct {
	r         io.Reader
	printer   *core.Printer
	bytesRead int64
	start     time.Time
}

func newUploadProgressStatic(r io.Reader, p *core.Printer) *uploadProgressStatic {
	return &uploadProgressStatic{
		r:       r,
		printer: p,
		start:   time.Now(),
	}
}

func (ps *uploadProgressStatic) Read(p []byte) (int, error) {
	n, err := ps.r.Read(p)
	ps.bytesRead += int64(n)
	return n, err
}

func (ps *uploadProgressStatic) Close(err error) {
	if err != nil {
		return
	}

	dur := time.Since(ps.start)
	writeUploadFinalProgress(ps.printer, ps.bytesRead, dur, -1)
	ps.printer.Flush()
}

func writeUploadFinalProgress(p *core.Printer, bytesRead int64, dur time.Duration, toClear int) {
	if toClear >= 0 {
		p.WriteString("\r")
	}

	p.WriteString("Uploaded ")
	p.Set(core.Bold)
	p.WriteString(formatSize(bytesRead))
	p.Reset()
	p.WriteString(" in ")
	p.Set(core.Italic)
	p.WriteString(formatDuration(dur))
	p.Reset()

	for range toClear {
		p.WriteString(" ")
	}
	p.WriteString("\n")
}
