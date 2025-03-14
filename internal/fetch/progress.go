package fetch

import (
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

// progressBar is a wrapper around an io.Reader that displays a progress bar
// to stderr. When reading is complete, the Close method MUST be called.
type progressBar struct {
	r          io.Reader
	printer    *core.Printer
	bytesRead  int64
	totalBytes int64
	chRead     chan int64
	start      time.Time
	wg         sync.WaitGroup
}

func newProgressBar(r io.Reader, p *core.Printer, totalBytes int64) *progressBar {
	pr := &progressBar{
		r:          r,
		printer:    p,
		totalBytes: totalBytes,
		chRead:     make(chan int64, 1),
		start:      time.Now(),
	}
	pr.wg.Add(1)
	go pr.renderLoop()
	return pr
}

func (pb *progressBar) Read(p []byte) (int, error) {
	n, err := pb.r.Read(p)
	if n > 0 {
		pb.chRead <- int64(n)
	}
	return n, err
}

func (pb *progressBar) Close(err error) {
	// Close the reader channel and wait for the loop to exit.
	close(pb.chRead)
	pb.wg.Wait()

	p := pb.printer
	if err != nil {
		// An error will be printed after this.
		p.WriteString("\n\n")
	} else {
		// Replace the progress bar with a summary.
		end := time.Now()
		p.WriteString("\rDownloaded ")
		p.Set(core.Bold)
		p.WriteString(formatSize(pb.bytesRead))
		p.Reset()
		p.WriteString(" in ")
		p.Set(core.Italic)
		p.WriteString(formatDuration(end.Sub(pb.start)))
		p.Reset()
		for range 32 {
			p.WriteString(" ")
		}
		p.WriteString("\n")
	}
	p.Flush()
}

func (pb *progressBar) renderLoop() {
	defer pb.wg.Done()

	lastUpdateTime := pb.start
	var chTimeout <-chan time.Time
	for {
		select {
		case <-chTimeout:
			chTimeout = nil
		case n, ok := <-pb.chRead:
			if !ok {
				// Reader channel has been closed, exit.
				pb.render()
				return
			}
			pb.bytesRead += n

			if chTimeout != nil {
				// We're waiting on a timeout to re-render.
				continue
			}

			// Check if enough time has passed since the last
			// render. If not, set a timeout and continue.
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

func (pb *progressBar) render() {
	const barWidth = 30
	percentage := pb.bytesRead * 100 / pb.totalBytes
	completedWidth := min(barWidth*percentage/100, barWidth)

	p := pb.printer
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

// progressSpinner is a wrapper around an io.Reader that displays a progress
// spinner to stderr. When reading is complete, the Close method MUST be called.
type progressSpinner struct {
	r         io.Reader
	printer   *core.Printer
	bytesRead int64
	chRead    chan int64
	position  int64
	wg        sync.WaitGroup
	start     time.Time
}

func newProgressSpinner(r io.Reader, p *core.Printer) *progressSpinner {
	ps := &progressSpinner{
		r:       r,
		printer: p,
		chRead:  make(chan int64, 1),
		start:   time.Now(),
	}
	ps.wg.Add(1)
	go ps.renderLoop()
	return ps
}

func (ps *progressSpinner) Close(err error) {
	close(ps.chRead)
	ps.wg.Wait()

	p := ps.printer
	if err != nil {
		p.WriteString("\n\n")
	} else {
		// Replace the progress spinner with a summary.
		end := time.Now()
		p.WriteString("\rDownloaded ")
		p.Set(core.Bold)
		p.WriteString(formatSize(ps.bytesRead))
		p.Reset()
		p.WriteString(" in ")
		p.Set(core.Italic)
		p.WriteString(formatDuration(end.Sub(ps.start)))
		p.Reset()
		for range 20 {
			p.WriteString(" ")
		}
		p.WriteString("\n")
	}
	p.Flush()
}

func (ps *progressSpinner) Read(p []byte) (int, error) {
	n, err := ps.r.Read(p)
	if n > 0 {
		ps.chRead <- int64(n)
	}
	return n, err
}

func (ps *progressSpinner) renderLoop() {
	defer ps.wg.Done()

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ps.render()
			ps.position++
		case n, ok := <-ps.chRead:
			if !ok {
				// Reader channel has been closed, exit.
				ps.render()
				return
			}
			ps.bytesRead += n
		}
	}
}

func (ps *progressSpinner) render() {
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

// formatSize converts bytes to a human-readable string.
func formatSize(bytes int64) string {
	const units = "KMGTPE"
	const unit = 1024
	if bytes < unit {
		return strconv.FormatInt(bytes, 10) + "B"
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= 1000; n /= unit {
		div *= unit
		exp++
	}
	value := float64(bytes) / float64(div)
	if exp >= len(units) {
		return "NaN"
	}
	return strconv.FormatFloat(value, 'f', 1, 64) + string(units[exp]) + "B"
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
