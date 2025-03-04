package fetch

import (
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

// progressReader is a wrapper around an io.Reader that displays a progress bar
// to stderr. When reading is complete, the Close method MUST be called.
type progressReader struct {
	r          io.Reader
	printer    *core.Printer
	bytesRead  int64
	totalBytes int64
	chRender   chan int64
	start      time.Time
	wg         sync.WaitGroup
}

func newProgressReader(r io.Reader, p *core.Printer, totalBytes int64) *progressReader {
	pr := &progressReader{
		r:          r,
		printer:    p,
		totalBytes: totalBytes,
		chRender:   make(chan int64, 1),
		start:      time.Now(),
	}
	pr.wg.Add(1)
	go pr.renderLoop()
	return pr
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.r.Read(p)
	if n > 0 {
		pr.chRender <- int64(n)
	}
	return n, err
}

func (pr *progressReader) Close(err error) {
	// Close the render channel and wait for the loop to exit.
	close(pr.chRender)
	pr.wg.Wait()

	p := pr.printer
	if err != nil {
		// An error will be printed after this.
		p.WriteString("\n\n")
	} else {
		// Replace the progress bar with a summary.
		end := time.Now()
		p.WriteString("\rDownloaded ")
		p.Set(core.Bold)
		p.WriteString(formatSize(pr.bytesRead))
		p.Reset()
		p.WriteString(" in ")
		p.Set(core.Italic)
		p.WriteString(formatDuration(end.Sub(pr.start)))
		p.Reset()
		for range 42 {
			p.WriteString(" ")
		}
		p.WriteString("\n")
	}
	p.Flush()
}

func (pr *progressReader) renderLoop() {
	defer pr.wg.Done()

	lastUpdateTime := pr.start
	var chTimeout <-chan time.Time
	for {
		select {
		case <-chTimeout:
			chTimeout = nil
		case n, ok := <-pr.chRender:
			if !ok {
				// Render channel has been closed, exit.
				pr.render()
				return
			}
			pr.bytesRead += n

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

		pr.render()
	}
}

func (pr *progressReader) render() {
	const barWidth = 40
	percentage := pr.bytesRead * 100 / pr.totalBytes
	completedWidth := min(barWidth*percentage/100, barWidth)

	p := pr.printer
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
	p.WriteString(formatSize(pr.bytesRead))
	p.WriteString(" / ")
	p.WriteString(formatSize(pr.totalBytes))
	p.WriteString(")")
	p.Reset()
	p.Flush()
}

// formatSize converts bytes to a human-readable string.
func formatSize(bytes int64) string {
	const units = "KMGTPE"
	const unit = 1024
	if bytes < unit {
		return strconv.FormatInt(bytes, 10) + " B"
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	if exp >= len(units) {
		return "NaN"
	}
	value := float64(bytes) / float64(div)
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
