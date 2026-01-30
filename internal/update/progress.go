package update

import (
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

// updateProgress wraps an io.ReadCloser and displays a progress bar to stderr.
type updateProgress struct {
	rc         io.ReadCloser
	printer    *core.Printer
	bytesRead  int64
	totalBytes int64
	chRead     chan int64
	wg         sync.WaitGroup
}

func newUpdateProgress(rc io.ReadCloser, p *core.Printer, totalBytes int64) *updateProgress {
	up := &updateProgress{
		rc:         rc,
		printer:    p,
		totalBytes: totalBytes,
		chRead:     make(chan int64, 1),
	}
	up.wg.Add(1)
	go up.renderLoop()
	return up
}

func (up *updateProgress) Read(p []byte) (int, error) {
	n, err := up.rc.Read(p)
	if n > 0 {
		up.chRead <- int64(n)
	}
	return n, err
}

func (up *updateProgress) Close() error {
	err := up.rc.Close()
	close(up.chRead)
	up.wg.Wait()
	up.clearLine()
	return err
}

func (up *updateProgress) renderLoop() {
	defer up.wg.Done()

	start := time.Now()
	var chTimeout <-chan time.Time
	for {
		select {
		case <-chTimeout:
			chTimeout = nil
		case n, ok := <-up.chRead:
			if !ok {
				up.render()
				return
			}
			up.bytesRead += n

			if chTimeout != nil {
				continue
			}

			dur := time.Until(start.Add(100 * time.Millisecond))
			if dur > 0 {
				chTimeout = time.After(dur)
				continue
			}
			start = time.Now()
		}

		up.render()
	}
}

func (up *updateProgress) render() {
	const barWidth = 30
	percentage := up.bytesRead * 100 / up.totalBytes
	completedWidth := min(barWidth*percentage/100, barWidth)

	p := up.printer

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
	size := updateFormatSize(up.bytesRead)
	for range 7 - len(size) {
		p.WriteString(" ")
	}
	p.WriteString(size)
	p.WriteString(" / ")
	p.WriteString(updateFormatSize(up.totalBytes))
	p.WriteString(")")
	p.Flush()
}

func (up *updateProgress) clearLine() {
	p := up.printer
	p.WriteString("\r")
	for range 60 {
		p.WriteString(" ")
	}
	p.WriteString("\r")
	p.Flush()
}

// updateSpinner wraps an io.ReadCloser and displays a bouncing spinner to stderr.
type updateSpinner struct {
	rc        io.ReadCloser
	printer   *core.Printer
	bytesRead int64
	chRead    chan int64
	position  int64
	wg        sync.WaitGroup
}

func newUpdateSpinner(rc io.ReadCloser, p *core.Printer) *updateSpinner {
	us := &updateSpinner{
		rc:      rc,
		printer: p,
		chRead:  make(chan int64, 1),
	}
	us.wg.Add(1)
	go us.renderLoop()
	return us
}

func (us *updateSpinner) Read(p []byte) (int, error) {
	n, err := us.rc.Read(p)
	if n > 0 {
		us.chRead <- int64(n)
	}
	return n, err
}

func (us *updateSpinner) Close() error {
	err := us.rc.Close()
	close(us.chRead)
	us.wg.Wait()
	us.clearLine()
	return err
}

func (us *updateSpinner) renderLoop() {
	defer us.wg.Done()

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			us.render()
			us.position++
		case n, ok := <-us.chRead:
			if !ok {
				us.render()
				return
			}
			us.bytesRead += n
		}
	}
}

func (us *updateSpinner) render() {
	const width = 20

	var value string
	var offset int
	position := us.position % (int64(width) * 2)
	if position < int64(width) {
		value = "=>"
		offset = int(position)
	} else {
		value = "<="
		offset = int(int64(width)*2 - position - 1)
	}

	p := us.printer
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
	size := updateFormatSize(us.bytesRead)
	for range 7 - len(size) {
		p.WriteString(" ")
	}
	p.WriteString(size)

	p.Flush()
}

func (us *updateSpinner) clearLine() {
	p := us.printer
	p.WriteString("\r")
	for range 40 {
		p.WriteString(" ")
	}
	p.WriteString("\r")
	p.Flush()
}

// updateFormatSize converts bytes to a human-readable string.
func updateFormatSize(bytes int64) string {
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
