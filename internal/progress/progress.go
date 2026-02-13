package progress

import (
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

// FormatSize converts bytes to a human-readable string.
func FormatSize(bytes int64) string {
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

// Bar wraps an io.Reader and displays a progress bar to stderr. When reading
// is complete, the Stop method must be called.
type Bar struct {
	r          io.Reader
	printer    *core.Printer
	bytesRead  int64
	totalBytes int64
	chRead     chan int64
	start      time.Time
	wg         sync.WaitGroup
	onRender   func(percentage int64)
}

// NewBar returns a new Bar that wraps r and displays a progress bar to stderr
// via p. The onRender callback, if non-nil, is called on each render with the
// current completion percentage.
func NewBar(r io.Reader, p *core.Printer, totalBytes int64, onRender func(percentage int64)) *Bar {
	b := &Bar{
		r:          r,
		printer:    p,
		totalBytes: totalBytes,
		chRead:     make(chan int64, 1),
		start:      time.Now(),
		onRender:   onRender,
	}
	b.wg.Add(1)
	go b.renderLoop()
	return b
}

func (b *Bar) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if n > 0 {
		b.chRead <- int64(n)
	}
	return n, err
}

// Stop signals the render loop to exit and waits for it to finish. It returns
// the total bytes read and the elapsed duration.
func (b *Bar) Stop() (bytesRead int64, elapsed time.Duration) {
	close(b.chRead)
	b.wg.Wait()
	return b.bytesRead, time.Since(b.start)
}

func (b *Bar) renderLoop() {
	defer b.wg.Done()

	lastRenderTime := b.start
	var chTimeout <-chan time.Time
	for {
		select {
		case <-chTimeout:
			chTimeout = nil
		case n, ok := <-b.chRead:
			if !ok {
				b.render()
				return
			}
			b.bytesRead += n

			if chTimeout != nil {
				continue
			}

			now := time.Now()
			dur := lastRenderTime.Add(100 * time.Millisecond).Sub(now)
			if dur > 0 {
				chTimeout = time.After(dur)
				continue
			}
			lastRenderTime = now
		}

		b.render()
	}
}

func (b *Bar) render() {
	const barWidth = 30
	percentage := b.bytesRead * 100 / b.totalBytes
	completedWidth := min(barWidth*percentage/100, barWidth)

	if b.onRender != nil {
		b.onRender(percentage)
	}

	p := b.printer

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
	size := FormatSize(b.bytesRead)
	for range 7 - len(size) {
		p.WriteString(" ")
	}
	p.WriteString(size)
	p.WriteString(" / ")
	p.WriteString(FormatSize(b.totalBytes))
	p.WriteString(")")
	p.Flush()
}

// Spinner wraps an io.Reader and displays a bouncing spinner to stderr. When
// reading is complete, the Stop method must be called.
type Spinner struct {
	r         io.Reader
	printer   *core.Printer
	bytesRead int64
	chRead    chan int64
	position  int64
	start     time.Time
	wg        sync.WaitGroup
	onStart   func()
}

// NewSpinner returns a new Spinner that wraps r and displays a bouncing
// spinner to stderr via p. The onStart callback, if non-nil, is called once
// at the beginning of the render loop.
func NewSpinner(r io.Reader, p *core.Printer, onStart func()) *Spinner {
	s := &Spinner{
		r:       r,
		printer: p,
		chRead:  make(chan int64, 1),
		start:   time.Now(),
		onStart: onStart,
	}
	s.wg.Add(1)
	go s.renderLoop()
	return s
}

func (s *Spinner) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if n > 0 {
		s.chRead <- int64(n)
	}
	return n, err
}

// Stop signals the render loop to exit and waits for it to finish. It returns
// the total bytes read and the elapsed duration.
func (s *Spinner) Stop() (bytesRead int64, elapsed time.Duration) {
	close(s.chRead)
	s.wg.Wait()
	return s.bytesRead, time.Since(s.start)
}

func (s *Spinner) renderLoop() {
	defer s.wg.Done()

	if s.onStart != nil {
		s.onStart()
	}

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.render()
			s.position++
		case n, ok := <-s.chRead:
			if !ok {
				s.render()
				return
			}
			s.bytesRead += n
		}
	}
}

func (s *Spinner) render() {
	const width = 20

	var value string
	var offset int
	position := s.position % (width * 2)
	if position < width {
		value = "=>"
		offset = int(position)
	} else {
		value = "<="
		offset = int(width*2 - position - 1)
	}

	p := s.printer
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
	size := FormatSize(s.bytesRead)
	for range 7 - len(size) {
		p.WriteString(" ")
	}
	p.WriteString(size)

	p.Flush()
}
