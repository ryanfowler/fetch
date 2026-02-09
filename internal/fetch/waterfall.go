package fetch

import (
	"io"
	"strings"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

// timedReader wraps an io.ReadCloser to measure body download wall time.
// It is used on a single goroutine: reads happen sequentially and wallTime
// is called after the body is fully consumed.
type timedReader struct {
	r         io.ReadCloser
	firstRead time.Time
	lastRead  time.Time
}

func newTimedReader(r io.ReadCloser) *timedReader {
	return &timedReader{r: r}
}

func (t *timedReader) Read(p []byte) (int, error) {
	before := time.Now()
	n, err := t.r.Read(p)
	if n > 0 {
		if t.firstRead.IsZero() {
			t.firstRead = before
		}
		t.lastRead = time.Now()
	}
	return n, err
}

func (t *timedReader) Close() error {
	return t.r.Close()
}

func (t *timedReader) wallTime() time.Duration {
	if t.firstRead.IsZero() {
		return 0
	}
	return t.lastRead.Sub(t.firstRead)
}

// phase represents a single timing phase in the waterfall.
type phase struct {
	label string
	color core.Sequence
	dur   time.Duration
}

// buildPhases constructs the list of timing phases from metrics.
// A phase is included if its start time is non-zero, even when its
// measured duration rounds to 0.
func buildPhases(m *connectionMetrics, body *timedReader) []phase {
	var phases []phase
	if !m.reused {
		if !m.dnsStart.IsZero() {
			phases = append(phases, phase{"DNS", core.Cyan, m.dnsDur})
		}
		if !m.tcpStart.IsZero() {
			phases = append(phases, phase{"TCP", core.Green, m.tcpDur})
		}
		if !m.tlsStart.IsZero() {
			phases = append(phases, phase{"TLS", core.Yellow, m.tlsDur})
		}
	}
	if !m.ttfbStart.IsZero() {
		phases = append(phases, phase{"TTFB", core.Magenta, m.ttfbDur})
	}
	if body != nil && !body.firstRead.IsZero() {
		phases = append(phases, phase{"Body", core.Blue, body.wallTime()})
	}
	return phases
}

// renderWaterfall prints an ASCII waterfall chart of timing phases to stderr.
func renderWaterfall(p *core.Printer, m *connectionMetrics, body *timedReader) {
	phases := buildPhases(m, body)
	if len(phases) == 0 {
		return
	}

	// Compute total duration.
	var total time.Duration
	for _, ph := range phases {
		total += ph.dur
	}
	// Pre-compute all duration strings and find the max width.
	durStrs := make([]string, len(phases))
	maxDurWidth := 0
	for i, ph := range phases {
		durStrs[i] = formatTimingDuration(ph.dur)
		if len(durStrs[i]) > maxDurWidth {
			maxDurWidth = len(durStrs[i])
		}
	}
	totalDurStr := formatTimingDuration(total)
	if len(totalDurStr) > maxDurWidth {
		maxDurWidth = len(totalDurStr)
	}

	// Avoid division by zero when all phases are instantaneous (e.g.
	// fast localhost on Windows). Each phase still gets a minimum-width bar.
	if total <= 0 {
		total = 1
	}

	// Determine bar width from terminal width.
	// Layout: "* " (2) + label (5) + "  " (2) + bar + "  " + duration
	const labelWidth = 5
	fixedWidth := 2 + labelWidth + 2 + 2 + maxDurWidth
	termCols := core.GetTerminalCols()
	if termCols <= 0 {
		termCols = 80
	}
	barWidth := min(max(termCols-fixedWidth, 10), 60)

	p.WriteString("\n")

	// Render each phase.
	var offset time.Duration
	var nextStart int
	for i, ph := range phases {
		startCol := nextStart
		endCol := int(float64(offset+ph.dur) / float64(total) * float64(barWidth))
		offset += ph.dur
		// Ensure at least 1 char for non-zero phase.
		if endCol <= startCol {
			endCol = startCol + 1
		}
		if endCol > barWidth {
			endCol = barWidth
		}
		nextStart = endCol

		p.WriteInfoPrefix()

		// Label (right-padded to labelWidth).
		p.Set(core.Bold)
		p.Set(ph.color)
		label := ph.label
		if len(label) < labelWidth {
			label += strings.Repeat(" ", labelWidth-len(label))
		}
		p.WriteString(label)
		p.Reset()
		p.WriteString("  ")

		// Bar.
		for j := range barWidth {
			if j >= startCol && j < endCol {
				p.Set(ph.color)
				p.WriteString("█")
				p.Reset()
			} else {
				p.Set(core.Dim)
				p.WriteString("░")
				p.Reset()
			}
		}

		// Duration (right-aligned).
		p.WriteString("  ")
		dur := durStrs[i]
		if pad := maxDurWidth - len(dur); pad > 0 {
			p.WriteString(strings.Repeat(" ", pad))
		}
		p.Set(core.Dim)
		p.WriteString(dur)
		p.Reset()
		p.WriteString("\n")
	}

	// Total line.
	p.WriteInfoPrefix()
	p.Set(core.Dim)
	label := "Total"
	if len(label) < labelWidth {
		label += strings.Repeat(" ", labelWidth-len(label))
	}
	p.WriteString(label)
	p.WriteString("  ")
	p.WriteString(strings.Repeat("─", barWidth))
	p.WriteString("  ")
	if pad := maxDurWidth - len(totalDurStr); pad > 0 {
		p.WriteString(strings.Repeat(" ", pad))
	}
	p.WriteString(totalDurStr)
	p.Reset()
	p.WriteString("\n")
}
