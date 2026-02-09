package fetch

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

// readTimedReader is a test helper that creates a timedReader and reads all
// data from it so that firstRead is populated.
func readTimedReader(data string) *timedReader {
	r := newTimedReader(io.NopCloser(strings.NewReader(data)))
	buf := make([]byte, len(data))
	r.Read(buf)
	return r
}

func TestBuildPhases_FullHTTPS(t *testing.T) {
	now := time.Now()
	m := &connectionMetrics{
		dnsStart:  now,
		dnsDur:    5 * time.Millisecond,
		tcpStart:  now,
		tcpDur:    4 * time.Millisecond,
		tlsStart:  now,
		tlsDur:    12 * time.Millisecond,
		ttfbStart: now,
		ttfbDur:   7 * time.Millisecond,
	}
	phases := buildPhases(m, readTimedReader("x"))
	if len(phases) != 5 {
		t.Fatalf("expected 5 phases, got %d", len(phases))
	}
	labels := []string{"DNS", "TCP", "TLS", "TTFB", "Body"}
	for i, want := range labels {
		if phases[i].label != want {
			t.Errorf("phase %d: expected label %q, got %q", i, want, phases[i].label)
		}
	}
}

func TestBuildPhases_HTTPOnly(t *testing.T) {
	now := time.Now()
	m := &connectionMetrics{
		dnsStart:  now,
		dnsDur:    5 * time.Millisecond,
		tcpStart:  now,
		tcpDur:    4 * time.Millisecond,
		ttfbStart: now,
		ttfbDur:   7 * time.Millisecond,
	}
	phases := buildPhases(m, readTimedReader("x"))
	if len(phases) != 4 {
		t.Fatalf("expected 4 phases (no TLS), got %d", len(phases))
	}
	for _, ph := range phases {
		if ph.label == "TLS" {
			t.Error("TLS phase should not be present for HTTP")
		}
	}
}

func TestBuildPhases_ReusedConnection(t *testing.T) {
	now := time.Now()
	m := &connectionMetrics{
		dnsStart:  now,
		dnsDur:    5 * time.Millisecond,
		tcpStart:  now,
		tcpDur:    4 * time.Millisecond,
		tlsStart:  now,
		tlsDur:    12 * time.Millisecond,
		ttfbStart: now,
		ttfbDur:   2 * time.Millisecond,
		reused:    true,
	}
	phases := buildPhases(m, readTimedReader("x"))
	if len(phases) != 2 {
		t.Fatalf("expected 2 phases (TTFB + Body), got %d", len(phases))
	}
	if phases[0].label != "TTFB" {
		t.Errorf("expected first phase TTFB, got %q", phases[0].label)
	}
	if phases[1].label != "Body" {
		t.Errorf("expected second phase Body, got %q", phases[1].label)
	}
}

func TestBuildPhases_NoBody(t *testing.T) {
	now := time.Now()
	m := &connectionMetrics{
		dnsStart:  now,
		dnsDur:    5 * time.Millisecond,
		tcpStart:  now,
		tcpDur:    4 * time.Millisecond,
		tlsStart:  now,
		tlsDur:    12 * time.Millisecond,
		ttfbStart: now,
		ttfbDur:   7 * time.Millisecond,
	}
	phases := buildPhases(m, nil)
	if len(phases) != 4 {
		t.Fatalf("expected 4 phases (no Body), got %d", len(phases))
	}
	for _, ph := range phases {
		if ph.label == "Body" {
			t.Error("Body phase should not be present when body is nil")
		}
	}
}

func TestBuildPhases_NoBodyUnread(t *testing.T) {
	now := time.Now()
	m := &connectionMetrics{
		dnsStart:  now,
		dnsDur:    5 * time.Millisecond,
		tcpStart:  now,
		tcpDur:    4 * time.Millisecond,
		ttfbStart: now,
		ttfbDur:   7 * time.Millisecond,
	}
	// timedReader exists but was never read from.
	body := newTimedReader(io.NopCloser(strings.NewReader("")))
	phases := buildPhases(m, body)
	if len(phases) != 3 {
		t.Fatalf("expected 3 phases (no Body), got %d", len(phases))
	}
	for _, ph := range phases {
		if ph.label == "Body" {
			t.Error("Body phase should not be present when body was not read")
		}
	}
}

func TestBuildPhases_AllZero(t *testing.T) {
	m := &connectionMetrics{}
	phases := buildPhases(m, nil)
	if len(phases) != 0 {
		t.Fatalf("expected 0 phases, got %d", len(phases))
	}
}

func TestBuildPhases_ZeroDuration(t *testing.T) {
	now := time.Now()
	m := &connectionMetrics{
		dnsStart:  now,
		dnsDur:    0,
		tcpStart:  now,
		tcpDur:    0,
		ttfbStart: now,
		ttfbDur:   0,
	}
	phases := buildPhases(m, nil)
	if len(phases) != 3 {
		t.Fatalf("expected 3 phases (DNS, TCP, TTFB with zero dur), got %d", len(phases))
	}
	labels := []string{"DNS", "TCP", "TTFB"}
	for i, want := range labels {
		if phases[i].label != want {
			t.Errorf("phase %d: expected label %q, got %q", i, want, phases[i].label)
		}
	}
}

func TestRenderWaterfall_ContainsLabels(t *testing.T) {
	now := time.Now()
	m := &connectionMetrics{
		dnsStart:  now,
		dnsDur:    5 * time.Millisecond,
		tcpStart:  now,
		tcpDur:    4 * time.Millisecond,
		ttfbStart: now,
		ttfbDur:   7 * time.Millisecond,
	}

	p := core.NewHandle(core.ColorOff).Stderr()
	renderWaterfall(p, m, readTimedReader("x"))
	output := string(p.Bytes())

	for _, label := range []string{"DNS", "TCP", "TTFB", "Body", "Total"} {
		if !strings.Contains(output, label) {
			t.Errorf("output should contain %q", label)
		}
	}
}

func TestRenderWaterfall_AllZero(t *testing.T) {
	m := &connectionMetrics{}
	p := core.NewHandle(core.ColorOff).Stderr()
	renderWaterfall(p, m, nil)
	output := string(p.Bytes())
	if output != "" {
		t.Errorf("expected empty output for all-zero metrics, got %q", output)
	}
}

func TestRenderWaterfall_ZeroDurations(t *testing.T) {
	// Simulates a fast localhost request where all phase durations are 0
	// (e.g. Windows timer resolution). Should still render a waterfall.
	now := time.Now()
	m := &connectionMetrics{
		ttfbStart: now,
		ttfbDur:   0,
		reused:    true,
	}

	p := core.NewHandle(core.ColorOff).Stderr()
	renderWaterfall(p, m, nil)
	output := string(p.Bytes())

	if !strings.Contains(output, "TTFB") {
		t.Error("output should contain TTFB label")
	}
	if !strings.Contains(output, "Total") {
		t.Error("output should contain Total label")
	}
}

func TestRenderWaterfall_NoColumnOverlap(t *testing.T) {
	// Simulate the user's scenario: DNS=3.5ms with total ~410ms.
	// Before the fix, the short DNS phase caused vertical overlap.
	now := time.Now()
	m := &connectionMetrics{
		dnsStart:  now,
		dnsDur:    3500 * time.Microsecond, // 3.5ms
		tcpStart:  now,
		tcpDur:    25 * time.Millisecond,
		tlsStart:  now,
		tlsDur:    80 * time.Millisecond,
		ttfbStart: now,
		ttfbDur:   300 * time.Millisecond,
	}

	p := core.NewHandle(core.ColorOff).Stderr()
	renderWaterfall(p, m, nil)
	output := string(p.Bytes())

	// Parse each phase row and record which columns contain '█'.
	lines := strings.Split(output, "\n")
	var barRows []string
	for _, line := range lines {
		if strings.Contains(line, "█") {
			barRows = append(barRows, line)
		}
	}
	if len(barRows) == 0 {
		t.Fatal("expected bar rows in output")
	}

	// For each column index, count how many rows have a filled block.
	maxLen := 0
	for _, row := range barRows {
		if len([]rune(row)) > maxLen {
			maxLen = len([]rune(row))
		}
	}
	for col := 0; col < maxLen; col++ {
		filled := 0
		for _, row := range barRows {
			runes := []rune(row)
			if col < len(runes) && runes[col] == '█' {
				filled++
			}
		}
		if filled > 1 {
			t.Errorf("column %d is filled by %d phases (expected at most 1)", col, filled)
		}
	}
}

func TestTimedReader_WallTime(t *testing.T) {
	data := "hello world"
	r := newTimedReader(io.NopCloser(strings.NewReader(data)))

	buf := make([]byte, 5)
	r.Read(buf)
	time.Sleep(10 * time.Millisecond)
	r.Read(buf)

	d := r.wallTime()
	if d < 10*time.Millisecond {
		t.Errorf("expected wall time >= 10ms, got %v", d)
	}
}

func TestTimedReader_NoReads(t *testing.T) {
	r := newTimedReader(io.NopCloser(strings.NewReader("hello")))
	if d := r.wallTime(); d != 0 {
		t.Errorf("expected 0 wall time with no reads, got %v", d)
	}
}
