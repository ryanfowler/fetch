package progress

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

func testPrinter() *core.Printer {
	return core.NewHandle(core.ColorOff).Stderr()
}

func TestFormatSize(t *testing.T) {
	tests := []struct {
		bytes int64
		want  string
	}{
		{0, "0B"},
		{1, "1B"},
		{512, "512B"},
		{1023, "1023B"},
		{1024, "1.0KB"},
		{1536, "1.5KB"},
		{10240, "10.0KB"},
		{1048576, "1.0MB"},
		{1572864, "1.5MB"},
		{1073741824, "1.0GB"},
		{1099511627776, "1.0TB"},
		{1125899906842624, "1.0PB"},
		{1152921504606846976, "1.0EB"},
	}

	for _, tt := range tests {
		got := FormatSize(tt.bytes)
		if got != tt.want {
			t.Errorf("FormatSize(%d) = %q, want %q", tt.bytes, got, tt.want)
		}
	}
}

func TestFormatSizeBoundaries(t *testing.T) {
	// Values just under and at unit boundaries.
	tests := []struct {
		name  string
		bytes int64
		want  string
	}{
		{"just under 1KB", 1023, "1023B"},
		{"exactly 1KB", 1024, "1.0KB"},
		{"just under 1MB", 1048575, "1.0MB"},
		{"exactly 1MB", 1048576, "1.0MB"},
		{"999KB", 999 * 1024, "999.0KB"},
		{"1000KB promotes to MB", 1000 * 1024, "1.0MB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatSize(tt.bytes)
			if got != tt.want {
				t.Errorf("FormatSize(%d) = %q, want %q", tt.bytes, got, tt.want)
			}
		})
	}
}

func TestBarReadPassthrough(t *testing.T) {
	data := []byte("hello, world!")
	r := bytes.NewReader(data)
	p := testPrinter()

	bar := NewBar(r, p, int64(len(data)), nil)

	got, err := io.ReadAll(bar)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("Read data = %q, want %q", got, data)
	}

	bytesRead, elapsed := bar.Stop()
	if bytesRead != int64(len(data)) {
		t.Errorf("bytesRead = %d, want %d", bytesRead, len(data))
	}
	if elapsed < 0 {
		t.Error("elapsed should be non-negative")
	}
}

func TestBarReadLargeData(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 100_000)
	r := bytes.NewReader(data)
	p := testPrinter()

	bar := NewBar(r, p, int64(len(data)), nil)

	got, err := io.ReadAll(bar)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if len(got) != len(data) {
		t.Errorf("Read %d bytes, want %d", len(got), len(data))
	}

	bytesRead, _ := bar.Stop()
	if bytesRead != int64(len(data)) {
		t.Errorf("bytesRead = %d, want %d", bytesRead, len(data))
	}
}

func TestBarOnRenderCallback(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 1024)
	r := bytes.NewReader(data)
	p := testPrinter()

	var called bool
	onRender := func(pct int64) {
		called = true
		if pct < 0 || pct > 100 {
			t.Errorf("percentage out of range: %d", pct)
		}
	}

	bar := NewBar(r, p, int64(len(data)), onRender)
	io.ReadAll(bar)
	bar.Stop()

	if !called {
		t.Error("onRender callback was never called")
	}
}

func TestSpinnerReadPassthrough(t *testing.T) {
	data := []byte("spinner test data")
	r := bytes.NewReader(data)
	p := testPrinter()

	spinner := NewSpinner(r, p, nil)

	got, err := io.ReadAll(spinner)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("Read data = %q, want %q", got, data)
	}

	bytesRead, elapsed := spinner.Stop()
	if bytesRead != int64(len(data)) {
		t.Errorf("bytesRead = %d, want %d", bytesRead, len(data))
	}
	if elapsed < 0 {
		t.Error("elapsed should be non-negative")
	}
}

func TestSpinnerOnStartCallback(t *testing.T) {
	data := []byte("test")
	r := bytes.NewReader(data)
	p := testPrinter()

	var called bool
	onStart := func() {
		called = true
	}

	spinner := NewSpinner(r, p, onStart)
	io.ReadAll(spinner)
	spinner.Stop()

	if !called {
		t.Error("onStart callback was never called")
	}
}

func TestBarEmptyRead(t *testing.T) {
	r := strings.NewReader("")
	p := testPrinter()

	bar := NewBar(r, p, 1, nil)

	got, err := io.ReadAll(bar)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty read, got %d bytes", len(got))
	}

	bytesRead, _ := bar.Stop()
	if bytesRead != 0 {
		t.Errorf("bytesRead = %d, want 0", bytesRead)
	}
}

func TestSpinnerEmptyRead(t *testing.T) {
	r := strings.NewReader("")
	p := testPrinter()

	spinner := NewSpinner(r, p, nil)

	got, err := io.ReadAll(spinner)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty read, got %d bytes", len(got))
	}

	bytesRead, _ := spinner.Stop()
	if bytesRead != 0 {
		t.Errorf("bytesRead = %d, want 0", bytesRead)
	}
}
