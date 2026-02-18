package format

import (
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestFormatCSV(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "basic csv",
			input:   "name,age,city\nAlice,30,NYC\nBob,25,LA",
			wantErr: false,
		},
		{
			name:    "tab separated",
			input:   "name\tage\tcity\nAlice\t30\tNYC\nBob\t25\tLA",
			wantErr: false,
		},
		{
			name:    "semicolon separated",
			input:   "name;age;city\nAlice;30;NYC\nBob;25;LA",
			wantErr: false,
		},
		{
			name:    "pipe separated",
			input:   "name|age|city\nAlice|30|NYC\nBob|25|LA",
			wantErr: false,
		},
		{
			name:    "quoted fields with commas",
			input:   `name,location,notes` + "\n" + `Alice,"New York, NY","Has a cat, dog"` + "\n" + `Bob,LA,None`,
			wantErr: false,
		},
		{
			name:    "embedded newlines in quotes",
			input:   "name,bio\nAlice,\"Line1\nLine2\"\nBob,Simple",
			wantErr: false,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: false,
		},
		{
			name:    "ragged rows",
			input:   "a,b,c\n1,2\n3,4,5,6",
			wantErr: false,
		},
		{
			name:    "single column",
			input:   "name\nAlice\nBob",
			wantErr: false,
		},
		{
			name:    "single row",
			input:   "name,age,city",
			wantErr: false,
		},
		{
			name:    "unicode content",
			input:   "名前,年齢\n太郎,25\n花子,30",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.NewHandle(core.ColorOff).Stderr()
			err := FormatCSV([]byte(tt.input), p)
			if (err != nil) != tt.wantErr {
				t.Errorf("FormatCSV() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFormatCSVOutput(t *testing.T) {
	input := "name,age,city\nAlice,30,NYC\nBob,25,LA"
	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatCSV([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatCSV() error = %v", err)
	}

	output := string(p.Bytes())
	// Check that all values are present
	for _, want := range []string{"name", "age", "city", "Alice", "30", "NYC", "Bob", "25", "LA"} {
		if !strings.Contains(output, want) {
			t.Errorf("output should contain %q, got: %s", want, output)
		}
	}
	// Check for newlines (rows separated)
	if strings.Count(output, "\n") < 3 {
		t.Errorf("output should have at least 3 newlines, got: %s", output)
	}
}

func TestFormatCSVAlignment(t *testing.T) {
	// Test that columns are aligned properly
	input := "a,bb,ccc\n111,22,3"
	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatCSV([]byte(input), p)
	if err != nil {
		t.Fatalf("FormatCSV() error = %v", err)
	}

	output := string(p.Bytes())
	lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	// The header "a" should be padded to width 3 (same as "111")
	// The header "bb" should be padded to width 2 (same as "22")
	// Check that "a" is followed by spaces for padding
	if !strings.HasPrefix(lines[0], "a  ") {
		t.Errorf("expected 'a' to be padded, got: %q", lines[0])
	}
}

func TestDetectDelimiter(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  rune
	}{
		{
			name:  "comma",
			input: "a,b,c",
			want:  ',',
		},
		{
			name:  "tab",
			input: "a\tb\tc",
			want:  '\t',
		},
		{
			name:  "semicolon",
			input: "a;b;c",
			want:  ';',
		},
		{
			name:  "pipe",
			input: "a|b|c",
			want:  '|',
		},
		{
			name:  "empty defaults to comma",
			input: "",
			want:  ',',
		},
		{
			name:  "no delimiters defaults to comma",
			input: "abc",
			want:  ',',
		},
		{
			name:  "mixed prefers most common",
			input: "a,b,c;d",
			want:  ',',
		},
		{
			name:  "multiline uses first line",
			input: "a;b;c\na,b,c,d,e",
			want:  ';',
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectDelimiter([]byte(tt.input))
			if got != tt.want {
				t.Errorf("detectDelimiter() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatCSVEmpty(t *testing.T) {
	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatCSV([]byte(""), p)
	if err != nil {
		t.Fatalf("FormatCSV() error = %v", err)
	}
	if len(p.Bytes()) != 0 {
		t.Errorf("expected empty output for empty input, got: %q", string(p.Bytes()))
	}
}

func TestCalculateTotalWidth(t *testing.T) {
	tests := []struct {
		name      string
		colWidths []int
		want      int
	}{
		{
			name:      "single column",
			colWidths: []int{10},
			want:      10,
		},
		{
			name:      "two columns",
			colWidths: []int{10, 20},
			want:      32, // 10 + 20 + 2 (separator)
		},
		{
			name:      "three columns",
			colWidths: []int{5, 10, 15},
			want:      34, // 5 + 10 + 15 + 4 (2 separators)
		},
		{
			name:      "empty",
			colWidths: []int{},
			want:      0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateTotalWidth(tt.colWidths)
			if got != tt.want {
				t.Errorf("calculateTotalWidth() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestVerticalOutput(t *testing.T) {
	// Test vertical output format directly
	records := [][]string{
		{"name", "age", "city"},
		{"Alice", "30", "NYC"},
		{"Bob", "25", "LA"},
	}

	p := core.NewHandle(core.ColorOff).Stderr()
	err := writeVertical(p, records)
	if err != nil {
		t.Fatalf("writeVertical() error = %v", err)
	}

	output := string(p.Bytes())

	// Check for row separators
	if !strings.Contains(output, "--- Row 1 ---") {
		t.Errorf("output should contain '--- Row 1 ---', got: %s", output)
	}
	if !strings.Contains(output, "--- Row 2 ---") {
		t.Errorf("output should contain '--- Row 2 ---', got: %s", output)
	}

	// Check that all field labels and values are present
	for _, want := range []string{"name:", "age:", "city:", "Alice", "30", "NYC", "Bob", "25", "LA"} {
		if !strings.Contains(output, want) {
			t.Errorf("output should contain %q, got: %s", want, output)
		}
	}
}

func TestVerticalOutputHeaderAlignment(t *testing.T) {
	// Test that headers are right-aligned in vertical mode
	records := [][]string{
		{"a", "longer_header"},
		{"val1", "val2"},
	}

	p := core.NewHandle(core.ColorOff).Stderr()
	err := writeVertical(p, records)
	if err != nil {
		t.Fatalf("writeVertical() error = %v", err)
	}

	output := string(p.Bytes())
	lines := strings.SplitSeq(output, "\n")

	// Find the line with "a:" - it should have padding before it
	for line := range lines {
		if strings.Contains(line, "a:") {
			// "a" should be right-aligned to match "longer_header" (13 chars)
			// So there should be 12 spaces before "a:"
			if !strings.HasPrefix(line, "            a:") {
				t.Errorf("expected 'a' to be right-aligned with padding, got: %q", line)
			}
			break
		}
	}
}

func TestUnicodeDisplayWidth(t *testing.T) {
	// Test that CJK characters and emoji are measured correctly
	tests := []struct {
		name    string
		records [][]string
		wantMax int // expected max width for first column
	}{
		{
			name: "ascii",
			records: [][]string{
				{"hello"},
				{"world"},
			},
			wantMax: 5,
		},
		{
			name: "cjk",
			records: [][]string{
				{"名前"}, // 2 CJK chars = 4 display columns
				{"ab"}, // 2 ASCII chars = 2 display columns
			},
			wantMax: 4,
		},
		{
			name: "mixed",
			records: [][]string{
				{"hello世界"}, // 5 ASCII + 2 CJK = 5 + 4 = 9 display columns
				{"test"},    // 4 ASCII = 4 display columns
			},
			wantMax: 9,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			widths := calculateColumnWidths(tt.records)
			if len(widths) == 0 {
				t.Fatalf("expected at least one column width")
			}
			if widths[0] != tt.wantMax {
				t.Errorf("calculateColumnWidths() first column = %d, want %d", widths[0], tt.wantMax)
			}
		})
	}
}

func TestVerticalModeWithRaggedRows(t *testing.T) {
	// Test vertical mode with rows that have fewer columns than the header
	records := [][]string{
		{"a", "b", "c"},
		{"1", "2"}, // Missing third column
		{"x", "y", "z"},
	}

	p := core.NewHandle(core.ColorOff).Stderr()
	err := writeVertical(p, records)
	if err != nil {
		t.Fatalf("writeVertical() error = %v", err)
	}

	output := string(p.Bytes())

	// Should still contain all rows
	if !strings.Contains(output, "--- Row 1 ---") {
		t.Errorf("output should contain '--- Row 1 ---'")
	}
	if !strings.Contains(output, "--- Row 2 ---") {
		t.Errorf("output should contain '--- Row 2 ---'")
	}

	// Row 1 should have only 2 fields displayed
	// Row 2 should have all 3 fields
	if !strings.Contains(output, "x") && !strings.Contains(output, "y") && !strings.Contains(output, "z") {
		t.Errorf("output should contain all values from row 2")
	}
}

func TestVerticalModeWithExtraColumns(t *testing.T) {
	// Test vertical mode with rows that have more columns than the header
	records := [][]string{
		{"a", "b"},
		{"1", "2", "3"}, // Extra column without header
	}

	p := core.NewHandle(core.ColorOff).Stderr()
	err := writeVertical(p, records)
	if err != nil {
		t.Fatalf("writeVertical() error = %v", err)
	}

	output := string(p.Bytes())

	// Should contain the extra value even without a header
	if !strings.Contains(output, "3") {
		t.Errorf("output should contain '3' even without header, got: %s", output)
	}
}
