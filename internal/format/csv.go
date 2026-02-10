package format

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strings"

	"github.com/ryanfowler/fetch/internal/core"

	"github.com/mattn/go-runewidth"
)

// FormatCSV formats the provided CSV data to the Printer.
func FormatCSV(buf []byte, p *core.Printer) error {
	err := formatCSV(buf, p)
	if err != nil {
		p.Discard()
	}
	return err
}

func formatCSV(buf []byte, p *core.Printer) error {
	if len(buf) == 0 {
		return nil
	}

	delimiter := detectDelimiter(buf)

	reader := csv.NewReader(bytes.NewReader(buf))
	reader.Comma = delimiter
	reader.FieldsPerRecord = -1 // Allow ragged rows
	reader.LazyQuotes = true    // Lenient parsing

	records, err := reader.ReadAll()
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return nil
	}

	// Calculate column widths
	colWidths := calculateColumnWidths(records)
	totalWidth := calculateTotalWidth(colWidths)
	termCols := core.GetTerminalCols()

	// Use vertical mode if terminal width is known and content exceeds it
	if termCols > 0 && totalWidth > termCols && len(records) > 1 {
		return writeVertical(p, records)
	}

	// Output formatted rows (horizontal mode)
	for i, row := range records {
		if i > 0 {
			p.WriteString("\n")
		}
		writeRow(p, row, colWidths, i == 0)
	}
	p.WriteString("\n")

	return nil
}

// detectDelimiter auto-detects the delimiter from the first line.
// Checks comma, tab, semicolon, and pipe. Defaults to comma.
func detectDelimiter(buf []byte) rune {
	// Find the first line
	firstLine, _, _ := bytes.Cut(buf, []byte{'\n'})

	delimiters := []rune{',', '\t', ';', '|'}
	counts := make(map[rune]int)

	for _, d := range delimiters {
		counts[d] = strings.Count(string(firstLine), string(d))
	}

	// Pick the delimiter with the highest count
	maxCount := 0
	bestDelimiter := ','
	for _, d := range delimiters {
		if counts[d] > maxCount {
			maxCount = counts[d]
			bestDelimiter = d
		}
	}

	return bestDelimiter
}

// calculateColumnWidths finds the max display width per column across all rows.
func calculateColumnWidths(records [][]string) []int {
	if len(records) == 0 {
		return nil
	}

	// Find max number of columns
	maxCols := 0
	for _, row := range records {
		if len(row) > maxCols {
			maxCols = len(row)
		}
	}

	widths := make([]int, maxCols)
	for _, row := range records {
		for j, cell := range row {
			w := runewidth.StringWidth(cell)
			if w > widths[j] {
				widths[j] = w
			}
		}
	}

	return widths
}

// calculateTotalWidth returns the total display width of horizontal output.
func calculateTotalWidth(colWidths []int) int {
	total := 0
	for _, w := range colWidths {
		total += w
	}
	if len(colWidths) > 1 {
		total += (len(colWidths) - 1) * 2 // separator width ("  ")
	}
	return total
}

// writeRow writes a single row with proper alignment and coloring.
func writeRow(p *core.Printer, row []string, colWidths []int, isHeader bool) {
	for j, cell := range row {
		if j > 0 {
			p.WriteString("  ") // Column separator
		}

		// Apply color
		if isHeader {
			p.Set(core.Blue)
			p.Set(core.Bold)
		} else {
			p.Set(core.Green)
		}

		p.WriteString(cell)
		p.Reset()

		// Add padding for alignment (except for the last column)
		if j < len(colWidths)-1 {
			cellWidth := runewidth.StringWidth(cell)
			padding := colWidths[j] - cellWidth
			for range padding {
				p.WriteString(" ")
			}
		}
	}
}

// writeVertical renders each data row as a vertical record with field labels.
func writeVertical(p *core.Printer, records [][]string) error {
	headers := records[0]

	// Calculate max header display width for right-alignment
	maxHeaderWidth := 0
	for _, h := range headers {
		if w := runewidth.StringWidth(h); w > maxHeaderWidth {
			maxHeaderWidth = w
		}
	}

	for i, row := range records[1:] { // Skip header row
		if i > 0 {
			p.WriteString("\n")
		}

		// Row separator
		p.Set(core.Dim)
		fmt.Fprintf(p, "--- Row %d ---\n", i+1)
		p.Reset()

		for j, cell := range row {
			header := ""
			if j < len(headers) {
				header = headers[j]
			}

			// Right-align header using display width
			padding := maxHeaderWidth - runewidth.StringWidth(header)
			for range padding {
				p.WriteString(" ")
			}

			// Header in blue+bold
			p.Set(core.Blue)
			p.Set(core.Bold)
			p.WriteString(header)
			p.Reset()
			p.WriteString(": ")

			// Value in green
			p.Set(core.Green)
			p.WriteString(cell)
			p.Reset()
			p.WriteString("\n")
		}
	}

	return nil
}
