package format

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/ryanfowler/fetch/internal/core"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	east "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/text"
)

// FormatMarkdown formats the provided Markdown to the Printer.
func FormatMarkdown(buf []byte, p *core.Printer) error {
	if len(buf) == 0 {
		return nil
	}

	frontMatter, rest := extractFrontMatter(buf)
	if frontMatter != nil {
		if err := FormatYAML(frontMatter, p); err != nil {
			// FormatYAML calls Discard on error, so fall through to
			// render the original buffer as plain markdown.
			rest = buf
		} else if len(rest) > 0 {
			p.WriteString("\n\n")
		}
	}

	if len(rest) == 0 {
		return nil
	}

	md := goldmark.New(goldmark.WithExtensions(extension.Strikethrough, extension.Table))
	doc := md.Parser().Parse(text.NewReader(rest))

	r := &mdRenderer{printer: p, source: rest}
	return ast.Walk(doc, r.walk)
}

// extractFrontMatter checks if buf starts with YAML front matter delimited by
// "---" lines and returns the front matter (including delimiters) and the
// remaining content. If no valid front matter is found, it returns (nil, buf).
func extractFrontMatter(buf []byte) (frontMatter, rest []byte) {
	// Must start with "---\n" or "---\r\n".
	if !bytes.HasPrefix(buf, []byte("---\n")) && !bytes.HasPrefix(buf, []byte("---\r\n")) {
		return nil, buf
	}

	// Scan past the opening delimiter line.
	i := bytes.IndexByte(buf, '\n') + 1

	// Look for a closing "---" line.
	for i < len(buf) {
		lineEnd := bytes.IndexByte(buf[i:], '\n')
		var line []byte
		if lineEnd == -1 {
			line = buf[i:]
		} else {
			line = buf[i : i+lineEnd]
		}

		// Trim trailing \r for Windows line endings.
		line = bytes.TrimRight(line, "\r")

		if string(line) == "---" {
			// End of front matter: include the closing delimiter line.
			end := i + len(line)
			if lineEnd != -1 {
				end = i + lineEnd + 1
			}
			return buf[:end], buf[end:]
		}

		if lineEnd == -1 {
			// Reached end of input without closing delimiter.
			break
		}
		i += lineEnd + 1
	}

	return nil, buf
}

// mdRenderer walks a goldmark AST and writes ANSI-styled output.
type mdRenderer struct {
	printer *core.Printer
	source  []byte
	styles  []core.Sequence
	bqDepth int
}

// pushStyle appends a style to the stack and sets it on the printer.
func (r *mdRenderer) pushStyle(s core.Sequence) {
	r.styles = append(r.styles, s)
	r.printer.Set(s)
}

// popStyle removes the top style, resets all, and re-applies remaining styles.
func (r *mdRenderer) popStyle() {
	if len(r.styles) == 0 {
		return
	}
	r.styles = r.styles[:len(r.styles)-1]
	r.printer.Reset()
	for _, s := range r.styles {
		r.printer.Set(s)
	}
}

// writeBqPrefix writes the blockquote prefix ("> " repeated bqDepth times).
func (r *mdRenderer) writeBqPrefix() {
	for range r.bqDepth {
		r.printer.Set(core.Dim)
		r.printer.WriteString(">")
		r.popAllAndRestore()
		r.printer.WriteString(" ")
	}
}

// popAllAndRestore resets then re-applies all styles on the stack.
func (r *mdRenderer) popAllAndRestore() {
	r.printer.Reset()
	for _, s := range r.styles {
		r.printer.Set(s)
	}
}

// reapplyStyles re-emits all styles on the stack without resetting first.
// Used after line breaks to ensure styles persist across lines.
func (r *mdRenderer) reapplyStyles() {
	for _, s := range r.styles {
		r.printer.Set(s)
	}
}

// nodeText returns the concatenated text content of a node's children segments.
func (r *mdRenderer) nodeText(n ast.Node) string {
	var sb strings.Builder
	for i := 0; i < n.Lines().Len(); i++ {
		seg := n.Lines().At(i)
		sb.Write(seg.Value(r.source))
	}
	return sb.String()
}

func (r *mdRenderer) walk(n ast.Node, entering bool) (ast.WalkStatus, error) {
	switch v := n.(type) {
	case *ast.Document:
		// No output for document node.

	case *ast.Heading:
		if entering {
			r.writeBqPrefix()
			hashes := strings.Repeat("#", v.Level)
			r.printer.Set(core.Bold)
			r.printer.Set(core.Blue)
			r.printer.WriteString(hashes)
			r.popAllAndRestore()
			if v.HasChildren() {
				r.printer.WriteString(" ")
			}
			r.pushStyle(core.Bold)
		} else {
			r.popStyle()
			r.printer.WriteString("\n")
			if n.NextSibling() != nil {
				r.writeBqPrefix()
				r.printer.WriteString("\n")
			}
		}

	case *ast.Paragraph:
		if entering {
			// Write blockquote prefix unless inside a list item (marker already written).
			if _, inList := n.Parent().(*ast.ListItem); !inList {
				r.writeBqPrefix()
			}
		} else {
			r.printer.WriteString("\n")
			// Add blank line after paragraph unless it's the last child or in a tight list.
			if n.NextSibling() != nil {
				if _, inList := n.Parent().(*ast.ListItem); !inList {
					r.writeBqPrefix()
					r.printer.WriteString("\n")
				}
			}
		}

	case *ast.TextBlock:
		if entering {
			if _, inList := n.Parent().(*ast.ListItem); !inList {
				r.writeBqPrefix()
			}
		} else {
			r.printer.WriteString("\n")
		}

	case *ast.ThematicBreak:
		if entering {
			r.writeBqPrefix()
			r.printer.Set(core.Dim)
			r.printer.WriteString("---")
			r.popAllAndRestore()
			r.printer.WriteString("\n")
			if n.NextSibling() != nil {
				r.writeBqPrefix()
				r.printer.WriteString("\n")
			}
		}

	case *ast.CodeBlock:
		if entering {
			// Indented code block — render as cyan, skip children.
			content := r.nodeText(v)
			content = strings.TrimRight(content, "\n")
			for _, line := range strings.Split(content, "\n") {
				r.writeBqPrefix()
				r.printer.Set(core.Cyan)
				r.printer.WriteString(line)
				r.popAllAndRestore()
				r.printer.WriteString("\n")
			}
			if n.NextSibling() != nil {
				r.writeBqPrefix()
				r.printer.WriteString("\n")
			}
			return ast.WalkSkipChildren, nil
		}

	case *ast.FencedCodeBlock:
		if entering {
			status, err := r.renderFencedCodeBlock(v)
			if err != nil {
				return status, err
			}
			if n.NextSibling() != nil {
				r.writeBqPrefix()
				r.printer.WriteString("\n")
			}
			return status, nil
		}

	case *ast.Blockquote:
		if entering {
			r.bqDepth++
		} else {
			r.bqDepth--
			if n.NextSibling() != nil {
				r.writeBqPrefix()
				r.printer.WriteString("\n")
			}
		}

	case *ast.List:
		if !entering && n.NextSibling() != nil {
			r.writeBqPrefix()
			r.printer.WriteString("\n")
		}

	case *ast.ListItem:
		if entering {
			list := v.Parent().(*ast.List)
			indent := r.listIndent(v)
			r.writeBqPrefix()
			r.printer.WriteString(indent)
			r.printer.Set(core.Blue)
			if list.IsOrdered() {
				num := list.Start
				// Count preceding siblings to determine item number.
				for sib := v.Parent().FirstChild(); sib != nil && sib != n; sib = sib.NextSibling() {
					num++
				}
				r.printer.WriteString(fmt.Sprintf("%d.", num))
			} else {
				r.printer.WriteString(string(list.Marker))
			}
			r.popAllAndRestore()
			r.printer.WriteString(" ")
		} else {
			// newline handled by child paragraph/textblock
		}

	case *ast.HTMLBlock:
		if entering {
			content := r.nodeText(v)
			content = strings.TrimRight(content, "\n")
			for _, line := range strings.Split(content, "\n") {
				r.writeBqPrefix()
				r.printer.Set(core.Dim)
				r.printer.WriteString(line)
				r.popAllAndRestore()
				r.printer.WriteString("\n")
			}
			if n.NextSibling() != nil {
				r.writeBqPrefix()
				r.printer.WriteString("\n")
			}
			return ast.WalkSkipChildren, nil
		}

	// Inline elements.

	case *ast.Text:
		if entering {
			r.printer.Write(v.Segment.Value(r.source))
			if v.SoftLineBreak() {
				r.printer.WriteString("\n")
				r.writeBqPrefix()
				r.reapplyStyles()
			}
			if v.HardLineBreak() {
				r.printer.WriteString("\n")
				r.writeBqPrefix()
				r.reapplyStyles()
			}
		}

	case *ast.CodeSpan:
		if entering {
			r.printer.Set(core.Cyan)
			for c := v.FirstChild(); c != nil; c = c.NextSibling() {
				if t, ok := c.(*ast.Text); ok {
					seg := t.Segment
					// Restore leading whitespace that paragraph parsing
					// stripped from continuation lines.
					start := seg.Start
					for start > 0 && (r.source[start-1] == ' ' || r.source[start-1] == '\t') {
						start--
					}
					if start < seg.Start && start > 0 && r.source[start-1] == '\n' {
						r.printer.Write(r.source[start:seg.Start])
					}
					r.printer.Write(seg.Value(r.source))
				}
			}
			r.popAllAndRestore()
			return ast.WalkSkipChildren, nil
		}

	case *ast.Emphasis:
		if entering {
			if v.Level == 2 {
				r.pushStyle(core.Bold)
			} else {
				r.pushStyle(core.Italic)
			}
		} else {
			r.popStyle()
		}

	case *ast.Link:
		if entering {
			r.printer.Set(core.Dim)
			r.printer.WriteString("[")
			r.popAllAndRestore()
			r.pushStyle(core.Underline)
		} else {
			r.popStyle()
			r.printer.Set(core.Dim)
			r.printer.WriteString("](")
			r.popAllAndRestore()
			r.printer.Set(core.Cyan)
			r.printer.Write(v.Destination)
			r.popAllAndRestore()
			r.printer.Set(core.Dim)
			r.printer.WriteString(")")
			r.popAllAndRestore()
		}

	case *ast.Image:
		if entering {
			r.printer.Set(core.Dim)
			r.printer.WriteString("![")
			r.popAllAndRestore()
			r.pushStyle(core.Italic)
		} else {
			r.popStyle()
			r.printer.Set(core.Dim)
			r.printer.WriteString("](")
			r.popAllAndRestore()
			r.printer.Set(core.Cyan)
			r.printer.Write(v.Destination)
			r.popAllAndRestore()
			r.printer.Set(core.Dim)
			r.printer.WriteString(")")
			r.popAllAndRestore()
		}

	case *ast.AutoLink:
		if entering {
			r.printer.WriteString("<")
			r.printer.Set(core.Cyan)
			r.printer.Write(v.URL(r.source))
			r.popAllAndRestore()
			r.printer.WriteString(">")
		}

	case *ast.RawHTML:
		if entering {
			r.printer.Set(core.Dim)
			for i := 0; i < v.Segments.Len(); i++ {
				seg := v.Segments.At(i)
				r.printer.Write(seg.Value(r.source))
			}
			r.popAllAndRestore()
			return ast.WalkSkipChildren, nil
		}

	case *ast.String:
		if entering {
			r.printer.Write(v.Value)
		}

	// Extension: Strikethrough
	case *east.Strikethrough:
		if entering {
			r.pushStyle(core.Dim)
		} else {
			r.popStyle()
		}

	// Extension: Table
	case *east.Table:
		if entering {
			status, err := r.renderTable(v)
			if err != nil {
				return status, err
			}
			if n.NextSibling() != nil {
				r.writeBqPrefix()
				r.printer.WriteString("\n")
			}
			return status, nil
		}
	}

	return ast.WalkContinue, nil
}

// listIndent returns indentation string based on list nesting depth.
func (r *mdRenderer) listIndent(item *ast.ListItem) string {
	depth := 0
	for p := item.Parent(); p != nil; p = p.Parent() {
		if _, ok := p.(*ast.ListItem); ok {
			depth++
		}
	}
	return strings.Repeat("  ", depth)
}

// renderFencedCodeBlock renders a fenced code block, delegating to known formatters.
func (r *mdRenderer) renderFencedCodeBlock(v *ast.FencedCodeBlock) (ast.WalkStatus, error) {
	lang := ""
	if v.Info != nil {
		lang = strings.TrimSpace(string(v.Info.Segment.Value(r.source)))
		// Strip anything after a space (e.g. "js title=foo" → "js").
		if idx := strings.IndexByte(lang, ' '); idx >= 0 {
			lang = lang[:idx]
		}
	}

	// Opening fence.
	r.writeBqPrefix()
	r.printer.Set(core.Dim)
	r.printer.WriteString("```")
	if lang != "" {
		r.printer.WriteString(lang)
	}
	r.printer.Reset()
	r.printer.WriteString("\n")

	// Collect body lines.
	var lines []string
	for i := 0; i < v.Lines().Len(); i++ {
		seg := v.Lines().At(i)
		line := string(seg.Value(r.source))
		line = strings.TrimRight(line, "\n")
		lines = append(lines, line)
	}

	// Try to delegate to a known formatter. Flush before delegating so
	// that a formatter's Discard on error cannot erase prior output.
	// Skip delegation inside blockquotes since delegated formatters
	// cannot emit blockquote prefixes.
	delegated := false
	if lang != "" && len(lines) > 0 && r.bqDepth == 0 {
		content := strings.Join(lines, "\n")
		if formatter := getFormatterForLang(lang); formatter != nil {
			r.printer.Flush()
			if err := formatter([]byte(content), r.printer); err == nil {
				delegated = true
				if content[len(content)-1] != '\n' {
					r.printer.WriteString("\n")
				}
			}
		}
	}

	// Default: write each line in cyan independently.
	if !delegated {
		for _, line := range lines {
			r.writeBqPrefix()
			r.printer.Set(core.Cyan)
			r.printer.WriteString(line)
			r.printer.Reset()
			r.printer.WriteString("\n")
		}
	}

	// Closing fence.
	r.writeBqPrefix()
	r.printer.Set(core.Dim)
	r.printer.WriteString("```")
	r.printer.Reset()
	r.printer.WriteString("\n")

	return ast.WalkSkipChildren, nil
}

// renderTable renders a table extension node.
func (r *mdRenderer) renderTable(table *east.Table) (ast.WalkStatus, error) {
	// Collect all rows (header + body).
	var rows [][]string
	var alignments []east.Alignment

	for row := table.FirstChild(); row != nil; row = row.NextSibling() {
		var cells []string
		for cell := row.FirstChild(); cell != nil; cell = cell.NextSibling() {
			cells = append(cells, r.inlineText(cell))
		}
		rows = append(rows, cells)
	}

	if len(rows) == 0 {
		return ast.WalkSkipChildren, nil
	}

	// Get alignments from header cells.
	if header := table.FirstChild(); header != nil {
		for cell := header.FirstChild(); cell != nil; cell = cell.NextSibling() {
			if tc, ok := cell.(*east.TableCell); ok {
				alignments = append(alignments, tc.Alignment)
			}
		}
	}

	// Calculate column widths.
	numCols := 0
	for _, row := range rows {
		if len(row) > numCols {
			numCols = len(row)
		}
	}
	widths := make([]int, numCols)
	for _, row := range rows {
		for i, cell := range row {
			if len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}
	// Minimum width of 3 for separator row.
	for i := range widths {
		if widths[i] < 3 {
			widths[i] = 3
		}
	}

	// Render header row.
	r.writeBqPrefix()
	r.renderTableRow(rows[0], widths, true)
	r.printer.WriteString("\n")

	// Render separator.
	r.writeBqPrefix()
	r.printer.Set(core.Dim)
	r.printer.WriteString("|")
	for i, w := range widths {
		a := east.AlignNone
		if i < len(alignments) {
			a = alignments[i]
		}
		switch a {
		case east.AlignLeft:
			r.printer.WriteString(":")
			r.printer.WriteString(strings.Repeat("-", w-1))
		case east.AlignRight:
			r.printer.WriteString(strings.Repeat("-", w-1))
			r.printer.WriteString(":")
		case east.AlignCenter:
			r.printer.WriteString(":")
			r.printer.WriteString(strings.Repeat("-", w-2))
			r.printer.WriteString(":")
		default:
			r.printer.WriteString(strings.Repeat("-", w))
		}
		r.printer.WriteString("|")
	}
	r.popAllAndRestore()
	r.printer.WriteString("\n")

	// Render body rows.
	for _, row := range rows[1:] {
		r.writeBqPrefix()
		r.renderTableRow(row, widths, false)
		r.printer.WriteString("\n")
	}

	return ast.WalkSkipChildren, nil
}

// renderTableRow renders a single table row.
func (r *mdRenderer) renderTableRow(cells []string, widths []int, isHeader bool) {
	r.printer.Set(core.Dim)
	r.printer.WriteString("|")
	r.popAllAndRestore()
	for i, w := range widths {
		cell := ""
		if i < len(cells) {
			cell = cells[i]
		}
		r.printer.WriteString(" ")
		if isHeader {
			r.printer.Set(core.Bold)
		}
		r.printer.WriteString(cell)
		if isHeader {
			r.popAllAndRestore()
		}
		r.printer.WriteString(strings.Repeat(" ", w-len(cell)))
		r.printer.WriteString(" ")
		r.printer.Set(core.Dim)
		r.printer.WriteString("|")
		r.popAllAndRestore()
	}
}

// inlineText extracts the plain text from an inline node's children.
func (r *mdRenderer) inlineText(n ast.Node) string {
	var sb strings.Builder
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		r.collectText(&sb, c)
	}
	return sb.String()
}

func (r *mdRenderer) collectText(sb *strings.Builder, n ast.Node) {
	if t, ok := n.(*ast.Text); ok {
		sb.Write(t.Segment.Value(r.source))
	}
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		r.collectText(sb, c)
	}
}

// getFormatterForLang returns a BufferedFormatter for the given language tag,
// or nil if no matching formatter exists.
func getFormatterForLang(lang string) BufferedFormatter {
	switch strings.ToLower(lang) {
	case "json":
		return FormatJSON
	case "yaml", "yml":
		return FormatYAML
	case "xml":
		return FormatXML
	case "html":
		return FormatHTML
	case "css":
		return FormatCSS
	default:
		return nil
	}
}
