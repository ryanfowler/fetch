package format

import (
	"bytes"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ryanfowler/fetch/internal/core"

	"github.com/mattn/go-runewidth"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	east "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

const (
	maxMarkdownBlockquoteOpeners = 256
	defaultMarkdownMaxWidth      = 100
)

// MarkdownOptions controls terminal-only Markdown presentation.
//
// MaxWidth is a maximum display width in terminal columns. A zero value uses
// the smaller of the current terminal width and 100 columns when the
// destination is a TTY. Non-terminal output remains raw Markdown regardless
// of this value.
type MarkdownOptions struct {
	MaxWidth int
}

// FormatMarkdown formats the provided Markdown to the Printer.
func FormatMarkdown(buf []byte, p *core.Printer) error {
	return FormatMarkdownWithOptions(buf, p, MarkdownOptions{})
}

// FormatMarkdownWithOptions formats the provided Markdown to the Printer
// using the supplied terminal presentation options.
func FormatMarkdownWithOptions(buf []byte, p *core.Printer, options MarkdownOptions) error {
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
	rest = truncateMarkdownBlockquoteOpeners(rest)

	md := goldmark.New(goldmark.WithExtensions(extension.Strikethrough, extension.Table))
	doc := md.Parser().Parse(text.NewReader(rest))

	width := 0
	if p.IsTerminal() {
		width = markdownWidth(options.MaxWidth, core.GetTerminalCols())
	}

	r := &mdRenderer{printer: p, source: rest, width: width}
	r.tty = p.IsTerminal()
	return ast.Walk(doc, r.walk)
}

func markdownWidth(maxWidth, terminalWidth int) int {
	if maxWidth <= 0 {
		maxWidth = defaultMarkdownMaxWidth
	}
	if terminalWidth > 0 && terminalWidth < maxWidth {
		return terminalWidth
	}
	return maxWidth
}

// truncateMarkdownBlockquoteOpeners caps line-leading blockquote opener runs.
// Goldmark's container handling becomes quadratic at extreme nesting depths, so
// discard openers beyond the largest depth that is useful for terminal output.
func truncateMarkdownBlockquoteOpeners(buf []byte) []byte {
	var out []byte
	copyFrom := 0

	for lineStart := 0; lineStart < len(buf); {
		lineEnd := lineStart
		for lineEnd < len(buf) && buf[lineEnd] != '\n' {
			lineEnd++
		}

		pos := lineStart
		for pos < lineEnd && pos-lineStart < 3 && buf[pos] == ' ' {
			pos++
		}

		keptEnd := pos
		openers := 0
		for pos < lineEnd && buf[pos] == '>' {
			pos++
			if pos < lineEnd && (buf[pos] == ' ' || buf[pos] == '\t') {
				pos++
			}
			openers++
			if openers == maxMarkdownBlockquoteOpeners {
				keptEnd = pos
			}
		}

		if openers > maxMarkdownBlockquoteOpeners {
			if out == nil {
				out = make([]byte, 0, len(buf)-(pos-keptEnd))
			}
			out = append(out, buf[copyFrom:keptEnd]...)
			copyFrom = pos
		}

		lineStart = lineEnd
		if lineStart < len(buf) {
			lineStart++
		}
	}

	if out == nil {
		return buf
	}
	return append(out, buf[copyFrom:]...)
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
	printer           *core.Printer
	source            []byte
	styles            []core.Sequence
	bqDepth           int
	links             []bool
	linkTargets       []string
	listContinuations []string
	width             int
	lineWidth         int
	pendingSpace      string
	tty               bool
}

type mdTableCell struct {
	node ast.Node
	text string
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

// popLink removes the active-state marker for the current link or image.
func (r *mdRenderer) popLink() bool {
	if len(r.links) == 0 {
		return false
	}
	active := r.links[len(r.links)-1]
	r.links = r.links[:len(r.links)-1]
	r.linkTargets = r.linkTargets[:len(r.linkTargets)-1]
	return active
}

// writeString writes trusted visible text while tracking its terminal display
// width. ANSI and OSC 8 sequences are emitted separately by Printer and do
// not reach this method, so byte length is never used as display width.
func (r *mdRenderer) writeString(s string) {
	_, _ = r.printer.WriteString(s)
	if r.width <= 0 {
		return
	}

	for len(s) > 0 {
		line := s
		if newline := strings.IndexByte(line, '\n'); newline >= 0 {
			line = line[:newline]
		}
		r.lineWidth = displayWidth(line, r.lineWidth)
		if len(line) == len(s) {
			return
		}
		r.lineWidth = 0
		s = s[len(line)+1:]
	}
}

// writeUntrusted writes terminal-safe visible text while tracking its display
// width after escaping controls.
func (r *mdRenderer) writeUntrusted(s string) {
	r.flushPendingSpace()
	r.writeString(core.TerminalSafeText(s))
}

// writeLinePrefix writes the prefix used by a continuation line. Blockquote
// rules come first, followed by indentation under the current list marker.
func (r *mdRenderer) writeLinePrefix() {
	r.writeBqPrefix()
	if r.width <= 0 {
		return
	}
	if n := len(r.listContinuations); n > 0 {
		r.writeString(r.listContinuations[n-1])
	}
}

// activeLinkTarget returns the target for the innermost active OSC 8 link.
func (r *mdRenderer) activeLinkTarget() string {
	if len(r.links) == 0 || !r.links[len(r.links)-1] {
		return ""
	}
	return r.linkTargets[len(r.linkTargets)-1]
}

// writeWrappedUntrusted writes text without allowing ordinary prose to
// exceed the configured display width. Wrapping is performed on terminal-safe
// text, so escaped control bytes are measured as the characters the terminal
// will actually display.
func (r *mdRenderer) writeWrappedUntrusted(s string) {
	r.writeWrappedUntrustedToWidth(s, r.width)
}

// writeWrappedUntrustedToWidth is writeWrappedUntrusted with an optional
// tighter line limit for text that must leave room for a following suffix.
func (r *mdRenderer) writeWrappedUntrustedToWidth(s string, limit int) {
	s = core.TerminalSafeText(s)
	if limit <= 0 {
		r.flushPendingSpace()
		r.writeString(s)
		return
	}

	pendingSpace := r.pendingSpace
	r.pendingSpace = ""
	for len(s) > 0 {
		if s[0] == '\n' {
			r.writeLineBreak()
			pendingSpace = ""
			s = s[1:]
			continue
		}

		// Consume a run of whitespace or non-whitespace. Whitespace at a
		// wrap point is discarded, just as terminal prose wrapping normally
		// does, while whitespace that fits is preserved.
		isSpace, _ := markdownSpaceAt(s)
		i := 0
		for i < len(s) && s[i] != '\n' {
			currentSpace, size := markdownSpaceAt(s[i:])
			if currentSpace != isSpace {
				break
			}
			i += size
		}
		token := s[:i]
		tokenWidth := runewidth.StringWidth(token)

		if isSpace {
			pendingSpace += token
			s = s[i:]
			continue
		}

		if r.lineWidth > 0 {
			pendingWidth := displayWidth(pendingSpace, r.lineWidth) - r.lineWidth
			switch {
			case r.lineWidth+pendingWidth+tokenWidth <= limit:
				r.writeString(pendingSpace)
			case r.lineWidth <= limit && r.lineWidth+tokenWidth > limit:
				r.writeLineBreak()
			}
		}
		pendingSpace = ""
		if tokenWidth == 0 || r.lineWidth+tokenWidth <= limit {
			r.writeString(token)
			s = s[i:]
			continue
		}

		// A single unbreakable word is split by display cell, ensuring that
		// prose has a useful upper bound even for long hashes or URLs.
		for len(token) > 0 {
			available := limit - r.lineWidth
			if available <= 0 {
				// A structural prefix can itself be as wide as the requested
				// width. There is no useful continuation line in that case;
				// emit the token rather than repeatedly reproducing the prefix.
				r.writeString(token)
				break
			}
			j := 0
			used := 0
			for j < len(token) {
				runeValue, size := utf8.DecodeRuneInString(token[j:])
				runeWidth := runewidth.RuneWidth(runeValue)
				if used > 0 && used+runeWidth > available {
					break
				}
				j += size
				used += runeWidth
			}
			if j == 0 {
				j = len(token[:1])
			}
			r.writeString(token[:j])
			token = token[j:]
			if len(token) > 0 {
				r.writeLineBreak()
			}
		}
		s = s[i:]
	}
	r.pendingSpace = pendingSpace
}

// flushPendingSpace emits whitespace retained for the next inline node.
// Block and line boundaries discard pending whitespace separately, so
// formatted output does not acquire trailing spaces.
func (r *mdRenderer) flushPendingSpace() {
	if r.pendingSpace == "" {
		return
	}

	pendingSpace := r.pendingSpace
	r.pendingSpace = ""
	if r.width > 0 && r.lineWidth > 0 &&
		displayWidth(pendingSpace, r.lineWidth) > r.width {
		r.writeLineBreak()
		return
	}
	r.writeString(pendingSpace)
}

// discardPendingSpace drops whitespace that ended an inline node at a block
// or line boundary.
func (r *mdRenderer) discardPendingSpace() {
	r.pendingSpace = ""
}

func markdownSpaceAt(s string) (bool, int) {
	r, size := utf8.DecodeRuneInString(s)
	return unicode.IsSpace(r), size
}

// displayWidth returns the terminal cell width of s starting at column start.
// Tabs are retained in terminal-safe text, so they must advance to the next
// eight-column tab stop rather than being treated as zero-width runes.
func displayWidth(s string, start int) int {
	width := start
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		s = s[size:]
		switch r {
		case '\n':
			width = 0
		case '\t':
			width += 8 - width%8
		default:
			width += runewidth.RuneWidth(r)
		}
	}
	return width
}

// writeLineBreak inserts a renderer-owned line break and restores the
// prefixes and styles needed by the continuation line. OSC 8 hyperlinks are
// temporarily closed so list or blockquote indentation cannot become part of
// the clickable region.
func (r *mdRenderer) writeLineBreak() {
	r.discardPendingSpace()
	if r.width <= 0 {
		r.writeString("\n")
		r.writeBqPrefix()
		r.reapplyStyles()
		return
	}

	linkTarget := r.activeLinkTarget()
	if linkTarget != "" {
		r.printer.EndHyperlink()
	}
	r.writeString("\n")
	r.writeLinePrefix()
	r.reapplyStyles()
	if linkTarget != "" {
		_ = r.printer.StartHyperlink(linkTarget)
	}
}

// writeBqPrefix writes the blockquote prefix repeatedly for the current
// nesting depth. TTY output uses a vertical rule; non-terminal output keeps
// the Markdown marker.
func (r *mdRenderer) writeBqPrefix() {
	r.discardPendingSpace()
	for range r.bqDepth {
		r.printer.Set(core.Dim)
		if r.tty {
			r.writeString("│")
		} else {
			r.writeString(">")
		}
		r.popAllAndRestore()
		r.writeString(" ")
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
			if r.tty {
				r.pushStyle(core.Bold)
				r.pushStyle(core.Blue)
			} else {
				hashes := strings.Repeat("#", v.Level)
				r.printer.Set(core.Bold)
				r.printer.Set(core.Blue)
				r.writeString(hashes)
				r.popAllAndRestore()
				if v.HasChildren() {
					r.writeString(" ")
				}
				r.pushStyle(core.Bold)
			}
		} else {
			if r.tty {
				r.popStyle()
				r.popStyle()
			} else {
				r.popStyle()
			}
			r.writeString("\n")
			if n.NextSibling() != nil {
				r.writeBqPrefix()
				r.writeString("\n")
			}
		}

	case *ast.Paragraph:
		if entering {
			// Write blockquote prefix unless inside a list item (marker already written).
			if _, inList := n.Parent().(*ast.ListItem); !inList {
				r.writeBqPrefix()
			}
		} else {
			r.writeString("\n")
			// Add blank line after paragraph unless it's the last child or in a tight list.
			if n.NextSibling() != nil {
				if _, inList := n.Parent().(*ast.ListItem); !inList {
					r.writeBqPrefix()
					r.writeString("\n")
				}
			}
		}

	case *ast.TextBlock:
		if entering {
			if _, inList := n.Parent().(*ast.ListItem); !inList {
				r.writeBqPrefix()
			}
		} else {
			r.writeString("\n")
		}

	case *ast.ThematicBreak:
		if entering {
			r.writeBqPrefix()
			r.printer.Set(core.Dim)
			r.writeString("---")
			r.popAllAndRestore()
			r.writeString("\n")
			if n.NextSibling() != nil {
				r.writeBqPrefix()
				r.writeString("\n")
			}
		}

	case *ast.CodeBlock:
		if entering {
			// Indented code block — render as cyan, skip children.
			content := r.nodeText(v)
			content = strings.TrimRight(content, "\n")
			for line := range strings.SplitSeq(content, "\n") {
				r.writeBqPrefix()
				r.printer.Set(core.Cyan)
				r.writeUntrusted(line)
				r.popAllAndRestore()
				r.writeString("\n")
			}
			if n.NextSibling() != nil {
				r.writeBqPrefix()
				r.writeString("\n")
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
				r.writeString("\n")
			}
			return status, nil
		}

	case *ast.Blockquote:
		if entering {
			// Keep quoted prose visually subordinate to the document around it.
			// One style layer is enough for nested quotes; their additional
			// vertical rules still communicate the nesting depth.
			if r.bqDepth == 0 {
				r.pushStyle(core.Dim)
			}
			r.bqDepth++
		} else {
			r.bqDepth--
			if r.bqDepth == 0 {
				r.popStyle()
			}
			if n.NextSibling() != nil {
				r.writeBqPrefix()
				r.writeString("\n")
			}
		}

	case *ast.List:
		if !entering && n.NextSibling() != nil {
			r.writeBqPrefix()
			r.writeString("\n")
		}

	case *ast.ListItem:
		if entering {
			list := v.Parent().(*ast.List)
			indent := r.listIndent(v)
			r.writeBqPrefix()
			r.writeString(indent)
			r.printer.Set(core.Blue)
			marker := ""
			if list.IsOrdered() {
				num := list.Start
				// Count preceding siblings to determine item number.
				for sib := v.Parent().FirstChild(); sib != nil && sib != n; sib = sib.NextSibling() {
					num++
				}
				marker = fmt.Sprintf("%d.", num)
			} else {
				if r.tty {
					marker = "•"
				} else {
					marker = string(list.Marker)
				}
			}
			r.writeString(marker)
			r.popAllAndRestore()
			r.writeString(" ")
			r.listContinuations = append(r.listContinuations,
				strings.Repeat(" ", runewidth.StringWidth(indent)+runewidth.StringWidth(marker)+1))
		} else {
			// newline handled by child paragraph/textblock
			if len(r.listContinuations) > 0 {
				r.listContinuations = r.listContinuations[:len(r.listContinuations)-1]
			}
		}

	case *ast.HTMLBlock:
		if entering {
			content := r.nodeText(v)
			content = strings.TrimRight(content, "\n")
			for line := range strings.SplitSeq(content, "\n") {
				r.writeBqPrefix()
				r.printer.Set(core.Dim)
				r.writeUntrusted(line)
				r.popAllAndRestore()
				r.writeString("\n")
			}
			if n.NextSibling() != nil {
				r.writeBqPrefix()
				r.writeString("\n")
			}
			return ast.WalkSkipChildren, nil
		}

	// Inline elements.

	case *ast.Text:
		if entering {
			r.writeWrappedUntrusted(string(v.Segment.Value(r.source)))
			if v.SoftLineBreak() {
				r.writeLineBreak()
			}
			if v.HardLineBreak() {
				r.writeLineBreak()
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
						r.writeUntrusted(string(r.source[start:seg.Start]))
					}
					r.writeUntrusted(string(seg.Value(r.source)))
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
			target := markdownLinkDestination(v.Destination)
			r.flushPendingSpace()
			active := r.printer.StartHyperlink(target)
			r.links = append(r.links, active)
			r.linkTargets = append(r.linkTargets, target)
			if !active {
				r.printer.Set(core.Dim)
				r.writeString("[")
				r.popAllAndRestore()
			}
			r.pushStyle(core.Underline)
		} else {
			active := r.popLink()
			r.popStyle()
			if active {
				r.flushPendingSpace()
				r.printer.EndHyperlink()
			} else {
				r.flushPendingSpace()
				r.printer.Set(core.Dim)
				r.writeString("](")
				r.popAllAndRestore()
				r.printer.Set(core.Cyan)
				r.writeWrappedUntrusted(string(v.Destination))
				r.popAllAndRestore()
				r.printer.Set(core.Dim)
				r.writeString(")")
				r.popAllAndRestore()
			}
		}

	case *ast.Image:
		if entering {
			target := markdownLinkDestination(v.Destination)
			r.flushPendingSpace()
			active := r.printer.StartHyperlink(target)
			r.links = append(r.links, active)
			r.linkTargets = append(r.linkTargets, target)
			if !active {
				r.printer.Set(core.Dim)
				r.writeString("![")
				r.popAllAndRestore()
			}
			r.pushStyle(core.Italic)
		} else {
			active := r.popLink()
			r.popStyle()
			if active {
				r.flushPendingSpace()
				r.printer.EndHyperlink()
			} else {
				r.flushPendingSpace()
				r.printer.Set(core.Dim)
				r.writeString("](")
				r.popAllAndRestore()
				r.printer.Set(core.Cyan)
				r.writeWrappedUntrusted(string(v.Destination))
				r.popAllAndRestore()
				r.printer.Set(core.Dim)
				r.writeString(")")
				r.popAllAndRestore()
			}
		}

	case *ast.AutoLink:
		if entering {
			label := string(v.Label(r.source))
			target := markdownAutoLinkTarget(v, r.source)
			r.flushPendingSpace()
			active := r.printer.StartHyperlink(target)
			r.links = append(r.links, active)
			r.linkTargets = append(r.linkTargets, target)
			if active {
				r.pushStyle(core.Underline)
				r.printer.Set(core.Cyan)
				r.writeWrappedUntrusted(label)
				r.popStyle()
				r.popLink()
				r.printer.EndHyperlink()
			} else {
				r.flushPendingSpace()
				r.writeString("<")
				r.printer.Set(core.Cyan)
				r.writeWrappedUntrusted(label)
				r.popAllAndRestore()
				r.writeString(">")
				r.popLink()
			}
		}

	case *ast.RawHTML:
		if entering {
			r.printer.Set(core.Dim)
			for i := 0; i < v.Segments.Len(); i++ {
				seg := v.Segments.At(i)
				r.writeUntrusted(string(seg.Value(r.source)))
			}
			r.popAllAndRestore()
			return ast.WalkSkipChildren, nil
		}

	case *ast.String:
		if entering {
			r.writeWrappedUntrusted(string(v.Value))
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
				r.writeString("\n")
			}
			return status, nil
		}
	}

	return ast.WalkContinue, nil
}

// markdownLinkDestination resolves Markdown escapes and entities before the
// value is placed in a terminal hyperlink target. Goldmark keeps the source
// spelling in the AST, while a terminal link needs the actual URL.
func markdownLinkDestination(destination []byte) string {
	return string(util.URLEscape(destination, true))
}

// markdownAutoLinkTarget returns the normalized target for an autolink. Email
// autolinks display their address but need an explicit mailto: target.
func markdownAutoLinkTarget(link *ast.AutoLink, source []byte) string {
	target := string(link.URL(source))
	if link.AutoLinkType == ast.AutoLinkEmail && !strings.HasPrefix(strings.ToLower(target), "mailto:") {
		target = "mailto:" + target
	}
	return string(util.URLEscape([]byte(target), false))
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
	r.writeString("```")
	if lang != "" {
		r.writeUntrusted(lang)
	}
	r.popAllAndRestore()
	r.writeString("\n")

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
				r.lineWidth = 0
				if len(content) > 0 && content[len(content)-1] != '\n' {
					r.writeString("\n")
				}
			}
		}
	}

	// Default: write each line in cyan independently.
	if !delegated {
		for _, line := range lines {
			r.writeBqPrefix()
			r.printer.Set(core.Cyan)
			r.writeUntrusted(line)
			r.popAllAndRestore()
			r.writeString("\n")
		}
	}

	// Closing fence.
	r.writeBqPrefix()
	r.printer.Set(core.Dim)
	r.writeString("```")
	r.popAllAndRestore()
	r.writeString("\n")

	return ast.WalkSkipChildren, nil
}

// renderTable renders a table extension node.
func (r *mdRenderer) renderTable(table *east.Table) (ast.WalkStatus, error) {
	// Collect all rows (header + body).
	var rows [][]mdTableCell
	var alignments []east.Alignment

	for row := table.FirstChild(); row != nil; row = row.NextSibling() {
		var cells []mdTableCell
		for cell := row.FirstChild(); cell != nil; cell = cell.NextSibling() {
			cells = append(cells, mdTableCell{node: cell, text: r.inlineText(cell)})
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
			cellText := terminalTableCell(cell.text)
			if width := runewidth.StringWidth(cellText); width > widths[i] {
				widths[i] = width
			}
		}
	}
	// Minimum width of 3 for separator row.
	for i := range widths {
		if widths[i] < 3 {
			widths[i] = 3
		}
	}

	// A wide table is more readable as a sequence of labeled records than as
	// a grid that forces the terminal to wrap every row independently. The
	// vertical form also gives long cell values the normal prose wrapper.
	if r.width > 0 && tableDisplayWidth(widths)+r.bqPrefixWidth() > r.width {
		return r.renderVerticalTable(rows), nil
	}

	// Render header row.
	r.writeBqPrefix()
	r.renderTableRow(rows[0], widths, true)
	r.writeString("\n")

	// Render separator.
	r.writeBqPrefix()
	r.printer.Set(core.Dim)
	r.writeString("|")
	for i, w := range widths {
		a := east.AlignNone
		if i < len(alignments) {
			a = alignments[i]
		}
		switch a {
		case east.AlignLeft:
			r.writeString(":")
			r.writeString(strings.Repeat("-", w-1))
		case east.AlignRight:
			r.writeString(strings.Repeat("-", w-1))
			r.writeString(":")
		case east.AlignCenter:
			r.writeString(":")
			r.writeString(strings.Repeat("-", w-2))
			r.writeString(":")
		default:
			r.writeString(strings.Repeat("-", w))
		}
		r.writeString("|")
	}
	r.popAllAndRestore()
	r.writeString("\n")

	// Render body rows.
	for _, row := range rows[1:] {
		r.writeBqPrefix()
		r.renderTableRow(row, widths, false)
		r.writeString("\n")
	}

	return ast.WalkSkipChildren, nil
}

func tableDisplayWidth(widths []int) int {
	width := 1 // leading border
	for _, columnWidth := range widths {
		width += columnWidth + 3 // spaces, cell, and trailing border
	}
	return width
}

func (r *mdRenderer) bqPrefixWidth() int {
	return r.bqDepth * 2 // rule plus following space
}

// renderVerticalTable renders a wide Markdown table as labeled records. The
// values are kept styled when they fit on one line; oversized values use the
// same display-width-aware wrapper as prose.
func (r *mdRenderer) renderVerticalTable(rows [][]mdTableCell) ast.WalkStatus {
	if len(rows) == 0 {
		return ast.WalkSkipChildren
	}

	headers := rows[0]
	body := rows[1:]
	if len(body) == 0 {
		body = rows[:1]
	}

	for rowIndex, row := range body {
		if rowIndex > 0 {
			r.writeString("\n")
		}
		r.writeBqPrefix()
		r.writeWrappedUntrusted(fmt.Sprintf("--- Row %d ---", rowIndex+1))
		r.writeString("\n")

		columnCount := max(len(headers), len(row))
		for column := range columnCount {
			r.writeBqPrefix()
			label := ""
			if column < len(headers) {
				label = terminalTableCell(headers[column].text)
			}
			// Wrap the label separately so the separator is retained even
			// though the prose wrapper intentionally drops trailing spaces.
			labelLimit := r.width
			if labelLimit > 0 {
				// Keep the ": " separator on the same logical field line,
				// including when the label would otherwise exactly fill it.
				labelLimit -= 2
			}
			r.writeWrappedUntrustedToWidth(label, labelLimit)
			r.writeString(": ")

			cell := mdTableCell{}
			if column < len(row) {
				cell = row[column]
			}
			safeCell := terminalTableCell(cell.text)
			if r.width <= 0 || runewidth.StringWidth(safeCell) <= r.width-r.lineWidth {
				r.renderTableCell(cell.node)
			} else {
				r.writeWrappedUntrusted(safeCell)
			}
			r.writeString("\n")
		}
	}

	return ast.WalkSkipChildren
}

// renderTableRow renders a single table row.
func (r *mdRenderer) renderTableRow(cells []mdTableCell, widths []int, isHeader bool) {
	r.printer.Set(core.Dim)
	r.writeString("|")
	r.popAllAndRestore()
	for i, w := range widths {
		cell := mdTableCell{}
		if i < len(cells) {
			cell = cells[i]
		}
		safeCell := terminalTableCell(cell.text)
		r.writeString(" ")
		if isHeader {
			r.pushStyle(core.Bold)
			r.pushStyle(core.Blue)
		}
		if r.tty {
			r.renderTableCell(cell.node)
		} else {
			r.writeUntrusted(safeCell)
		}
		if isHeader {
			r.popStyle()
			r.popStyle()
		}
		r.writeString(strings.Repeat(" ", w-runewidth.StringWidth(safeCell)))
		r.writeString(" ")
		r.printer.Set(core.Dim)
		r.writeString("|")
		r.popAllAndRestore()
	}
}

// renderTableCell renders inline nodes while keeping line breaks inside a
// table cell from escaping the row. This lets TTY tables retain semantic
// formatting, including clickable links.
func (r *mdRenderer) renderTableCell(cell ast.Node) {
	if cell == nil {
		return
	}
	for child := cell.FirstChild(); child != nil; child = child.NextSibling() {
		_ = ast.Walk(child, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
			if t, ok := n.(*ast.Text); ok && entering {
				text := strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(string(t.Segment.Value(r.source)))
				r.writeUntrusted(text)
				if t.SoftLineBreak() || t.HardLineBreak() {
					r.writeString(" ")
				}
				return ast.WalkSkipChildren, nil
			}
			return r.walk(n, entering)
		})
	}
}

// terminalTableCell keeps a cell on one display row. Markdown permits line
// breaks inside table cells, but preserving them would move the following
// cells out of alignment in a terminal table.
func terminalTableCell(cell string) string {
	cell = strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t':
			return ' '
		default:
			return r
		}
	}, cell)
	return core.TerminalSafeText(cell)
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
	if s, ok := n.(*ast.String); ok {
		sb.Write(s.Value)
	}
	if a, ok := n.(*ast.AutoLink); ok {
		sb.Write(a.Label(r.source))
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
