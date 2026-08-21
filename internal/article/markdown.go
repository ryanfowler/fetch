// Package article contains the bounded, text-only rendering used by article
// extraction. It deliberately accepts a DOM instead of an HTML string so the
// extractor does not need to serialize and parse its result again.
package article

import (
	"errors"
	"strconv"
	"strings"
	"unicode"

	"github.com/ryanfowler/fetch/internal/core"
	html "golang.org/x/net/html"
)

const (
	// MaxMarkdownDepth is separate from readability's element limit. A deeply
	// nested, otherwise small document must not consume an unbounded Go stack.
	MaxMarkdownDepth = core.MaxNestingDepth

	// Markdown can grow when text is escaped. Keep that growth bounded even
	// though article input is bounded separately by the extraction pipeline.
	maxMarkdownBytes = int(core.MaxArticleBodyBytes) * 2
)

var (
	// ErrNilNode reports an invalid conversion root.
	ErrNilNode = errors.New("article markdown: nil HTML node")
	// ErrMarkdownTooLarge reports output that cannot be retained safely.
	ErrMarkdownTooLarge = errors.New("article markdown: rendered output exceeds the size limit")
)

// Convert renders root and its descendants as deterministic CommonMark-style
// Markdown. root may be a document node or any content node. The result has a
// single trailing newline when it contains content.
//
// The renderer is intentionally conservative. It omits executable and
// presentation-only elements, treats unknown elements according to their
// block/inline role, and skips descendants beyond MaxMarkdownDepth.
func Convert(root *html.Node) (string, error) {
	if root == nil {
		return "", ErrNilNode
	}
	r := renderer{active: make(map[*html.Node]bool)}
	var blocks []string
	var err error
	if root.Type == html.ElementNode && isBlockNode(root) {
		var value string
		value, err = r.block(root)
		if value != "" {
			blocks = []string{value}
		}
	} else if root.Type == html.TextNode {
		value := strings.TrimSpace(escapeText(root.Data))
		if value != "" {
			blocks = []string{value}
		}
	} else if root.Type == html.ElementNode {
		var value string
		value, err = r.inline(root)
		if value != "" {
			blocks = []string{strings.TrimSpace(value)}
		}
	} else {
		blocks, err = r.blocks(root)
	}
	if err != nil {
		return "", err
	}
	result, err := joinBlocks(blocks)
	if err != nil {
		return "", err
	}
	result = strings.TrimRight(result, " \t\r\n")
	if result == "" {
		return "", nil
	}
	result += "\n"
	if err := r.check(result); err != nil {
		return "", err
	}
	return result, nil
}

type renderer struct {
	active map[*html.Node]bool
	depth  int
}

func (r *renderer) check(value string) error {
	if len(value) > maxMarkdownBytes {
		return ErrMarkdownTooLarge
	}
	return nil
}

func (r *renderer) enter(node *html.Node) bool {
	if node == nil || r.depth >= MaxMarkdownDepth || r.active[node] {
		return false
	}
	r.depth++
	r.active[node] = true
	return true
}

func (r *renderer) leave(node *html.Node) {
	delete(r.active, node)
	r.depth--
}

func (r *renderer) blocks(root *html.Node) ([]string, error) {
	if root == nil {
		return nil, nil
	}
	if root.Type == html.TextNode {
		value := strings.TrimSpace(escapeText(root.Data))
		if value == "" {
			return nil, nil
		}
		return []string{value}, nil
	}
	if isOmitted(root) {
		return nil, nil
	}
	if !r.enter(root) {
		return nil, nil
	}
	defer r.leave(root)

	return r.blocksChildren(root)
}

func (r *renderer) blocksChildren(root *html.Node) ([]string, error) {
	var blocks []string
	var inline strings.Builder
	seenChildren := make(map[*html.Node]bool)
	flushInline := func() error {
		value := strings.TrimSpace(inline.String())
		inline.Reset()
		if value == "" {
			return nil
		}
		if err := r.check(value); err != nil {
			return err
		}
		blocks = append(blocks, value)
		return nil
	}

	for child := root.FirstChild; child != nil && !seenChildren[child]; child = child.NextSibling {
		seenChildren[child] = true
		if isOmitted(child) {
			continue
		}
		if isBlockNode(child) || isBlockContainer(child) {
			if err := flushInline(); err != nil {
				return nil, err
			}
			value, err := r.block(child)
			if err != nil {
				return nil, err
			}
			if value != "" {
				blocks = append(blocks, value)
			}
			continue
		}
		value, err := r.inline(child)
		if err != nil {
			return nil, err
		}
		if err := appendInlineBounded(&inline, value); err != nil {
			return nil, err
		}
	}
	if err := flushInline(); err != nil {
		return nil, err
	}
	return blocks, nil
}

func (r *renderer) block(node *html.Node) (string, error) {
	if node == nil || isOmitted(node) {
		return "", nil
	}
	if !r.enter(node) {
		return "", nil
	}
	defer r.leave(node)

	tag := nodeTag(node)
	switch {
	case isHeading(tag):
		value, err := r.inlineChildren(node)
		if err != nil {
			return "", err
		}
		value = strings.TrimSpace(value)
		if value == "" {
			return "", nil
		}
		result := strings.Repeat("#", headingLevel(tag)) + " " + value
		return result, r.check(result)
	case tag == "p" || tag == "figcaption" || tag == "summary" || tag == "dt" || tag == "dd":
		value, err := r.inlineChildren(node)
		if err != nil {
			return "", err
		}
		result := strings.TrimSpace(value)
		return result, r.check(result)
	case tag == "pre":
		return r.codeBlock(node)
	case tag == "blockquote":
		return r.blockQuote(node)
	case tag == "ul" || tag == "ol":
		return r.list(node)
	case tag == "table":
		return r.table(node)
	case tag == "hr":
		return "---", nil
	case tag == "li":
		parts, err := r.listItemParts(node)
		if err != nil {
			return "", err
		}
		return joinParts(parts)
	case tag == "thead" || tag == "tbody" || tag == "tfoot" || tag == "tr":
		return r.container(node)
	default:
		if isBlockTag(tag) {
			return r.container(node)
		}
		if hasBlockChild(node) {
			children, err := r.blocksChildren(node)
			if err != nil {
				return "", err
			}
			return joinBlocks(children)
		}
		return r.inline(node)
	}
}

func (r *renderer) container(node *html.Node) (string, error) {
	children, err := r.blocksChildren(node)
	if err != nil {
		return "", err
	}
	return joinBlocks(children)
}

func (r *renderer) inlineChildren(node *html.Node) (string, error) {
	if node == nil {
		return "", nil
	}
	var out strings.Builder
	seenChildren := make(map[*html.Node]bool)
	for child := node.FirstChild; child != nil && !seenChildren[child]; child = child.NextSibling {
		seenChildren[child] = true
		if isOmitted(child) {
			continue
		}
		value, err := r.inline(child)
		if err != nil {
			return "", err
		}
		if child.Type == html.TextNode {
			value = escapeTextInContext(child.Data, out.String())
		}
		if err := appendInlineBounded(&out, value); err != nil {
			return "", err
		}
	}
	return out.String(), nil
}

func (r *renderer) inline(node *html.Node) (string, error) {
	if node == nil || isOmitted(node) {
		return "", nil
	}
	if node.Type == html.TextNode {
		return escapeText(node.Data), nil
	}
	if node.Type != html.ElementNode {
		return "", nil
	}
	if !r.enter(node) {
		return "", nil
	}
	defer r.leave(node)

	tag := nodeTag(node)
	if !isInlineTag(tag) && hasBlockChild(node) {
		blocks, err := r.blocksChildren(node)
		if err != nil {
			return "", err
		}
		return joinBlocks(blocks)
	}
	children, err := r.inlineChildren(node)
	if err != nil {
		return "", err
	}
	switch tag {
	case "strong", "b":
		return r.wrap(children, "**", "**")
	case "em", "i":
		return r.wrap(children, "*", "*")
	case "del", "s", "strike":
		return r.wrap(children, "~~", "~~")
	case "code":
		value, err := r.rawText(node)
		if err != nil {
			return "", err
		}
		return inlineCode(value), nil
	case "a":
		href := attr(node, "href")
		if href == "" {
			return children, nil
		}
		if strings.TrimSpace(children) == "" {
			children = escapeText(href)
		}
		result := "[" + children + "](" + escapeDestination(href)
		if title := attr(node, "title"); title != "" {
			result += " \"" + escapeLinkTitle(title) + "\""
		}
		result += ")"
		return result, r.check(result)
	case "img":
		src := attr(node, "src")
		if src == "" {
			return "", nil
		}
		result := "![" + escapeText(attr(node, "alt")) + "](" + escapeDestination(src)
		if title := attr(node, "title"); title != "" {
			result += " \"" + escapeLinkTitle(title) + "\""
		}
		result += ")"
		return result, r.check(result)
	case "br":
		return "  \n", nil
	case "wbr":
		return "", nil
	case "input", "button", "select", "option", "textarea", "canvas", "svg":
		return "", nil
	default:
		return children, r.check(children)
	}
}

func (r *renderer) codeBlock(node *html.Node) (string, error) {
	content, err := r.rawText(node)
	if err != nil {
		return "", err
	}
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")
	fence := longestRun(content, '`') + 1
	if fence < 3 {
		fence = 3
	}
	language := ""
	if code := firstElement(node, "code"); code != nil {
		class := attr(code, "class")
		for _, value := range strings.Fields(class) {
			if strings.HasPrefix(value, "language-") && len(value) > len("language-") {
				candidate := strings.TrimSpace(value[len("language-"):])
				if safeCodeLanguage(candidate) {
					language = candidate
				}
				break
			}
		}
	}
	content = strings.TrimSuffix(content, "\n")
	result := strings.Repeat("`", fence) + language + "\n" + content + "\n" + strings.Repeat("`", fence)
	return result, r.check(result)
}

func (r *renderer) blockQuote(node *html.Node) (string, error) {
	children, err := r.blocksChildren(node)
	if err != nil {
		return "", err
	}
	value, err := joinBlocks(children)
	if err != nil {
		return "", err
	}
	if value == "" {
		return "", nil
	}
	lines := strings.Split(value, "\n")
	for i, line := range lines {
		if line == "" {
			lines[i] = ">"
		} else {
			lines[i] = "> " + line
		}
	}
	result := strings.Join(lines, "\n")
	return result, r.check(result)
}

type listPart struct {
	value   string
	compact bool
}

func (r *renderer) listItemParts(node *html.Node) ([]listPart, error) {
	var parts []listPart
	var inline strings.Builder
	seenChildren := make(map[*html.Node]bool)
	flush := func() error {
		value := strings.TrimSpace(inline.String())
		inline.Reset()
		if value != "" {
			parts = append(parts, listPart{value: value})
		}
		return nil
	}
	for child := node.FirstChild; child != nil && !seenChildren[child]; child = child.NextSibling {
		seenChildren[child] = true
		if isOmitted(child) {
			continue
		}
		if child.Type == html.ElementNode && (nodeTag(child) == "ul" || nodeTag(child) == "ol") {
			if err := flush(); err != nil {
				return nil, err
			}
			value, err := r.list(child)
			if err != nil {
				return nil, err
			}
			if value != "" {
				parts = append(parts, listPart{value: value, compact: true})
			}
			continue
		}
		if isBlockNode(child) {
			if err := flush(); err != nil {
				return nil, err
			}
			value, err := r.block(child)
			if err != nil {
				return nil, err
			}
			if value != "" {
				parts = append(parts, listPart{value: value})
			}
			continue
		}
		value, err := r.inline(child)
		if err != nil {
			return nil, err
		}
		if err := appendInlineBounded(&inline, value); err != nil {
			return nil, err
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return parts, nil
}

func (r *renderer) list(node *html.Node) (string, error) {
	ordered := nodeTag(node) == "ol"
	start := 1
	if ordered {
		if value, err := strconv.Atoi(attr(node, "start")); err == nil && value > 0 {
			start = value
		}
	}
	var out strings.Builder
	itemNumber := start
	seenChildren := make(map[*html.Node]bool)
	for child := node.FirstChild; child != nil && !seenChildren[child]; child = child.NextSibling {
		seenChildren[child] = true
		if child.Type != html.ElementNode || nodeTag(child) != "li" || isOmitted(child) {
			continue
		}
		parts, err := r.listItemParts(child)
		if err != nil {
			return "", err
		}
		if len(parts) == 0 {
			continue
		}
		marker := "- "
		if ordered {
			marker = strconv.Itoa(itemNumber) + ". "
			itemNumber++
		}
		value, err := joinListParts(parts)
		if err != nil {
			return "", err
		}
		lines := strings.Split(value, "\n")
		if out.Len() > 0 {
			if err := appendBounded(&out, "\n"); err != nil {
				return "", err
			}
		}
		if err := appendBounded(&out, marker); err != nil {
			return "", err
		}
		if err := appendBounded(&out, lines[0]); err != nil {
			return "", err
		}
		indent := strings.Repeat(" ", len(marker))
		for _, line := range lines[1:] {
			if err := appendBounded(&out, "\n"+indent+line); err != nil {
				return "", err
			}
		}
	}
	return out.String(), nil
}

func (r *renderer) table(node *html.Node) (string, error) {
	rows := tableRows(node)
	if len(rows) == 0 {
		return "", nil
	}
	caption := ""
	if value, err := r.inlineChildren(firstElement(node, "caption")); err == nil && strings.TrimSpace(value) != "" {
		caption = strings.TrimSpace(value)
	} else if err != nil {
		return "", err
	}

	rectangular := len(rows[0]) > 0
	for _, row := range rows {
		if len(row) != len(rows[0]) {
			rectangular = false
			break
		}
		for _, cell := range row {
			if attrInt(cell, "rowspan") > 1 || attrInt(cell, "colspan") > 1 {
				rectangular = false
			}
		}
	}
	var (
		result string
		err    error
	)
	if rectangular {
		result, err = r.rectangularTable(rows)
	} else {
		result, err = r.irregularTable(rows)
	}
	if err != nil {
		return "", err
	}
	if caption != "" {
		result = caption + "\n\n" + result
	}
	return result, r.check(result)
}

func (r *renderer) rectangularTable(rows [][]*html.Node) (string, error) {
	values := make([][]string, len(rows))
	for i, row := range rows {
		values[i] = make([]string, len(row))
		for j, cell := range row {
			value, err := r.inlineChildren(cell)
			if err != nil {
				return "", err
			}
			values[i][j] = tableCell(value)
		}
	}
	var out strings.Builder
	writeRow := func(row []string) error {
		if err := appendBounded(&out, "| "); err != nil {
			return err
		}
		for i, value := range row {
			if i > 0 {
				if err := appendBounded(&out, " | "); err != nil {
					return err
				}
			}
			if err := appendBounded(&out, value); err != nil {
				return err
			}
		}
		return appendBounded(&out, " |\n")
	}
	if err := writeRow(values[0]); err != nil {
		return "", err
	}
	separator := make([]string, len(values[0]))
	for i := range separator {
		separator[i] = "---"
	}
	if err := writeRow(separator); err != nil {
		return "", err
	}
	for _, row := range values[1:] {
		if err := writeRow(row); err != nil {
			return "", err
		}
	}
	return strings.TrimRight(out.String(), "\n"), nil
}

func (r *renderer) irregularTable(rows [][]*html.Node) (string, error) {
	var out strings.Builder
	for i, row := range rows {
		if i > 0 {
			if err := appendBounded(&out, "\n"); err != nil {
				return "", err
			}
		}
		if err := appendBounded(&out, "- "); err != nil {
			return "", err
		}
		for j, cell := range row {
			if j > 0 {
				if err := appendBounded(&out, "; "); err != nil {
					return "", err
				}
			}
			value, err := r.inlineChildren(cell)
			if err != nil {
				return "", err
			}
			if err := appendBounded(&out, tableCell(value)); err != nil {
				return "", err
			}
		}
	}
	return out.String(), nil
}

func joinBlocks(blocks []string) (string, error) {
	var out strings.Builder
	written := false
	for _, block := range blocks {
		block = strings.Trim(block, " \t\r\n")
		if block == "" {
			continue
		}
		if written {
			if err := appendBounded(&out, "\n\n"); err != nil {
				return "", err
			}
		}
		if err := appendBounded(&out, block); err != nil {
			return "", err
		}
		written = true
	}
	return out.String(), nil
}

func joinParts(parts []listPart) (string, error) {
	var out strings.Builder
	for i, part := range parts {
		if i > 0 {
			separator := "\n\n"
			if part.compact || parts[i-1].compact {
				separator = "\n"
			}
			if err := appendBounded(&out, separator); err != nil {
				return "", err
			}
		}
		if err := appendBounded(&out, strings.Trim(part.value, " \t\r\n")); err != nil {
			return "", err
		}
	}
	return out.String(), nil
}

func appendBounded(out *strings.Builder, value string) error {
	if len(value) > maxMarkdownBytes-out.Len() {
		return ErrMarkdownTooLarge
	}
	out.WriteString(value)
	return nil
}

func appendInlineBounded(out *strings.Builder, value string) error {
	if out.Len() > 0 {
		previous := out.String()
		if strings.HasSuffix(previous, " ") || strings.HasSuffix(previous, "\n") {
			value = strings.TrimLeftFunc(value, unicode.IsSpace)
		}
	}
	return appendBounded(out, value)
}

func (r *renderer) wrap(value, prefix, suffix string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", nil
	}
	// Every wrapper otherwise copies its complete child string. Make the
	// permitted intermediate copy smaller as nesting grows, so a deep tree
	// cannot turn one bounded article into quadratic or exponential work.
	copyLimit := maxMarkdownBytes / max(1, r.depth)
	if len(value) > copyLimit {
		return "", ErrMarkdownTooLarge
	}
	leading := len(value) - len(strings.TrimLeftFunc(value, unicode.IsSpace))
	trailing := len(strings.TrimRightFunc(value, unicode.IsSpace))
	result := value[:leading] + prefix + trimmed + suffix + value[trailing:]
	return result, r.check(result)
}

func joinListParts(parts []listPart) (string, error) { return joinParts(parts) }

func nodeTag(node *html.Node) string { return strings.ToLower(node.Data) }

func attr(node *html.Node, name string) string {
	if node == nil {
		return ""
	}
	for _, value := range node.Attr {
		if strings.EqualFold(value.Key, name) {
			return value.Val
		}
	}
	return ""
}

func attrInt(node *html.Node, name string) int {
	value, err := strconv.Atoi(attr(node, name))
	if err != nil {
		return 0
	}
	return value
}

func firstElement(node *html.Node, tag string) *html.Node {
	if node == nil {
		return nil
	}
	seenChildren := make(map[*html.Node]bool)
	for child := node.FirstChild; child != nil && !seenChildren[child]; child = child.NextSibling {
		seenChildren[child] = true
		if child.Type == html.ElementNode && nodeTag(child) == tag {
			return child
		}
	}
	return nil
}

func isBlockContainer(node *html.Node) bool {
	return node != nil && node.Type == html.ElementNode && !isInlineTag(nodeTag(node)) && hasBlockChild(node)
}

func isInlineTag(tag string) bool {
	switch tag {
	case "a", "b", "br", "code", "del", "em", "i", "img", "s", "span", "strong", "strike", "sub", "sup", "u", "wbr":
		return true
	default:
		return false
	}
}

func hasBlockChild(node *html.Node) bool {
	seenChildren := make(map[*html.Node]bool)
	for child := node.FirstChild; child != nil && !seenChildren[child]; child = child.NextSibling {
		seenChildren[child] = true
		if isBlockNode(child) {
			return true
		}
	}
	return false
}

func isHeading(tag string) bool {
	return len(tag) == 2 && tag[0] == 'h' && tag[1] >= '1' && tag[1] <= '6'
}

func headingLevel(tag string) int { return int(tag[1] - '0') }

func isBlockNode(node *html.Node) bool {
	if node == nil || node.Type != html.ElementNode {
		return false
	}
	return isBlockTag(nodeTag(node))
}

func isBlockTag(tag string) bool {
	if isHeading(tag) {
		return true
	}
	switch tag {
	case "address", "article", "aside", "blockquote", "body", "caption", "dd", "div", "dl", "dt", "fieldset", "figcaption", "figure", "footer", "form", "header", "hr", "html", "li", "main", "ol", "p", "pre", "section", "summary", "table", "tbody", "td", "tfoot", "th", "thead", "tr", "ul":
		return true
	default:
		return false
	}
}

func isOmitted(node *html.Node) bool {
	if node == nil {
		return true
	}
	if node.Type == html.CommentNode || node.Type == html.DoctypeNode {
		return true
	}
	if node.Type != html.ElementNode {
		return false
	}
	switch nodeTag(node) {
	case "head", "title", "meta", "base", "link", "script", "style", "template", "noscript", "nav", "svg", "canvas", "input", "button", "select", "option", "textarea":
		return true
	}
	if _, ok := attrValue(node, "hidden"); ok {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(attr(node, "aria-hidden")), "true") {
		return true
	}
	style := strings.ToLower(strings.Join(strings.Fields(attr(node, "style")), ""))
	return strings.Contains(style, "display:none") || strings.Contains(style, "visibility:hidden")
}

func attrValue(node *html.Node, name string) (string, bool) {
	for _, value := range node.Attr {
		if strings.EqualFold(value.Key, name) {
			return value.Val, true
		}
	}
	return "", false
}

func escapeText(value string) string {
	var out strings.Builder
	pendingSpace := false
	leadingSpace := false
	hasContent := false
	numberCandidate := true
	numberSeen := false
	runes := []rune(value)
	for index, ch := range runes {
		if unicode.IsSpace(ch) {
			if hasContent {
				pendingSpace = true
			} else {
				leadingSpace = true
			}
			numberCandidate = true
			numberSeen = false
			continue
		}
		atLineStart := !hasContent
		if leadingSpace {
			out.WriteByte(' ')
			leadingSpace = false
		}
		if pendingSpace {
			out.WriteByte(' ')
			pendingSpace = false
		}
		switch ch {
		case '\\', '`', '*', '_', '[', ']', '<', '>', '|', '~':
			out.WriteByte('\\')
		case '&':
			if startsCharacterReference(runes, index) {
				out.WriteByte('\\')
			}
		case '#', '+', '-', '=':
			if atLineStart {
				out.WriteByte('\\')
			}
		case '.':
			if numberSeen {
				out.WriteByte('\\')
			}
		case '!':
			if index+1 < len(runes) && runes[index+1] == '[' {
				out.WriteByte('\\')
			}
		}
		out.WriteRune(ch)
		hasContent = true
		if numberCandidate && ch >= '0' && ch <= '9' {
			numberSeen = true
		} else {
			numberCandidate = false
		}
	}
	if pendingSpace || leadingSpace {
		if hasContent || len(value) > 0 {
			out.WriteByte(' ')
		}
	}
	return out.String()
}

func startsCharacterReference(runes []rune, start int) bool {
	if start+2 >= len(runes) || runes[start] != '&' {
		return false
	}
	end := start + 1
	if runes[end] == '#' {
		end++
		if end < len(runes) && (runes[end] == 'x' || runes[end] == 'X') {
			end++
		}
	}
	contentStart := end
	for end < len(runes) && end-contentStart < 32 {
		ch := runes[end]
		if ch == ';' {
			candidate := string(runes[start : end+1])
			return html.UnescapeString(candidate) != candidate
		}
		if !(unicode.IsLetter(ch) || unicode.IsDigit(ch) || ch == '#') {
			return false
		}
		end++
	}
	return false
}

func escapeTextInContext(raw, previous string) string {
	value := escapeText(raw)
	if strings.HasPrefix(value, ".") && endsWithOrderedNumber(previous) {
		return "\\" + value
	}
	return value
}

func endsWithOrderedNumber(value string) bool {
	value = strings.TrimRight(value, " \t")
	if value == "" {
		return false
	}
	end := len(value)
	start := end
	for start > 0 && value[start-1] >= '0' && value[start-1] <= '9' {
		start--
	}
	if start == end || (start > 0 && value[start-1] != '\n') {
		return start == 0
	}
	return true
}

func escapeDestination(value string) string {
	const hex = "0123456789ABCDEF"
	var out strings.Builder
	for _, ch := range value {
		if unicode.IsSpace(ch) || ch < 0x20 || ch == 0x7f {
			for _, byteValue := range []byte(string(ch)) {
				out.WriteByte('%')
				out.WriteByte(hex[byteValue>>4])
				out.WriteByte(hex[byteValue&0x0f])
			}
			continue
		}
		switch ch {
		case '\\', '(', ')', '|':
			out.WriteByte('\\')
		}
		out.WriteRune(ch)
	}
	return out.String()
}

func escapeLinkTitle(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	value = strings.ReplaceAll(value, "\r", " ")
	return strings.ReplaceAll(value, "\n", " ")
}

func inlineCode(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	value = strings.ReplaceAll(value, "\n", " ")
	fence := longestRun(value, '`') + 1
	if fence == 1 {
		return "`" + value + "`"
	}
	padding := ""
	if strings.HasPrefix(value, "`") || strings.HasSuffix(value, "`") || strings.HasPrefix(value, " ") || strings.HasSuffix(value, " ") {
		padding = " "
	}
	return strings.Repeat("`", fence) + padding + value + padding + strings.Repeat("`", fence)
}

func safeCodeLanguage(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, ch := range value {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || strings.ContainsRune("._:+-", ch) {
			continue
		}
		return false
	}
	return true
}

func longestRun(value string, target rune) int {
	longest, current := 0, 0
	for _, ch := range value {
		if ch == target {
			current++
			if current > longest {
				longest = current
			}
		} else {
			current = 0
		}
	}
	return longest
}

func (r *renderer) rawText(node *html.Node) (string, error) {
	if node == nil || isOmitted(node) {
		return "", nil
	}
	type frame struct {
		node  *html.Node
		depth int
		exit  bool
	}
	stack := []frame{{node: node}}
	active := make(map[*html.Node]bool)
	var out strings.Builder
	for len(stack) > 0 {
		last := len(stack) - 1
		current := stack[last]
		stack = stack[:last]
		if current.node == nil || isOmitted(current.node) {
			continue
		}
		if current.exit {
			delete(active, current.node)
			continue
		}
		if active[current.node] || current.depth >= MaxMarkdownDepth {
			continue
		}
		if current.node.Type == html.TextNode {
			if err := appendBounded(&out, current.node.Data); err != nil {
				return "", err
			}
			continue
		}
		if current.node.Type != html.ElementNode && current.node.Type != html.DocumentNode {
			continue
		}
		active[current.node] = true
		stack = append(stack, frame{node: current.node, depth: current.depth, exit: true})
		var children []*html.Node
		seen := make(map[*html.Node]bool)
		for child := current.node.FirstChild; child != nil && !seen[child]; child = child.NextSibling {
			seen[child] = true
			children = append(children, child)
		}
		for i := len(children) - 1; i >= 0; i-- {
			stack = append(stack, frame{node: children[i], depth: current.depth + 1})
		}
	}
	return out.String(), nil
}

func tableRows(table *html.Node) [][]*html.Node {
	if table == nil {
		return nil
	}
	type frame struct {
		node  *html.Node
		depth int
		exit  bool
	}
	var rows [][]*html.Node
	stack := []frame{{node: table}}
	active := make(map[*html.Node]bool)
	for len(stack) > 0 {
		last := len(stack) - 1
		current := stack[last]
		stack = stack[:last]
		if current.node == nil || isOmitted(current.node) {
			continue
		}
		if current.exit {
			delete(active, current.node)
			continue
		}
		if active[current.node] || current.depth >= MaxMarkdownDepth {
			continue
		}
		if current.node.Type == html.ElementNode && nodeTag(current.node) == "tr" {
			var cells []*html.Node
			cellSeen := make(map[*html.Node]bool)
			for cell := current.node.FirstChild; cell != nil && !cellSeen[cell]; cell = cell.NextSibling {
				cellSeen[cell] = true
				if cell.Type == html.ElementNode && (nodeTag(cell) == "td" || nodeTag(cell) == "th") && !isOmitted(cell) {
					cells = append(cells, cell)
				}
			}
			rows = append(rows, cells)
			continue
		}
		active[current.node] = true
		stack = append(stack, frame{node: current.node, depth: current.depth, exit: true})
		var children []*html.Node
		seen := make(map[*html.Node]bool)
		for child := current.node.FirstChild; child != nil && !seen[child]; child = child.NextSibling {
			seen[child] = true
			children = append(children, child)
		}
		for i := len(children) - 1; i >= 0; i-- {
			child := children[i]
			if child.Type == html.ElementNode && nodeTag(child) == "table" && child != table {
				continue
			}
			stack = append(stack, frame{node: child, depth: current.depth + 1})
		}
	}
	return rows
}

func tableCell(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.TrimSpace(value)
	var out strings.Builder
	backslashes := 0
	for _, ch := range value {
		if ch == '|' && backslashes%2 == 0 {
			out.WriteByte('\\')
		}
		out.WriteRune(ch)
		if ch == '\\' {
			backslashes++
		} else {
			backslashes = 0
		}
	}
	return out.String()
}
