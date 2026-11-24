package format

import (
	"errors"
	"io"
	"strings"

	"github.com/ryanfowler/fetch/internal/core"
)

// CSS token types
type cssTokenType int

const (
	cssTokenEOF        cssTokenType = iota
	cssTokenIdent                   // property names, selectors, keywords
	cssTokenHash                    // #id selectors
	cssTokenAtKeyword               // @media, @import, @keyframes
	cssTokenString                  // "..." or '...'
	cssTokenNumber                  // 123, 1.5
	cssTokenDimension               // 10px, 2em, 100%
	cssTokenFunction                // calc(, rgba(, url(
	cssTokenComment                 // /* ... */
	cssTokenDelim                   // single chars: { } : ; , . > + ~ * [ ] ( )
	cssTokenWhitespace              // spaces, tabs, newlines
	cssTokenURL                     // url(...) with an unquoted value, kept as written
)

// cssToken represents a single token from the CSS input.
type cssToken struct {
	typ   cssTokenType
	value string
}

// cssTokenizer tokenizes CSS input byte by byte.
type cssTokenizer struct {
	input []byte
	pos   int
}

func newCSSTokenizer(input []byte) *cssTokenizer {
	return &cssTokenizer{input: input}
}

func (t *cssTokenizer) peek() byte {
	if t.pos >= len(t.input) {
		return 0
	}
	return t.input[t.pos]
}

func (t *cssTokenizer) peekN(n int) byte {
	if t.pos+n >= len(t.input) {
		return 0
	}
	return t.input[t.pos+n]
}

func (t *cssTokenizer) advance() byte {
	if t.pos >= len(t.input) {
		return 0
	}
	b := t.input[t.pos]
	t.pos++
	return b
}

func (t *cssTokenizer) next() cssToken {
	// Skip whitespace, but return a whitespace token if any was found
	if t.consumeWhitespace() {
		return cssToken{typ: cssTokenWhitespace, value: " "}
	}

	if t.pos >= len(t.input) {
		return cssToken{typ: cssTokenEOF}
	}

	c := t.peek()

	// Comment
	if c == '/' && t.peekN(1) == '*' {
		return t.scanComment()
	}

	// String
	if c == '"' || c == '\'' {
		return t.scanString(c)
	}

	// At-keyword
	if c == '@' {
		return t.scanAtKeyword()
	}

	// Hash (ID selector)
	if c == '#' {
		return t.scanHash()
	}

	// Number or dimension
	if isDigit(c) || (c == '.' && isDigit(t.peekN(1))) || (c == '-' && (isDigit(t.peekN(1)) || t.peekN(1) == '.')) {
		return t.scanNumber()
	}

	// Identifier or function
	if isIdentStart(c) || c == '-' || c == '_' {
		return t.scanIdentOrFunction()
	}

	// Single character delimiters
	t.advance()
	return cssToken{typ: cssTokenDelim, value: string(c)}
}

func (t *cssTokenizer) consumeWhitespace() bool {
	found := false
	for t.pos < len(t.input) {
		c := t.peek()
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' {
			t.advance()
			found = true
		} else {
			break
		}
	}
	return found
}

func (t *cssTokenizer) scanComment() cssToken {
	start := t.pos
	t.advance() // consume /
	t.advance() // consume *

	for t.pos < len(t.input) {
		if t.peek() == '*' && t.peekN(1) == '/' {
			t.advance() // consume *
			t.advance() // consume /
			break
		}
		t.advance()
	}

	return cssToken{typ: cssTokenComment, value: string(t.input[start:t.pos])}
}

func (t *cssTokenizer) scanString(quote byte) cssToken {
	start := t.pos
	t.advance() // consume opening quote

	for t.pos < len(t.input) {
		c := t.peek()
		if c == quote {
			t.advance()
			break
		}
		if c == '\\' {
			t.advance() // consume backslash
			if t.pos < len(t.input) {
				t.advance() // consume escaped char
			}
			continue
		}
		if c == '\n' || c == '\r' {
			// Unterminated string
			break
		}
		t.advance()
	}

	return cssToken{typ: cssTokenString, value: string(t.input[start:t.pos])}
}

func (t *cssTokenizer) scanAtKeyword() cssToken {
	start := t.pos
	t.advance() // consume @

	for t.pos < len(t.input) {
		c := t.peek()
		if isIdentChar(c) {
			t.advance()
		} else {
			break
		}
	}

	return cssToken{typ: cssTokenAtKeyword, value: string(t.input[start:t.pos])}
}

func (t *cssTokenizer) scanHash() cssToken {
	start := t.pos
	t.advance() // consume #

	for t.pos < len(t.input) {
		c := t.peek()
		if isIdentChar(c) {
			t.advance()
		} else {
			break
		}
	}

	return cssToken{typ: cssTokenHash, value: string(t.input[start:t.pos])}
}

func (t *cssTokenizer) scanNumber() cssToken {
	start := t.pos

	// Optional sign
	if t.peek() == '-' || t.peek() == '+' {
		t.advance()
	}

	// Integer part
	for t.pos < len(t.input) && isDigit(t.peek()) {
		t.advance()
	}

	// Decimal part
	if t.peek() == '.' && isDigit(t.peekN(1)) {
		t.advance() // consume .
		for t.pos < len(t.input) && isDigit(t.peek()) {
			t.advance()
		}
	}

	// Check for unit (makes it a dimension)
	if isIdentStart(t.peek()) || t.peek() == '%' {
		if t.peek() == '%' {
			t.advance()
		} else {
			for t.pos < len(t.input) && isIdentChar(t.peek()) {
				t.advance()
			}
		}
		return cssToken{typ: cssTokenDimension, value: string(t.input[start:t.pos])}
	}

	return cssToken{typ: cssTokenNumber, value: string(t.input[start:t.pos])}
}

func (t *cssTokenizer) scanIdentOrFunction() cssToken {
	start := t.pos

	// Allow leading - or --
	for t.peek() == '-' {
		t.advance()
	}

	for t.pos < len(t.input) {
		c := t.peek()
		if isIdentChar(c) {
			t.advance()
		} else {
			break
		}
	}

	value := string(t.input[start:t.pos])

	// Check if it's a function (followed by open paren)
	if t.peek() == '(' {
		t.advance()
		if strings.EqualFold(value, "url") {
			if url, ok := t.scanUnquotedURL(start); ok {
				return url
			}
		}
		return cssToken{typ: cssTokenFunction, value: value + "("}
	}

	return cssToken{typ: cssTokenIdent, value: value}
}

// scanUnquotedURL scans the rest of an unquoted url(...) after "url(", as
// CSS Syntax defines it: the value is raw text up to ")", so it can contain
// characters such as "{", ";", and ",". start is the position of "url". It
// reports false, without consuming input, for a quoted value, which is an
// ordinary function argument.
func (t *cssTokenizer) scanUnquotedURL(start int) (cssToken, bool) {
	pos := t.pos
	for pos < len(t.input) && (t.input[pos] == ' ' || t.input[pos] == '\t' || t.input[pos] == '\n' || t.input[pos] == '\r' || t.input[pos] == '\f') {
		pos++
	}
	if pos < len(t.input) && (t.input[pos] == '"' || t.input[pos] == '\'') {
		return cssToken{}, false
	}
	for pos < len(t.input) && t.input[pos] != ')' {
		if t.input[pos] == '\\' && pos+1 < len(t.input) {
			pos++
		}
		pos++
	}
	if pos < len(t.input) {
		pos++ // the closing ")"
	}
	t.pos = pos
	return cssToken{typ: cssTokenURL, value: string(t.input[start:pos])}, true
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func isIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c >= 0x80
}

func isIdentChar(c byte) bool {
	return isIdentStart(c) || isDigit(c) || c == '-'
}

// cssFormatter formats CSS tokens with pretty-printing and colors.
type cssFormatter struct {
	tok       *cssTokenizer
	printer   *core.Printer
	indent    int
	current   cssToken
	atNewline bool
	wroteRule bool // tracks if we've written any top-level rules (for blank line separation)
	err       error
}

// FormatCSS formats the provided CSS to the Printer.
func FormatCSS(buf []byte, p *core.Printer) error {
	return FormatCSSIndented(buf, p, 0)
}

// FormatCSSIndented formats CSS with a base indentation level.
// Used for formatting CSS embedded in HTML <style> tags.
func FormatCSSIndented(buf []byte, p *core.Printer, baseIndent int) error {
	if baseIndent < 0 {
		return errors.New("CSS base indentation must be non-negative")
	}
	if len(buf) == 0 {
		return nil
	}

	out := p.NewBoundedWriter(io.Discard, core.MaxFormattedBodyBytes, "CSS formatted output")
	err := formatCSSIndented(buf, out, baseIndent)
	if err == nil {
		err = out.Err()
	}
	if err != nil {
		// p is unchanged: the output was built in a separate buffer. Do
		// not Discard p, because an HTML caller holds earlier output in it.
		return err
	}
	// Write is all or nothing, so p is unchanged when it fails.
	_, err = p.Write(out.Bytes())
	return err
}

func formatCSSIndented(buf []byte, p *core.Printer, baseIndent int) error {
	if baseIndent < 0 || baseIndent > core.MaxFormatterNestingDepth {
		return core.LimitError{Subsystem: "CSS nesting depth", Limit: core.MaxFormatterNestingDepth}
	}

	f := &cssFormatter{
		tok:       newCSSTokenizer(buf),
		printer:   p,
		indent:    baseIndent,
		atNewline: true,
	}
	f.advance()
	return f.format()
}

func (f *cssFormatter) advance() {
	f.current = f.tok.next()
}

func (f *cssFormatter) skipWhitespace() {
	for f.current.typ == cssTokenWhitespace {
		f.advance()
	}
}

func (f *cssFormatter) enterBlock() bool {
	if f.indent >= core.MaxFormatterNestingDepth {
		f.err = core.LimitError{Subsystem: "CSS nesting depth", Limit: core.MaxFormatterNestingDepth}
		return false
	}
	f.indent++
	return true
}

func (f *cssFormatter) format() error {
	for f.current.typ != cssTokenEOF && f.err == nil {
		f.skipWhitespace()
		if f.current.typ == cssTokenEOF {
			break
		}

		if f.current.typ == cssTokenComment {
			// Add blank line between top-level rules
			if f.indent == 0 && f.wroteRule {
				f.printer.WriteString("\n")
			}
			f.formatComment()
			f.wroteRule = true
			continue
		}

		if f.current.typ == cssTokenAtKeyword {
			// Add blank line between top-level rules
			if f.indent == 0 && f.wroteRule {
				f.printer.WriteString("\n")
			}
			f.formatAtRule()
			continue
		}

		// Skip a stray ";" or "}" at the top level.
		if f.current.typ == cssTokenDelim && (f.current.value == ";" || f.current.value == "}") {
			f.advance()
			continue
		}

		// Must be a qualified rule (selector + declaration block)
		// Add blank line between top-level rules
		if f.indent == 0 && f.wroteRule {
			f.printer.WriteString("\n")
		}
		f.formatQualifiedRule()
	}

	return f.err
}

func (f *cssFormatter) formatComment() {
	f.writeIndent()
	comment := f.current.value
	if !strings.HasSuffix(comment, "*/") {
		// An unterminated comment runs to the end of the input. Its
		// trailing whitespace is not part of its text.
		comment = strings.TrimRight(comment, " \t\r\n\f")
	}
	f.printer.Set(core.Dim)
	f.printer.WriteStringUntrusted(comment)
	f.printer.Reset()
	f.printer.WriteString("\n")
	f.atNewline = true
	f.advance()
}

func (f *cssFormatter) formatAtRule() {
	f.writeIndent()

	// Write at-keyword
	f.printer.Set(core.Bold)
	f.printer.Set(core.Blue)
	f.printer.WriteStringUntrusted(f.current.value)
	f.printer.Reset()
	f.advance()

	// Collect the prelude (everything until { or ;)
	f.formatAtRulePrelude()
	if f.err != nil {
		return
	}

	f.skipWhitespace()

	if f.current.typ == cssTokenDelim && f.current.value == "{" {
		// Block at-rule (e.g., @media, @keyframes)
		if !f.enterBlock() {
			return
		}
		f.printer.WriteString(" {\n")
		f.atNewline = true
		f.advance()

		// Parse contents
		f.formatAtRuleBody()

		f.indent--
		f.writeIndent()
		f.printer.WriteString("}\n")
		f.atNewline = true
		// Advance past the closing brace
		if f.current.typ == cssTokenDelim && f.current.value == "}" {
			f.advance()
		}
		if f.indent == 0 {
			f.wroteRule = true
		}
	} else if f.current.typ == cssTokenDelim && f.current.value == ";" {
		// Statement at-rule (e.g., @import, @charset)
		f.printer.WriteString(";\n")
		f.atNewline = true
		f.advance()
		if f.indent == 0 {
			f.wroteRule = true
		}
	} else {
		// No terminator found, just newline
		f.printer.WriteString("\n")
		f.atNewline = true
	}
}

func (f *cssFormatter) formatAtRulePrelude() {
	// Whitespace separates the parts of a prelude, as in
	// "screen and (min-width: 768px)", also inside parentheses, as in
	// "(not (display: grid))". Removing it would join words, and a word
	// followed by "(" would become a function, such as "and(".
	needSpace := false
	parenDepth := 0

	for f.current.typ != cssTokenEOF {
		if f.current.typ == cssTokenDelim {
			if f.current.value == "{" || f.current.value == ";" || f.current.value == "}" {
				break
			}
			if f.current.value == "(" {
				if needSpace {
					f.printer.WriteString(" ")
				}
				parenDepth++
				f.printer.WriteString("(")
				f.advance()
				f.skipWhitespace()
				needSpace = false
				continue
			}
			if f.current.value == ")" {
				parenDepth--
				f.printer.WriteString(")")
				f.advance()
				needSpace = false
				continue
			}
			if f.current.value == "," {
				f.printer.WriteString(",")
				f.advance()
				needSpace = true
				continue
			}
			if f.current.value == ":" {
				// A media feature, as in "(min-width: 768px)", or a page
				// selector, as in "@page :first".
				if needSpace && parenDepth == 0 {
					f.printer.WriteString(" ")
				}
				f.printer.WriteString(":")
				f.advance()
				f.skipWhitespace()
				needSpace = parenDepth > 0
				continue
			}
		}

		if f.current.typ == cssTokenWhitespace {
			f.advance()
			needSpace = true
			continue
		}

		if needSpace {
			f.printer.WriteString(" ")
			needSpace = false
		}

		f.formatValueToken()
	}
}

func (f *cssFormatter) formatAtRuleBody() {
	f.formatBlockContents()
}

// cssBlockItem is the kind of item that starts at the current token inside a
// block.
type cssBlockItem int

const (
	cssBlockDeclaration cssBlockItem = iota // property: value;
	cssBlockRule                            // selector { ... }
	cssBlockJunk                            // anything else, up to ";" or "}"
)

// classifyBlockItem looks ahead on a copy of the tokenizer, so it does not
// consume tokens. A block can hold declarations, as in a style rule or
// @font-face, and nested rules, as in @media or CSS nesting. A nested rule's
// selector ends with "{"; a declaration ends with ";" or "}". A selector can
// also contain a colon, as in "a:hover {". Braces and semicolons inside
// parentheses do not count. A custom property, such as "--x: {a:b};", can
// hold braces in its value.
func (f *cssFormatter) classifyBlockItem() cssBlockItem {
	lookahead := *f.tok
	tok := f.current
	declaration, custom := false, false
	if tok.typ == cssTokenIdent {
		custom = strings.HasPrefix(tok.value, "--")
		tok = lookahead.next()
		for tok.typ == cssTokenWhitespace || tok.typ == cssTokenComment {
			tok = lookahead.next()
		}
		declaration = tok.typ == cssTokenDelim && tok.value == ":"
	}
	parens, braces := 0, 0
	for {
		switch {
		case tok.typ == cssTokenEOF, tok.typ == cssTokenAtKeyword && parens == 0 && braces == 0:
			// Neither a selector nor a value can contain an at-keyword.
			if declaration {
				return cssBlockDeclaration
			}
			return cssBlockJunk
		case tok.typ == cssTokenFunction || (tok.typ == cssTokenDelim && tok.value == "("):
			parens++
		case tok.typ == cssTokenDelim && tok.value == ")":
			parens = max(parens-1, 0)
		case parens > 0:
		case tok.typ == cssTokenDelim && tok.value == "{":
			if !(declaration && custom) {
				return cssBlockRule
			}
			braces++
		case tok.typ == cssTokenDelim && tok.value == "}" && braces > 0:
			braces--
		case tok.typ == cssTokenDelim && (tok.value == ";" || tok.value == "}") && braces == 0:
			if declaration {
				return cssBlockDeclaration
			}
			return cssBlockJunk
		}
		tok = lookahead.next()
	}
}

// formatBlockContents formats the items of a block up to its closing brace,
// which it does not consume.
func (f *cssFormatter) formatBlockContents() {
	for f.current.typ != cssTokenEOF && f.err == nil {
		f.skipWhitespace()
		if f.current.typ == cssTokenEOF {
			break
		}
		if f.current.typ == cssTokenDelim && f.current.value == "}" {
			break
		}
		switch {
		case f.current.typ == cssTokenComment:
			f.formatComment()
		case f.current.typ == cssTokenAtKeyword:
			f.formatAtRule()
		default:
			switch f.classifyBlockItem() {
			case cssBlockDeclaration:
				f.formatDeclaration()
			case cssBlockRule:
				// In @keyframes, selectors can be percentages (0%, 100%) or
				// keywords (from, to). CSS nesting allows "&" selectors.
				f.formatQualifiedRule()
			default:
				f.formatJunk()
			}
		}
	}
}

// formatJunk writes an item that is neither a declaration nor a rule, as in
// malformed input, as written and ends it with ";". It stops at ";", which
// it consumes, or before "}", an at-keyword, or the end of the input. An
// empty item, such as a stray ";", writes nothing.
func (f *cssFormatter) formatJunk() {
	wrote, needSpace := false, false
	for f.current.typ != cssTokenEOF && f.current.typ != cssTokenAtKeyword {
		if f.current.typ == cssTokenDelim && f.current.value == "}" {
			break
		}
		if f.current.typ == cssTokenDelim && f.current.value == ";" {
			f.advance()
			break
		}
		if f.current.typ == cssTokenWhitespace || f.current.typ == cssTokenComment {
			needSpace = wrote
			f.advance()
			continue
		}
		if !wrote {
			f.writeIndent()
		} else if needSpace {
			f.printer.WriteString(" ")
		}
		needSpace = false
		f.printer.WriteStringUntrusted(f.current.value)
		f.advance()
		wrote = true
	}
	if wrote {
		f.printer.WriteString(";\n")
		f.atNewline = true
	}
}

func (f *cssFormatter) formatQualifiedRule() {
	f.writeIndent()

	// Format selector
	f.formatSelector()
	if f.err != nil {
		return
	}

	f.skipWhitespace()

	if f.current.typ == cssTokenDelim && f.current.value == "{" {
		if !f.enterBlock() {
			return
		}
		f.printer.WriteString(" {\n")
		f.atNewline = true
		f.advance()

		f.formatDeclarationBlock()

		f.indent--
		f.writeIndent()
		f.printer.WriteString("}\n")
		f.atNewline = true
		// Advance past the closing brace
		if f.current.typ == cssTokenDelim && f.current.value == "}" {
			f.advance()
		}
		if f.indent == 0 {
			f.wroteRule = true
		}
	} else if !f.atNewline {
		// A selector without a block, in malformed input. End it with ";",
		// so formatting the output again does not join it to the next line.
		f.printer.WriteString(";\n")
		f.atNewline = true
	}
}

func (f *cssFormatter) formatSelector() {
	needSpace := false
	bracketDepth := 0

	for f.current.typ != cssTokenEOF && f.current.typ != cssTokenAtKeyword {
		if f.current.typ == cssTokenDelim {
			// A selector ends at "{". It cannot contain ";", "}", or an
			// at-keyword, so stop there too instead of printing malformed
			// input as a selector.
			if f.current.value == "{" || f.current.value == ";" || f.current.value == "}" {
				break
			}
			if bracketDepth > 0 && f.current.value != "[" && f.current.value != "]" {
				// An attribute operator, such as "^=", "|=", "$=", "~=", or
				// "*=", or a namespace separator. Operators take no spaces.
				f.printer.Set(core.Bold)
				f.printer.Set(core.Blue)
				f.printer.WriteStringUntrusted(f.current.value)
				f.printer.Reset()
				f.advance()
				f.skipWhitespace()
				needSpace = false
				continue
			}
			if f.current.value == "[" {
				bracketDepth++
				f.printer.Set(core.Bold)
				f.printer.Set(core.Blue)
				f.printer.WriteString("[")
				f.printer.Reset()
				f.advance()
				needSpace = false
				continue
			}
			if f.current.value == "]" {
				bracketDepth--
				f.printer.Set(core.Bold)
				f.printer.Set(core.Blue)
				f.printer.WriteString("]")
				f.printer.Reset()
				f.advance()
				needSpace = true
				continue
			}
			if f.current.value == "," {
				f.printer.WriteString(",")
				f.advance()
				needSpace = true
				continue
			}
			// Combinators: > + ~
			if f.current.value == ">" || f.current.value == "+" || f.current.value == "~" {
				if needSpace {
					f.printer.WriteString(" ")
				}
				f.printer.Set(core.Bold)
				f.printer.Set(core.Blue)
				f.printer.WriteStringUntrusted(f.current.value)
				f.printer.Reset()
				f.advance()
				needSpace = true
				continue
			}
			// Other selector parts: . * :
			if f.current.value == "." || f.current.value == "*" || f.current.value == ":" {
				// Keep whitespace before ":" too: "a :hover" (a descendant
				// combinator) and "a:hover" are different selectors.
				if needSpace {
					f.printer.WriteString(" ")
				}
				f.printer.Set(core.Bold)
				f.printer.Set(core.Blue)
				f.printer.WriteStringUntrusted(f.current.value)
				f.printer.Reset()
				f.advance()
				needSpace = false
				continue
			}
			// = for attribute selectors
			if f.current.value == "=" {
				f.printer.Set(core.Bold)
				f.printer.Set(core.Blue)
				f.printer.WriteString("=")
				f.printer.Reset()
				f.advance()
				needSpace = false
				continue
			}
		}

		if f.current.typ == cssTokenWhitespace {
			// Inside brackets, whitespace separates a value from a flag, as
			// in [href$=".pdf" i].
			f.advance()
			needSpace = true
			continue
		}

		if needSpace {
			f.printer.WriteString(" ")
			needSpace = false
		}

		// Selector elements
		switch f.current.typ {
		case cssTokenIdent:
			f.printer.Set(core.Bold)
			f.printer.Set(core.Blue)
			f.printer.WriteStringUntrusted(f.current.value)
			f.printer.Reset()
			f.advance()
			needSpace = false
		case cssTokenHash:
			f.printer.Set(core.Bold)
			f.printer.Set(core.Blue)
			f.printer.WriteStringUntrusted(f.current.value)
			f.printer.Reset()
			f.advance()
			needSpace = false
		case cssTokenString, cssTokenURL:
			f.printer.Set(core.Green)
			f.printer.WriteStringUntrusted(f.current.value)
			f.printer.Reset()
			f.advance()
			needSpace = false
		case cssTokenFunction:
			// For pseudo-class functions like :not()
			f.printer.Set(core.Bold)
			f.printer.Set(core.Blue)
			f.printer.WriteStringUntrusted(f.current.value)
			f.printer.Reset()
			f.advance()
			f.formatFunctionArgs()
			needSpace = false
		case cssTokenDimension, cssTokenNumber:
			// For @keyframes selectors like 0%, 100%
			f.printer.Set(core.Bold)
			f.printer.Set(core.Blue)
			f.printer.WriteStringUntrusted(f.current.value)
			f.printer.Reset()
			f.advance()
			needSpace = false
		case cssTokenDelim:
			// Another selector part, such as the "&" nesting selector or a
			// "|" namespace separator. Keep it as written.
			f.printer.Set(core.Bold)
			f.printer.Set(core.Blue)
			f.printer.WriteStringUntrusted(f.current.value)
			f.printer.Reset()
			f.advance()
			needSpace = false
		default:
			// Keep any other token, such as an at-keyword or a comment.
			f.printer.WriteStringUntrusted(f.current.value)
			f.advance()
			needSpace = false
		}
	}
}

func (f *cssFormatter) formatDeclarationBlock() {
	f.formatBlockContents()
}

func (f *cssFormatter) formatDeclaration() {
	f.writeIndent()

	// Property name
	custom := strings.HasPrefix(f.current.value, "--")
	f.printer.Set(core.Cyan)
	f.printer.WriteStringUntrusted(f.current.value)
	f.printer.Reset()
	f.advance()

	f.skipWhitespace()

	// Colon. The value starts after one space.
	if f.current.typ == cssTokenDelim && f.current.value == ":" {
		f.printer.WriteString(": ")
		f.advance()
		f.skipWhitespace()
	}

	// Property value
	f.formatValue(custom)

	f.skipWhitespace()

	// Semicolon
	if f.current.typ == cssTokenDelim && f.current.value == ";" {
		f.printer.WriteString(";\n")
		f.atNewline = true
		f.advance()
	} else {
		// A missing semicolon, before "}" or at the end of the input.
		f.printer.WriteString(";\n")
		f.atNewline = true
	}
}

// formatValue formats a declaration value up to its ";" or "}". The value of
// a custom property can contain balanced braces, as in "--x: {a:b}".
func (f *cssFormatter) formatValue(custom bool) {
	needSpace := false
	parenDepth := 0
	braceDepth := 0

	for f.current.typ != cssTokenEOF && f.err == nil {
		if f.current.typ == cssTokenAtKeyword && parenDepth == 0 && braceDepth == 0 {
			// A value cannot contain an at-keyword; it starts the next item.
			break
		}
		if f.current.typ == cssTokenDelim {
			if custom && f.current.value == "{" {
				braceDepth++
			} else if braceDepth > 0 && f.current.value == "}" {
				braceDepth--
			} else if braceDepth == 0 && (f.current.value == ";" || f.current.value == "}") {
				break
			}
			if f.current.value == "(" {
				parenDepth++
				f.printer.WriteString("(")
				f.advance()
				needSpace = false
				continue
			}
			if f.current.value == ")" {
				parenDepth--
				f.printer.WriteString(")")
				f.advance()
				needSpace = true
				continue
			}
			if f.current.value == "," {
				f.printer.WriteString(",")
				f.advance()
				needSpace = true
				continue
			}
			if f.current.value == "/" {
				f.printer.WriteString("/")
				f.advance()
				needSpace = false
				continue
			}
		}

		if f.current.typ == cssTokenWhitespace {
			f.advance()
			needSpace = true
			continue
		}

		if needSpace {
			f.printer.WriteString(" ")
			needSpace = false
		}

		f.formatValueToken()
	}
}

func (f *cssFormatter) formatValueToken() {
	switch f.current.typ {
	case cssTokenIdent:
		// Check for !important
		if f.current.value == "important" {
			f.printer.Set(core.Green)
			f.printer.WriteStringUntrusted(f.current.value)
			f.printer.Reset()
		} else {
			f.printer.Set(core.Green)
			f.printer.WriteStringUntrusted(f.current.value)
			f.printer.Reset()
		}
		f.advance()
	case cssTokenNumber, cssTokenDimension:
		f.printer.Set(core.Green)
		f.printer.WriteStringUntrusted(f.current.value)
		f.printer.Reset()
		f.advance()
	case cssTokenString, cssTokenURL:
		f.printer.Set(core.Green)
		f.printer.WriteStringUntrusted(f.current.value)
		f.printer.Reset()
		f.advance()
	case cssTokenHash:
		f.printer.Set(core.Green)
		f.printer.WriteStringUntrusted(f.current.value)
		f.printer.Reset()
		f.advance()
	case cssTokenFunction:
		f.printer.Set(core.Green)
		f.printer.WriteStringUntrusted(f.current.value)
		f.printer.Reset()
		f.advance()
		f.formatFunctionArgsValue(0)
	case cssTokenDelim:
		// "!" of !important, or another delimiter, such as an operator.
		f.printer.Set(core.Green)
		f.printer.WriteStringUntrusted(f.current.value)
		f.printer.Reset()
		f.advance()
	default:
		// Keep any other token, such as an at-keyword or a comment.
		f.printer.WriteStringUntrusted(f.current.value)
		f.advance()
	}
}

// formatFunctionArgs formats the arguments of a selector function, such as
// :not(), :is(), or :nth-child(), up to its closing parenthesis. It keeps
// every token, and one space where the input has whitespace, because the
// arguments are selectors or expressions such as "2n+1".
func (f *cssFormatter) formatFunctionArgs() {
	depth := 1
	needSpace := false
	for f.current.typ != cssTokenEOF && depth > 0 {
		tok := f.current
		switch {
		case tok.typ == cssTokenWhitespace || tok.typ == cssTokenComment:
			f.advance()
			needSpace = true
			continue
		case tok.typ == cssTokenFunction || (tok.typ == cssTokenDelim && tok.value == "("):
			depth++
		case tok.typ == cssTokenDelim && tok.value == ")":
			depth--
			needSpace = false
		}
		if needSpace {
			f.printer.WriteString(" ")
			needSpace = false
		}
		if tok.typ == cssTokenString || tok.typ == cssTokenURL {
			f.printer.Set(core.Green)
		} else {
			f.printer.Set(core.Bold)
			f.printer.Set(core.Blue)
		}
		f.printer.WriteStringUntrusted(tok.value)
		f.printer.Reset()
		f.advance()
		if tok.typ == cssTokenFunction || (tok.typ == cssTokenDelim && tok.value == "(") {
			f.skipWhitespace()
		}
	}
}

func (f *cssFormatter) formatFunctionArgsValue(functionDepth int) {
	if functionDepth >= core.MaxFormatterNestingDepth {
		f.err = core.LimitError{Subsystem: "CSS function nesting depth", Limit: core.MaxFormatterNestingDepth}
		return
	}

	parenDepth := 1
	needSpace := false

	for f.current.typ != cssTokenEOF && parenDepth > 0 && f.err == nil {
		if f.current.typ == cssTokenDelim && f.current.value == "(" {
			parenDepth++
			f.printer.WriteString("(")
			f.advance()
			needSpace = false
			continue
		}
		if f.current.typ == cssTokenDelim && f.current.value == ")" {
			parenDepth--
			f.printer.WriteString(")")
			f.advance()
			needSpace = true
			continue
		}
		if f.current.typ == cssTokenDelim && f.current.value == "," {
			f.printer.WriteString(",")
			f.advance()
			needSpace = true
			continue
		}
		if f.current.typ == cssTokenDelim && f.current.value == "/" {
			f.printer.WriteString("/")
			f.advance()
			needSpace = false
			continue
		}
		if f.current.typ == cssTokenWhitespace {
			f.advance()
			needSpace = true
			continue
		}

		if needSpace {
			f.printer.WriteString(" ")
			needSpace = false
		}

		switch f.current.typ {
		case cssTokenIdent, cssTokenNumber, cssTokenDimension:
			f.printer.WriteStringUntrusted(f.current.value)
			f.advance()
		case cssTokenString, cssTokenURL:
			f.printer.WriteStringUntrusted(f.current.value)
			f.advance()
		case cssTokenHash:
			f.printer.WriteStringUntrusted(f.current.value)
			f.advance()
		case cssTokenFunction:
			f.printer.WriteStringUntrusted(f.current.value)
			f.advance()
			f.formatFunctionArgsValue(functionDepth + 1)
		case cssTokenDelim:
			// An operator, such as "+" or "*" in calc().
			f.printer.WriteStringUntrusted(f.current.value)
			f.advance()
		default:
			// Keep any other token, such as an at-keyword or a comment.
			f.printer.WriteStringUntrusted(f.current.value)
			f.advance()
		}
	}
}

func (f *cssFormatter) writeIndent() {
	if f.atNewline {
		writeIndent(f.printer, f.indent)
		f.atNewline = false
	}
}
