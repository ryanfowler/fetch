package format

import "github.com/ryanfowler/fetch/internal/core"

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
		return cssToken{typ: cssTokenFunction, value: value + "("}
	}

	return cssToken{typ: cssTokenIdent, value: value}
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
}

// FormatCSS formats the provided CSS to the Printer.
func FormatCSS(buf []byte, p *core.Printer) error {
	return FormatCSSIndented(buf, p, 0)
}

// FormatCSSIndented formats CSS with a base indentation level.
// Used for formatting CSS embedded in HTML <style> tags.
func FormatCSSIndented(buf []byte, p *core.Printer, baseIndent int) error {
	if len(buf) == 0 {
		return nil
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

func (f *cssFormatter) format() error {
	for f.current.typ != cssTokenEOF {
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

		// Must be a qualified rule (selector + declaration block)
		// Add blank line between top-level rules
		if f.indent == 0 && f.wroteRule {
			f.printer.WriteString("\n")
		}
		f.formatQualifiedRule()
	}

	return nil
}

func (f *cssFormatter) formatComment() {
	f.writeIndent()
	f.printer.Set(core.Dim)
	f.printer.WriteString(f.current.value)
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
	f.printer.WriteString(f.current.value)
	f.printer.Reset()
	f.advance()

	// Collect the prelude (everything until { or ;)
	f.formatAtRulePrelude()

	f.skipWhitespace()

	if f.current.typ == cssTokenDelim && f.current.value == "{" {
		// Block at-rule (e.g., @media, @keyframes)
		f.printer.WriteString(" {\n")
		f.atNewline = true
		f.advance()
		f.indent++

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
	needSpace := false
	parenDepth := 0

	for f.current.typ != cssTokenEOF {
		if f.current.typ == cssTokenDelim {
			if f.current.value == "{" || f.current.value == ";" {
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
			if f.current.value == ":" {
				f.printer.WriteString(":")
				f.advance()
				needSpace = false
				continue
			}
		}

		if f.current.typ == cssTokenWhitespace {
			f.advance()
			if parenDepth == 0 {
				needSpace = true
			}
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
	for f.current.typ != cssTokenEOF {
		f.skipWhitespace()
		if f.current.typ == cssTokenEOF {
			break
		}

		if f.current.typ == cssTokenDelim && f.current.value == "}" {
			break
		}

		if f.current.typ == cssTokenComment {
			f.formatComment()
			continue
		}

		if f.current.typ == cssTokenAtKeyword {
			f.formatAtRule()
			continue
		}

		// Either a nested rule or a declaration
		// In @keyframes, selectors can be percentages (0%, 100%) or keywords (from, to)
		f.formatQualifiedRule()
	}
}

func (f *cssFormatter) formatQualifiedRule() {
	f.writeIndent()

	// Format selector
	f.formatSelector()

	f.skipWhitespace()

	if f.current.typ == cssTokenDelim && f.current.value == "{" {
		f.printer.WriteString(" {\n")
		f.atNewline = true
		f.advance()
		f.indent++

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
	}
}

func (f *cssFormatter) formatSelector() {
	needSpace := false
	bracketDepth := 0

	for f.current.typ != cssTokenEOF {
		if f.current.typ == cssTokenDelim {
			if f.current.value == "{" {
				break
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
				f.printer.WriteString(f.current.value)
				f.printer.Reset()
				f.advance()
				needSpace = true
				continue
			}
			// Other selector parts: . * :
			if f.current.value == "." || f.current.value == "*" || f.current.value == ":" {
				if needSpace && f.current.value != ":" {
					f.printer.WriteString(" ")
				}
				f.printer.Set(core.Bold)
				f.printer.Set(core.Blue)
				f.printer.WriteString(f.current.value)
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
			f.advance()
			if bracketDepth == 0 {
				needSpace = true
			}
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
			f.printer.WriteString(f.current.value)
			f.printer.Reset()
			f.advance()
			needSpace = false
		case cssTokenHash:
			f.printer.Set(core.Bold)
			f.printer.Set(core.Blue)
			f.printer.WriteString(f.current.value)
			f.printer.Reset()
			f.advance()
			needSpace = false
		case cssTokenString:
			f.printer.Set(core.Green)
			f.printer.WriteString(f.current.value)
			f.printer.Reset()
			f.advance()
			needSpace = false
		case cssTokenFunction:
			// For pseudo-class functions like :not()
			f.printer.Set(core.Bold)
			f.printer.Set(core.Blue)
			f.printer.WriteString(f.current.value)
			f.printer.Reset()
			f.advance()
			f.formatFunctionArgs()
			needSpace = false
		case cssTokenDimension, cssTokenNumber:
			// For @keyframes selectors like 0%, 100%
			f.printer.Set(core.Bold)
			f.printer.Set(core.Blue)
			f.printer.WriteString(f.current.value)
			f.printer.Reset()
			f.advance()
			needSpace = false
		default:
			f.advance()
		}
	}
}

func (f *cssFormatter) formatDeclarationBlock() {
	for f.current.typ != cssTokenEOF {
		f.skipWhitespace()
		if f.current.typ == cssTokenEOF {
			break
		}

		if f.current.typ == cssTokenDelim && f.current.value == "}" {
			break
		}

		if f.current.typ == cssTokenComment {
			f.formatComment()
			continue
		}

		// Property declaration
		if f.current.typ == cssTokenIdent {
			f.formatDeclaration()
		} else {
			// Skip unexpected tokens
			f.advance()
		}
	}
}

func (f *cssFormatter) formatDeclaration() {
	f.writeIndent()

	// Property name
	f.printer.Set(core.Cyan)
	f.printer.WriteString(f.current.value)
	f.printer.Reset()
	f.advance()

	f.skipWhitespace()

	// Colon
	if f.current.typ == cssTokenDelim && f.current.value == ":" {
		f.printer.WriteString(": ")
		f.advance()
	}

	// Property value
	f.formatValue()

	f.skipWhitespace()

	// Semicolon
	if f.current.typ == cssTokenDelim && f.current.value == ";" {
		f.printer.WriteString(";\n")
		f.atNewline = true
		f.advance()
	} else if f.current.typ == cssTokenDelim && f.current.value == "}" {
		// Missing semicolon before closing brace (lenient)
		f.printer.WriteString(";\n")
		f.atNewline = true
	} else {
		f.printer.WriteString("\n")
		f.atNewline = true
	}
}

func (f *cssFormatter) formatValue() {
	needSpace := false
	parenDepth := 0

	for f.current.typ != cssTokenEOF {
		if f.current.typ == cssTokenDelim {
			if f.current.value == ";" || f.current.value == "}" {
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
			f.printer.WriteString(f.current.value)
			f.printer.Reset()
		} else {
			f.printer.Set(core.Green)
			f.printer.WriteString(f.current.value)
			f.printer.Reset()
		}
		f.advance()
	case cssTokenNumber, cssTokenDimension:
		f.printer.Set(core.Green)
		f.printer.WriteString(f.current.value)
		f.printer.Reset()
		f.advance()
	case cssTokenString:
		f.printer.Set(core.Green)
		f.printer.WriteString(f.current.value)
		f.printer.Reset()
		f.advance()
	case cssTokenHash:
		f.printer.Set(core.Green)
		f.printer.WriteString(f.current.value)
		f.printer.Reset()
		f.advance()
	case cssTokenFunction:
		f.printer.Set(core.Green)
		f.printer.WriteString(f.current.value)
		f.printer.Reset()
		f.advance()
		f.formatFunctionArgsValue()
	case cssTokenDelim:
		if f.current.value == "!" {
			f.printer.Set(core.Green)
			f.printer.WriteString("!")
			f.printer.Reset()
			f.advance()
		} else {
			f.advance()
		}
	default:
		f.advance()
	}
}

func (f *cssFormatter) formatFunctionArgs() {
	depth := 1
	for f.current.typ != cssTokenEOF && depth > 0 {
		if f.current.typ == cssTokenDelim && f.current.value == "(" {
			depth++
			f.printer.Set(core.Bold)
			f.printer.Set(core.Blue)
			f.printer.WriteString("(")
			f.printer.Reset()
			f.advance()
			continue
		}
		if f.current.typ == cssTokenDelim && f.current.value == ")" {
			depth--
			f.printer.Set(core.Bold)
			f.printer.Set(core.Blue)
			f.printer.WriteString(")")
			f.printer.Reset()
			f.advance()
			continue
		}
		if f.current.typ == cssTokenWhitespace {
			f.advance()
			continue
		}

		// Selector elements inside function
		switch f.current.typ {
		case cssTokenIdent:
			f.printer.Set(core.Bold)
			f.printer.Set(core.Blue)
			f.printer.WriteString(f.current.value)
			f.printer.Reset()
			f.advance()
		case cssTokenHash:
			f.printer.Set(core.Bold)
			f.printer.Set(core.Blue)
			f.printer.WriteString(f.current.value)
			f.printer.Reset()
			f.advance()
		case cssTokenDelim:
			if f.current.value == "." || f.current.value == ":" || f.current.value == "*" {
				f.printer.Set(core.Bold)
				f.printer.Set(core.Blue)
				f.printer.WriteString(f.current.value)
				f.printer.Reset()
			}
			f.advance()
		default:
			f.advance()
		}
	}
}

func (f *cssFormatter) formatFunctionArgsValue() {
	depth := 1
	needSpace := false

	for f.current.typ != cssTokenEOF && depth > 0 {
		if f.current.typ == cssTokenDelim && f.current.value == "(" {
			depth++
			f.printer.WriteString("(")
			f.advance()
			needSpace = false
			continue
		}
		if f.current.typ == cssTokenDelim && f.current.value == ")" {
			depth--
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
			f.printer.WriteString(f.current.value)
			f.advance()
		case cssTokenString:
			f.printer.WriteString(f.current.value)
			f.advance()
		case cssTokenHash:
			f.printer.WriteString(f.current.value)
			f.advance()
		case cssTokenFunction:
			f.printer.WriteString(f.current.value)
			f.advance()
			f.formatFunctionArgsValue()
		default:
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
