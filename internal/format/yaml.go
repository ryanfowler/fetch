package format

import (
	"fmt"

	"github.com/ryanfowler/fetch/internal/core"

	"github.com/goccy/go-yaml/lexer"
	"github.com/goccy/go-yaml/token"
)

// FormatYAML formats the provided raw YAML data to the Printer.
func FormatYAML(buf []byte, p *core.Printer) error {
	err := formatYAML(buf, p)
	if err != nil {
		p.Reset()
	}
	return err
}

func formatYAML(buf []byte, p *core.Printer) error {
	tokens := lexer.Tokenize(string(buf))

	if inv := tokens.InvalidToken(); inv != nil {
		return fmt.Errorf("invalid yaml: %s", inv.Error)
	}

	for _, tok := range tokens {
		writeYAMLToken(p, tok)
	}

	return nil
}

func writeYAMLToken(p *core.Printer, tok *token.Token) {
	switch tok.Type {
	case token.StringType, token.SingleQuoteType, token.DoubleQuoteType:
		if isYAMLKey(tok) {
			p.Set(core.Blue)
			p.Set(core.Bold)
			p.WriteString(tok.Origin)
			p.Reset()
		} else {
			p.Set(core.Green)
			p.WriteString(tok.Origin)
			p.Reset()
		}

	case token.MergeKeyType:
		p.Set(core.Blue)
		p.Set(core.Bold)
		p.WriteString(tok.Origin)
		p.Reset()

	case token.CommentType:
		p.Set(core.Dim)
		p.WriteString(tok.Origin)
		p.Reset()

	case token.TagType, token.AnchorType, token.AliasType, token.DirectiveType:
		p.Set(core.Cyan)
		p.WriteString(tok.Origin)
		p.Reset()

	case token.DocumentHeaderType, token.DocumentEndType:
		p.Set(core.Dim)
		p.WriteString(tok.Origin)
		p.Reset()

	default:
		p.WriteString(tok.Origin)
	}
}

func isYAMLKey(tok *token.Token) bool {
	return tok.Next != nil && tok.NextType() == token.MappingValueType
}
