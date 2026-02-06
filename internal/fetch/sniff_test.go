package fetch

import (
	"testing"
)

func TestSniffContentType(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  ContentType
	}{
		// JSON
		{"json object", []byte(`{"key": "value"}`), TypeJSON},
		{"json array", []byte(`[1, 2, 3]`), TypeJSON},
		{"json with whitespace", []byte("  \n  { \"key\": 1 }"), TypeJSON},
		{"json with bom", []byte("\xEF\xBB\xBF{\"key\": 1}"), TypeJSON},
		{"json array with bom and whitespace", []byte("\xEF\xBB\xBF  [1]"), TypeJSON},

		// XML
		{"xml declaration", []byte(`<?xml version="1.0"?><root/>`), TypeXML},
		{"xml element", []byte(`<root><child/></root>`), TypeXML},
		{"xml with whitespace", []byte("  \n  <?xml version=\"1.0\"?>"), TypeXML},
		{"xml comment", []byte(`<!-- comment --><root/>`), TypeXML},
		{"xml cdata", []byte(`<![CDATA[data]]>`), TypeXML},
		{"xml doctype", []byte(`<!DOCTYPE note SYSTEM "note.dtd">`), TypeXML},
		{"xml unknown element", []byte(`<catalog><book/></catalog>`), TypeXML},

		// HTML
		{"html doctype", []byte(`<!DOCTYPE html><html></html>`), TypeHTML},
		{"html doctype lowercase", []byte(`<!doctype html><html></html>`), TypeHTML},
		{"html tag", []byte(`<html><body></body></html>`), TypeHTML},
		{"head tag", []byte(`<head><title>test</title></head>`), TypeHTML},
		{"body tag", []byte(`<body>content</body>`), TypeHTML},
		{"div tag", []byte(`<div class="test">content</div>`), TypeHTML},
		{"p tag", []byte(`<p>paragraph</p>`), TypeHTML},
		{"span tag", []byte(`<span>text</span>`), TypeHTML},
		{"section tag", []byte(`<section>content</section>`), TypeHTML},
		{"article tag", []byte(`<article>content</article>`), TypeHTML},
		{"html with bom", []byte("\xEF\xBB\xBF<!doctype html>"), TypeHTML},
		{"h1 tag", []byte(`<h1>heading</h1>`), TypeHTML},
		{"table tag", []byte(`<table><tr><td>cell</td></tr></table>`), TypeHTML},
		{"nav tag", []byte(`<nav>navigation</nav>`), TypeHTML},
		{"html self-closing", []byte(`<br/>`), TypeHTML},
		{"html tag with attributes", []byte(`<div id="main">`), TypeHTML},

		// YAML
		{"yaml document start", []byte("---\nkey: value"), TypeYAML},
		{"yaml with whitespace", []byte("  \n  ---\nkey: value"), TypeYAML},
		{"yaml with bom", []byte("\xEF\xBB\xBF---\nkey: value"), TypeYAML},

		// Images
		{"png image", []byte("\x89PNG\r\n\x1a\n"), TypeImage},
		{"jpeg image", []byte("\xff\xd8\xff\xe0"), TypeImage},
		{"gif image", []byte("GIF89a"), TypeImage},
		{"bmp image", []byte("BM\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), TypeImage},

		// Unknown
		{"empty", []byte{}, TypeUnknown},
		{"plain text", []byte("hello world"), TypeUnknown},
		{"csv-like", []byte("name,age\nalice,30"), TypeUnknown},
		{"number", []byte("12345"), TypeUnknown},
		{"whitespace only", []byte("   \n\t  "), TypeUnknown},
		{"single dash", []byte("-"), TypeUnknown},
		{"two dashes", []byte("--"), TypeUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sniffContentType(tt.input)
			if got != tt.want {
				t.Errorf("sniffContentType(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsHTMLTag(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{"html", []byte("html>"), true},
		{"HTML uppercase", []byte("HTML>"), true},
		{"div with space", []byte("div class=\"x\">"), true},
		{"body end", []byte("body>"), true},
		{"custom tag", []byte("mycomponent>"), false},
		{"partial match", []byte("divider>"), false},
		{"h1", []byte("h1>"), true},
		{"h1 with space", []byte("h1 id=\"x\">"), true},
		{"a tag", []byte("a href=\"/\">"), true},
		{"img self-close", []byte("img/>"), true},
		{"br", []byte("br>"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isHTMLTag(tt.input)
			if got != tt.want {
				t.Errorf("isHTMLTag(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsLetter(t *testing.T) {
	tests := []struct {
		c    byte
		want bool
	}{
		{'a', true},
		{'z', true},
		{'A', true},
		{'Z', true},
		{'m', true},
		{'0', false},
		{'!', false},
		{' ', false},
		{'<', false},
	}
	for _, tt := range tests {
		t.Run(string(tt.c), func(t *testing.T) {
			got := isLetter(tt.c)
			if got != tt.want {
				t.Errorf("isLetter(%q) = %v, want %v", tt.c, got, tt.want)
			}
		})
	}
}
