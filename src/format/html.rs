use std::fmt;

use crate::core::{Sequence, write_styled_to_string};
use crate::format::css;

const BOLD: Sequence = Sequence::Bold;
const DIM: Sequence = Sequence::Dim;
const BLUE: Sequence = Sequence::Blue;
const CYAN: Sequence = Sequence::Cyan;
const GREEN: Sequence = Sequence::Green;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HtmlError(String);

impl fmt::Display for HtmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for HtmlError {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HtmlAttr {
    name: String,
    value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HtmlToken {
    Eof,
    Doctype(String),
    StartTag { name: String, attrs: Vec<HtmlAttr> },
    EndTag(String),
    SelfClosingTag { name: String, attrs: Vec<HtmlAttr> },
    Text(Vec<u8>),
    Comment(String),
}

struct HtmlTokenizer<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> HtmlTokenizer<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    fn next(&mut self, raw_tag: Option<&str>) -> HtmlToken {
        if let Some(tag) = raw_tag
            && !self.starts_with_raw_end_tag(tag)
        {
            if let Some(end) =
                find_case_insensitive(&self.input[self.pos..], raw_end_tag(tag).as_bytes())
            {
                if end > 0 {
                    let text = self.input[self.pos..self.pos + end].to_vec();
                    self.pos += end;
                    return HtmlToken::Text(text);
                }
            } else if self.pos < self.input.len() {
                let text = self.input[self.pos..].to_vec();
                self.pos = self.input.len();
                return HtmlToken::Text(text);
            }
        }

        if self.pos >= self.input.len() {
            return HtmlToken::Eof;
        }

        if self.input[self.pos] != b'<' {
            let start = self.pos;
            while self.pos < self.input.len() && self.input[self.pos] != b'<' {
                self.pos += 1;
            }
            return HtmlToken::Text(self.input[start..self.pos].to_vec());
        }

        if self.starts_with(b"<!--") {
            return self.scan_comment();
        }
        if self.starts_with(b"</") {
            return self.scan_end_tag();
        }
        if self.starts_with_case_insensitive(b"<!doctype") {
            return self.scan_doctype();
        }
        if self.starts_with(b"<!") {
            return self.scan_doctype();
        }
        if self
            .input
            .get(self.pos + 1)
            .is_some_and(|byte| is_name_start(*byte))
        {
            return self.scan_start_tag();
        }

        self.pos += 1;
        HtmlToken::Text(b"<".to_vec())
    }

    fn starts_with(&self, needle: &[u8]) -> bool {
        self.input[self.pos..].starts_with(needle)
    }

    fn starts_with_case_insensitive(&self, needle: &[u8]) -> bool {
        self.input[self.pos..]
            .get(..needle.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(needle))
    }

    fn starts_with_raw_end_tag(&self, tag: &str) -> bool {
        self.input[self.pos..]
            .get(..tag.len() + 2)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(raw_end_tag(tag).as_bytes()))
    }

    fn scan_comment(&mut self) -> HtmlToken {
        self.pos += 4;
        let start = self.pos;
        while self.pos + 2 < self.input.len() {
            if self.input[self.pos..].starts_with(b"-->") {
                let data = bytes_to_string(&self.input[start..self.pos]);
                self.pos += 3;
                return HtmlToken::Comment(data);
            }
            self.pos += 1;
        }
        let data = bytes_to_string(&self.input[start..]);
        self.pos = self.input.len();
        HtmlToken::Comment(data)
    }

    fn scan_doctype(&mut self) -> HtmlToken {
        self.pos += 2;
        let start = self.pos;
        while self.pos < self.input.len() && self.input[self.pos] != b'>' {
            self.pos += 1;
        }
        let raw = bytes_to_string(&self.input[start..self.pos]);
        if self.pos < self.input.len() {
            self.pos += 1;
        }
        let trimmed = raw.trim();
        let data = strip_ascii_prefix(trimmed, "doctype")
            .map(str::trim_start)
            .unwrap_or(trimmed)
            .to_string();
        HtmlToken::Doctype(data)
    }

    fn scan_end_tag(&mut self) -> HtmlToken {
        self.pos += 2;
        self.skip_whitespace();
        let name = self.scan_name();
        while self.pos < self.input.len() && self.input[self.pos] != b'>' {
            self.pos += 1;
        }
        if self.pos < self.input.len() {
            self.pos += 1;
        }
        HtmlToken::EndTag(name)
    }

    fn scan_start_tag(&mut self) -> HtmlToken {
        self.pos += 1;
        let name = self.scan_name();
        let mut attrs = Vec::new();
        let mut self_closing = false;

        loop {
            self.skip_whitespace();
            if self.pos >= self.input.len() {
                break;
            }
            match self.input[self.pos] {
                b'>' => {
                    self.pos += 1;
                    break;
                }
                b'/' if self.input.get(self.pos + 1) == Some(&b'>') => {
                    self.pos += 2;
                    self_closing = true;
                    break;
                }
                b'/' => {
                    self.pos += 1;
                    continue;
                }
                _ => {}
            }

            let attr_name = self.scan_attr_name();
            if attr_name.is_empty() {
                self.pos += 1;
                continue;
            }
            self.skip_whitespace();
            let value = if self.input.get(self.pos) == Some(&b'=') {
                self.pos += 1;
                self.skip_whitespace();
                Some(self.scan_attr_value())
            } else {
                None
            };
            attrs.push(HtmlAttr {
                name: attr_name,
                value,
            });
        }

        if self_closing {
            HtmlToken::SelfClosingTag { name, attrs }
        } else {
            HtmlToken::StartTag { name, attrs }
        }
    }

    fn scan_name(&mut self) -> String {
        let start = self.pos;
        while self.pos < self.input.len()
            && !matches!(
                self.input[self.pos],
                b' ' | b'\t' | b'\n' | b'\r' | b'\x0c' | b'/' | b'>'
            )
        {
            self.pos += 1;
        }
        bytes_to_string(&self.input[start..self.pos])
    }

    fn scan_attr_name(&mut self) -> String {
        let start = self.pos;
        while self.pos < self.input.len()
            && !matches!(
                self.input[self.pos],
                b' ' | b'\t' | b'\n' | b'\r' | b'\x0c' | b'=' | b'/' | b'>'
            )
        {
            self.pos += 1;
        }
        bytes_to_string(&self.input[start..self.pos])
    }

    fn scan_attr_value(&mut self) -> String {
        if self.pos >= self.input.len() {
            return String::new();
        }
        match self.input[self.pos] {
            quote @ (b'"' | b'\'') => {
                self.pos += 1;
                let start = self.pos;
                while self.pos < self.input.len() && self.input[self.pos] != quote {
                    self.pos += 1;
                }
                let value = bytes_to_string(&self.input[start..self.pos]);
                if self.pos < self.input.len() {
                    self.pos += 1;
                }
                value
            }
            _ => {
                let start = self.pos;
                while self.pos < self.input.len()
                    && !matches!(
                        self.input[self.pos],
                        b' ' | b'\t' | b'\n' | b'\r' | b'\x0c' | b'/' | b'>'
                    )
                {
                    self.pos += 1;
                }
                bytes_to_string(&self.input[start..self.pos])
            }
        }
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.input.len()
            && matches!(self.input[self.pos], b' ' | b'\t' | b'\n' | b'\r' | b'\x0c')
        {
            self.pos += 1;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HtmlStackEntry {
    tag_name: String,
    is_block: bool,
    has_block_child: bool,
}

pub fn format_html(buf: &[u8], color: bool) -> Result<Vec<u8>, HtmlError> {
    let mut formatter = HtmlFormatter::new(buf, color);
    formatter.format()?;
    Ok(formatter.out.into_bytes())
}

struct HtmlFormatter<'a> {
    tokenizer: HtmlTokenizer<'a>,
    color: bool,
    out: String,
    stack: Vec<HtmlStackEntry>,
}

impl<'a> HtmlFormatter<'a> {
    fn new(input: &'a [u8], color: bool) -> Self {
        Self {
            tokenizer: HtmlTokenizer::new(input),
            color,
            out: String::new(),
            stack: Vec::new(),
        }
    }

    fn format(&mut self) -> Result<(), HtmlError> {
        loop {
            let raw_tag = self.raw_text_tag().map(str::to_string);
            match self.tokenizer.next(raw_tag.as_deref()) {
                HtmlToken::Eof => return Ok(()),
                HtmlToken::Doctype(data) => {
                    self.out.push_str("<!");
                    self.write_doctype(&data);
                    self.out.push_str(">\n");
                }
                HtmlToken::StartTag { name, attrs } => self.format_start_tag(&name, &attrs),
                HtmlToken::EndTag(name) => self.format_end_tag(&name),
                HtmlToken::SelfClosingTag { name, attrs } => {
                    self.format_self_closing_tag(&name, &attrs);
                }
                HtmlToken::Text(text) => self.format_text(&text)?,
                HtmlToken::Comment(comment) => self.format_comment(&comment),
            }
        }
    }

    fn raw_text_tag(&self) -> Option<&str> {
        let tag = self.stack.last()?.tag_name.as_str();
        if is_raw_text_element(tag) || tag == "textarea" {
            Some(tag)
        } else {
            None
        }
    }

    fn format_start_tag(&mut self, name: &str, attrs: &[HtmlAttr]) {
        let tag_name_lower = name.to_ascii_lowercase();
        let is_block = is_block_element(&tag_name_lower);
        let is_void = is_void_element(&tag_name_lower);

        if is_block && !self.stack.is_empty() {
            let parent = self.stack.last_mut().expect("stack is not empty");
            if !parent.has_block_child {
                self.out.push('\n');
            }
            parent.has_block_child = true;
            write_indent(&mut self.out, self.stack.len());
        }

        self.out.push('<');
        self.write_tag_name(name);
        self.write_attributes(attrs);
        self.out.push('>');

        if !is_void {
            self.stack.push(HtmlStackEntry {
                tag_name: tag_name_lower,
                is_block,
                has_block_child: false,
            });
        } else if is_block {
            self.out.push('\n');
        }
    }

    fn format_end_tag(&mut self, name: &str) {
        let tag_name_lower = name.to_ascii_lowercase();
        if is_void_element(&tag_name_lower) {
            return;
        }

        let mut entry = HtmlStackEntry {
            tag_name: String::new(),
            is_block: false,
            has_block_child: false,
        };
        let mut found = false;
        for i in (0..self.stack.len()).rev() {
            if self.stack[i].tag_name == tag_name_lower {
                entry = self.stack[i].clone();
                self.stack.truncate(i);
                found = true;
                break;
            }
        }

        if entry.is_block && entry.has_block_child {
            write_indent(&mut self.out, self.stack.len());
        }

        self.out.push_str("</");
        self.write_tag_name(name);
        self.out.push('>');

        if found && entry.is_block {
            self.out.push('\n');
        }
    }

    fn format_self_closing_tag(&mut self, name: &str, attrs: &[HtmlAttr]) {
        let tag_name_lower = name.to_ascii_lowercase();
        let is_block = is_block_element(&tag_name_lower);

        if is_block && !self.stack.is_empty() {
            let parent = self.stack.last_mut().expect("stack is not empty");
            if !parent.has_block_child {
                self.out.push('\n');
            }
            parent.has_block_child = true;
            write_indent(&mut self.out, self.stack.len());
        }

        self.out.push('<');
        self.write_tag_name(name);
        self.write_attributes(attrs);
        self.out.push('>');

        if is_block {
            self.out.push('\n');
        }
    }

    fn format_text(&mut self, text: &[u8]) -> Result<(), HtmlError> {
        let current_tag = self.stack.last().map(|entry| entry.tag_name.as_str());
        let in_raw_text = current_tag.is_some_and(is_raw_text_element);
        let in_preserve_ws = current_tag.is_some_and(is_preserve_whitespace_element);

        if in_raw_text || in_preserve_ws {
            if current_tag == Some("style") {
                self.out.push('\n');
                let trimmed = trim_ascii_whitespace(text);
                if !trimmed.is_empty() {
                    match css::format_css_indented(trimmed, self.color, self.stack.len()) {
                        Ok(formatted) => self.out.push_str(&formatted),
                        Err(_) => self.write_text(text),
                    }
                }
                if let Some(entry) = self.stack.last_mut() {
                    entry.has_block_child = true;
                }
            } else {
                self.write_text(text);
            }
            return Ok(());
        }

        let trimmed = trim_ascii_whitespace(text);
        if !trimmed.is_empty() {
            let has_leading_space = text.first().is_some_and(|byte| is_inline_space(*byte));
            let has_trailing_space = text.last().is_some_and(|byte| is_inline_space(*byte));
            if has_leading_space {
                self.out.push(' ');
            }
            self.write_text(trimmed);
            if has_trailing_space {
                self.out.push(' ');
            }
        }
        Ok(())
    }

    fn format_comment(&mut self, comment: &str) {
        if !self.stack.is_empty() {
            let parent = self.stack.last_mut().expect("stack is not empty");
            if !parent.has_block_child {
                self.out.push('\n');
            }
            parent.has_block_child = true;
            write_indent(&mut self.out, self.stack.len());
        }
        self.out.push_str("<!--");
        self.write_comment(comment);
        self.out.push_str("-->\n");
    }

    fn write_attributes(&mut self, attrs: &[HtmlAttr]) {
        for attr in attrs {
            self.out.push(' ');
            self.write_attr_name(&attr.name);
            if let Some(value) = &attr.value {
                self.out.push_str("=\"");
                self.write_attr_value(value);
                self.out.push('"');
            }
        }
    }

    fn write_tag_name(&mut self, name: &str) {
        write_styled_to_string(&mut self.out, name, &[BOLD, BLUE], self.color);
    }

    fn write_attr_name(&mut self, name: &str) {
        write_styled_to_string(&mut self.out, name, &[CYAN], self.color);
    }

    fn write_attr_value(&mut self, value: &str) {
        let mut escaped = String::new();
        escape_html_attr_value_into(&mut escaped, value);
        write_styled_to_string(&mut self.out, &escaped, &[GREEN], self.color);
    }

    fn write_text(&mut self, text: &[u8]) {
        write_styled_to_string(&mut self.out, &bytes_to_string(text), &[GREEN], self.color);
    }

    fn write_doctype(&mut self, data: &str) {
        write_styled_to_string(
            &mut self.out,
            &format!("DOCTYPE {data}"),
            &[CYAN],
            self.color,
        );
    }

    fn write_comment(&mut self, comment: &str) {
        write_styled_to_string(&mut self.out, comment, &[DIM], self.color);
    }
}

fn write_indent(out: &mut String, level: usize) {
    for _ in 0..level {
        out.push_str("  ");
    }
}

fn escape_html_attr_value_into(out: &mut String, value: &str) {
    let mut last = 0;
    for (i, ch) in value.char_indices() {
        let escape = match ch {
            '"' => "&quot;",
            '&' => "&amp;",
            '<' => "&lt;",
            '>' => "&gt;",
            _ => continue,
        };
        out.push_str(&value[last..i]);
        out.push_str(escape);
        last = i + ch.len_utf8();
    }
    out.push_str(&value[last..]);
}

fn strip_ascii_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value.get(..prefix.len()).and_then(|head| {
        if head.eq_ignore_ascii_case(prefix) {
            Some(&value[prefix.len()..])
        } else {
            None
        }
    })
}

fn raw_end_tag(tag: &str) -> String {
    format!("</{tag}")
}

fn find_case_insensitive(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
}

fn trim_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while let Some((first, rest)) = bytes.split_first() {
        if first.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    while let Some((last, rest)) = bytes.split_last() {
        if last.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

fn bytes_to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn is_inline_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

fn is_name_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic()
}

fn is_void_element(tag: &str) -> bool {
    matches!(
        tag,
        "area"
            | "base"
            | "br"
            | "col"
            | "embed"
            | "hr"
            | "img"
            | "input"
            | "link"
            | "meta"
            | "param"
            | "source"
            | "track"
            | "wbr"
    )
}

fn is_block_element(tag: &str) -> bool {
    matches!(
        tag,
        "html"
            | "head"
            | "body"
            | "title"
            | "meta"
            | "link"
            | "base"
            | "div"
            | "p"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
            | "ul"
            | "ol"
            | "li"
            | "table"
            | "thead"
            | "tbody"
            | "tfoot"
            | "tr"
            | "td"
            | "th"
            | "form"
            | "fieldset"
            | "section"
            | "article"
            | "nav"
            | "aside"
            | "header"
            | "footer"
            | "main"
            | "figure"
            | "figcaption"
            | "blockquote"
            | "pre"
            | "address"
            | "details"
            | "summary"
            | "dialog"
            | "script"
            | "style"
            | "noscript"
            | "template"
            | "canvas"
            | "video"
            | "audio"
            | "iframe"
            | "object"
            | "select"
            | "option"
            | "optgroup"
            | "datalist"
            | "textarea"
            | "dl"
            | "dt"
            | "dd"
            | "hr"
            | "br"
            | "img"
            | "input"
            | "area"
            | "col"
            | "embed"
            | "source"
            | "track"
            | "wbr"
    )
}

fn is_raw_text_element(tag: &str) -> bool {
    matches!(tag, "script" | "style")
}

fn is_preserve_whitespace_element(tag: &str) -> bool {
    matches!(tag, "pre" | "textarea")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn formatted(input: &str) -> String {
        String::from_utf8(format_html(input.as_bytes(), false).unwrap()).unwrap()
    }

    #[test]
    fn test_format_html() {
        let cases = [
            ("valid simple html", "<html><body>text</body></html>"),
            (
                "valid nested html",
                "<html><head><title>test</title></head><body><div>content</div></body></html>",
            ),
            (
                "valid html with attributes",
                r#"<div class="container" id="main"><p>text</p></div>"#,
            ),
            ("void elements br", "<p>line1<br>line2</p>"),
            ("void elements img", r#"<img src="test.jpg" alt="test">"#),
            ("void elements input", r#"<input type="text" name="field">"#),
            ("self-closing syntax", "<br/>"),
            ("doctype", "<!DOCTYPE html><html></html>"),
            ("comment", "<!-- this is a comment --><div>content</div>"),
            (
                "script content preservation",
                r#"<script>var x = "<p>not html</p>";</script>"#,
            ),
            (
                "style content preservation",
                r#"<style>.class { content: "<div>"; }</style>"#,
            ),
            ("pre whitespace preservation", "<pre>  line1\n  line2</pre>"),
            (
                "textarea whitespace preservation",
                "<textarea>  some text\n  more text</textarea>",
            ),
            ("malformed html unclosed tag", "<div><p>unclosed"),
            ("malformed html mismatched tags", "<div><span></div></span>"),
            (
                "boolean attributes",
                r#"<input type="checkbox" checked disabled>"#,
            ),
            (
                "multiple attributes",
                r#"<a href="http://example.com" target="_blank" rel="noopener">link</a>"#,
            ),
            (
                "inline elements",
                "<p>Text with <strong>bold</strong> and <em>italic</em></p>",
            ),
            ("empty input", ""),
        ];

        for (name, input) in cases {
            assert!(
                format_html(input.as_bytes(), false).is_ok(),
                "{name} should format"
            );
        }
    }

    #[test]
    fn test_format_html_output() {
        let output = formatted("<html><body><p>text</p></body></html>");
        assert!(output.contains("<html>"));
        assert!(output.contains("</html>"));
        assert!(output.contains("text"));
    }

    #[test]
    fn test_format_html_indentation() {
        let output = formatted(
            "<html><head><title>Test</title></head><body><div><p>content</p></div></body></html>",
        );
        assert!(
            output
                .lines()
                .any(|line| line.contains("<div>") && line.starts_with("    ")),
            "expected indented <div>, got output:\n{output}"
        );
    }

    #[test]
    fn test_format_html_doctype() {
        let output = formatted("<!DOCTYPE html><html><body></body></html>");
        assert!(output.contains("<!DOCTYPE html>"), "{output}");
    }

    #[test]
    fn test_format_html_comment() {
        let output = formatted("<!-- test comment --><div>content</div>");
        assert!(output.contains("<!-- test comment -->"), "{output}");
    }

    #[test]
    fn test_format_html_void_elements() {
        let cases = [
            ("br element", "<p>line1<br>line2</p>", "<br>"),
            ("hr element", "<div><hr></div>", "<hr>"),
            (
                "img element",
                r#"<img src="test.jpg">"#,
                r#"<img src="test.jpg">"#,
            ),
            (
                "input element",
                r#"<input type="text">"#,
                r#"<input type="text">"#,
            ),
            (
                "meta element",
                r#"<meta charset="utf-8">"#,
                r#"<meta charset="utf-8">"#,
            ),
            (
                "link element",
                r#"<link rel="stylesheet" href="style.css">"#,
                r#"<link rel="stylesheet" href="style.css">"#,
            ),
        ];

        for (name, input, check) in cases {
            let output = formatted(input);
            assert!(output.contains(check), "{name}: {output}");
            let tag_name = check
                .trim_start_matches('<')
                .split(' ')
                .next()
                .unwrap_or_default()
                .trim_end_matches('>');
            let closing_tag = format!("</{tag_name}>");
            assert!(
                !output.contains(&closing_tag),
                "{name}: output should not contain {closing_tag}, got {output}"
            );
        }
    }

    #[test]
    fn test_format_html_preserves_raw_text() {
        let output = formatted(r#"<script>if (x < 5 && y > 3) { alert("<test>"); }</script>"#);
        assert!(output.contains(r#"if (x < 5 && y > 3)"#), "{output}");
    }

    #[test]
    fn test_format_html_preserves_pre_whitespace() {
        let output = formatted("<pre>  line1\n    line2</pre>");
        assert!(output.contains("  line1"), "{output}");
        assert!(output.contains("    line2"), "{output}");
    }

    #[test]
    fn test_format_html_plan_example() {
        let input = r#"<!DOCTYPE html><html><head><title>Test</title></head><body><div class="container"><h1>Hello</h1><p>Text with <strong>bold</strong></p><br><img src="x.jpg"></div></body></html>"#;
        let expected = r#"<!DOCTYPE html>
<html>
  <head>
    <title>Test</title>
  </head>
  <body>
    <div class="container">
      <h1>Hello</h1>
      <p>Text with <strong>bold</strong></p>
      <br>
      <img src="x.jpg">
    </div>
  </body>
</html>
"#;
        assert_eq!(formatted(input), expected);
    }

    #[test]
    fn test_format_html_embedded_css() {
        let output = formatted("<style>body{color:red}</style>");
        assert!(output.contains("body"), "{output}");
        assert!(output.contains("color"), "{output}");
        assert!(output.contains("red"), "{output}");

        let output = formatted("<html><head><style>.a{margin:0}</style></head></html>");
        assert!(output.contains(".a"), "{output}");
        assert!(output.contains("margin"), "{output}");

        let output = formatted("<style></style>");
        assert!(output.contains("<style>"), "{output}");
        assert!(output.contains("</style>"), "{output}");

        let output = formatted("<style>\n   </style>");
        assert!(output.contains("<style>"), "{output}");

        let output = formatted("<script>var x = 1;</script>");
        assert!(output.contains("var x = 1;"), "{output}");

        let output = formatted("<style>.a{}</style><style>.b{}</style>");
        assert!(output.contains(".a"), "{output}");
        assert!(output.contains(".b"), "{output}");

        let output = formatted(
            "<html><head><style>body{color:red;margin:0}.container{display:flex}</style></head></html>",
        );
        assert!(output.contains("body"), "{output}");
        assert!(output.contains(".container"), "{output}");
        assert!(output.contains("display"), "{output}");
        assert!(output.contains("flex"), "{output}");
    }

    #[test]
    fn test_escape_html_attr_value() {
        let cases = [
            ("no escape needed", "hello world", "hello world"),
            ("with ampersand", "foo & bar", "foo &amp; bar"),
            ("with less than", "a < b", "a &lt; b"),
            ("with greater than", "a > b", "a &gt; b"),
            ("with quotes", r#"say "hello""#, "say &quot;hello&quot;"),
            (
                "mixed special chars",
                r#"<script>"alert('&')"</script>"#,
                "&lt;script&gt;&quot;alert('&amp;')&quot;&lt;/script&gt;",
            ),
        ];

        for (name, input, want) in cases {
            let mut got = String::new();
            escape_html_attr_value_into(&mut got, input);
            assert_eq!(got, want, "{name}");
        }
    }

    #[test]
    fn formats_html_with_color_when_requested() {
        let output =
            String::from_utf8(format_html(b"<div class=\"x\">text</div>", true).unwrap()).unwrap();
        assert!(output.contains("\x1b[1m\x1b[34mdiv\x1b[0m"), "{output:?}");
        assert!(output.contains("\x1b[36mclass\x1b[0m"), "{output:?}");
        assert!(output.contains("\x1b[32mx\x1b[0m"), "{output:?}");
        assert!(output.contains("\x1b[32mtext\x1b[0m"), "{output:?}");
    }
}
