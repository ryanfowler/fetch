use std::fmt;

use crate::core::{Sequence, write_styled_to_string};

const BOLD: Sequence = Sequence::Bold;
const DIM: Sequence = Sequence::Dim;
const BLUE: Sequence = Sequence::Blue;
const CYAN: Sequence = Sequence::Cyan;
const GREEN: Sequence = Sequence::Green;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CssError(String);

impl fmt::Display for CssError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CssError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CssTokenType {
    Eof,
    Ident,
    Hash,
    AtKeyword,
    String,
    Number,
    Dimension,
    Function,
    Comment,
    Delim,
    Whitespace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CssToken {
    typ: CssTokenType,
    value: String,
}

struct CssTokenizer<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> CssTokenizer<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    fn peek(&self) -> u8 {
        self.input.get(self.pos).copied().unwrap_or_default()
    }

    fn peek_n(&self, n: usize) -> u8 {
        self.input.get(self.pos + n).copied().unwrap_or_default()
    }

    fn advance_byte(&mut self) -> u8 {
        let byte = self.peek();
        if self.pos < self.input.len() {
            self.pos += 1;
        }
        byte
    }

    fn next(&mut self) -> CssToken {
        if self.consume_whitespace() {
            return CssToken {
                typ: CssTokenType::Whitespace,
                value: " ".to_string(),
            };
        }

        if self.pos >= self.input.len() {
            return CssToken {
                typ: CssTokenType::Eof,
                value: String::new(),
            };
        }

        let c = self.peek();
        if c == b'/' && self.peek_n(1) == b'*' {
            return self.scan_comment();
        }
        if c == b'"' || c == b'\'' {
            return self.scan_string(c);
        }
        if c == b'@' {
            return self.scan_at_keyword();
        }
        if c == b'#' {
            return self.scan_hash();
        }
        if is_digit(c)
            || (c == b'.' && is_digit(self.peek_n(1)))
            || (c == b'-' && (is_digit(self.peek_n(1)) || self.peek_n(1) == b'.'))
        {
            return self.scan_number();
        }
        if is_ident_start(c) || c == b'-' || c == b'_' {
            return self.scan_ident_or_function();
        }

        self.advance_byte();
        CssToken {
            typ: CssTokenType::Delim,
            value: byte_to_string(c),
        }
    }

    fn consume_whitespace(&mut self) -> bool {
        let mut found = false;
        while self.pos < self.input.len() {
            match self.peek() {
                b' ' | b'\t' | b'\n' | b'\r' | b'\x0c' => {
                    self.advance_byte();
                    found = true;
                }
                _ => break,
            }
        }
        found
    }

    fn scan_comment(&mut self) -> CssToken {
        let start = self.pos;
        self.advance_byte();
        self.advance_byte();
        while self.pos < self.input.len() {
            if self.peek() == b'*' && self.peek_n(1) == b'/' {
                self.advance_byte();
                self.advance_byte();
                break;
            }
            self.advance_byte();
        }
        CssToken {
            typ: CssTokenType::Comment,
            value: bytes_to_string(&self.input[start..self.pos]),
        }
    }

    fn scan_string(&mut self, quote: u8) -> CssToken {
        let start = self.pos;
        self.advance_byte();
        while self.pos < self.input.len() {
            let c = self.peek();
            if c == quote {
                self.advance_byte();
                break;
            }
            if c == b'\\' {
                self.advance_byte();
                if self.pos < self.input.len() {
                    self.advance_byte();
                }
                continue;
            }
            if c == b'\n' || c == b'\r' {
                break;
            }
            self.advance_byte();
        }
        CssToken {
            typ: CssTokenType::String,
            value: bytes_to_string(&self.input[start..self.pos]),
        }
    }

    fn scan_at_keyword(&mut self) -> CssToken {
        let start = self.pos;
        self.advance_byte();
        while self.pos < self.input.len() && is_ident_char(self.peek()) {
            self.advance_byte();
        }
        CssToken {
            typ: CssTokenType::AtKeyword,
            value: bytes_to_string(&self.input[start..self.pos]),
        }
    }

    fn scan_hash(&mut self) -> CssToken {
        let start = self.pos;
        self.advance_byte();
        while self.pos < self.input.len() && is_ident_char(self.peek()) {
            self.advance_byte();
        }
        CssToken {
            typ: CssTokenType::Hash,
            value: bytes_to_string(&self.input[start..self.pos]),
        }
    }

    fn scan_number(&mut self) -> CssToken {
        let start = self.pos;
        if self.peek() == b'-' || self.peek() == b'+' {
            self.advance_byte();
        }
        while self.pos < self.input.len() && is_digit(self.peek()) {
            self.advance_byte();
        }
        if self.peek() == b'.' && is_digit(self.peek_n(1)) {
            self.advance_byte();
            while self.pos < self.input.len() && is_digit(self.peek()) {
                self.advance_byte();
            }
        }
        if is_ident_start(self.peek()) || self.peek() == b'%' {
            if self.peek() == b'%' {
                self.advance_byte();
            } else {
                while self.pos < self.input.len() && is_ident_char(self.peek()) {
                    self.advance_byte();
                }
            }
            return CssToken {
                typ: CssTokenType::Dimension,
                value: bytes_to_string(&self.input[start..self.pos]),
            };
        }
        CssToken {
            typ: CssTokenType::Number,
            value: bytes_to_string(&self.input[start..self.pos]),
        }
    }

    fn scan_ident_or_function(&mut self) -> CssToken {
        let start = self.pos;
        while self.peek() == b'-' {
            self.advance_byte();
        }
        while self.pos < self.input.len() && is_ident_char(self.peek()) {
            self.advance_byte();
        }
        let value = bytes_to_string(&self.input[start..self.pos]);
        if self.peek() == b'(' {
            self.advance_byte();
            return CssToken {
                typ: CssTokenType::Function,
                value: format!("{value}("),
            };
        }
        CssToken {
            typ: CssTokenType::Ident,
            value,
        }
    }
}

fn is_digit(c: u8) -> bool {
    c.is_ascii_digit()
}

fn is_ident_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_' || c >= 0x80
}

fn is_ident_char(c: u8) -> bool {
    is_ident_start(c) || is_digit(c) || c == b'-'
}

fn bytes_to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn byte_to_string(byte: u8) -> String {
    String::from_utf8_lossy(&[byte]).into_owned()
}

pub fn format_css(buf: &[u8], color: bool) -> Result<Vec<u8>, CssError> {
    let output = format_css_indented(buf, color, 0)?;
    Ok(output.into_bytes())
}

pub(crate) fn format_css_indented(
    buf: &[u8],
    color: bool,
    base_indent: usize,
) -> Result<String, CssError> {
    if buf.is_empty() {
        return Ok(String::new());
    }

    let mut formatter = CssFormatter::new(buf, color, base_indent);
    formatter.advance();
    formatter.format()?;
    Ok(formatter.out)
}

struct CssFormatter<'a> {
    tok: CssTokenizer<'a>,
    color: bool,
    out: String,
    indent: usize,
    current: CssToken,
    at_newline: bool,
    wrote_rule: bool,
}

impl<'a> CssFormatter<'a> {
    fn new(input: &'a [u8], color: bool, indent: usize) -> Self {
        Self {
            tok: CssTokenizer::new(input),
            color,
            out: String::new(),
            indent,
            current: CssToken {
                typ: CssTokenType::Eof,
                value: String::new(),
            },
            at_newline: true,
            wrote_rule: false,
        }
    }

    fn advance(&mut self) {
        self.current = self.tok.next();
    }

    fn skip_whitespace(&mut self) {
        while self.current.typ == CssTokenType::Whitespace {
            self.advance();
        }
    }

    fn format(&mut self) -> Result<(), CssError> {
        while self.current.typ != CssTokenType::Eof {
            self.skip_whitespace();
            if self.current.typ == CssTokenType::Eof {
                break;
            }

            if self.current.typ == CssTokenType::Comment {
                if self.indent == 0 && self.wrote_rule {
                    self.out.push('\n');
                }
                self.format_comment();
                self.wrote_rule = true;
                continue;
            }

            if self.current.typ == CssTokenType::AtKeyword {
                if self.indent == 0 && self.wrote_rule {
                    self.out.push('\n');
                }
                self.format_at_rule();
                continue;
            }

            if self.indent == 0 && self.wrote_rule {
                self.out.push('\n');
            }
            self.format_qualified_rule();
        }
        Ok(())
    }

    fn format_comment(&mut self) {
        self.write_indent();
        write_styled(&mut self.out, &self.current.value, &[DIM], self.color);
        self.out.push('\n');
        self.at_newline = true;
        self.advance();
    }

    fn format_at_rule(&mut self) {
        self.write_indent();
        write_styled(
            &mut self.out,
            &self.current.value,
            &[BOLD, BLUE],
            self.color,
        );
        self.advance();
        self.format_at_rule_prelude();
        self.skip_whitespace();

        if self.current.typ == CssTokenType::Delim && self.current.value == "{" {
            self.out.push_str(" {\n");
            self.at_newline = true;
            self.advance();
            self.indent += 1;
            self.format_at_rule_body();
            self.indent -= 1;
            self.write_indent();
            self.out.push_str("}\n");
            self.at_newline = true;
            if self.current.typ == CssTokenType::Delim && self.current.value == "}" {
                self.advance();
            }
            if self.indent == 0 {
                self.wrote_rule = true;
            }
        } else if self.current.typ == CssTokenType::Delim && self.current.value == ";" {
            self.out.push_str(";\n");
            self.at_newline = true;
            self.advance();
            if self.indent == 0 {
                self.wrote_rule = true;
            }
        } else {
            self.out.push('\n');
            self.at_newline = true;
        }
    }

    fn format_at_rule_prelude(&mut self) {
        let mut need_space = false;
        let mut paren_depth = 0usize;

        while self.current.typ != CssTokenType::Eof {
            if self.current.typ == CssTokenType::Delim {
                match self.current.value.as_str() {
                    "{" | ";" => break,
                    "(" => {
                        paren_depth += 1;
                        self.out.push('(');
                        self.advance();
                        need_space = false;
                        continue;
                    }
                    ")" => {
                        paren_depth = paren_depth.saturating_sub(1);
                        self.out.push(')');
                        self.advance();
                        need_space = true;
                        continue;
                    }
                    "," => {
                        self.out.push(',');
                        self.advance();
                        need_space = true;
                        continue;
                    }
                    ":" => {
                        self.out.push(':');
                        self.advance();
                        need_space = false;
                        continue;
                    }
                    _ => {}
                }
            }

            if self.current.typ == CssTokenType::Whitespace {
                self.advance();
                if paren_depth == 0 {
                    need_space = true;
                }
                continue;
            }

            if need_space {
                self.out.push(' ');
                need_space = false;
            }
            self.format_value_token();
        }
    }

    fn format_at_rule_body(&mut self) {
        while self.current.typ != CssTokenType::Eof {
            self.skip_whitespace();
            if self.current.typ == CssTokenType::Eof {
                break;
            }
            if self.current.typ == CssTokenType::Delim && self.current.value == "}" {
                break;
            }
            if self.current.typ == CssTokenType::Comment {
                self.format_comment();
                continue;
            }
            if self.current.typ == CssTokenType::AtKeyword {
                self.format_at_rule();
                continue;
            }
            self.format_qualified_rule();
        }
    }

    fn format_qualified_rule(&mut self) {
        self.write_indent();
        self.format_selector();
        self.skip_whitespace();

        if self.current.typ == CssTokenType::Delim && self.current.value == "{" {
            self.out.push_str(" {\n");
            self.at_newline = true;
            self.advance();
            self.indent += 1;
            self.format_declaration_block();
            self.indent -= 1;
            self.write_indent();
            self.out.push_str("}\n");
            self.at_newline = true;
            if self.current.typ == CssTokenType::Delim && self.current.value == "}" {
                self.advance();
            }
            if self.indent == 0 {
                self.wrote_rule = true;
            }
        }
    }

    fn format_selector(&mut self) {
        let mut need_space = false;
        let mut bracket_depth = 0usize;

        while self.current.typ != CssTokenType::Eof {
            if self.current.typ == CssTokenType::Delim {
                match self.current.value.as_str() {
                    "{" => break,
                    "[" => {
                        bracket_depth += 1;
                        write_styled(&mut self.out, "[", &[BOLD, BLUE], self.color);
                        self.advance();
                        need_space = false;
                        continue;
                    }
                    "]" => {
                        bracket_depth = bracket_depth.saturating_sub(1);
                        write_styled(&mut self.out, "]", &[BOLD, BLUE], self.color);
                        self.advance();
                        need_space = true;
                        continue;
                    }
                    "," => {
                        self.out.push(',');
                        self.advance();
                        need_space = true;
                        continue;
                    }
                    ">" | "+" | "~" => {
                        if need_space {
                            self.out.push(' ');
                        }
                        write_styled(
                            &mut self.out,
                            &self.current.value,
                            &[BOLD, BLUE],
                            self.color,
                        );
                        self.advance();
                        need_space = true;
                        continue;
                    }
                    "." | "*" | ":" => {
                        if need_space && self.current.value != ":" {
                            self.out.push(' ');
                        }
                        write_styled(
                            &mut self.out,
                            &self.current.value,
                            &[BOLD, BLUE],
                            self.color,
                        );
                        self.advance();
                        need_space = false;
                        continue;
                    }
                    "=" => {
                        write_styled(&mut self.out, "=", &[BOLD, BLUE], self.color);
                        self.advance();
                        need_space = false;
                        continue;
                    }
                    _ => {}
                }
            }

            if self.current.typ == CssTokenType::Whitespace {
                self.advance();
                if bracket_depth == 0 {
                    need_space = true;
                }
                continue;
            }

            if need_space {
                self.out.push(' ');
                need_space = false;
            }

            match self.current.typ {
                CssTokenType::Ident | CssTokenType::Hash => {
                    write_styled(
                        &mut self.out,
                        &self.current.value,
                        &[BOLD, BLUE],
                        self.color,
                    );
                    self.advance();
                    need_space = false;
                }
                CssTokenType::String => {
                    write_styled(&mut self.out, &self.current.value, &[GREEN], self.color);
                    self.advance();
                    need_space = false;
                }
                CssTokenType::Function => {
                    write_styled(
                        &mut self.out,
                        &self.current.value,
                        &[BOLD, BLUE],
                        self.color,
                    );
                    self.advance();
                    self.format_function_args();
                    need_space = false;
                }
                CssTokenType::Dimension | CssTokenType::Number => {
                    write_styled(
                        &mut self.out,
                        &self.current.value,
                        &[BOLD, BLUE],
                        self.color,
                    );
                    self.advance();
                    need_space = false;
                }
                _ => self.advance(),
            }
        }
    }

    fn format_declaration_block(&mut self) {
        while self.current.typ != CssTokenType::Eof {
            self.skip_whitespace();
            if self.current.typ == CssTokenType::Eof {
                break;
            }
            if self.current.typ == CssTokenType::Delim && self.current.value == "}" {
                break;
            }
            if self.current.typ == CssTokenType::Comment {
                self.format_comment();
                continue;
            }
            if self.current.typ == CssTokenType::Ident {
                self.format_declaration();
            } else {
                self.advance();
            }
        }
    }

    fn format_declaration(&mut self) {
        self.write_indent();
        write_styled(&mut self.out, &self.current.value, &[CYAN], self.color);
        self.advance();
        self.skip_whitespace();

        if self.current.typ == CssTokenType::Delim && self.current.value == ":" {
            self.out.push_str(": ");
            self.advance();
        }

        self.format_value();
        self.skip_whitespace();

        if self.current.typ == CssTokenType::Delim && self.current.value == ";" {
            self.out.push_str(";\n");
            self.at_newline = true;
            self.advance();
        } else if self.current.typ == CssTokenType::Delim && self.current.value == "}" {
            self.out.push_str(";\n");
            self.at_newline = true;
        } else {
            self.out.push('\n');
            self.at_newline = true;
        }
    }

    fn format_value(&mut self) {
        let mut need_space = false;
        let mut paren_depth = 0usize;

        while self.current.typ != CssTokenType::Eof {
            if self.current.typ == CssTokenType::Delim {
                match self.current.value.as_str() {
                    ";" | "}" => break,
                    "(" => {
                        paren_depth += 1;
                        self.out.push('(');
                        self.advance();
                        need_space = false;
                        continue;
                    }
                    ")" => {
                        paren_depth = paren_depth.saturating_sub(1);
                        self.out.push(')');
                        self.advance();
                        need_space = true;
                        continue;
                    }
                    "," => {
                        self.out.push(',');
                        self.advance();
                        need_space = true;
                        continue;
                    }
                    "/" => {
                        self.out.push('/');
                        self.advance();
                        need_space = false;
                        continue;
                    }
                    _ => {}
                }
            }

            if self.current.typ == CssTokenType::Whitespace {
                self.advance();
                need_space = true;
                continue;
            }

            if need_space {
                self.out.push(' ');
                need_space = false;
            }
            self.format_value_token();
        }
    }

    fn format_value_token(&mut self) {
        match self.current.typ {
            CssTokenType::Ident
            | CssTokenType::Number
            | CssTokenType::Dimension
            | CssTokenType::String
            | CssTokenType::Hash => {
                write_styled(&mut self.out, &self.current.value, &[GREEN], self.color);
                self.advance();
            }
            CssTokenType::Function => {
                write_styled(&mut self.out, &self.current.value, &[GREEN], self.color);
                self.advance();
                self.format_function_args_value();
            }
            CssTokenType::Delim => {
                if self.current.value == "!" {
                    write_styled(&mut self.out, "!", &[GREEN], self.color);
                }
                self.advance();
            }
            _ => self.advance(),
        }
    }

    fn format_function_args(&mut self) {
        let mut depth = 1usize;
        while self.current.typ != CssTokenType::Eof && depth > 0 {
            if self.current.typ == CssTokenType::Delim && self.current.value == "(" {
                depth += 1;
                write_styled(&mut self.out, "(", &[BOLD, BLUE], self.color);
                self.advance();
                continue;
            }
            if self.current.typ == CssTokenType::Delim && self.current.value == ")" {
                depth = depth.saturating_sub(1);
                write_styled(&mut self.out, ")", &[BOLD, BLUE], self.color);
                self.advance();
                continue;
            }
            if self.current.typ == CssTokenType::Whitespace {
                self.advance();
                continue;
            }

            match self.current.typ {
                CssTokenType::Ident | CssTokenType::Hash => {
                    write_styled(
                        &mut self.out,
                        &self.current.value,
                        &[BOLD, BLUE],
                        self.color,
                    );
                    self.advance();
                }
                CssTokenType::Delim => {
                    if matches!(self.current.value.as_str(), "." | ":" | "*") {
                        write_styled(
                            &mut self.out,
                            &self.current.value,
                            &[BOLD, BLUE],
                            self.color,
                        );
                    }
                    self.advance();
                }
                _ => self.advance(),
            }
        }
    }

    fn format_function_args_value(&mut self) {
        let mut depth = 1usize;
        let mut need_space = false;

        while self.current.typ != CssTokenType::Eof && depth > 0 {
            if self.current.typ == CssTokenType::Delim && self.current.value == "(" {
                depth += 1;
                self.out.push('(');
                self.advance();
                need_space = false;
                continue;
            }
            if self.current.typ == CssTokenType::Delim && self.current.value == ")" {
                depth = depth.saturating_sub(1);
                self.out.push(')');
                self.advance();
                need_space = true;
                continue;
            }
            if self.current.typ == CssTokenType::Delim && self.current.value == "," {
                self.out.push(',');
                self.advance();
                need_space = true;
                continue;
            }
            if self.current.typ == CssTokenType::Delim && self.current.value == "/" {
                self.out.push('/');
                self.advance();
                need_space = false;
                continue;
            }
            if self.current.typ == CssTokenType::Whitespace {
                self.advance();
                need_space = true;
                continue;
            }

            if need_space {
                self.out.push(' ');
                need_space = false;
            }

            match self.current.typ {
                CssTokenType::Ident
                | CssTokenType::Number
                | CssTokenType::Dimension
                | CssTokenType::String
                | CssTokenType::Hash => {
                    self.out.push_str(&self.current.value);
                    self.advance();
                }
                CssTokenType::Function => {
                    self.out.push_str(&self.current.value);
                    self.advance();
                    self.format_function_args_value();
                }
                _ => self.advance(),
            }
        }
    }

    fn write_indent(&mut self) {
        if self.at_newline {
            write_indent(&mut self.out, self.indent);
            self.at_newline = false;
        }
    }
}

fn write_indent(out: &mut String, indent: usize) {
    for _ in 0..indent {
        out.push_str("  ");
    }
}

fn write_styled(out: &mut String, value: &str, styles: &[Sequence], color: bool) {
    write_styled_to_string(out, value, styles, color);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_css() {
        let tests = [
            ("empty input", "", false),
            ("simple rule", "body { color: red; }", false),
            (
                "minified CSS",
                "body{color:red;margin:0}.container{display:flex}",
                false,
            ),
            (
                "multiple declarations",
                "div { color: red; font-size: 14px; margin: 10px; }",
                false,
            ),
            ("class selector", ".container { width: 100%; }", false),
            ("id selector", "#header { height: 60px; }", false),
            ("descendant combinator", "div p { color: blue; }", false),
            ("child combinator", "div > p { color: green; }", false),
            (
                "adjacent sibling combinator",
                "h1 + p { margin-top: 0; }",
                false,
            ),
            (
                "general sibling combinator",
                "h1 ~ p { color: gray; }",
                false,
            ),
            (
                "attribute selector",
                r#"input[type="text"] { border: 1px solid black; }"#,
                false,
            ),
            ("pseudo-class", "a:hover { color: red; }", false),
            (
                "pseudo-element",
                "p::first-line { font-weight: bold; }",
                false,
            ),
            (
                "complex selector",
                "div.container > p.intro:first-child { color: blue; }",
                false,
            ),
            ("@import", r#"@import url("style.css");"#, false),
            ("@charset", r#"@charset "UTF-8";"#, false),
            (
                "@media",
                "@media screen and (min-width: 768px) { .container { width: 750px; } }",
                false,
            ),
            (
                "@keyframes",
                "@keyframes slide { from { left: 0; } to { left: 100px; } }",
                false,
            ),
            (
                "@font-face",
                r#"@font-face { font-family: "MyFont"; src: url("font.woff2"); }"#,
                false,
            ),
            (
                "comment",
                "/* This is a comment */ body { color: red; }",
                false,
            ),
            (
                "multiline comment",
                "/* Multi\nline\ncomment */ div { margin: 0; }",
                false,
            ),
            ("color hex", "div { color: #ff0000; }", false),
            ("color rgb", "div { color: rgb(255, 0, 0); }", false),
            (
                "color rgba",
                "div { background: rgba(0, 0, 0, 0.5); }",
                false,
            ),
            ("color hsl", "div { color: hsl(120, 100%, 50%); }", false),
            ("calc function", "div { width: calc(100% - 20px); }", false),
            ("var function", "div { color: var(--main-color); }", false),
            ("url function", "div { background: url(image.png); }", false),
            (
                "url function quoted",
                r#"div { background: url("image.png"); }"#,
                false,
            ),
            (
                "dimensions",
                "div { width: 100px; height: 50%; margin: 1em; padding: 2rem; }",
                false,
            ),
            ("important", "div { color: red !important; }", false),
            (
                "vendor prefix",
                "div { -webkit-transform: rotate(45deg); }",
                false,
            ),
            ("custom property", ":root { --main-color: #06c; }", false),
            ("missing semicolon", "div { color: red }", false),
            (
                "multiple selectors",
                "h1, h2, h3 { font-weight: bold; }",
                false,
            ),
            (
                "nested media query",
                "@media print { @page { margin: 1cm; } body { font-size: 12pt; } }",
                false,
            ),
            ("universal selector", "* { box-sizing: border-box; }", false),
            (
                "not pseudo-class",
                "p:not(.special) { color: gray; }",
                false,
            ),
        ];

        for (name, input, want_err) in tests {
            let got_err = format_css(input.as_bytes(), false).is_err();
            assert_eq!(got_err, want_err, "{name}");
        }
    }

    #[test]
    fn test_format_css_output() {
        let output = String::from_utf8(
            format_css(b"body{color:red;margin:0}.container{display:flex}", false).unwrap(),
        )
        .unwrap();
        for want in [
            "body",
            "color",
            "red",
            "margin",
            "0",
            "container",
            "display",
            "flex",
        ] {
            assert!(output.contains(want), "missing {want:?}: {output}");
        }
        assert!(output.contains("{\n"), "{output}");
        assert!(output.contains("}\n"), "{output}");
    }

    #[test]
    fn test_format_css_indentation() {
        let output = String::from_utf8(format_css(b"body{color:red}", false).unwrap()).unwrap();
        let lines = output
            .trim_end_matches('\n')
            .split('\n')
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 3, "{output:?}");
        assert!(lines[0].starts_with("body"));
        assert!(lines[1].starts_with("  "));
        assert_eq!(lines[2], "}");
    }

    #[test]
    fn test_format_css_media_query() {
        let output = String::from_utf8(
            format_css(b"@media(min-width:768px){.container{width:750px}}", false).unwrap(),
        )
        .unwrap();
        assert!(output.starts_with("@media"), "{output}");
        assert!(output.contains(".container"), "{output}");
        assert!(output.contains("    width"), "{output}");
    }

    #[test]
    fn test_format_css_comment() {
        let output =
            String::from_utf8(format_css(b"/* comment */ body { color: red; }", false).unwrap())
                .unwrap();
        assert!(output.contains("/* comment */"), "{output}");
    }

    #[test]
    fn test_format_css_empty() {
        assert_eq!(format_css(b"", false).unwrap(), b"");
    }

    #[test]
    fn test_css_tokenizer() {
        let tests = [
            ("empty", "", vec![CssTokenType::Eof]),
            (
                "identifier",
                "body",
                vec![CssTokenType::Ident, CssTokenType::Eof],
            ),
            ("hash", "#id", vec![CssTokenType::Hash, CssTokenType::Eof]),
            (
                "at-keyword",
                "@media",
                vec![CssTokenType::AtKeyword, CssTokenType::Eof],
            ),
            (
                "string double quote",
                r#""hello""#,
                vec![CssTokenType::String, CssTokenType::Eof],
            ),
            (
                "string single quote",
                "'hello'",
                vec![CssTokenType::String, CssTokenType::Eof],
            ),
            (
                "number",
                "123",
                vec![CssTokenType::Number, CssTokenType::Eof],
            ),
            (
                "dimension",
                "10px",
                vec![CssTokenType::Dimension, CssTokenType::Eof],
            ),
            (
                "percentage",
                "50%",
                vec![CssTokenType::Dimension, CssTokenType::Eof],
            ),
            (
                "function",
                "calc(",
                vec![CssTokenType::Function, CssTokenType::Eof],
            ),
            (
                "comment",
                "/* comment */",
                vec![CssTokenType::Comment, CssTokenType::Eof],
            ),
            (
                "delimiters",
                "{}:;",
                vec![
                    CssTokenType::Delim,
                    CssTokenType::Delim,
                    CssTokenType::Delim,
                    CssTokenType::Delim,
                    CssTokenType::Eof,
                ],
            ),
            (
                "whitespace",
                "  \t\n",
                vec![CssTokenType::Whitespace, CssTokenType::Eof],
            ),
            (
                "simple rule",
                "body { color: red; }",
                vec![
                    CssTokenType::Ident,
                    CssTokenType::Whitespace,
                    CssTokenType::Delim,
                    CssTokenType::Whitespace,
                    CssTokenType::Ident,
                    CssTokenType::Delim,
                    CssTokenType::Whitespace,
                    CssTokenType::Ident,
                    CssTokenType::Delim,
                    CssTokenType::Whitespace,
                    CssTokenType::Delim,
                    CssTokenType::Eof,
                ],
            ),
            (
                "custom property",
                "--main-color",
                vec![CssTokenType::Ident, CssTokenType::Eof],
            ),
            (
                "negative number",
                "-10px",
                vec![CssTokenType::Dimension, CssTokenType::Eof],
            ),
            (
                "decimal number",
                "1.5em",
                vec![CssTokenType::Dimension, CssTokenType::Eof],
            ),
            (
                "vendor prefix",
                "-webkit-transform",
                vec![CssTokenType::Ident, CssTokenType::Eof],
            ),
        ];

        for (name, input, want_types) in tests {
            let mut tok = CssTokenizer::new(input.as_bytes());
            let mut got_types = Vec::new();
            loop {
                let token = tok.next();
                got_types.push(token.typ);
                if token.typ == CssTokenType::Eof {
                    break;
                }
            }
            assert_eq!(got_types, want_types, "{name}");
        }
    }

    #[test]
    fn test_css_tokenizer_values() {
        let tests = [
            ("identifier", "body", "body"),
            ("hash", "#header", "#header"),
            ("at-keyword", "@media", "@media"),
            ("string", r#""hello world""#, r#""hello world""#),
            (
                "string with escape",
                r#""hello\"world""#,
                r#""hello\"world""#,
            ),
            ("dimension", "10px", "10px"),
            ("comment", "/* test */", "/* test */"),
            ("function", "rgba(", "rgba("),
            ("custom property", "--color", "--color"),
        ];

        for (name, input, want_value) in tests {
            let mut tok = CssTokenizer::new(input.as_bytes());
            assert_eq!(tok.next().value, want_value, "{name}");
        }
    }

    #[test]
    fn test_format_css_keyframes() {
        let output = String::from_utf8(
            format_css(
                b"@keyframes fadeIn { 0% { opacity: 0; } 100% { opacity: 1; } }",
                false,
            )
            .unwrap(),
        )
        .unwrap();
        for want in ["@keyframes", "0%", "100%", "opacity"] {
            assert!(output.contains(want), "missing {want:?}: {output}");
        }
    }

    #[test]
    fn test_format_css_complex_selector() {
        let output = String::from_utf8(
            format_css(
                b"div.container > ul.nav li.item:hover a { color: blue; }",
                false,
            )
            .unwrap(),
        )
        .unwrap();
        for want in [
            "div",
            ".container",
            ">",
            "ul",
            ".nav",
            "li",
            ".item",
            ":hover",
            "a",
        ] {
            assert!(output.contains(want), "missing {want:?}: {output}");
        }
    }

    #[test]
    fn test_format_css_font_face() {
        let output = String::from_utf8(
            format_css(
                br#"@font-face { font-family: "Open Sans"; src: url("opensans.woff2") format("woff2"); font-weight: 400; }"#,
                false,
            )
            .unwrap(),
        )
        .unwrap();
        for want in ["@font-face", "font-family", "Open Sans"] {
            assert!(output.contains(want), "missing {want:?}: {output}");
        }
    }

    #[test]
    fn test_format_css_calc() {
        let output = String::from_utf8(
            format_css(
                b"div { width: calc(100% - 20px); height: calc(50vh + 10px); }",
                false,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(output.contains("calc("), "{output}");
        assert!(output.contains("100%"), "{output}");
    }

    #[test]
    fn test_format_css_blank_lines_between_rules() {
        let output =
            String::from_utf8(format_css(b".a{color:red}.b{color:blue}", false).unwrap()).unwrap();
        assert!(output.contains("}\n\n."), "{output:?}");
    }

    #[test]
    fn test_format_css_trailing_newline() {
        let tests = [
            ("single rule", "body{color:red}"),
            ("multiple rules", ".a{color:red}.b{color:blue}"),
            ("with media query", "@media screen{.a{color:red}}"),
            ("with import", r#"@import url("style.css");"#),
        ];

        for (name, input) in tests {
            let output = String::from_utf8(format_css(input.as_bytes(), false).unwrap()).unwrap();
            assert!(output.ends_with('\n'), "{name}: {output:?}");
            assert!(!output.ends_with("\n\n"), "{name}: {output:?}");
        }
    }

    #[test]
    fn test_format_css_custom_properties() {
        let output = String::from_utf8(
            format_css(
                b":root { --primary-color: #06c; --spacing: 1rem; } .element { color: var(--primary-color); padding: var(--spacing); }",
                false,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(output.contains("--primary-color"), "{output}");
        assert!(output.contains("var("), "{output}");
    }

    #[test]
    fn formats_css_with_color_when_requested() {
        let output =
            String::from_utf8(format_css(b"body{color:red}/* comment */", true).unwrap()).unwrap();
        assert!(output.contains("\x1b[1m\x1b[34mbody\x1b[0m"));
        assert!(output.contains("\x1b[36mcolor\x1b[0m"));
        assert!(output.contains("\x1b[32mred\x1b[0m"));
        assert!(output.contains("\x1b[2m/* comment */\x1b[0m"));
    }
}
