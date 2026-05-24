use std::borrow::Cow;
use std::fmt;

use crate::core::{Sequence, write_styled_to_string};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YamlError(String);

impl fmt::Display for YamlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for YamlError {}

pub fn format_yaml(buf: &[u8], color: bool) -> Result<Vec<u8>, YamlError> {
    let input = String::from_utf8_lossy(buf);
    if !color {
        validate_quotes(&input)?;
        return Ok(match input {
            Cow::Borrowed(_) => buf.to_vec(),
            Cow::Owned(value) => value.into_bytes(),
        });
    }

    let mut out = String::new();
    for segment in LineSegments::new(&input) {
        write_yaml_line(&mut out, segment.body, color)?;
        out.push_str(segment.ending);
    }
    Ok(out.into_bytes())
}

fn validate_quotes(input: &str) -> Result<(), YamlError> {
    for segment in LineSegments::new(input) {
        let mut index = 0;
        while index < segment.body.len() {
            let ch = segment.body[index..].chars().next().unwrap();
            if ch == '#' {
                break;
            }
            if ch == '\'' || ch == '"' {
                index = parse_quoted(segment.body, index, ch)?;
                continue;
            }
            index += ch.len_utf8();
        }
    }
    Ok(())
}

struct LineSegment<'a> {
    body: &'a str,
    ending: &'a str,
}

struct LineSegments<'a> {
    input: &'a str,
    offset: usize,
}

impl<'a> LineSegments<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, offset: 0 }
    }
}

impl<'a> Iterator for LineSegments<'a> {
    type Item = LineSegment<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.input.len() {
            return None;
        }

        let rest = &self.input[self.offset..];
        let newline = rest.find('\n');
        let (line, ending_len) = match newline {
            Some(index) => (&rest[..index], 1),
            None => (rest, 0),
        };
        let (body, ending) = if let Some(body) = line.strip_suffix('\r') {
            (body, "\r\n")
        } else if ending_len == 1 {
            (line, "\n")
        } else {
            (line, "")
        };

        self.offset += line.len() + ending_len;
        Some(LineSegment { body, ending })
    }
}

fn write_yaml_line(out: &mut String, line: &str, color: bool) -> Result<(), YamlError> {
    let first = first_non_space(line);
    if let Some(first) = first {
        let rest = &line[first..];
        if rest.starts_with('#') {
            out.push_str(&line[..first]);
            write_styled(out, rest, &[Sequence::Dim], color);
            return Ok(());
        }
        if marker_at_line_start(rest, "---") || marker_at_line_start(rest, "...") {
            out.push_str(&line[..first]);
            write_styled(out, &rest[..3], &[Sequence::Dim], color);
            out.push_str(&rest[3..]);
            return Ok(());
        }
        if rest.starts_with('%') {
            out.push_str(&line[..first]);
            let end = first + token_end(rest, 0);
            write_styled(out, &line[first..end], &[Sequence::Cyan], color);
            out.push_str(&line[end..]);
            return Ok(());
        }
    }

    let mut index = 0;
    while index < line.len() {
        let ch = line[index..].chars().next().unwrap();
        match ch {
            '#' => {
                write_styled(out, &line[index..], &[Sequence::Dim], color);
                break;
            }
            '\'' | '"' => {
                let end = parse_quoted(line, index, ch)?;
                let token = &line[index..end];
                if is_yaml_key(line, end) {
                    write_styled(out, token, &[Sequence::Blue, Sequence::Bold], color);
                } else {
                    write_styled(out, token, &[Sequence::Green], color);
                }
                index = end;
            }
            '&' | '*' => {
                let end = index + token_end(&line[index..], 0);
                write_styled(out, &line[index..end], &[Sequence::Cyan], color);
                index = end;
            }
            '!' => {
                let end = index + token_end(&line[index..], 0);
                write_styled(out, &line[index..end], &[Sequence::Cyan], color);
                index = end;
            }
            c if c.is_whitespace() || is_yaml_punctuation(c) => {
                out.push(c);
                index += c.len_utf8();
            }
            _ => {
                let end = index + token_end(&line[index..], 0);
                let token = &line[index..end];
                if is_yaml_key(line, end) {
                    write_styled(out, token, &[Sequence::Blue, Sequence::Bold], color);
                } else if is_plain_string_token(token) {
                    write_styled(out, token, &[Sequence::Green], color);
                } else {
                    out.push_str(token);
                }
                index = end;
            }
        }
    }

    Ok(())
}

fn first_non_space(line: &str) -> Option<usize> {
    line.char_indices()
        .find(|(_, ch)| !matches!(ch, ' ' | '\t'))
        .map(|(index, _)| index)
}

fn marker_at_line_start(rest: &str, marker: &str) -> bool {
    rest.starts_with(marker)
        && rest[marker.len()..]
            .chars()
            .next()
            .is_none_or(char::is_whitespace)
}

fn parse_quoted(line: &str, start: usize, quote: char) -> Result<usize, YamlError> {
    let mut index = start + quote.len_utf8();
    while index < line.len() {
        let ch = line[index..].chars().next().unwrap();
        index += ch.len_utf8();
        if quote == '"' && ch == '\\' {
            if index < line.len() {
                let escaped = line[index..].chars().next().unwrap();
                index += escaped.len_utf8();
            }
            continue;
        }
        if quote == '\'' && ch == '\'' {
            if line[index..].starts_with('\'') {
                index += '\''.len_utf8();
                continue;
            }
            return Ok(index);
        }
        if quote == '"' && ch == '"' {
            return Ok(index);
        }
    }
    Err(YamlError("invalid yaml: found unclosed quote".to_string()))
}

fn token_end(line: &str, start: usize) -> usize {
    let mut end = start;
    for (offset, ch) in line[start..].char_indices() {
        if ch.is_whitespace() || is_yaml_token_boundary(ch) {
            break;
        }
        end = start + offset + ch.len_utf8();
    }
    end
}

fn is_yaml_key(line: &str, after_token: usize) -> bool {
    line[after_token..].chars().find(|ch| !ch.is_whitespace()) == Some(':')
}

fn is_yaml_token_boundary(ch: char) -> bool {
    matches!(ch, ':' | '[' | ']' | '{' | '}' | ',' | '#')
}

fn is_yaml_punctuation(ch: char) -> bool {
    matches!(ch, ':' | '-' | '[' | ']' | '{' | '}' | ',' | '|' | '>')
}

fn is_plain_string_token(token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    let lower = token.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "null" | "~" | "true" | "false" | "yes" | "no" | "on" | "off"
    ) {
        return false;
    }
    token.parse::<i64>().is_err() && token.parse::<f64>().is_err()
}

fn write_styled(out: &mut String, value: &str, styles: &[Sequence], color: bool) {
    write_styled_to_string(out, value, styles, color);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_yaml() {
        let tests = [
            ("empty input", "", false),
            ("null scalar", "null\n", false),
            ("boolean true", "true\n", false),
            ("boolean false", "false\n", false),
            ("integer", "42\n", false),
            ("float", "3.14\n", false),
            ("simple string", "hello\n", false),
            ("simple mapping", "key: value\n", false),
            ("nested mapping", "parent:\n  child: value\n", false),
            ("sequence", "- one\n- two\n- three\n", false),
            (
                "mapping with sequence",
                "items:\n  - first\n  - second\n",
                false,
            ),
            ("flow mapping", "{a: 1, b: 2}\n", false),
            ("flow sequence", "[1, 2, 3]\n", false),
            ("comment", "# this is a comment\nkey: value\n", false),
            ("inline comment", "key: value # inline\n", false),
            ("multi-document", "---\na: 1\n---\nb: 2\n...\n", false),
            (
                "anchor and alias",
                "defaults: &defaults\n  color: red\nitem:\n  <<: *defaults\n",
                false,
            ),
            ("tag", "value: !!str 123\n", false),
            (
                "block literal scalar",
                "text: |\n  line one\n  line two\n",
                false,
            ),
            (
                "block folded scalar",
                "text: >\n  line one\n  line two\n",
                false,
            ),
            ("unicode values", "name: 日本語\n", false),
            ("double quoted string", "key: \"hello world\"\n", false),
            ("single quoted string", "key: 'hello world'\n", false),
            (
                "complex nested",
                "server:\n  host: localhost\n  port: 8080\n  features:\n    - auth\n    - logging\n",
                false,
            ),
            (
                "merge key",
                "base: &base\n  x: 1\nderived:\n  <<: *base\n  y: 2\n",
                false,
            ),
            ("unclosed double quote", "key: \"value\n", true),
            ("unclosed single quote", "key: 'value\n", true),
        ];

        for (name, input, want_err) in tests {
            let got_err = format_yaml(input.as_bytes(), false).is_err();
            assert_eq!(got_err, want_err, "{name}");
        }
    }

    #[test]
    fn test_format_yaml_output() {
        let input = "name: John\nage: 30\nitems:\n  - one\n  - two\n";
        let output = String::from_utf8(format_yaml(input.as_bytes(), false).unwrap()).unwrap();
        for want in ["name", "John", "age", "30", "one", "two"] {
            assert!(
                output.contains(want),
                "output should contain {want:?}, got: {output}"
            );
        }
    }

    #[test]
    fn test_format_yaml_preserves_structure() {
        let inputs = [
            "key: value",
            "a: 1\nb: 2",
            "items:\n  - one\n  - two",
            "nested:\n  child:\n    value: hello",
        ];

        for input in inputs {
            let output = String::from_utf8(format_yaml(input.as_bytes(), false).unwrap()).unwrap();
            assert_eq!(output, input, "{input:?}");
        }
    }

    #[test]
    fn formats_yaml_with_color_when_requested() {
        let input =
            "---\n# comment\nname: John\nitems:\n  - one\nref: &base\nmerged:\n  <<: *base\n";
        let output = String::from_utf8(format_yaml(input.as_bytes(), true).unwrap()).unwrap();
        assert!(output.contains("\x1b[2m---\x1b[0m"));
        assert!(output.contains("\x1b[2m# comment\x1b[0m"));
        assert!(output.contains("\x1b[34m\x1b[1mname\x1b[0m"));
        assert!(output.contains("\x1b[32mJohn\x1b[0m"));
        assert!(output.contains("\x1b[36m&base\x1b[0m"));
        assert!(output.contains("\x1b[34m\x1b[1m<<\x1b[0m"));
        assert!(output.contains("\x1b[36m*base\x1b[0m"));
    }
}
