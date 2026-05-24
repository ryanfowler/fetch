use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use std::fmt;
use std::io::Cursor;

use crate::core::{Sequence, write_styled_to_string};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlError(String);

impl fmt::Display for XmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for XmlError {}

pub fn format_xml(buf: &[u8], color: bool) -> Result<Vec<u8>, XmlError> {
    let mut reader = Reader::from_reader(Cursor::new(buf));
    reader.config_mut().trim_text(false);

    let mut scratch = Vec::new();
    let mut stack = Vec::new();
    let mut out = String::new();
    let mut pending_text = String::new();

    loop {
        match reader
            .read_event_into(&mut scratch)
            .map_err(|err| XmlError(err.to_string()))?
        {
            Event::Start(element) => {
                flush_xml_text(&mut out, &mut pending_text, color);
                let name = write_start_element(&mut out, &element, &reader, &mut stack, color)?;
                stack.push((name, false));
            }
            Event::Empty(element) => {
                flush_xml_text(&mut out, &mut pending_text, color);
                let name = write_start_element(&mut out, &element, &reader, &mut stack, color)?;
                out.push_str("</");
                write_xml_tag_name(&mut out, &name, color);
                out.push_str(">\n");
            }
            Event::End(element) => {
                flush_xml_text(&mut out, &mut pending_text, color);
                let name = local_name(element.name().as_ref());
                if let Some((_open_name, had_child)) = stack.pop()
                    && had_child
                {
                    write_indent(&mut out, stack.len());
                }
                out.push_str("</");
                write_xml_tag_name(&mut out, &name, color);
                out.push_str(">\n");
            }
            Event::Text(text) => {
                let decoded = text.decode().map_err(|err| XmlError(err.to_string()))?;
                let unescaped = quick_xml::escape::unescape(&decoded)
                    .map_err(|err| XmlError(err.to_string()))?;
                pending_text.push_str(&unescaped);
            }
            Event::CData(text) => {
                let decoded = text.decode().map_err(|err| XmlError(err.to_string()))?;
                pending_text.push_str(&decoded);
            }
            Event::Comment(comment) => {
                flush_xml_text(&mut out, &mut pending_text, color);
                write_indent(&mut out, stack.len());
                out.push_str("<!--");
                write_xml_comment(&mut out, &String::from_utf8_lossy(comment.as_ref()), color);
                out.push_str("-->\n");
            }
            Event::Decl(decl) => {
                flush_xml_text(&mut out, &mut pending_text, color);
                let raw = String::from_utf8_lossy(decl.as_ref());
                let raw = if raw.trim_start().starts_with("xml") {
                    raw.into_owned()
                } else {
                    format!("xml {}", raw.trim())
                };
                write_proc_inst_raw(&mut out, stack.len(), &raw, color);
            }
            Event::PI(pi) => {
                flush_xml_text(&mut out, &mut pending_text, color);
                write_proc_inst_raw(
                    &mut out,
                    stack.len(),
                    &String::from_utf8_lossy(pi.as_ref()),
                    color,
                );
            }
            Event::DocType(doctype) => {
                flush_xml_text(&mut out, &mut pending_text, color);
                write_indent(&mut out, stack.len());
                out.push_str("<!DOCTYPE ");
                write_xml_directive(&mut out, &String::from_utf8_lossy(doctype.as_ref()), color);
                out.push_str(">\n");
            }
            Event::GeneralRef(reference) => {
                let decoded = reference
                    .decode()
                    .map_err(|err| XmlError(err.to_string()))?;
                let entity = format!("&{decoded};");
                let unescaped = quick_xml::escape::unescape(&entity)
                    .map_err(|err| XmlError(err.to_string()))?;
                pending_text.push_str(&unescaped);
            }
            Event::Eof => {
                flush_xml_text(&mut out, &mut pending_text, color);
                return Ok(out.into_bytes());
            }
        }
        scratch.clear();
    }
}

fn flush_xml_text(out: &mut String, pending_text: &mut String, color: bool) {
    let trimmed = pending_text.trim();
    if !trimmed.is_empty() {
        write_xml_text(out, trimmed, color);
    }
    pending_text.clear();
}

fn write_start_element(
    out: &mut String,
    element: &BytesStart<'_>,
    reader: &Reader<Cursor<&[u8]>>,
    stack: &mut [(String, bool)],
    color: bool,
) -> Result<String, XmlError> {
    if let Some((_name, had_child)) = stack.last()
        && !*had_child
    {
        out.push('\n');
    }
    write_indent(out, stack.len());

    let name = local_name(element.name().as_ref());
    out.push('<');
    write_xml_tag_name(out, &name, color);

    let mut saw_attr = false;
    for attr in element.attributes() {
        let attr = attr.map_err(|err| XmlError(err.to_string()))?;
        if !saw_attr {
            out.push(' ');
            saw_attr = true;
        } else {
            out.push(' ');
        }
        write_xml_attr_name(out, &local_name(attr.key.as_ref()), color);
        out.push_str("=\"");
        let value = attr
            .decoded_and_normalized_value(XmlVersion::Implicit1_0, reader.decoder())
            .map_err(|err| XmlError(err.to_string()))?;
        write_xml_attr_val(out, &value, color);
        out.push('"');
    }
    out.push('>');

    if let Some((_name, had_child)) = stack.last_mut() {
        *had_child = true;
    }

    Ok(name)
}

fn write_proc_inst_raw(out: &mut String, indent: usize, raw: &str, color: bool) {
    let raw = raw.trim();
    if raw.is_empty() {
        return;
    }

    let mut split = raw.splitn(2, char::is_whitespace);
    let target = split.next().unwrap_or_default();
    let inst = split.next().unwrap_or_default().trim();

    write_indent(out, indent);
    out.push_str("<?");
    write_xml_tag_name(out, target, color);
    write_xml_proc_inst(out, inst, color);
    out.push_str("?>\n");
}

fn write_xml_proc_inst(out: &mut String, inst: &str, color: bool) {
    for pair in inst.split_whitespace() {
        out.push(' ');
        if let Some((key, value)) = pair.split_once('=') {
            write_styled(out, key, &[Sequence::Cyan], color);
            out.push('=');
            if let Some(value) = value.strip_prefix('"') {
                out.push('"');
                if let Some(value) = value.strip_suffix('"') {
                    write_styled(out, value, &[Sequence::Green], color);
                    out.push('"');
                    continue;
                }
                write_styled(out, value, &[Sequence::Cyan], color);
            } else {
                write_styled(out, value, &[Sequence::Cyan], color);
            }
        } else {
            write_styled(out, pair, &[Sequence::Cyan], color);
        }
    }
}

fn local_name(bytes: &[u8]) -> String {
    let value = String::from_utf8_lossy(bytes);
    value
        .rsplit_once(':')
        .map_or_else(|| value.to_string(), |(_prefix, local)| local.to_string())
}

fn write_xml_tag_name(out: &mut String, value: &str, color: bool) {
    let escaped = escape_xml_string(value);
    write_styled(out, &escaped, &[Sequence::Bold, Sequence::Blue], color);
}

fn write_xml_attr_name(out: &mut String, value: &str, color: bool) {
    let escaped = escape_xml_string(value);
    write_styled(out, &escaped, &[Sequence::Cyan], color);
}

fn write_xml_attr_val(out: &mut String, value: &str, color: bool) {
    let escaped = escape_xml_string(value);
    write_styled(out, &escaped, &[Sequence::Green], color);
}

fn write_xml_text(out: &mut String, value: &str, color: bool) {
    let escaped = escape_xml_string(value);
    write_styled(out, &escaped, &[Sequence::Green], color);
}

fn write_xml_directive(out: &mut String, value: &str, color: bool) {
    write_styled(out, value, &[Sequence::Cyan], color);
}

fn write_xml_comment(out: &mut String, value: &str, color: bool) {
    write_styled(out, value, &[Sequence::Dim], color);
}

fn write_indent(out: &mut String, indent: usize) {
    for _ in 0..indent {
        out.push_str("  ");
    }
}

fn write_styled(out: &mut String, value: &str, styles: &[Sequence], color: bool) {
    write_styled_to_string(out, value, styles, color);
}

fn escape_xml_string(value: &str) -> String {
    let mut out = String::new();
    for c in value.chars() {
        match c {
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c if !is_in_xml_character_range(c) => out.push('\u{fffd}'),
            c => out.push(c),
        }
    }
    out
}

fn is_in_xml_character_range(c: char) -> bool {
    matches!(
        c as u32,
        0x09 | 0x0a | 0x0d | 0x20..=0xd7ff | 0xe000..=0xfffd | 0x10000..=0x10ffff
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_xml() {
        let tests = [
            (
                "valid simple xml",
                "<root><child>text</child></root>",
                false,
            ),
            ("valid nested xml", "<a><b><c>text</c></b></a>", false),
            (
                "valid xml with attributes",
                r#"<root attr="value"><child id="1">text</child></root>"#,
                false,
            ),
            (
                "malformed xml extra closing tag at start",
                "</foo><bar></bar>",
                true,
            ),
            (
                "malformed xml extra closing tag at end",
                "<a></a></a>",
                true,
            ),
            (
                "malformed xml multiple extra closing tags",
                "</x></y></z>",
                true,
            ),
        ];

        for (name, input, want_err) in tests {
            let err = format_xml(input.as_bytes(), false).is_err();
            assert_eq!(err, want_err, "{name}");
        }
    }

    #[test]
    fn test_format_xml_output() {
        let output =
            String::from_utf8(format_xml(b"<root><child>text</child></root>", false).unwrap())
                .unwrap();
        assert_eq!(output, "<root>\n  <child>text</child>\n</root>\n");
    }

    #[test]
    fn formats_xml_with_attributes() {
        let output = String::from_utf8(
            format_xml(
                br#"<root attr="value"><child id="1">text</child></root>"#,
                false,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            output,
            "<root attr=\"value\">\n  <child id=\"1\">text</child>\n</root>\n"
        );
    }

    #[test]
    fn formats_xml_declaration_comment_directive_and_empty_elements() {
        let output = String::from_utf8(
            format_xml(
                br#"<?xml version="1.0"?><!--top--><!DOCTYPE note SYSTEM "note.dtd"><root><empty/></root>"#,
                false,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            output,
            "<?xml version=\"1.0\"?>\n<!--top-->\n<!DOCTYPE note SYSTEM \"note.dtd\">\n<root>\n  <empty></empty>\n</root>\n"
        );
    }

    #[test]
    fn escapes_text_and_attribute_values_after_xml_decoding() {
        let output = String::from_utf8(
            format_xml(br#"<root attr="foo &amp; bar">a &lt; b</root>"#, false).unwrap(),
        )
        .unwrap();
        assert_eq!(output, "<root attr=\"foo &amp; bar\">a &lt; b</root>\n");
    }

    #[test]
    fn formats_xml_with_color_when_requested() {
        let output =
            String::from_utf8(format_xml(br#"<root attr="value">text</root>"#, true).unwrap())
                .unwrap();
        assert!(output.contains("\x1b[1m\x1b[34mroot\x1b[0m"));
        assert!(output.contains("\x1b[36mattr\x1b[0m"));
        assert!(output.contains("\x1b[32mvalue\x1b[0m"));
        assert!(output.contains("\x1b[32mtext\x1b[0m"));
    }

    #[test]
    fn test_escape_xml_string() {
        let tests = [
            ("ascii no escape needed", "hello world", "hello world"),
            ("with ampersand", "foo & bar", "foo &amp; bar"),
            ("with less than", "a < b", "a &lt; b"),
            ("with greater than", "a > b", "a &gt; b"),
            ("with quotes", r#""quoted""#, "&quot;quoted&quot;"),
            ("with single quotes", "'quoted'", "&apos;quoted&apos;"),
            ("with tab", "a\tb", "a&#x9;b"),
            ("with newline", "a\nb", "a&#xA;b"),
            ("with carriage return", "a\rb", "a&#xD;b"),
            ("unicode chars", "日本語", "日本語"),
            ("invalid xml character", "\u{0}", "\u{fffd}"),
        ];

        for (name, input, want) in tests {
            assert_eq!(escape_xml_string(input), want, "{name}");
        }
    }
}
