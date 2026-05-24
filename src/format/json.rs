use serde_json::Value;

use crate::core::{Printer, Sequence};

pub fn format_json(bytes: &[u8], color: bool) -> Result<Vec<u8>, serde_json::Error> {
    let value: Value = serde_json::from_slice(bytes)?;
    let mut out = Printer::new(color);
    write_value(&mut out, &value, 0);
    out.push('\n');
    Ok(out.into_bytes())
}

pub fn format_json_line(bytes: &[u8], color: bool) -> Result<Vec<u8>, serde_json::Error> {
    let value: Value = serde_json::from_slice(bytes)?;
    let mut out = Printer::new(color);
    write_line_value(&mut out, &value);
    out.push('\n');
    Ok(out.into_bytes())
}

pub fn format_ndjson(bytes: &[u8], color: bool) -> Result<Vec<u8>, serde_json::Error> {
    let mut out = Printer::new(color);
    let stream = serde_json::Deserializer::from_slice(bytes).into_iter::<Value>();
    for value in stream {
        let value = value?;
        write_line_value(&mut out, &value);
        out.push('\n');
    }
    Ok(out.into_bytes())
}

fn write_value(out: &mut Printer, value: &Value, indent: usize) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(value) => out.push_str(&value.to_string()),
        Value::Number(value) => out.push_str(&value.to_string()),
        Value::String(value) => write_json_string(out, value, &[Sequence::Green]),
        Value::Array(values) => write_array(out, values, indent),
        Value::Object(values) => write_object(out, values, indent),
    }
}

fn write_line_value(out: &mut Printer, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(value) => out.push_str(&value.to_string()),
        Value::Number(value) => out.push_str(&value.to_string()),
        Value::String(value) => write_json_string(out, value, &[Sequence::Green]),
        Value::Array(values) => write_line_array(out, values),
        Value::Object(values) => write_line_object(out, values),
    }
}

fn write_line_array(out: &mut Printer, values: &[Value]) {
    out.push('[');
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        write_line_value(out, value);
    }
    out.push(']');
}

fn write_line_object(out: &mut Printer, values: &serde_json::Map<String, Value>) {
    out.push('{');
    for (index, (key, value)) in values.iter().enumerate() {
        if index == 0 {
            out.push(' ');
        } else {
            out.push_str(", ");
        }
        write_json_string(out, key, &[Sequence::Blue, Sequence::Bold]);
        out.push_str(": ");
        write_line_value(out, value);
    }
    if !values.is_empty() {
        out.push(' ');
    }
    out.push('}');
}

fn write_array(out: &mut Printer, values: &[Value], indent: usize) {
    if values.is_empty() {
        out.push_str("[]");
        return;
    }

    out.push('[');
    out.push('\n');
    for (index, value) in values.iter().enumerate() {
        write_indent(out, indent + 1);
        write_value(out, value, indent + 1);
        if index + 1 != values.len() {
            out.push(',');
        }
        out.push('\n');
    }
    write_indent(out, indent);
    out.push(']');
}

fn write_object(out: &mut Printer, values: &serde_json::Map<String, Value>, indent: usize) {
    if values.is_empty() {
        out.push_str("{}");
        return;
    }

    out.push('{');
    out.push('\n');
    for (index, (key, value)) in values.iter().enumerate() {
        write_indent(out, indent + 1);
        write_json_string(out, key, &[Sequence::Blue, Sequence::Bold]);
        out.push_str(": ");
        write_value(out, value, indent + 1);
        if index + 1 != values.len() {
            out.push(',');
        }
        out.push('\n');
    }
    write_indent(out, indent);
    out.push('}');
}

fn write_json_string(out: &mut Printer, value: &str, color_codes: &[Sequence]) {
    out.push('"');
    let escaped = escape_json_string(value);
    out.write_styled(&escaped, color_codes);
    out.push('"');
}

fn write_indent(out: &mut Printer, indent: usize) {
    for _ in 0..indent {
        out.push_str("  ");
    }
}

fn escape_json_string(value: &str) -> String {
    let mut out = String::new();
    for c in value.chars() {
        match c {
            '\u{08}' => out.push_str(r"\b"),
            '\u{0c}' => out.push_str(r"\f"),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\t' => out.push_str(r"\t"),
            '"' => out.push_str(r#"\""#),
            '\\' => out.push_str(r"\\"),
            c if c < ' ' || c == '\u{7f}' => out.push_str(&format!(r"\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_json_with_indentation() {
        let got = format_json(br#"{"ok":"yes"}"#, false).unwrap();

        assert_eq!(String::from_utf8(got).unwrap(), "{\n  \"ok\": \"yes\"\n}\n");
    }

    #[test]
    fn formats_json_with_color_when_requested() {
        let got = format_json(br#"{"ok":"yes"}"#, true).unwrap();
        let got = String::from_utf8(got).unwrap();

        assert!(got.contains("\"\x1b[34m\x1b[1mok\x1b[0m\""));
        assert!(got.contains("\"\x1b[32myes\x1b[0m\""));
    }

    #[test]
    fn formats_json_line_like_go_ndjson_formatter() {
        let cases = [
            (r#"{"key":"value"}"#, "{ \"key\": \"value\" }\n"),
            (r#"{"a":{"b":"c"}}"#, "{ \"a\": { \"b\": \"c\" } }\n"),
            ("[1,2,3]", "[1, 2, 3]\n"),
            (r#""hello""#, "\"hello\"\n"),
            ("42", "42\n"),
            ("true", "true\n"),
            ("null", "null\n"),
        ];

        for (input, want) in cases {
            let got = format_json_line(input.as_bytes(), false).unwrap();

            assert_eq!(String::from_utf8(got).unwrap(), want);
        }
    }

    #[test]
    fn format_json_line_rejects_invalid_or_trailing_json() {
        assert!(format_json_line(br#"{invalid"#, false).is_err());
        assert!(format_json_line(br#"{} extra"#, false).is_err());
    }

    #[test]
    fn formats_ndjson_stream_like_go_formatter() {
        let got = format_ndjson(br#"{"a":1} {"b":[true,null]}"#, false).unwrap();

        assert_eq!(
            String::from_utf8(got).unwrap(),
            "{ \"a\": 1 }\n{ \"b\": [true, null] }\n"
        );
    }

    #[test]
    fn format_ndjson_rejects_invalid_json() {
        assert!(format_ndjson(br#"{"ok":true}"#, false).is_ok());
        assert!(format_ndjson(br#"{"ok":true} {invalid"#, false).is_err());
    }

    #[test]
    fn escapes_json_strings_like_go_formatter() {
        let cases = [
            ("ascii no escape needed", "hello world", "hello world"),
            ("with backspace", "a\u{08}b", r"a\bb"),
            ("with form feed", "a\x0cb", r"a\fb"),
            ("with newline", "a\nb", r"a\nb"),
            ("with carriage return", "a\rb", r"a\rb"),
            ("with tab", "a\tb", r"a\tb"),
            ("with double quote", r#"a"b"#, r#"a\"b"#),
            ("with backslash", r"a\b", r"a\\b"),
            ("null character", "a\x00b", r"a\u0000b"),
            ("SOH control character", "a\x01b", r"a\u0001b"),
            ("escape character", "a\x1bb", r"a\u001bb"),
            ("unit separator", "a\x1fb", r"a\u001fb"),
            ("DEL character", "a\x7fb", r"a\u007fb"),
            ("space is not escaped", "a b", "a b"),
            ("printable ASCII not escaped", "abc123!@#", "abc123!@#"),
            ("unicode chars", "日本語", "日本語"),
            (
                "multiple control characters",
                "\x01\x02\x03",
                r"\u0001\u0002\u0003",
            ),
        ];

        for (name, input, want) in cases {
            assert_eq!(escape_json_string(input), want, "{name}");
        }
    }

    #[test]
    fn formats_json_preserves_object_order_and_number_lexemes() {
        let got = format_json(br#"{"b":1.2300,"a":2}"#, false).unwrap();

        assert_eq!(
            String::from_utf8(got).unwrap(),
            "{\n  \"b\": 1.2300,\n  \"a\": 2\n}\n"
        );
    }
}
