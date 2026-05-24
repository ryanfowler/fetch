use std::fmt;
use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtobufError(String);

impl fmt::Display for ProtobufError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ProtobufError {}

pub fn format_protobuf(buf: &[u8]) -> Result<String, ProtobufError> {
    let mut out = String::new();
    format_message(buf, &mut out, 0)?;
    Ok(out)
}

fn format_message(mut buf: &[u8], out: &mut String, indent: usize) -> Result<(), ProtobufError> {
    while !buf.is_empty() {
        let (key, n) = consume_varint(buf)?;
        buf = &buf[n..];

        let field_number = key >> 3;
        let wire_type = key & 0x07;
        if field_number == 0 {
            return Err(ProtobufError("invalid field number".to_string()));
        }

        write_indent(out, indent);
        write!(out, "{field_number}").expect("write to string cannot fail");
        out.push(':');

        match wire_type {
            0 => {
                let (value, n) = consume_varint(buf)?;
                buf = &buf[n..];
                out.push_str(" (varint) ");
                write!(out, "{value}").expect("write to string cannot fail");
                out.push('\n');
            }
            1 => {
                if buf.len() < 8 {
                    return Err(ProtobufError(
                        "unexpected EOF while reading fixed64".to_string(),
                    ));
                }
                let value = u64::from_le_bytes(buf[..8].try_into().expect("slice length checked"));
                buf = &buf[8..];
                out.push_str(" (fixed64) ");
                write!(out, "0x{value:016x}").expect("write to string cannot fail");
                out.push('\n');
            }
            2 => {
                let (len, n) = consume_varint(buf)?;
                buf = &buf[n..];
                let len = usize::try_from(len)
                    .map_err(|_| ProtobufError("bytes field length overflows usize".to_string()))?;
                if buf.len() < len {
                    return Err(ProtobufError(
                        "unexpected EOF while reading bytes".to_string(),
                    ));
                }
                let value = &buf[..len];
                buf = &buf[len..];

                if is_valid_protobuf(value) {
                    out.push_str(" (message) {\n");
                    format_message(value, out, indent + 1)?;
                    write_indent(out, indent);
                    out.push_str("}\n");
                } else if is_printable_bytes(value) {
                    out.push_str(" (bytes) ");
                    write_protobuf_string(out, String::from_utf8_lossy(value).as_ref());
                    out.push('\n');
                } else {
                    out.push_str(" (bytes) ");
                    write_protobuf_bytes(out, value);
                    out.push('\n');
                }
            }
            5 => {
                if buf.len() < 4 {
                    return Err(ProtobufError(
                        "unexpected EOF while reading fixed32".to_string(),
                    ));
                }
                let value = u32::from_le_bytes(buf[..4].try_into().expect("slice length checked"));
                buf = &buf[4..];
                out.push_str(" (fixed32) ");
                write!(out, "0x{value:08x}").expect("write to string cannot fail");
                out.push('\n');
            }
            3 | 4 => return Err(ProtobufError("deprecated group wire type".to_string())),
            other => return Err(ProtobufError(format!("unknown wire type: {other}"))),
        }
    }
    Ok(())
}

fn is_valid_protobuf(mut buf: &[u8]) -> bool {
    if buf.is_empty() {
        return false;
    }

    while !buf.is_empty() {
        let Ok((key, n)) = consume_varint(buf) else {
            return false;
        };
        buf = &buf[n..];

        let field_number = key >> 3;
        let wire_type = key & 0x07;
        if field_number == 0 {
            return false;
        }

        let consumed = match wire_type {
            0 => consume_varint(buf).map(|(_, n)| n),
            1 => {
                if buf.len() >= 8 {
                    Ok(8)
                } else {
                    Err(ProtobufError(String::new()))
                }
            }
            2 => consume_varint(buf).and_then(|(len, n)| {
                let len = usize::try_from(len)
                    .map_err(|_| ProtobufError("bytes field length overflows usize".to_string()))?;
                if buf.len() >= n + len {
                    Ok(n + len)
                } else {
                    Err(ProtobufError(String::new()))
                }
            }),
            5 => {
                if buf.len() >= 4 {
                    Ok(4)
                } else {
                    Err(ProtobufError(String::new()))
                }
            }
            _ => return false,
        };

        let Ok(n) = consumed else {
            return false;
        };
        buf = &buf[n..];
    }
    true
}

fn is_printable_bytes(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    text.chars().all(|c| !c.is_control() || c.is_whitespace())
}

fn write_indent(out: &mut String, indent: usize) {
    for _ in 0..indent {
        out.push_str("  ");
    }
}

fn write_protobuf_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\t' => out.push_str(r"\t"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str(r"\\"),
            ch if (ch as u32) < 0x20 || ch == '\u{7f}' => {
                write!(out, "\\u{:04x}", ch as u32).expect("write to string cannot fail");
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}

fn write_protobuf_bytes(out: &mut String, bytes: &[u8]) {
    out.push('<');
    for (idx, byte) in bytes.iter().enumerate() {
        if idx > 0 {
            out.push(' ');
        }
        write!(out, "{byte:02x}").expect("write to string cannot fail");
    }
    out.push('>');
}

fn consume_varint(buf: &[u8]) -> Result<(u64, usize), ProtobufError> {
    let mut value = 0u64;
    for idx in 0..10 {
        let Some(byte) = buf.get(idx).copied() else {
            return Err(ProtobufError(
                "unexpected EOF while reading varint".to_string(),
            ));
        };
        let low = (byte & 0x7f) as u64;
        if idx == 9 && low > 1 {
            return Err(ProtobufError("varint overflow".to_string()));
        }
        value |= low << (idx * 7);
        if byte < 0x80 {
            return Ok((value, idx + 1));
        }
    }
    Err(ProtobufError("varint overflow".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_protobuf() {
        let cases = [
            (
                "varint field",
                append_varint(Vec::new(), 1, 123),
                false,
                vec!["1:", "(varint)", "123"],
            ),
            (
                "fixed64 field",
                append_fixed64(Vec::new(), 2, 0x123456789abcdef0),
                false,
                vec!["2:", "(fixed64)", "0x123456789abcdef0"],
            ),
            (
                "fixed32 field",
                append_fixed32(Vec::new(), 3, 0x12345678),
                false,
                vec!["3:", "(fixed32)", "0x12345678"],
            ),
            (
                "string field",
                append_bytes(Vec::new(), 4, b"hello world"),
                false,
                vec!["4:", "(bytes)", "\"hello world\""],
            ),
            (
                "binary bytes field",
                append_bytes(Vec::new(), 5, &[0x00, 0xff, 0x80]),
                false,
                vec!["5:", "(bytes)", "<00 ff 80>"],
            ),
            (
                "multiple fields",
                append_bytes(append_varint(Vec::new(), 1, 42), 2, b"test"),
                false,
                vec!["1:", "42", "2:", "\"test\""],
            ),
            (
                "nested message",
                append_bytes(Vec::new(), 3, &append_varint(Vec::new(), 1, 456)),
                false,
                vec!["3:", "(message)", "{", "1:", "456", "}"],
            ),
            ("empty input", Vec::new(), false, Vec::new()),
            (
                "invalid tag",
                vec![
                    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01,
                ],
                true,
                Vec::new(),
            ),
            ("truncated varint", vec![0x08, 0x80], true, Vec::new()),
        ];

        for (name, input, want_err, contains) in cases {
            let got = format_protobuf(&input);
            assert_eq!(got.is_err(), want_err, "{name}: {got:?}");
            if want_err {
                continue;
            }
            let got = got.unwrap();
            for want in contains {
                assert!(
                    got.contains(want),
                    "{name}: output should contain {want:?}, got {got:?}"
                );
            }
        }
    }

    #[test]
    fn test_format_protobuf_nested() {
        let innermost = append_varint(Vec::new(), 3, 789);
        let middle = append_bytes(Vec::new(), 2, &innermost);
        let outer = append_bytes(Vec::new(), 1, &middle);

        let output = format_protobuf(&outer).unwrap();
        assert!(output.contains("1:"));
        assert!(output.contains("2:"));
        assert!(output.contains("3:"));
        assert!(output.contains("789"));
        assert_eq!(output.matches('{').count(), 2);
        assert_eq!(output.matches('}').count(), 2);
    }

    #[test]
    fn test_format_protobuf_all_wire_types() {
        let mut bytes = append_varint(Vec::new(), 1, 100);
        bytes = append_fixed64(bytes, 2, 200);
        bytes = append_fixed32(bytes, 3, 300);
        bytes = append_bytes(bytes, 4, b"string");

        let output = format_protobuf(&bytes).unwrap();
        assert!(output.contains("(varint)"));
        assert!(output.contains("(fixed64)"));
        assert!(output.contains("(fixed32)"));
        assert!(output.contains("(bytes)"));
    }

    #[test]
    fn test_is_valid_protobuf() {
        let cases = [
            ("empty", Vec::new(), false),
            ("valid varint", append_varint(Vec::new(), 1, 123), true),
            (
                "valid multiple fields",
                append_bytes(append_varint(Vec::new(), 1, 1), 2, b"test"),
                true,
            ),
            ("invalid tag", vec![0x00], false),
            ("truncated", vec![0x08], false),
            ("random bytes", vec![0xff, 0xff, 0xff], false),
        ];

        for (name, input, want) in cases {
            assert_eq!(is_valid_protobuf(&input), want, "{name}");
        }
    }

    #[test]
    fn test_is_printable_bytes() {
        let cases = [
            ("ascii text", b"hello world".as_slice(), true),
            ("unicode text", "hello 世界".as_bytes(), true),
            ("with newline", b"hello\nworld".as_slice(), true),
            ("with tab", b"hello\tworld".as_slice(), true),
            ("binary data", &[0x00, 0x01, 0x02], false),
            ("invalid utf8", &[0xff, 0xfe], false),
            ("empty", b"".as_slice(), true),
        ];

        for (name, input, want) in cases {
            assert_eq!(is_printable_bytes(input), want, "{name}");
        }
    }

    #[test]
    fn test_write_protobuf_string() {
        let cases = [
            ("simple string", "hello", "\"hello\""),
            ("with newline", "hello\nworld", "\"hello\\nworld\""),
            ("with tab", "hello\tworld", "\"hello\\tworld\""),
            ("with quotes", "say \"hello\"", "\"say \\\"hello\\\"\""),
            ("with backslash", r"path\to\file", r#""path\\to\\file""#),
            ("with carriage return", "hello\rworld", "\"hello\\rworld\""),
        ];

        for (name, input, want) in cases {
            let mut got = String::new();
            write_protobuf_string(&mut got, input);
            assert_eq!(got, want, "{name}");
        }
    }

    #[test]
    fn test_write_protobuf_bytes() {
        let cases = [
            ("single byte", vec![0xab], "<ab>"),
            ("multiple bytes", vec![0x00, 0xff, 0x80], "<00 ff 80>"),
            ("empty", Vec::new(), "<>"),
        ];

        for (name, input, want) in cases {
            let mut got = String::new();
            write_protobuf_bytes(&mut got, &input);
            assert_eq!(got, want, "{name}");
        }
    }

    pub(crate) fn append_varint(mut bytes: Vec<u8>, field_number: u64, value: u64) -> Vec<u8> {
        append_tag(&mut bytes, field_number, 0);
        append_raw_varint(&mut bytes, value);
        bytes
    }

    pub(crate) fn append_fixed64(mut bytes: Vec<u8>, field_number: u64, value: u64) -> Vec<u8> {
        append_tag(&mut bytes, field_number, 1);
        bytes.extend_from_slice(&value.to_le_bytes());
        bytes
    }

    pub(crate) fn append_fixed32(mut bytes: Vec<u8>, field_number: u64, value: u32) -> Vec<u8> {
        append_tag(&mut bytes, field_number, 5);
        bytes.extend_from_slice(&value.to_le_bytes());
        bytes
    }

    pub(crate) fn append_bytes(mut bytes: Vec<u8>, field_number: u64, value: &[u8]) -> Vec<u8> {
        append_tag(&mut bytes, field_number, 2);
        append_raw_varint(&mut bytes, value.len() as u64);
        bytes.extend_from_slice(value);
        bytes
    }

    fn append_tag(bytes: &mut Vec<u8>, field_number: u64, wire_type: u64) {
        append_raw_varint(bytes, (field_number << 3) | wire_type);
    }

    fn append_raw_varint(bytes: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            bytes.push(((value as u8) & 0x7f) | 0x80);
            value >>= 7;
        }
        bytes.push(value as u8);
    }
}
