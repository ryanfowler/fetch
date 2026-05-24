use std::fmt;

use base64::Engine;

use crate::format::json;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgPackError(String);

impl MsgPackError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for MsgPackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for MsgPackError {}

pub fn format_msgpack(buf: &[u8], color: bool) -> Result<Vec<u8>, MsgPackError> {
    let json_bytes = msgpack_to_json(buf)?;
    json::format_json(json_bytes.as_bytes(), color)
        .map_err(|err| MsgPackError::new(err.to_string()))
}

fn msgpack_to_json(buf: &[u8]) -> Result<String, MsgPackError> {
    let mut parser = MsgPackParser::new(buf);
    let mut out = String::new();
    parser.write_value(&mut out)?;
    if !parser.is_eof() {
        return Err(MsgPackError::new("unexpected trailing MessagePack data"));
    }
    Ok(out)
}

struct MsgPackParser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> MsgPackParser<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    fn is_eof(&self) -> bool {
        self.pos == self.input.len()
    }

    fn write_value(&mut self, out: &mut String) -> Result<(), MsgPackError> {
        let marker = self.read_u8()?;
        match marker {
            0x00..=0x7f => out.push_str(&marker.to_string()),
            0x80..=0x8f => self.write_map(out, u32::from(marker & 0x0f))?,
            0x90..=0x9f => self.write_array(out, u32::from(marker & 0x0f))?,
            0xa0..=0xbf => self.write_string(out, usize::from(marker & 0x1f))?,
            0xc0 => out.push_str("null"),
            0xc1 => return Err(MsgPackError::new("reserved MessagePack marker 0xc1")),
            0xc2 => out.push_str("false"),
            0xc3 => out.push_str("true"),
            0xc4 => {
                let len = usize::from(self.read_u8()?);
                self.write_binary(out, len)?;
            }
            0xc5 => {
                let len = usize::from(self.read_u16()?);
                self.write_binary(out, len)?;
            }
            0xc6 => {
                let len = self.read_len_u32()?;
                self.write_binary(out, len)?;
            }
            0xc7 => {
                let len = usize::from(self.read_u8()?);
                self.write_extension(out, len)?;
            }
            0xc8 => {
                let len = usize::from(self.read_u16()?);
                self.write_extension(out, len)?;
            }
            0xc9 => {
                let len = self.read_len_u32()?;
                self.write_extension(out, len)?;
            }
            0xca => out.push_str(&f64::from(f32::from_bits(self.read_u32()?)).to_string()),
            0xcb => out.push_str(&f64::from_bits(self.read_u64()?).to_string()),
            0xcc => out.push_str(&self.read_u8()?.to_string()),
            0xcd => out.push_str(&self.read_u16()?.to_string()),
            0xce => out.push_str(&self.read_u32()?.to_string()),
            0xcf => out.push_str(&self.read_u64()?.to_string()),
            0xd0 => out.push_str(&(self.read_u8()? as i8).to_string()),
            0xd1 => out.push_str(&(self.read_u16()? as i16).to_string()),
            0xd2 => out.push_str(&(self.read_u32()? as i32).to_string()),
            0xd3 => out.push_str(&(self.read_u64()? as i64).to_string()),
            0xd4 => self.write_extension(out, 1)?,
            0xd5 => self.write_extension(out, 2)?,
            0xd6 => self.write_extension(out, 4)?,
            0xd7 => self.write_extension(out, 8)?,
            0xd8 => self.write_extension(out, 16)?,
            0xd9 => {
                let len = usize::from(self.read_u8()?);
                self.write_string(out, len)?;
            }
            0xda => {
                let len = usize::from(self.read_u16()?);
                self.write_string(out, len)?;
            }
            0xdb => {
                let len = self.read_len_u32()?;
                self.write_string(out, len)?;
            }
            0xdc => {
                let len = u32::from(self.read_u16()?);
                self.write_array(out, len)?;
            }
            0xdd => {
                let len = self.read_u32()?;
                self.write_array(out, len)?;
            }
            0xde => {
                let len = u32::from(self.read_u16()?);
                self.write_map(out, len)?;
            }
            0xdf => {
                let len = self.read_u32()?;
                self.write_map(out, len)?;
            }
            0xe0..=0xff => out.push_str(&(marker as i8).to_string()),
        }
        Ok(())
    }

    fn write_array(&mut self, out: &mut String, len: u32) -> Result<(), MsgPackError> {
        out.push('[');
        for index in 0..len {
            if index > 0 {
                out.push(',');
            }
            self.write_value(out)?;
        }
        out.push(']');
        Ok(())
    }

    fn write_map(&mut self, out: &mut String, len: u32) -> Result<(), MsgPackError> {
        out.push('{');
        for index in 0..len {
            if index > 0 {
                out.push(',');
            }
            self.write_map_key(out)?;
            out.push(':');
            self.write_value(out)?;
        }
        out.push('}');
        Ok(())
    }

    fn write_map_key(&mut self, out: &mut String) -> Result<(), MsgPackError> {
        let marker = self.read_u8()?;
        match marker {
            0x00..=0x7f => write_json_string(out, marker.to_string().as_bytes()),
            0xa0..=0xbf => self.write_map_key_bytes(out, usize::from(marker & 0x1f))?,
            0xc4 => {
                let len = usize::from(self.read_u8()?);
                self.write_map_key_bytes(out, len)?;
            }
            0xc5 => {
                let len = usize::from(self.read_u16()?);
                self.write_map_key_bytes(out, len)?;
            }
            0xc6 => {
                let len = self.read_len_u32()?;
                self.write_map_key_bytes(out, len)?;
            }
            0xcc => write_json_string(out, self.read_u8()?.to_string().as_bytes()),
            0xcd => write_json_string(out, self.read_u16()?.to_string().as_bytes()),
            0xce => write_json_string(out, self.read_u32()?.to_string().as_bytes()),
            0xcf => write_json_string(out, self.read_u64()?.to_string().as_bytes()),
            0xd0 => write_json_string(out, (self.read_u8()? as i8).to_string().as_bytes()),
            0xd1 => write_json_string(out, (self.read_u16()? as i16).to_string().as_bytes()),
            0xd2 => write_json_string(out, (self.read_u32()? as i32).to_string().as_bytes()),
            0xd3 => write_json_string(out, (self.read_u64()? as i64).to_string().as_bytes()),
            0xd9 => {
                let len = usize::from(self.read_u8()?);
                self.write_map_key_bytes(out, len)?;
            }
            0xda => {
                let len = usize::from(self.read_u16()?);
                self.write_map_key_bytes(out, len)?;
            }
            0xdb => {
                let len = self.read_len_u32()?;
                self.write_map_key_bytes(out, len)?;
            }
            0xe0..=0xff => write_json_string(out, (marker as i8).to_string().as_bytes()),
            _ => return Err(MsgPackError::new("unsupported MessagePack map key type")),
        }
        Ok(())
    }

    fn write_map_key_bytes(&mut self, out: &mut String, len: usize) -> Result<(), MsgPackError> {
        if len == 0 {
            return Err(MsgPackError::new("empty MessagePack map key"));
        }
        let bytes = self.read_exact(len)?;
        write_json_string(out, bytes);
        Ok(())
    }

    fn write_string(&mut self, out: &mut String, len: usize) -> Result<(), MsgPackError> {
        let bytes = self.read_exact(len)?;
        write_json_string(out, bytes);
        Ok(())
    }

    fn write_binary(&mut self, out: &mut String, len: usize) -> Result<(), MsgPackError> {
        let bytes = self.read_exact(len)?;
        out.push('"');
        out.push_str(&base64::engine::general_purpose::STANDARD.encode(bytes));
        out.push('"');
        Ok(())
    }

    fn write_extension(&mut self, out: &mut String, len: usize) -> Result<(), MsgPackError> {
        let typ = self.read_u8()? as i8;
        let data = self.read_exact(len)?;
        out.push_str(r#"{"type":"#);
        out.push_str(&typ.to_string());
        out.push_str(r#","data":""#);
        out.push_str(&base64::engine::general_purpose::STANDARD.encode(data));
        out.push_str(r#""}"#);
        Ok(())
    }

    fn read_len_u32(&mut self) -> Result<usize, MsgPackError> {
        usize::try_from(self.read_u32()?)
            .map_err(|_| MsgPackError::new("MessagePack length overflows usize"))
    }

    fn read_u8(&mut self) -> Result<u8, MsgPackError> {
        let Some(value) = self.input.get(self.pos).copied() else {
            return Err(MsgPackError::new(
                "unexpected EOF while reading MessagePack",
            ));
        };
        self.pos += 1;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, MsgPackError> {
        let bytes = self.read_array::<2>()?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, MsgPackError> {
        let bytes = self.read_array::<4>()?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, MsgPackError> {
        let bytes = self.read_array::<8>()?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], MsgPackError> {
        let bytes = self.read_exact(N)?;
        let mut out = [0; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], MsgPackError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| MsgPackError::new("MessagePack length overflows usize"))?;
        let Some(bytes) = self.input.get(self.pos..end) else {
            return Err(MsgPackError::new(
                "unexpected EOF while reading MessagePack",
            ));
        };
        self.pos = end;
        Ok(bytes)
    }
}

fn write_json_string(out: &mut String, bytes: &[u8]) {
    out.push('"');
    let value = String::from_utf8_lossy(bytes);
    for c in value.chars() {
        match c {
            '\u{08}' => out.push_str(r"\b"),
            '\u{0c}' => out.push_str(r"\f"),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\t' => out.push_str(r"\t"),
            '"' => out.push_str(r#"\""#),
            '\\' => out.push_str(r"\\"),
            '<' => out.push_str(r"\u003c"),
            '>' => out.push_str(r"\u003e"),
            '&' => out.push_str(r"\u0026"),
            '\u{2028}' => out.push_str(r"\u2028"),
            '\u{2029}' => out.push_str(r"\u2029"),
            c if c < ' ' || c == '\u{7f}' => out.push_str(&format!(r"\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn test_format_msgpack() {
        let input = [
            0x82, 0xa4, b'k', b'e', b'y', b'1', 0xa4, b'v', b'a', b'l', b'1', 0xa4, b'k', b'e',
            b'y', b'2', 0xa4, b'v', b'a', b'l', b'2',
        ];
        let got = format_msgpack(&input, false).unwrap();
        let got: Value = serde_json::from_slice(&got).unwrap();
        let want: Value = serde_json::from_str(r#"{"key1":"val1","key2":"val2"}"#).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn formats_nested_msgpack_as_json() {
        let input = [
            0x85, 0xa3, b's', b't', b'r', 0xa5, b'h', b'e', b'l', b'l', b'o', 0xa3, b'a', b'r',
            b'r', 0x93, 0xc3, 0xc0, 0xd0, 0xfb, 0xa3, b'b', b'i', b'n', 0xc4, 0x03, b'a', b'b',
            b'c', 0xa5, b'f', b'l', b'o', b'a', b't', 0xca, 0x3f, 0x80, 0x00, 0x00, 0xff, 0xa3,
            b'n', b'e', b'g',
        ];
        let got = String::from_utf8(format_msgpack(&input, false).unwrap()).unwrap();
        assert_eq!(
            got,
            "{\n  \"str\": \"hello\",\n  \"arr\": [\n    true,\n    null,\n    -5\n  ],\n  \"bin\": \"YWJj\",\n  \"float\": 1,\n  \"-1\": \"neg\"\n}\n"
        );
    }

    #[test]
    fn numeric_map_keys_are_quoted_like_go_msgp() {
        let input = [
            0x82, 0xd0, 0xfb, 0xa3, b'n', b'e', b'g', 0xcc, 0x2a, 0xa3, b'p', b'o', b's',
        ];
        let got = String::from_utf8(format_msgpack(&input, false).unwrap()).unwrap();
        assert!(got.contains("\"-5\": \"neg\""), "{got}");
        assert!(got.contains("\"42\": \"pos\""), "{got}");
    }

    #[test]
    fn invalid_utf8_is_replaced_like_go_msgp_json() {
        let input = [0xa1, 0xe0];
        let got = String::from_utf8(format_msgpack(&input, false).unwrap()).unwrap();
        assert_eq!(got, "\"\u{fffd}\"\n");
    }

    #[test]
    fn malformed_msgpack_is_rejected() {
        assert!(format_msgpack(&[0xa2, b'a'], false).is_err());
        assert!(format_msgpack(&[0xc1], false).is_err());
        assert!(format_msgpack(&[0x01, 0x02], false).is_err());
    }

    #[test]
    fn formats_msgpack_with_color_when_requested() {
        let input = [0x81, 0xa2, b'o', b'k', 0xa3, b'y', b'e', b's'];
        let got = String::from_utf8(format_msgpack(&input, true).unwrap()).unwrap();
        assert!(got.contains("\"\x1b[34m\x1b[1mok\x1b[0m\""), "{got:?}");
        assert!(got.contains("\"\x1b[32myes\x1b[0m\""), "{got:?}");
    }
}
