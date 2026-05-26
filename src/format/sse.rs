use serde_json::Value;

use crate::core::{Sequence, write_styled_to_string};

pub fn format_event_stream(bytes: &[u8], color: bool) -> Result<String, std::str::Utf8Error> {
    let input = std::str::from_utf8(bytes)?;
    let mut formatter = EventStreamFormatter::new(color);
    let mut out = String::new();
    formatter.push_str(input, &mut out);
    formatter.finish(&mut out);
    Ok(out)
}

#[derive(Debug, Default)]
pub struct EventStreamFormatter {
    event_type: String,
    data: String,
    line: String,
    seen_first_line: bool,
    pending_cr: bool,
    color: bool,
}

impl EventStreamFormatter {
    pub fn new(color: bool) -> Self {
        Self {
            color,
            ..Self::default()
        }
    }

    pub fn push_str(&mut self, input: &str, out: &mut String) {
        for ch in input.chars() {
            if self.pending_cr {
                self.pending_cr = false;
                if ch == '\n' {
                    continue;
                }
            }

            match ch {
                '\n' => self.process_line(out),
                '\r' => {
                    self.process_line(out);
                    self.pending_cr = true;
                }
                _ => self.line.push(ch),
            }
        }
    }

    pub fn finish(&mut self, out: &mut String) {
        if !self.line.is_empty() {
            self.process_line(out);
        }
        if !self.data.is_empty() {
            self.dispatch_event(out);
        }
    }

    fn process_line(&mut self, out: &mut String) {
        if !self.seen_first_line {
            if self.line.starts_with('\u{feff}') {
                self.line.drain(..'\u{feff}'.len_utf8());
            }
            self.seen_first_line = true;
        }

        if self.line.is_empty() {
            self.dispatch_event(out);
            return;
        }

        let (name, value) = self.line.split_once(':').unwrap_or((&self.line, ""));
        if !name.is_empty() {
            let value = value.strip_prefix(' ').unwrap_or(value);
            match name {
                "event" => {
                    self.event_type.clear();
                    self.event_type.push_str(value);
                }
                "data" => {
                    self.data.push_str(value);
                    self.data.push('\n');
                }
                "id" => {}
                _ => {}
            }
        }
        self.line.clear();
    }

    fn dispatch_event(&mut self, out: &mut String) {
        let event_data = self.data.trim_end_matches('\n');
        if event_data.is_empty() {
            self.event_type.clear();
            self.data.clear();
            self.line.clear();
            return;
        }

        let event_type = if self.event_type.is_empty() {
            "message"
        } else {
            &self.event_type
        };
        write_sse_field(out, "event", event_type, self.color);
        out.push('\n');
        let formatted_data = format_event_data(event_data, self.color);
        for line in formatted_data.split('\n') {
            write_sse_field(out, "data", line, self.color);
            out.push('\n');
        }
        out.push('\n');
        self.event_type.clear();
        self.data.clear();
        self.line.clear();
    }
}

fn write_sse_field(out: &mut String, name: &str, value: &str, color: bool) {
    write_styled_to_string(out, name, &[Sequence::Bold, Sequence::Cyan], color);
    out.push_str(": ");
    out.push_str(value);
}

fn format_event_data(data: &str, color: bool) -> String {
    match serde_json::from_str::<Value>(data) {
        Ok(value) => format_json_inline(&value, color),
        Err(_) => data.to_string(),
    }
}

fn format_json_inline(value: &Value, color: bool) -> String {
    match value {
        Value::Array(values) => {
            if values.is_empty() {
                return "[]".to_string();
            }
            let values = values
                .iter()
                .map(|value| format_json_inline(value, color))
                .collect::<Vec<_>>()
                .join(", ");
            format!("[ {values} ]")
        }
        Value::Object(map) => {
            if map.is_empty() {
                return "{}".to_string();
            }
            let values = map
                .iter()
                .map(|(key, value)| {
                    let key = serde_json::to_string(key).expect("string key serializes");
                    let mut styled_key = String::new();
                    write_styled_to_string(
                        &mut styled_key,
                        &key,
                        &[Sequence::Blue, Sequence::Bold],
                        color,
                    );
                    format!("{}: {}", styled_key, format_json_inline(value, color))
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("{{ {values} }}")
        }
        Value::String(_) => {
            let value = serde_json::to_string(value).expect("JSON value serializes");
            let mut out = String::new();
            write_styled_to_string(&mut out, &value, &[Sequence::Green], color);
            out
        }
        _ => serde_json::to_string(value).expect("JSON value serializes"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_events_eof_dispatches_final_event_without_blank_line() {
        let got = format_event_stream(b"data: final\n", false).unwrap();

        assert_eq!(got, "event: message\ndata: final\n\n");
    }

    #[test]
    fn test_stream_events_eof_does_not_duplicate_final_event_with_blank_line() {
        let got = format_event_stream(b"data: final\n\n", false).unwrap();

        assert_eq!(got, "event: message\ndata: final\n\n");
    }

    #[test]
    fn formats_event_stream_like_go_integration() {
        let input = b":comment\n\ndata:{\"key\":\"val\"}\n\nevent:ev1\ndata: this is my data\n\n";

        let got = format_event_stream(input, false).unwrap();

        assert_eq!(
            got,
            "event: message\ndata: { \"key\": \"val\" }\n\nevent: ev1\ndata: this is my data\n\n"
        );
    }

    #[test]
    fn supports_crlf_and_bom() {
        let input = "\u{feff}event: greeting\r\ndata: hello\r\n\r\n";

        let got = format_event_stream(input.as_bytes(), false).unwrap();

        assert_eq!(got, "event: greeting\ndata: hello\n\n");
    }

    #[test]
    fn formatter_streams_events_across_chunks() {
        let mut formatter = EventStreamFormatter::new(false);
        let mut got = String::new();

        formatter.push_str("data: {\"a\"", &mut got);
        assert!(got.is_empty());
        formatter.push_str(":1}\r\n", &mut got);
        assert!(got.is_empty());
        formatter.push_str("\nevent: done\ndata: two\n\n", &mut got);
        formatter.finish(&mut got);

        assert_eq!(
            got,
            "event: message\ndata: { \"a\": 1 }\n\nevent: done\ndata: two\n\n"
        );
    }

    #[test]
    fn colors_sse_fields_and_json_data() {
        let got = format_event_stream(b"event: ev1\ndata: {\"key\":\"val\"}\n\n", true).unwrap();

        assert_eq!(
            got,
            "\x1b[1m\x1b[36mevent\x1b[0m: ev1\n\x1b[1m\x1b[36mdata\x1b[0m: { \x1b[34m\x1b[1m\"key\"\x1b[0m: \x1b[32m\"val\"\x1b[0m }\n\n"
        );
    }
}
