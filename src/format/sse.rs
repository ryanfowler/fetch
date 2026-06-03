use serde_json::Value;

use crate::core::{Printer, Sequence};

#[cfg(test)]
pub(crate) fn format_event_stream(bytes: &[u8], color: bool) -> Result<String, EventStreamError> {
    let mut out = Printer::new(color);
    format_event_stream_to(bytes, &mut out)?;
    Ok(out
        .into_string()
        .expect("event stream formatter output is valid UTF-8"))
}

pub fn format_event_stream_to(bytes: &[u8], out: &mut Printer) -> Result<(), EventStreamError> {
    let input = std::str::from_utf8(bytes)?;
    let mut formatter = EventStreamFormatter::new();
    formatter.push_str(input, out)?;
    formatter.finish(out)
}

#[derive(Debug)]
pub enum EventStreamError {
    InvalidUtf8(std::str::Utf8Error),
    PendingBufferTooLarge {
        kind: PendingBufferKind,
        max_bytes: usize,
    },
}

impl std::fmt::Display for EventStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUtf8(err) => write!(f, "invalid UTF-8 in event stream: {err}"),
            Self::PendingBufferTooLarge { kind, max_bytes } => write!(
                f,
                "SSE {kind} exceeds {max_bytes} bytes and cannot be formatted as a stream"
            ),
        }
    }
}

impl std::error::Error for EventStreamError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidUtf8(err) => Some(err),
            Self::PendingBufferTooLarge { .. } => None,
        }
    }
}

impl From<std::str::Utf8Error> for EventStreamError {
    fn from(err: std::str::Utf8Error) -> Self {
        Self::InvalidUtf8(err)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PendingBufferKind {
    Event,
    Line,
    Utf8,
}

impl std::fmt::Display for PendingBufferKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Event => "event",
            Self::Line => "line",
            Self::Utf8 => "UTF-8 buffer",
        };
        f.write_str(label)
    }
}

#[derive(Debug, Default)]
pub struct EventStreamFormatter {
    event_type: String,
    data: String,
    line: String,
    seen_first_line: bool,
    pending_cr: bool,
    max_pending_bytes: Option<usize>,
}

impl EventStreamFormatter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_pending_limit(max_pending_bytes: usize) -> Self {
        Self {
            max_pending_bytes: Some(max_pending_bytes),
            ..Self::default()
        }
    }

    pub fn max_pending_bytes(&self) -> Option<usize> {
        self.max_pending_bytes
    }

    pub fn push_str(&mut self, input: &str, out: &mut Printer) -> Result<(), EventStreamError> {
        for ch in input.chars() {
            if self.pending_cr {
                self.pending_cr = false;
                if ch == '\n' {
                    continue;
                }
            }

            match ch {
                '\n' => self.process_line(out)?,
                '\r' => {
                    self.process_line(out)?;
                    self.pending_cr = true;
                }
                _ => {
                    self.ensure_pending_line_len(ch.len_utf8())?;
                    self.line.push(ch);
                }
            }
        }
        Ok(())
    }

    pub fn finish(&mut self, out: &mut Printer) -> Result<(), EventStreamError> {
        if !self.line.is_empty() {
            self.process_line(out)?;
        }
        if !self.data.is_empty() {
            self.dispatch_event(out);
        }
        Ok(())
    }

    fn ensure_pending_line_len(&self, additional_bytes: usize) -> Result<(), EventStreamError> {
        if self
            .max_pending_bytes
            .is_some_and(|max| self.line.len().saturating_add(additional_bytes) > max)
        {
            return Err(EventStreamError::PendingBufferTooLarge {
                kind: PendingBufferKind::Line,
                max_bytes: self.max_pending_bytes.unwrap(),
            });
        }
        Ok(())
    }

    fn ensure_pending_event_len(
        &self,
        current_len: usize,
        additional_bytes: usize,
    ) -> Result<(), EventStreamError> {
        if self
            .max_pending_bytes
            .is_some_and(|max| current_len.saturating_add(additional_bytes) > max)
        {
            return Err(EventStreamError::PendingBufferTooLarge {
                kind: PendingBufferKind::Event,
                max_bytes: self.max_pending_bytes.unwrap(),
            });
        }
        Ok(())
    }

    fn process_line(&mut self, out: &mut Printer) -> Result<(), EventStreamError> {
        let mut line = std::mem::take(&mut self.line);
        if !self.seen_first_line {
            if line.starts_with('\u{feff}') {
                line.drain(..'\u{feff}'.len_utf8());
            }
            self.seen_first_line = true;
        }

        if line.is_empty() {
            self.dispatch_event(out);
            return Ok(());
        }

        let (name, value) = line.split_once(':').unwrap_or((&line, ""));
        if !name.is_empty() {
            let value = value.strip_prefix(' ').unwrap_or(value);
            match name {
                "event" => {
                    self.ensure_pending_event_len(0, value.len())?;
                    self.event_type.clear();
                    self.event_type.push_str(value);
                }
                "data" => {
                    self.ensure_pending_event_len(self.data.len(), value.len().saturating_add(1))?;
                    self.data.push_str(value);
                    self.data.push('\n');
                }
                "id" => {}
                _ => {}
            }
        }
        Ok(())
    }

    fn dispatch_event(&mut self, out: &mut Printer) {
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
        write_sse_field(out, "event", event_type);
        out.push('\n');
        let formatted_data = format_event_data(event_data, out.use_color());
        for line in formatted_data.split('\n') {
            write_sse_field(out, "data", line);
            out.push('\n');
        }
        out.push('\n');
        self.event_type.clear();
        self.data.clear();
        self.line.clear();
    }
}

fn write_sse_field(out: &mut Printer, name: &str, value: &str) {
    out.write_styled(name, &[Sequence::Bold, Sequence::Cyan]);
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
    let mut out = Printer::new(color);
    write_json_inline(value, &mut out);
    out.into_string()
        .expect("inline JSON formatter output is valid UTF-8")
}

fn write_json_inline(value: &Value, out: &mut Printer) {
    match value {
        Value::Array(values) => {
            if values.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push_str("[ ");
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write_json_inline(value, out);
            }
            out.push_str(" ]");
        }
        Value::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push_str("{ ");
            for (index, (key, value)) in map.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                let key = serde_json::to_string(key).expect("string key serializes");
                out.write_styled(&key, &[Sequence::Blue, Sequence::Bold]);
                out.push_str(": ");
                write_json_inline(value, out);
            }
            out.push_str(" }");
        }
        Value::String(_) => {
            let value = serde_json::to_string(value).expect("JSON value serializes");
            out.write_styled(&value, &[Sequence::Green]);
        }
        _ => out.push_str(&serde_json::to_string(value).expect("JSON value serializes")),
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
        let mut formatter = EventStreamFormatter::new();
        let mut got = Printer::new(false);

        formatter.push_str("data: {\"a\"", &mut got).unwrap();
        assert!(got.bytes().is_empty());
        formatter.push_str(":1}\r\n", &mut got).unwrap();
        assert!(got.bytes().is_empty());
        formatter
            .push_str("\nevent: done\ndata: two\n\n", &mut got)
            .unwrap();
        formatter.finish(&mut got).unwrap();
        let got = got
            .into_string()
            .expect("event stream formatter output is valid UTF-8");

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

    #[test]
    fn errors_when_pending_line_exceeds_limit() {
        let mut formatter = EventStreamFormatter::with_pending_limit(8);
        let mut got = Printer::new(false);

        let err = formatter.push_str("data: 123", &mut got).unwrap_err();

        assert_eq!(
            err.to_string(),
            "SSE line exceeds 8 bytes and cannot be formatted as a stream"
        );
        assert!(got.bytes().is_empty());
    }

    #[test]
    fn errors_when_pending_event_exceeds_limit() {
        let mut formatter = EventStreamFormatter::with_pending_limit(8);
        let mut got = Printer::new(false);

        formatter.push_str("data: ab\n", &mut got).unwrap();
        formatter.push_str("data: cd\n", &mut got).unwrap();
        let err = formatter.push_str("data: ef\n", &mut got).unwrap_err();

        assert_eq!(
            err.to_string(),
            "SSE event exceeds 8 bytes and cannot be formatted as a stream"
        );
        assert!(got.bytes().is_empty());
    }

    #[test]
    fn pending_event_limit_resets_after_dispatch() {
        let mut formatter = EventStreamFormatter::with_pending_limit(10);
        let mut got = Printer::new(false);

        formatter
            .push_str("data: 1234\ndata: 5678\n\n", &mut got)
            .unwrap();
        formatter
            .push_str("data: abcd\ndata: efgh\n\n", &mut got)
            .unwrap();
        formatter.finish(&mut got).unwrap();
        let got = got
            .into_string()
            .expect("event stream formatter output is valid UTF-8");

        assert_eq!(
            got,
            "event: message\ndata: 1234\ndata: 5678\n\nevent: message\ndata: abcd\ndata: efgh\n\n"
        );
    }
}
