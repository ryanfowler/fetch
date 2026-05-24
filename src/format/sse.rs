use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Event {
    event_type: String,
    data: String,
}

pub fn format_event_stream(bytes: &[u8]) -> Result<String, std::str::Utf8Error> {
    let input = std::str::from_utf8(bytes)?;
    let mut out = String::new();
    for (idx, event) in stream_events(input).into_iter().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        out.push('[');
        out.push_str(&event.event_type);
        out.push_str("]\n");
        out.push_str(&format_event_data(&event.data));
        out.push('\n');
    }
    Ok(out)
}

fn format_event_data(data: &str) -> String {
    match serde_json::from_str::<Value>(data) {
        Ok(value) => format_json_inline(&value),
        Err(_) => data.to_string(),
    }
}

fn format_json_inline(value: &Value) -> String {
    match value {
        Value::Array(values) => {
            if values.is_empty() {
                return "[]".to_string();
            }
            let values = values
                .iter()
                .map(format_json_inline)
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
                    format!(
                        "{}: {}",
                        serde_json::to_string(key).expect("string key serializes"),
                        format_json_inline(value)
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("{{ {values} }}")
        }
        _ => serde_json::to_string(value).expect("JSON value serializes"),
    }
}

fn stream_events(input: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let mut event_type = String::new();
    let mut data = String::new();
    let mut seen_first_line = false;

    for mut line in Lines::new(input) {
        if !seen_first_line {
            line = line.strip_prefix('\u{feff}').unwrap_or(line);
            seen_first_line = true;
        }

        if line.is_empty() {
            dispatch_event(&mut events, &mut event_type, &mut data);
            continue;
        }

        let (name, value) = line.split_once(':').unwrap_or((line, ""));
        if name.is_empty() {
            continue;
        }
        let value = value.strip_prefix(' ').unwrap_or(value);
        match name {
            "event" => event_type = value.to_string(),
            "data" => {
                data.push_str(value);
                data.push('\n');
            }
            "id" => {}
            _ => {}
        }
    }

    if !data.is_empty() {
        dispatch_event(&mut events, &mut event_type, &mut data);
    }

    events
}

fn dispatch_event(events: &mut Vec<Event>, event_type: &mut String, data: &mut String) {
    let event_data = data.trim_end_matches('\n').to_string();
    let event_name = std::mem::take(event_type);
    data.clear();

    if event_data.is_empty() {
        return;
    }

    events.push(Event {
        event_type: if event_name.is_empty() {
            "message".to_string()
        } else {
            event_name
        },
        data: event_data,
    });
}

struct Lines<'a> {
    input: &'a str,
}

impl<'a> Lines<'a> {
    fn new(input: &'a str) -> Self {
        Self { input }
    }
}

impl<'a> Iterator for Lines<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.input.is_empty() {
            return None;
        }

        for (idx, ch) in self.input.char_indices() {
            match ch {
                '\n' => {
                    let line = if idx > 0 && self.input.as_bytes()[idx - 1] == b'\r' {
                        &self.input[..idx - 1]
                    } else {
                        &self.input[..idx]
                    };
                    self.input = &self.input[idx + ch.len_utf8()..];
                    return Some(line);
                }
                '\r' => {
                    let line = &self.input[..idx];
                    let rest = &self.input[idx + ch.len_utf8()..];
                    self.input = rest.strip_prefix('\n').unwrap_or(rest);
                    return Some(line);
                }
                _ => {}
            }
        }

        let line = self.input;
        self.input = "";
        Some(line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_events_eof_dispatches_final_event_without_blank_line() {
        let got = stream_events("data: final\n");
        let want = vec![Event {
            event_type: "message".to_string(),
            data: "final".to_string(),
        }];

        assert_eq!(got, want);
    }

    #[test]
    fn test_stream_events_eof_does_not_duplicate_final_event_with_blank_line() {
        let got = stream_events("data: final\n\n");
        let want = vec![Event {
            event_type: "message".to_string(),
            data: "final".to_string(),
        }];

        assert_eq!(got, want);
    }

    #[test]
    fn formats_event_stream_like_go_integration() {
        let input = b":comment\n\ndata:{\"key\":\"val\"}\n\nevent:ev1\ndata: this is my data\n\n";

        let got = format_event_stream(input).unwrap();

        assert_eq!(
            got,
            "[message]\n{ \"key\": \"val\" }\n\n[ev1]\nthis is my data\n"
        );
    }

    #[test]
    fn supports_crlf_and_bom() {
        let input = "\u{feff}event: greeting\r\ndata: hello\r\n\r\n";

        let got = format_event_stream(input.as_bytes()).unwrap();

        assert_eq!(got, "[greeting]\nhello\n");
    }
}
