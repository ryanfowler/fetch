use std::collections::HashMap;

use md5::{Digest as Md5Digest, Md5};

pub(crate) fn parse_digest_auth_params(input: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut rest = input.trim();
    while !rest.is_empty() {
        let Some((key, after_key)) = rest.split_once('=') else {
            break;
        };
        let key = key.trim().to_ascii_lowercase();
        let after_key = after_key.trim_start();
        let (value, after_value) = if let Some(stripped) = after_key.strip_prefix('"') {
            let mut escaped = false;
            let mut value = String::new();
            let mut end_idx = stripped.len();
            for (idx, ch) in stripped.char_indices() {
                if escaped {
                    value.push(ch);
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    end_idx = idx + 1;
                    break;
                } else {
                    value.push(ch);
                }
            }
            (value, &stripped[end_idx..])
        } else if let Some((value, after)) = after_key.split_once(',') {
            (value.trim().to_string(), after)
        } else {
            (after_key.trim().to_string(), "")
        };
        out.insert(key, value);
        rest = after_value.trim_start();
        if let Some(stripped) = rest.strip_prefix(',') {
            rest = stripped.trim_start();
        }
    }
    out
}

pub(crate) fn md5_hex(input: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(input.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
