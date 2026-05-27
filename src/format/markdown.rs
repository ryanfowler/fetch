use std::fmt;

use crate::core::{Printer, Sequence};
use crate::format::{css, html, json, xml, yaml};

const BOLD: Sequence = Sequence::Bold;
const DIM: Sequence = Sequence::Dim;
const BLUE: Sequence = Sequence::Blue;
const CYAN: Sequence = Sequence::Cyan;
const ITALIC: Sequence = Sequence::Italic;
const UNDERLINE: Sequence = Sequence::Underline;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkdownError(String);

impl fmt::Display for MarkdownError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for MarkdownError {}

#[cfg(test)]
pub(crate) fn format_markdown(buf: &[u8], color: bool) -> Result<Vec<u8>, MarkdownError> {
    let mut out = Printer::new(color);
    format_markdown_to(buf, &mut out)?;
    Ok(out.into_bytes())
}

pub fn format_markdown_to(buf: &[u8], out: &mut Printer) -> Result<(), MarkdownError> {
    let rendered = render_markdown_bytes(buf, out.use_color())?;
    out.push_str(&String::from_utf8_lossy(&rendered));
    Ok(())
}

fn render_markdown_bytes(buf: &[u8], color: bool) -> Result<Vec<u8>, MarkdownError> {
    if buf.is_empty() {
        return Ok(Vec::new());
    }

    let mut out = String::new();
    let mut rest = buf;
    if let (Some(front_matter), after_front_matter) = extract_front_matter(buf) {
        match format_with_printer(color, |out| yaml::format_yaml_to(front_matter, out)) {
            Ok(mut formatted) => {
                trim_trailing_line_ending(&mut formatted);
                out.push_str(&String::from_utf8_lossy(&formatted));
                rest = after_front_matter;
                if !rest.is_empty() {
                    out.push_str("\n\n");
                }
            }
            Err(_) => {
                rest = buf;
            }
        }
    }

    if rest.is_empty() {
        return Ok(out.into_bytes());
    }

    let mut body = String::from_utf8_lossy(rest).replace("\r\n", "\n");
    body = body.replace('\r', "\n");
    while body.ends_with('\n') {
        body.pop();
    }
    if body.trim().is_empty() {
        return Ok(out.into_bytes());
    }

    let renderer = Renderer { color };
    out.push_str(&renderer.render(&body, 0));
    Ok(out.into_bytes())
}

fn extract_front_matter(buf: &[u8]) -> (Option<&[u8]>, &[u8]) {
    if !buf.starts_with(b"---\n") && !buf.starts_with(b"---\r\n") {
        return (None, buf);
    }

    let Some(first_newline) = buf.iter().position(|byte| *byte == b'\n') else {
        return (None, buf);
    };
    let mut i = first_newline + 1;
    while i < buf.len() {
        let rel_line_end = buf[i..].iter().position(|byte| *byte == b'\n');
        let line_end = rel_line_end.map(|end| i + end).unwrap_or(buf.len());
        let mut line = &buf[i..line_end];
        if line.ends_with(b"\r") {
            line = &line[..line.len() - 1];
        }
        if line == b"---" {
            let end = rel_line_end.map(|_| line_end + 1).unwrap_or(line_end);
            return (Some(&buf[..end]), &buf[end..]);
        }
        let Some(rel_line_end) = rel_line_end else {
            break;
        };
        i += rel_line_end + 1;
    }

    (None, buf)
}

fn trim_trailing_line_ending(buf: &mut Vec<u8>) {
    if buf.ends_with(b"\r\n") {
        buf.truncate(buf.len() - 2);
    } else if buf.ends_with(b"\n") || buf.ends_with(b"\r") {
        buf.truncate(buf.len() - 1);
    }
}

struct Renderer {
    color: bool,
}

impl Renderer {
    fn render(&self, input: &str, bq_depth: usize) -> String {
        let lines: Vec<&str> = input.split('\n').collect();
        let mut out = String::new();
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i];
            if line.trim().is_empty() {
                if has_next_nonblank(&lines, i + 1) && !out.is_empty() {
                    self.write_prefix(&mut out, bq_depth);
                    out.push('\n');
                }
                i += 1;
                continue;
            }

            if strip_blockquote_marker(line).is_some() {
                let start = i;
                while i < lines.len() && strip_blockquote_marker(lines[i]).is_some() {
                    i += 1;
                }
                let inner = lines[start..i]
                    .iter()
                    .map(|line| strip_blockquote_marker(line).unwrap_or(*line))
                    .collect::<Vec<_>>()
                    .join("\n");
                out.push_str(&self.render(&inner, bq_depth + 1));
                self.write_blank_between_immediate_blocks(&mut out, &lines, i, bq_depth);
                continue;
            }

            if let Some(fence) = parse_fence_open(line) {
                i = self.render_fenced_code(&mut out, &lines, i, fence, bq_depth);
                self.write_blank_between_immediate_blocks(&mut out, &lines, i, bq_depth);
                continue;
            }

            if is_indented_code(line) {
                i = self.render_indented_code(&mut out, &lines, i, bq_depth);
                self.write_blank_between_immediate_blocks(&mut out, &lines, i, bq_depth);
                continue;
            }

            if i + 1 < lines.len() && is_table_separator(lines[i + 1]) && line.contains('|') {
                i = self.render_table(&mut out, &lines, i, bq_depth);
                self.write_blank_between_immediate_blocks(&mut out, &lines, i, bq_depth);
                continue;
            }

            if let Some(level) = parse_setext_heading(lines.get(i + 1).copied()) {
                self.render_heading(&mut out, level, line.trim(), bq_depth);
                i += 2;
                self.write_blank_between_immediate_blocks(&mut out, &lines, i, bq_depth);
                continue;
            }

            if let Some((level, content)) = parse_atx_heading(line) {
                self.render_heading(&mut out, level, content, bq_depth);
                i += 1;
                self.write_blank_between_immediate_blocks(&mut out, &lines, i, bq_depth);
                continue;
            }

            if is_thematic_break(line) {
                self.write_prefix(&mut out, bq_depth);
                self.write_styled(&mut out, "---", &[DIM]);
                out.push('\n');
                i += 1;
                self.write_blank_between_immediate_blocks(&mut out, &lines, i, bq_depth);
                continue;
            }

            if parse_list_item(line).is_some() {
                i = self.render_list(&mut out, &lines, i, bq_depth);
                self.write_blank_between_immediate_blocks(&mut out, &lines, i, bq_depth);
                continue;
            }

            if looks_like_html_block(line) {
                i = self.render_html_block(&mut out, &lines, i, bq_depth);
                self.write_blank_between_immediate_blocks(&mut out, &lines, i, bq_depth);
                continue;
            }

            i = self.render_paragraph(&mut out, &lines, i, bq_depth);
            self.write_blank_between_immediate_blocks(&mut out, &lines, i, bq_depth);
        }

        out
    }

    fn render_heading(&self, out: &mut String, level: usize, content: &str, bq_depth: usize) {
        self.write_prefix(out, bq_depth);
        let hashes = "#".repeat(level);
        self.write_styled(out, &hashes, &[BOLD, BLUE]);
        if !content.is_empty() {
            out.push(' ');
            let text = render_inline(content, self.color);
            self.write_styled(out, &text, &[BOLD]);
        }
        out.push('\n');
    }

    fn render_fenced_code(
        &self,
        out: &mut String,
        lines: &[&str],
        start: usize,
        fence: Fence,
        bq_depth: usize,
    ) -> usize {
        self.write_prefix(out, bq_depth);
        self.write_styled(out, "```", &[DIM]);
        if !fence.lang.is_empty() {
            self.write_styled(out, fence.lang, &[DIM]);
        }
        out.push('\n');

        let mut body = Vec::new();
        let mut i = start + 1;
        while i < lines.len() {
            if parse_fence_close(lines[i], fence.marker, fence.len) {
                i += 1;
                break;
            }
            body.push(lines[i]);
            i += 1;
        }

        let mut delegated = false;
        if bq_depth == 0 && !fence.lang.is_empty() && !body.is_empty() {
            let content = body.join("\n");
            if let Some(formatted) = format_code_block(fence.lang, content.as_bytes(), self.color) {
                out.push_str(&String::from_utf8_lossy(&formatted));
                if !out.ends_with('\n') {
                    out.push('\n');
                }
                delegated = true;
            }
        }

        if !delegated {
            for line in body {
                self.write_prefix(out, bq_depth);
                self.write_styled(out, line, &[CYAN]);
                out.push('\n');
            }
        }

        self.write_prefix(out, bq_depth);
        self.write_styled(out, "```", &[DIM]);
        out.push('\n');
        i
    }

    fn render_indented_code(
        &self,
        out: &mut String,
        lines: &[&str],
        start: usize,
        bq_depth: usize,
    ) -> usize {
        let mut i = start;
        while i < lines.len() {
            if lines[i].trim().is_empty() {
                self.write_prefix(out, bq_depth);
                out.push('\n');
                i += 1;
                continue;
            }
            if !is_indented_code(lines[i]) {
                break;
            }
            self.write_prefix(out, bq_depth);
            self.write_styled(out, strip_code_indent(lines[i]), &[CYAN]);
            out.push('\n');
            i += 1;
        }
        i
    }

    fn render_list(
        &self,
        out: &mut String,
        lines: &[&str],
        start: usize,
        bq_depth: usize,
    ) -> usize {
        let mut i = start;
        while i < lines.len() {
            let Some(item) = parse_list_item(lines[i]) else {
                break;
            };
            self.write_prefix(out, bq_depth);
            out.push_str(&"  ".repeat(normalized_list_depth(item.indent)));
            self.write_styled(out, &item.marker, &[BLUE]);
            out.push(' ');
            out.push_str(&render_inline(item.content.trim(), self.color));
            out.push('\n');
            i += 1;
        }
        i
    }

    fn render_html_block(
        &self,
        out: &mut String,
        lines: &[&str],
        start: usize,
        bq_depth: usize,
    ) -> usize {
        let mut i = start;
        while i < lines.len() && !lines[i].trim().is_empty() {
            self.write_prefix(out, bq_depth);
            self.write_styled(out, lines[i].trim_end(), &[DIM]);
            out.push('\n');
            i += 1;
        }
        i
    }

    fn render_table(
        &self,
        out: &mut String,
        lines: &[&str],
        start: usize,
        bq_depth: usize,
    ) -> usize {
        let header = parse_table_row(lines[start]);
        let alignments = parse_table_alignments(lines[start + 1]);
        let mut rows = vec![header];
        let mut i = start + 2;
        while i < lines.len() && lines[i].contains('|') && !lines[i].trim().is_empty() {
            rows.push(parse_table_row(lines[i]));
            i += 1;
        }

        let mut cols = 0;
        for row in &rows {
            cols = cols.max(row.len());
        }
        let mut widths = vec![3usize; cols];
        for row in &rows {
            for (index, cell) in row.iter().enumerate() {
                widths[index] = widths[index].max(cell.len());
            }
        }

        self.write_prefix(out, bq_depth);
        self.render_table_row(out, &rows[0], &widths, true);
        out.push('\n');

        self.write_prefix(out, bq_depth);
        self.write_styled(out, "|", &[DIM]);
        for (index, width) in widths.iter().enumerate() {
            let alignment = alignments.get(index).copied().unwrap_or(Alignment::None);
            let separator = match alignment {
                Alignment::Left => format!(":{}", "-".repeat(width.saturating_sub(1))),
                Alignment::Right => format!("{}:", "-".repeat(width.saturating_sub(1))),
                Alignment::Center => {
                    format!(":{}:", "-".repeat(width.saturating_sub(2)))
                }
                Alignment::None => "-".repeat(*width),
            };
            self.write_styled(out, &separator, &[DIM]);
            self.write_styled(out, "|", &[DIM]);
        }
        out.push('\n');

        for row in rows.iter().skip(1) {
            self.write_prefix(out, bq_depth);
            self.render_table_row(out, row, &widths, false);
            out.push('\n');
        }

        i
    }

    fn render_table_row(
        &self,
        out: &mut String,
        cells: &[String],
        widths: &[usize],
        is_header: bool,
    ) {
        self.write_styled(out, "|", &[DIM]);
        for (index, width) in widths.iter().enumerate() {
            let cell = cells.get(index).map(String::as_str).unwrap_or("");
            out.push(' ');
            if is_header {
                self.write_styled(out, cell, &[BOLD]);
            } else {
                out.push_str(cell);
            }
            out.push_str(&" ".repeat(width.saturating_sub(cell.len())));
            out.push(' ');
            self.write_styled(out, "|", &[DIM]);
        }
    }

    fn render_paragraph(
        &self,
        out: &mut String,
        lines: &[&str],
        start: usize,
        bq_depth: usize,
    ) -> usize {
        let mut i = start;
        let mut paragraph_lines: Vec<&str> = Vec::new();
        while i < lines.len() {
            if lines[i].trim().is_empty() {
                break;
            }
            if i > start
                && is_block_start(lines, i)
                && !has_unclosed_code_span(&paragraph_lines.join("\n"))
            {
                break;
            }
            paragraph_lines.push(lines[i]);
            i += 1;
        }

        let rendered = render_inline(&paragraph_lines.join("\n"), self.color);
        for line in rendered.split('\n') {
            self.write_prefix(out, bq_depth);
            out.push_str(line);
            out.push('\n');
        }
        i
    }

    fn write_prefix(&self, out: &mut String, bq_depth: usize) {
        for _ in 0..bq_depth {
            self.write_styled(out, ">", &[DIM]);
            out.push(' ');
        }
    }

    fn write_blank_between_immediate_blocks(
        &self,
        out: &mut String,
        lines: &[&str],
        next: usize,
        bq_depth: usize,
    ) {
        if next < lines.len() && !lines[next].trim().is_empty() {
            self.write_prefix(out, bq_depth);
            out.push('\n');
        }
    }

    fn write_styled(&self, out: &mut String, text: &str, styles: &[Sequence]) {
        write_styled(out, text, styles, self.color);
    }
}

#[derive(Debug, Clone, Copy)]
struct Fence<'a> {
    marker: char,
    len: usize,
    lang: &'a str,
}

#[derive(Debug, Clone)]
struct ListItem<'a> {
    indent: usize,
    marker: String,
    content: &'a str,
}

#[derive(Debug, Clone, Copy)]
enum Alignment {
    None,
    Left,
    Right,
    Center,
}

fn render_inline(input: &str, color: bool) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < input.len() {
        let rest = &input[i..];
        if rest.starts_with("![")
            && let Some((alt, url, end)) = parse_link_like(input, i + 2)
        {
            write_styled(&mut out, "![", &[DIM], color);
            write_styled(&mut out, &render_inline(alt, color), &[ITALIC], color);
            write_styled(&mut out, "](", &[DIM], color);
            write_styled(&mut out, url, &[CYAN], color);
            write_styled(&mut out, ")", &[DIM], color);
            i = end;
            continue;
        }
        if rest.starts_with('[')
            && let Some((text, url, end)) = parse_link_like(input, i + 1)
        {
            write_styled(&mut out, "[", &[DIM], color);
            write_styled(&mut out, &render_inline(text, color), &[UNDERLINE], color);
            write_styled(&mut out, "](", &[DIM], color);
            write_styled(&mut out, url, &[CYAN], color);
            write_styled(&mut out, ")", &[DIM], color);
            i = end;
            continue;
        }
        if rest.starts_with("~~")
            && let Some(end) = find_nonempty_after(input, i + 2, "~~")
        {
            write_styled(
                &mut out,
                &render_inline(&input[i + 2..end], color),
                &[DIM],
                color,
            );
            i = end + 2;
            continue;
        }
        if rest.starts_with("***")
            && let Some(end) = find_nonempty_after(input, i + 3, "***")
        {
            write_styled(
                &mut out,
                &render_inline(&input[i + 3..end], color),
                &[BOLD, ITALIC],
                color,
            );
            i = end + 3;
            continue;
        }
        if rest.starts_with("**")
            && let Some(end) = find_nonempty_delimiter(input, i + 2, "**", '*')
        {
            write_styled(
                &mut out,
                &render_inline(&input[i + 2..end], color),
                &[BOLD],
                color,
            );
            i = end + 2;
            continue;
        }
        if rest.starts_with("__")
            && let Some(end) = find_nonempty_delimiter(input, i + 2, "__", '_')
        {
            write_styled(
                &mut out,
                &render_inline(&input[i + 2..end], color),
                &[BOLD],
                color,
            );
            i = end + 2;
            continue;
        }
        if rest.starts_with('*')
            && let Some(end) = find_nonempty_after(input, i + 1, "*")
        {
            write_styled(
                &mut out,
                &render_inline(&input[i + 1..end], color),
                &[ITALIC],
                color,
            );
            i = end + 1;
            continue;
        }
        if rest.starts_with('_')
            && let Some(end) = find_nonempty_after(input, i + 1, "_")
        {
            write_styled(
                &mut out,
                &render_inline(&input[i + 1..end], color),
                &[ITALIC],
                color,
            );
            i = end + 1;
            continue;
        }
        if rest.starts_with('`') {
            let tick_count = rest.bytes().take_while(|byte| *byte == b'`').count();
            let marker = "`".repeat(tick_count);
            if let Some(end) = find_after(input, i + tick_count, &marker) {
                let content = normalize_code_span(&input[i + tick_count..end]);
                write_styled(&mut out, &content, &[CYAN], color);
                i = end + tick_count;
                continue;
            }
        }

        let ch = rest.chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn write_styled(out: &mut String, text: &str, styles: &[Sequence], color: bool) {
    let mut printer = Printer::new(color);
    printer.write_styled(text, styles);
    out.push_str(
        &printer
            .into_string()
            .expect("markdown styled output is valid UTF-8"),
    );
}

fn parse_link_like(input: &str, text_start: usize) -> Option<(&str, &str, usize)> {
    let close = find_after(input, text_start, "](")?;
    let url_start = close + 2;
    let url_end = find_after(input, url_start, ")")?;
    Some((
        &input[text_start..close],
        &input[url_start..url_end],
        url_end + 1,
    ))
}

fn normalize_code_span(input: &str) -> String {
    input
        .trim_matches(|ch: char| ch.is_whitespace())
        .to_string()
}

fn has_unclosed_code_span(input: &str) -> bool {
    let mut opener = None;
    let mut i = 0;
    while i < input.len() {
        let rest = &input[i..];
        if !rest.starts_with('`') {
            let ch = rest.chars().next().unwrap();
            i += ch.len_utf8();
            continue;
        }
        let len = rest.bytes().take_while(|byte| *byte == b'`').count();
        if opener == Some(len) {
            opener = None;
        } else if opener.is_none() {
            opener = Some(len);
        }
        i += len;
    }
    opener.is_some()
}

fn find_after(input: &str, start: usize, needle: &str) -> Option<usize> {
    input.get(start..)?.find(needle).map(|index| start + index)
}

fn find_nonempty_after(input: &str, start: usize, needle: &str) -> Option<usize> {
    let end = find_after(input, start, needle)?;
    (end > start).then_some(end)
}

fn find_nonempty_delimiter(input: &str, start: usize, needle: &str, marker: char) -> Option<usize> {
    let mut search = start;
    while let Some(end) = find_after(input, search, needle) {
        if end == start {
            search = end + needle.len();
            continue;
        }
        let after = end + needle.len();
        if !input
            .get(after..)
            .is_some_and(|rest| rest.starts_with(marker))
        {
            return Some(end);
        }
        search = end + 1;
    }
    None
}

fn parse_atx_heading(line: &str) -> Option<(usize, &str)> {
    let trimmed = line.trim_start();
    let level = trimmed.bytes().take_while(|byte| *byte == b'#').count();
    if !(1..=6).contains(&level) {
        return None;
    }
    let rest = &trimmed[level..];
    if !rest.is_empty() && !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let content = strip_closing_hashes(rest.trim());
    Some((level, content))
}

fn strip_closing_hashes(content: &str) -> &str {
    let trimmed = content.trim_end();
    let without_hashes = trimmed.trim_end_matches('#').trim_end();
    if without_hashes.len() < trimmed.len()
        && trimmed[..without_hashes.len()]
            .chars()
            .last()
            .is_some_and(char::is_whitespace)
    {
        without_hashes
    } else {
        trimmed
    }
}

fn parse_setext_heading(next_line: Option<&str>) -> Option<usize> {
    let trimmed = next_line?.trim();
    if trimmed.len() < 2 {
        return None;
    }
    if trimmed.bytes().all(|byte| byte == b'=') {
        return Some(1);
    }
    if trimmed.bytes().all(|byte| byte == b'-') {
        return Some(2);
    }
    None
}

fn is_thematic_break(line: &str) -> bool {
    let trimmed = line.trim();
    let mut marker = None;
    let mut count = 0;
    for ch in trimmed.chars() {
        if ch.is_whitespace() {
            continue;
        }
        match ch {
            '-' | '*' | '_' => {
                if let Some(marker) = marker {
                    if marker != ch {
                        return false;
                    }
                } else {
                    marker = Some(ch);
                }
                count += 1;
            }
            _ => return false,
        }
    }
    count >= 3
}

fn strip_blockquote_marker(line: &str) -> Option<&str> {
    let trimmed = line.trim_start_matches(' ');
    if line.len() - trimmed.len() > 3 || !trimmed.starts_with('>') {
        return None;
    }
    let mut rest = &trimmed[1..];
    if rest.starts_with(' ') {
        rest = &rest[1..];
    }
    Some(rest)
}

fn parse_fence_open(line: &str) -> Option<Fence<'_>> {
    let trimmed = line.trim_start();
    let marker = trimmed.chars().next()?;
    if marker != '`' && marker != '~' {
        return None;
    }
    let len = trimmed.chars().take_while(|ch| *ch == marker).count();
    if len < 3 {
        return None;
    }
    let info = trimmed[len..].trim();
    let lang = info.split_whitespace().next().unwrap_or("");
    Some(Fence { marker, len, lang })
}

fn parse_fence_close(line: &str, marker: char, min_len: usize) -> bool {
    let trimmed = line.trim();
    let len = trimmed.chars().take_while(|ch| *ch == marker).count();
    len >= min_len && trimmed[len..].trim().is_empty()
}

fn is_indented_code(line: &str) -> bool {
    line.starts_with("    ")
}

fn strip_code_indent(line: &str) -> &str {
    line.strip_prefix("    ").unwrap_or(line)
}

fn parse_list_item(line: &str) -> Option<ListItem<'_>> {
    let indent = line.bytes().take_while(|byte| *byte == b' ').count();
    let rest = &line[indent..];
    let mut chars = rest.char_indices();
    let (_, first) = chars.next()?;
    if matches!(first, '-' | '*' | '+') {
        let (next_index, next) = chars.next()?;
        if !next.is_whitespace() {
            return None;
        }
        return Some(ListItem {
            indent,
            marker: first.to_string(),
            content: rest[next_index + next.len_utf8()..].trim_start(),
        });
    }
    if first.is_ascii_digit() {
        let marker_len = rest
            .bytes()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        let marker_end = rest.as_bytes().get(marker_len).copied()?;
        if marker_end != b'.' && marker_end != b')' {
            return None;
        }
        let after_marker = rest.get(marker_len + 1..)?;
        if !after_marker.starts_with(char::is_whitespace) {
            return None;
        }
        return Some(ListItem {
            indent,
            marker: format!("{}.", &rest[..marker_len]),
            content: after_marker.trim_start(),
        });
    }
    None
}

fn normalized_list_depth(indent: usize) -> usize {
    if indent == 0 {
        0
    } else {
        indent.div_ceil(2).max(1)
    }
}

fn looks_like_html_block(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with("<!--") || trimmed.starts_with("</") || trimmed.starts_with("<!") {
        return true;
    }
    if !trimmed.starts_with('<')
        || trimmed.starts_with("<http://")
        || trimmed.starts_with("<https://")
    {
        return false;
    }
    let Some(end) = trimmed.find('>') else {
        return false;
    };
    let tag = &trimmed[1..end];
    !tag.is_empty()
        && !tag.contains("://")
        && tag
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphabetic())
}

fn is_table_separator(line: &str) -> bool {
    let cells = parse_table_row(line);
    !cells.is_empty()
        && cells.iter().all(|cell| {
            let trimmed = cell.trim();
            let inner = trimmed.trim_matches(':');
            inner.len() >= 3 && inner.bytes().all(|byte| byte == b'-')
        })
}

fn parse_table_row(line: &str) -> Vec<String> {
    let trimmed = line.trim().trim_matches('|');
    trimmed
        .split('|')
        .map(|cell| render_inline(cell.trim(), false))
        .collect()
}

fn parse_table_alignments(line: &str) -> Vec<Alignment> {
    parse_table_row(line)
        .into_iter()
        .map(|cell| {
            let trimmed = cell.trim();
            match (trimmed.starts_with(':'), trimmed.ends_with(':')) {
                (true, true) => Alignment::Center,
                (true, false) => Alignment::Left,
                (false, true) => Alignment::Right,
                (false, false) => Alignment::None,
            }
        })
        .collect()
}

fn is_block_start(lines: &[&str], index: usize) -> bool {
    let line = lines[index];
    strip_blockquote_marker(line).is_some()
        || parse_fence_open(line).is_some()
        || is_indented_code(line)
        || (index + 1 < lines.len() && is_table_separator(lines[index + 1]) && line.contains('|'))
        || parse_setext_heading(lines.get(index + 1).copied()).is_some()
        || parse_atx_heading(line).is_some()
        || is_thematic_break(line)
        || parse_list_item(line).is_some()
        || looks_like_html_block(line)
}

fn has_next_nonblank(lines: &[&str], start: usize) -> bool {
    lines
        .get(start..)
        .is_some_and(|lines| lines.iter().any(|line| !line.trim().is_empty()))
}

fn format_code_block(lang: &str, content: &[u8], color: bool) -> Option<Vec<u8>> {
    match lang.to_ascii_lowercase().as_str() {
        "json" => format_with_printer(color, |out| json::format_json_to(content, out)).ok(),
        "yaml" | "yml" => format_with_printer(color, |out| yaml::format_yaml_to(content, out)).ok(),
        "xml" => format_with_printer(color, |out| xml::format_xml_to(content, out)).ok(),
        "html" => format_with_printer(color, |out| html::format_html_to(content, out)).ok(),
        "css" => format_with_printer(color, |out| css::format_css_to(content, out)).ok(),
        _ => None,
    }
}

fn format_with_printer<E>(
    color: bool,
    write: impl FnOnce(&mut Printer) -> Result<(), E>,
) -> Result<Vec<u8>, E> {
    let mut out = Printer::new(color);
    write(&mut out)?;
    Ok(out.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn format(input: &str) -> String {
        String::from_utf8(format_markdown(input.as_bytes(), false).unwrap()).unwrap()
    }

    fn format_color(input: &str) -> String {
        String::from_utf8(format_markdown(input.as_bytes(), true).unwrap()).unwrap()
    }

    #[test]
    fn test_format_markdown_heading_output() {
        let cases = [
            ("h1", "# Hello", "# Hello\n"),
            ("h2", "## World", "## World\n"),
            ("h6", "###### Deep", "###### Deep\n"),
            ("heading no text", "#", "#\n"),
            ("not a heading", "#nospace", "#nospace\n"),
            ("setext h1", "Title\n=====", "# Title\n"),
            ("setext h2", "Title\n-----", "## Title\n"),
        ];

        for (name, input, want) in cases {
            assert_eq!(format(input), want, "{name}");
        }
    }

    #[test]
    fn test_format_markdown_blockquote_output() {
        let cases = [
            ("simple", "> hello", "> hello\n"),
            ("nested", "> > nested", "> > nested\n"),
            (
                "multi-line blockquote",
                "> line1\n> line2",
                "> line1\n> line2\n",
            ),
            ("heading in blockquote", "> # Heading", "> # Heading\n"),
            (
                "heading then paragraph in blockquote",
                "> # Title\n>\n> text",
                "> # Title\n> \n> text\n",
            ),
            ("thematic break in blockquote", "> ---", "> ---\n"),
            (
                "fenced code in blockquote",
                "> ```\n> code\n> ```",
                "> ```\n> code\n> ```\n",
            ),
            ("list in blockquote", "> - a\n> - b", "> - a\n> - b\n"),
            ("nested heading in blockquote", "> > # Deep", "> > # Deep\n"),
            (
                "blockquote with multiple block types",
                "> # Title\n>\n> text\n>\n> ---",
                "> # Title\n> \n> text\n> \n> ---\n",
            ),
        ];

        for (name, input, want) in cases {
            assert_eq!(format(input), want, "{name}");
        }
    }

    #[test]
    fn test_format_markdown_list_output() {
        let cases = [
            ("dash list", "- item1\n- item2", "- item1\n- item2\n"),
            ("star list", "* item1\n* item2", "* item1\n* item2\n"),
            ("plus list", "+ item", "+ item\n"),
            (
                "nested list",
                "- parent\n  - child",
                "- parent\n  - child\n",
            ),
            (
                "ordered list",
                "1. first\n2. second",
                "1. first\n2. second\n",
            ),
            ("multi-digit ordered", "10. item", "10. item\n"),
        ];

        for (name, input, want) in cases {
            assert_eq!(format(input), want, "{name}");
        }
    }

    #[test]
    fn test_format_markdown_horizontal_rule_output() {
        for input in ["---", "***", "___", "-----", "- - -", "* * *", "_ _ _"] {
            assert_eq!(format(input), "---\n", "{input}");
        }
        assert_eq!(format("--"), "--\n");
    }

    #[test]
    fn test_format_markdown_code_block_output() {
        let cases = [
            ("simple code block", "```\nhello\n```", "```\nhello\n```\n"),
            (
                "tilde fence normalizes to backticks",
                "~~~\nhello\n~~~",
                "```\nhello\n```\n",
            ),
            (
                "unclosed fence still closes",
                "```\nhello",
                "```\nhello\n```\n",
            ),
            ("empty code block", "```\n```", "```\n```\n"),
            (
                "code with language",
                "```go\nfmt.Println()\n```",
                "```go\nfmt.Println()\n```\n",
            ),
            (
                "fenced code preserves indentation",
                "```js\nconst r = await fetch(\n  `https://example.com`,\n  {\n    headers: {\n      Accept: \"text/markdown\",\n    },\n  },\n);\n```",
                "```js\nconst r = await fetch(\n  `https://example.com`,\n  {\n    headers: {\n      Accept: \"text/markdown\",\n    },\n  },\n);\n```\n",
            ),
            (
                "indented code block",
                "text\n\n    line1\n      line2\n    line3",
                "text\n\nline1\n  line2\nline3\n",
            ),
        ];

        for (name, input, want) in cases {
            assert_eq!(format(input), want, "{name}");
        }
    }

    #[test]
    fn test_format_markdown_inline_output() {
        let cases = [
            ("bold", "**bold**", "bold\n"),
            ("italic", "*italic*", "italic\n"),
            ("code span", "`code`", "code\n"),
            ("link", "[text](url)", "[text](url)\n"),
            ("image", "![alt](url)", "![alt](url)\n"),
            ("markers in code span", "`**not bold**`", "**not bold**\n"),
            ("bold italic", "***text***", "text\n"),
            ("unclosed bold passthrough", "**text", "**text\n"),
            (
                "inline mixed",
                "Hello **world** and *foo*",
                "Hello world and foo\n",
            ),
            ("double backtick code span", "`` code ``", "code\n"),
            (
                "multi-line code span preserves indentation",
                "``\nconst r = await fetch(\n  `https://example.com`,\n  {\n    headers: {\n      Accept: \"text/markdown\",\n    },\n  },\n);\n``",
                "const r = await fetch(\n  `https://example.com`,\n  {\n    headers: {\n      Accept: \"text/markdown\",\n    },\n  },\n);\n",
            ),
            (
                "utf8 plain text",
                "café résumé naïve",
                "café résumé naïve\n",
            ),
            ("utf8 with bold", "**café**", "café\n"),
            ("utf8 cjk characters", "Hello 世界", "Hello 世界\n"),
            ("utf8 emoji", "Hello 👋🌍", "Hello 👋🌍\n"),
            ("strikethrough", "~~deleted~~", "deleted\n"),
            ("autolink", "<http://example.com>", "<http://example.com>\n"),
            (
                "nested emphasis",
                "**bold and *italic***",
                "bold and italic\n",
            ),
        ];

        for (name, input, want) in cases {
            assert_eq!(format(input), want, "{name}");
        }
    }

    #[test]
    fn test_format_markdown_color() {
        let cases = [
            ("heading uses bold blue", "# Title", vec![BOLD, BLUE]),
            ("bold text uses bold", "**bold**", vec![BOLD]),
            ("italic text uses italic", "*italic*", vec![ITALIC]),
            ("code span uses cyan", "`code`", vec![CYAN]),
            (
                "link url uses cyan",
                "[text](http://example.com)",
                vec![CYAN],
            ),
            (
                "link text uses underline and brackets use dim",
                "[text](url)",
                vec![UNDERLINE, DIM],
            ),
            ("horizontal rule uses dim", "---", vec![DIM]),
            ("blockquote marker uses dim", "> text", vec![DIM]),
            ("list marker uses blue", "- item", vec![BLUE]),
            ("ordered list marker uses blue", "1. item", vec![BLUE]),
            ("strikethrough uses dim", "~~deleted~~", vec![DIM]),
        ];

        for (name, input, seqs) in cases {
            let output = format_color(input);
            for seq in seqs {
                assert!(
                    output.contains(&seq.ansi()),
                    "{name}: output should contain {seq:?}, got {output:?}"
                );
            }
        }
    }

    #[test]
    fn test_format_markdown_code_block_delegation() {
        let output = format("```json\n{\"a\":1}\n```");
        assert!(output.contains("  "));
        assert!(output.contains("\"a\""));
    }

    #[test]
    fn test_format_markdown_windows_line_endings() {
        let output = format("# Hello\r\n\r\nworld\r\n");
        assert!(!output.contains('\r'));
        assert!(output.contains("# Hello"));
    }

    #[test]
    fn test_format_markdown_mixed_document() {
        let input = "# Title\n\nSome **bold** and *italic* text.\n\n- item 1\n- item 2\n\n1. ordered\n2. list\n\n> a blockquote\n\n```\ncode block\n```\n\n---\n";
        let output = format(input);
        for want in [
            "# Title",
            "bold",
            "italic",
            "- item 1",
            "1. ordered",
            ">",
            "code block",
            "---",
        ] {
            assert!(output.contains(want), "missing {want:?} in {output:?}");
        }
    }

    #[test]
    fn test_format_markdown_empty_input() {
        assert_eq!(format_markdown(b"", false).unwrap(), b"");
    }

    #[test]
    fn test_format_markdown_images_links_tables_and_quotes() {
        let image = format("See ![logo](http://example.com/logo.png) here");
        assert!(image.contains("logo"));
        assert!(image.contains("http://example.com/logo.png"));

        let link = format("[click\nhere](http://example.com)");
        assert!(link.contains("http://example.com"));

        let quote = format("> > deeply nested");
        assert!(quote.contains(">"));
        assert!(quote.contains("deeply nested"));

        let table = format("| Name | Age |\n|------|-----|\n| Alice | 30 |\n| Bob | 25 |\n");
        assert!(table.contains("Alice"));
        assert!(table.contains("Bob"));
        assert!(table.contains('|'));
    }

    #[test]
    fn test_format_markdown_block_spacing() {
        let cases = [
            (
                "list then paragraph",
                "- a\n- b\n\nparagraph\n",
                "- a\n- b\n\nparagraph\n",
            ),
            (
                "thematic break then paragraph",
                "---\n\nparagraph\n",
                "---\n\nparagraph\n",
            ),
            (
                "html block then paragraph",
                "<div>hi</div>\n\nparagraph\n",
                "<div>hi</div>\n\nparagraph\n",
            ),
            (
                "table then paragraph",
                "| A |\n|---|\n| 1 |\n\nparagraph\n",
                "| A   |\n|---|\n| 1   |\n\nparagraph\n",
            ),
            (
                "blockquote then paragraph",
                "> quote\n\nparagraph\n",
                "> quote\n\nparagraph\n",
            ),
            (
                "heading then paragraph",
                "# Title\n\nparagraph\n",
                "# Title\n\nparagraph\n",
            ),
            (
                "fenced code then paragraph",
                "```\ncode\n```\n\nparagraph\n",
                "```\ncode\n```\n\nparagraph\n",
            ),
            (
                "invalid json fence preserves prior output",
                "# Title\n\n```json\nnot json\n```\n\ntail\n",
                "# Title\n\n```json\nnot json\n```\n\ntail\n",
            ),
        ];

        for (name, input, want) in cases {
            assert_eq!(format(input), want, "{name}");
        }
    }

    #[test]
    fn test_extract_front_matter() {
        let cases = [
            (
                "simple",
                "---\ntitle: Hello\n---\nbody\n",
                Some("---\ntitle: Hello\n---\n"),
                "body\n",
            ),
            ("no front matter", "# Heading\n", None, "# Heading\n"),
            ("standalone dash rule", "---\n", None, "---\n"),
            (
                "unclosed",
                "---\ntitle: Hello\nbody\n",
                None,
                "---\ntitle: Hello\nbody\n",
            ),
            ("empty front matter", "---\n---\n", Some("---\n---\n"), ""),
            (
                "front matter only",
                "---\nkey: val\n---\n",
                Some("---\nkey: val\n---\n"),
                "",
            ),
            (
                "crlf",
                "---\r\ntitle: Hi\r\n---\r\nbody\r\n",
                Some("---\r\ntitle: Hi\r\n---\r\n"),
                "body\r\n",
            ),
            (
                "leading space not front matter",
                " ---\ntitle: x\n---\n",
                None,
                " ---\ntitle: x\n---\n",
            ),
            (
                "complex yaml",
                "---\ntags:\n  - go\n  - cli\ndate: 2024-01-01\n---\n# Post\n",
                Some("---\ntags:\n  - go\n  - cli\ndate: 2024-01-01\n---\n"),
                "# Post\n",
            ),
            (
                "closing without newline",
                "---\nkey: val\n---",
                Some("---\nkey: val\n---"),
                "",
            ),
        ];

        for (name, input, want_fm, want_rest) in cases {
            let (fm, rest) = extract_front_matter(input.as_bytes());
            assert_eq!(
                fm.map(|bytes| String::from_utf8_lossy(bytes).into_owned()),
                want_fm.map(str::to_string),
                "{name}"
            );
            assert_eq!(String::from_utf8_lossy(rest), want_rest, "{name}");
        }
    }

    #[test]
    fn test_format_markdown_front_matter() {
        let cases = [
            (
                "front matter with body",
                "---\ntitle: Hello\n---\n# Heading\n",
                "---\ntitle: Hello\n---\n\n# Heading\n",
            ),
            (
                "front matter only",
                "---\nkey: value\n---\n",
                "---\nkey: value\n---",
            ),
            (
                "empty front matter",
                "---\n---\nbody\n",
                "---\n---\n\nbody\n",
            ),
            ("no front matter passthrough", "# Heading\n", "# Heading\n"),
            (
                "unclosed treated as markdown",
                "---\ntitle: Hello\n",
                "---\n\ntitle: Hello\n",
            ),
        ];

        for (name, input, want) in cases {
            assert_eq!(format(input), want, "{name}");
        }
    }

    #[test]
    fn test_format_markdown_front_matter_color() {
        let cases = [
            (
                "dim delimiters and blue keys",
                "---\ntitle: Hello\n---\n",
                vec![DIM, BLUE],
            ),
            (
                "front matter with heading body",
                "---\nkey: val\n---\n# Title\n",
                vec![DIM, BLUE, BOLD],
            ),
        ];

        for (name, input, seqs) in cases {
            let output = format_color(input);
            for seq in seqs {
                assert!(
                    output.contains(&seq.ansi()),
                    "{name}: output should contain {seq:?}, got {output:?}"
                );
            }
        }
    }
}
