use std::io::Write;

use anstyle::{AnsiColor, Color::Ansi, Style};
use tree_sitter::Language;
use tree_sitter_highlight::{HighlightConfiguration, HighlightEvent, Highlighter};

use crate::fetch::TextType;

pub(crate) fn highlight(input: &[u8], text_type: TextType) -> Option<Vec<u8>> {
    let name = text_type.as_str();
    let language = get_language(text_type);
    let highlights = get_highlights(text_type);
    let mut config = HighlightConfiguration::new(language, name, highlights, "", "").ok()?;
    config.configure(&HIGHLIGHT_NAMES);

    let mut highligher = Highlighter::new();
    let highlights = highligher.highlight(&config, input, None, |_| None).ok()?;

    let mut out = Vec::new();
    let mut stack = vec![anstyle::Style::new()];
    for event in highlights {
        match event.ok()? {
            HighlightEvent::Source { start, end } => {
                let style = stack.last().unwrap();
                write!(&mut out, "{style}").unwrap();
                out.write_all(&input[start..end]).unwrap();
                write!(&mut out, "{style:#}").unwrap();
            }
            HighlightEvent::HighlightStart(style) => {
                stack.push(STYLES[style.0]);
            }
            HighlightEvent::HighlightEnd => {
                stack.pop();
            }
        }
    }

    Some(out)
}

extern "C" {
    fn tree_sitter_html() -> tree_sitter::Language;
    fn tree_sitter_json() -> tree_sitter::Language;
    fn tree_sitter_xml() -> tree_sitter::Language;
}

fn get_language(content_type: TextType) -> Language {
    match content_type {
        TextType::Html => unsafe { tree_sitter_html() },
        TextType::Json => unsafe { tree_sitter_json() },
        TextType::JsonLines => unsafe { tree_sitter_json() },
        TextType::Xml => unsafe { tree_sitter_xml() },
    }
}

static HTML_HIGHLIGHTS: &str = include_str!("../highlights/html.scm");
static JSON_HIGHLIGHTS: &str = include_str!("../highlights/json.scm");
static XML_HIGHLIGHTS: &str = include_str!("../highlights/xml.scm");

fn get_highlights(content_type: TextType) -> &'static str {
    match content_type {
        TextType::Html => HTML_HIGHLIGHTS,
        TextType::Json => JSON_HIGHLIGHTS,
        TextType::JsonLines => JSON_HIGHLIGHTS,
        TextType::Xml => XML_HIGHLIGHTS,
    }
}

static HIGHLIGHT_NAMES: [&str; 14] = [
    "boolean",
    "constant.builtin",
    "number",
    "property",
    "string",
    "punctuation.delimiter",
    "punctuation.bracket",
    "conceal",
    "string.escape",
    "tag",
    "tag.attribute",
    "tag.delimiter",
    "markup",
    "spell",
];

static STYLES: [anstyle::Style; 14] = [
    Style::new(),
    Style::new(),
    Style::new(),
    Style::new().bold().fg_color(Some(Ansi(AnsiColor::Blue))),
    Style::new().fg_color(Some(Ansi(AnsiColor::Green))),
    Style::new().bold(),
    Style::new().bold(),
    Style::new(),
    Style::new().fg_color(Some(Ansi(AnsiColor::Green))),
    Style::new().bold().fg_color(Some(Ansi(AnsiColor::Blue))),
    Style::new(),
    Style::new(),
    Style::new().fg_color(Some(Ansi(AnsiColor::Green))),
    Style::new().fg_color(Some(Ansi(AnsiColor::Green))),
];
