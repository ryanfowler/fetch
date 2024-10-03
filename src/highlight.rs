use std::io::Write;

use tree_sitter::Language;
use tree_sitter_highlight::{HighlightConfiguration, HighlightEvent, Highlighter};

use crate::{fetch::TextType, theme::Theme};

pub(crate) fn highlight(input: &[u8], text_type: TextType) -> Option<Vec<u8>> {
    let theme = Theme::default();

    let name = text_type.as_str();
    let language = get_language(text_type);
    let highlights = get_highlights(text_type);
    let mut config = HighlightConfiguration::new(language, name, highlights, "", "").ok()?;
    config.configure(theme.names());

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
                stack.push(theme.get_style(style.0));
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
    fn tree_sitter_toml() -> tree_sitter::Language;
    fn tree_sitter_xml() -> tree_sitter::Language;
}

fn get_language(content_type: TextType) -> Language {
    match content_type {
        TextType::Html => unsafe { tree_sitter_html() },
        TextType::Json => unsafe { tree_sitter_json() },
        TextType::JsonLines => unsafe { tree_sitter_json() },
        TextType::Toml => unsafe { tree_sitter_toml() },
        TextType::Xml => unsafe { tree_sitter_xml() },
    }
}

static HTML_HIGHLIGHTS: &str = include_str!("../highlights/html.scm");
static JSON_HIGHLIGHTS: &str = include_str!("../highlights/json.scm");
static TOML_HIGHLIGHTS: &str = include_str!("../highlights/toml.scm");
static XML_HIGHLIGHTS: &str = include_str!("../highlights/xml.scm");

fn get_highlights(content_type: TextType) -> &'static str {
    match content_type {
        TextType::Html => HTML_HIGHLIGHTS,
        TextType::Json => JSON_HIGHLIGHTS,
        TextType::JsonLines => JSON_HIGHLIGHTS,
        TextType::Toml => TOML_HIGHLIGHTS,
        TextType::Xml => XML_HIGHLIGHTS,
    }
}
