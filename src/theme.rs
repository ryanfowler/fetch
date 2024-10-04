use std::collections::BTreeMap;

use serde::Deserialize;

use crate::error::Error;

#[derive(Debug)]
pub(crate) struct Theme {
    names: Vec<String>,
    styles: Vec<anstyle::Style>,
}

impl Theme {
    pub(crate) fn parse(name: impl AsRef<str>, input: impl AsRef<str>) -> Result<Self, Error> {
        Self::parse_inner(input)
            .map_err(|e| Error::new(format!("unable to parse theme '{}': {}", name.as_ref(), e)))
    }

    pub(crate) fn names(&self) -> &[String] {
        &self.names
    }

    pub(crate) fn get_style(&self, i: usize) -> anstyle::Style {
        self.styles[i]
    }

    fn parse_inner(input: impl AsRef<str>) -> Result<Self, Error> {
        let raw_names: BTreeMap<String, Name> =
            toml::from_str(input.as_ref()).map_err(|e| Error::new(e.to_string()))?;

        let mut names = Vec::with_capacity(raw_names.len());
        let mut styles = Vec::with_capacity(raw_names.len());
        for (k, v) in raw_names {
            let style = match v {
                Name::Color(c) => anstyle::Style::new().fg_color(Some(parse_color(&c)?)),
                Name::Object {
                    fg,
                    bg,
                    bold,
                    dimmed,
                    italic,
                    underline,
                } => {
                    let mut style = anstyle::Style::new();
                    if let Some(fg) = fg {
                        style = style.fg_color(Some(parse_color(&fg)?));
                    }
                    if let Some(bg) = bg {
                        style = style.bg_color(Some(parse_color(&bg)?));
                    }
                    if bold {
                        style = style.bold();
                    }
                    if dimmed {
                        style = style.dimmed();
                    }
                    if italic {
                        style = style.italic();
                    }
                    if underline {
                        style = style.underline();
                    }
                    style
                }
            };
            names.push(k.to_string());
            styles.push(style);
        }

        Ok(Theme { names, styles })
    }
}

impl Default for Theme {
    fn default() -> Self {
        const DEFAULT_THEME_RAW: &str = include_str!("../themes/default.toml");
        Self::parse("default", DEFAULT_THEME_RAW).unwrap()
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Name {
    Color(String),
    Object {
        fg: Option<String>,
        bg: Option<String>,
        #[serde(default)]
        bold: bool,
        #[serde(default)]
        dimmed: bool,
        #[serde(default)]
        italic: bool,
        #[serde(default)]
        underline: bool,
    },
}

fn parse_color(color: &str) -> Result<anstyle::Color, Error> {
    str_to_color(color).ok_or_else(|| Error::new(format!("invalid color: {color}")))
}

fn str_to_color(input: &str) -> Option<anstyle::Color> {
    if let Ok(v) = input.parse::<u8>() {
        return Some(anstyle::Color::Ansi256(v.into()));
    }

    if let Some(ansi) = from_ansi_color(input) {
        return Some(anstyle::Color::Ansi(ansi));
    }

    None
}

fn from_ansi_color(input: &str) -> Option<anstyle::AnsiColor> {
    match input {
        "black" => Some(anstyle::AnsiColor::Black),
        "red" => Some(anstyle::AnsiColor::Red),
        "green" => Some(anstyle::AnsiColor::Green),
        "yellow" => Some(anstyle::AnsiColor::Yellow),
        "blue" => Some(anstyle::AnsiColor::Blue),
        "magenta" => Some(anstyle::AnsiColor::Magenta),
        "cyan" => Some(anstyle::AnsiColor::Cyan),
        "white" => Some(anstyle::AnsiColor::White),
        "bright_black" => Some(anstyle::AnsiColor::BrightBlack),
        "bright_red" => Some(anstyle::AnsiColor::BrightRed),
        "bright_green" => Some(anstyle::AnsiColor::BrightGreen),
        "bright_yellow" => Some(anstyle::AnsiColor::BrightYellow),
        "bright_blue" => Some(anstyle::AnsiColor::BrightBlue),
        "bright_magenta" => Some(anstyle::AnsiColor::BrightMagenta),
        "bright_cyan" => Some(anstyle::AnsiColor::BrightCyan),
        "bright_white" => Some(anstyle::AnsiColor::BrightWhite),
        _ => None,
    }
}
