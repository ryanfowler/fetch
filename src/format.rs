use std::io;

use reqwest::{
    blocking::Request,
    header::{HeaderMap, HOST},
    StatusCode, Version,
};
use termcolor::{Color, ColorSpec, WriteColor};

use crate::fetch::Verbosity;

pub(crate) fn format_headers(
    w: &mut impl WriteColor,
    version: Version,
    status: StatusCode,
    headers: &HeaderMap,
    verbosity: Verbosity,
) -> io::Result<()> {
    // Write HTTP version.
    w.set_color(ColorSpec::new().set_dimmed(true))?;
    write!(w, "{version:?} ")?;

    // Write HTTP status code and optional reason.
    w.set_color(color_for_code(status.as_u16()).set_bold(true))?;
    write!(w, "{}", status.as_str())?;
    if let Some(reason) = status.canonical_reason() {
        w.set_color(&color_for_code(status.as_u16()))?;
        write!(w, " {reason}")?;
    }
    writeln!(w)?;

    // Write headers, if necessary.
    if verbosity > Verbosity::Normal {
        for (key, val) in headers {
            w.set_color(ColorSpec::new().set_bold(true).set_fg(Some(Color::Cyan)))?;
            write!(w, "{key}")?;
            w.reset()?;
            if let Ok(v) = val.to_str() {
                writeln!(w, ": {v}")?;
            } else {
                writeln!(w, ": <invalid utf8>")?;
            }
        }
    }

    w.reset()?;
    writeln!(w)
}

fn color_for_code(code: u16) -> ColorSpec {
    let mut color = ColorSpec::new();
    match code {
        (200..300) => color.set_fg(Some(Color::Green)),
        (400..600) => color.set_fg(Some(Color::Red)),
        _ => color.set_fg(Some(Color::Yellow)),
    };
    color
}

pub(crate) fn format_request(w: &mut impl WriteColor, req: &Request) -> io::Result<()> {
    let version = req.version();
    let method = req.method();
    let url = req.url();
    let headers = req.headers();

    // Write request method, path, and HTTP version.
    w.set_color(ColorSpec::new().set_bold(true).set_fg(Some(Color::Yellow)))?;
    write!(w, "{method}")?;
    w.set_color(ColorSpec::new().set_bold(true).set_fg(Some(Color::Cyan)))?;
    write!(w, " {}", url.path())?;
    if let Some(query) = url.query() {
        w.set_color(ColorSpec::new().set_italic(true).set_fg(Some(Color::Cyan)))?;
        write!(w, "?{query}")?;
    }
    w.set_color(ColorSpec::new().set_dimmed(true))?;
    writeln!(w, " {version:?}")?;

    // Write HTTP headers.
    let mut key_color = ColorSpec::new();
    key_color.set_bold(true).set_fg(Some(Color::Blue));
    let host = url.authority();
    w.set_color(&key_color)?;
    write!(w, "{HOST}")?;
    w.reset()?;
    writeln!(w, ": {host}")?;
    for (key, val) in headers {
        w.set_color(&key_color)?;
        write!(w, "{key}")?;
        w.reset()?;
        if let Ok(v) = val.to_str() {
            writeln!(w, ": {v}")?;
        } else {
            writeln!(w, ": <invalid utf8>")?;
        }
    }

    w.reset()
}
