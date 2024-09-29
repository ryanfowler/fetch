use std::{
    env,
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process::{self, ExitCode, Stdio},
};

use lazy_static::lazy_static;
use mime::Mime;
use quick_xml::{events::Event, Reader, Writer};
use reqwest::header::{HeaderMap, CONTENT_TYPE};
use termcolor::{BufferedStandardStream, ColorChoice};

use crate::{
    error::Error,
    format::{self, format_request},
    highlight::highlight,
    http,
    image::Image,
    Cli,
};

lazy_static! {
    pub(crate) static ref IS_STDOUT_TTY: bool = std::io::stdout().is_terminal();
    pub(crate) static ref IS_STDERR_TTY: bool = std::io::stderr().is_terminal();
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd)]
pub(crate) enum Verbosity {
    Silent,
    Normal,
    Verbose,
    ExtraVerbose,
}

impl Verbosity {
    fn new(cli: &Cli) -> Self {
        if cli.silent {
            return Self::Silent;
        }
        match cli.verbose {
            0 => Self::Normal,
            1 => Self::Verbose,
            _ => Self::ExtraVerbose,
        }
    }
}

pub(crate) fn fetch(opts: Cli) -> ExitCode {
    match fetch_inner(opts) {
        Err(err) => {
            println!("Error: {}", err);
            ExitCode::FAILURE
        }
        Ok(ok) => {
            if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn fetch_inner(opts: Cli) -> Result<bool, Error> {
    let req = http::Request::new(&opts)?;

    // Print request info if necessary.
    let v = Verbosity::new(&opts);
    if v > Verbosity::Verbose || opts.dry_run {
        let choice = if *IS_STDERR_TTY {
            ColorChoice::Always
        } else {
            ColorChoice::Never
        };
        let mut stderr = BufferedStandardStream::stderr(choice);
        format_request(&mut stderr, &req)?;
        if opts.dry_run {
            return Ok(true);
        } else {
            writeln!(&mut stderr)?;
        }
    }

    let res = req.send()?;
    let version = res.version();
    let status = res.status();
    let is_success = (200..400).contains(&status.as_u16());

    if !matches!(v, Verbosity::Silent) {
        let choice = if *IS_STDERR_TTY {
            ColorChoice::Always
        } else {
            ColorChoice::Never
        };
        let mut stderr = BufferedStandardStream::stderr(choice);
        format::format_headers(&mut stderr, version, status, res.headers(), v)?;
    }

    if *IS_STDOUT_TTY {
        if let Some(content_type) = get_content_type(res.headers()) {
            // TODO(ryanfowler): Limit body before reading it all.
            let mut buf = Vec::with_capacity(1024);
            res.into_reader()?.read_to_end(&mut buf)?;
            match content_type {
                ContentType::Text(text_type) => {
                    let out = format_text(&buf, text_type)
                        .map_or_else(
                            || highlight(&buf, text_type),
                            |formatted| highlight(&formatted, text_type),
                        )
                        .unwrap_or(buf);
                    stream_to_stdout(&mut &out[..], opts.no_pager)?;
                    return Ok(is_success);
                }
                ContentType::Image(_image) => {
                    if let Some(img) = Image::new(&buf) {
                        img.write_to_stdout()?;
                        return Ok(is_success);
                    } else {
                        return Err(Error::new("unable to parse image"));
                    }
                }
            }
        }
    }

    stream_to_stdout(&mut res.into_reader()?, opts.no_pager)?;
    Ok(is_success)
}

#[derive(Copy, Clone, Debug)]
pub(crate) enum ContentType {
    Image(ImageType),
    Text(TextType),
}

#[derive(Copy, Clone, Debug)]
pub(crate) enum ImageType {
    Avif,
    Jpeg,
    Png,
    Tiff,
    Webp,
}

#[derive(Copy, Clone, Debug)]
pub(crate) enum TextType {
    Html,
    Json,
    Xml,
}

impl TextType {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            TextType::Html => "html",
            TextType::Json => "json",
            TextType::Xml => "xml",
        }
    }
}

fn get_content_type(headers: &HeaderMap) -> Option<ContentType> {
    let mt: Mime = headers.get(CONTENT_TYPE)?.to_str().ok()?.parse().ok()?;
    match (mt.type_(), mt.subtype().as_str()) {
        (mime::IMAGE, "avif") => Some(ContentType::Image(ImageType::Avif)),
        (mime::IMAGE, "jpeg") => Some(ContentType::Image(ImageType::Jpeg)),
        (mime::IMAGE, "png") => Some(ContentType::Image(ImageType::Png)),
        (mime::IMAGE, "tiff") => Some(ContentType::Image(ImageType::Tiff)),
        (mime::IMAGE, "webp") => Some(ContentType::Image(ImageType::Webp)),
        (_, "html") => Some(ContentType::Text(TextType::Html)),
        (_, "json") => Some(ContentType::Text(TextType::Json)),
        (_, "xml") => Some(ContentType::Text(TextType::Xml)),
        _ => None,
    }
}

fn format_text(input: &[u8], content_type: TextType) -> Option<Vec<u8>> {
    match content_type {
        TextType::Json => {
            let v: serde_json::Value = serde_json::from_slice(input).ok()?;
            let mut out = Vec::with_capacity(input.len() * 2);
            serde_json::to_writer_pretty(&mut out, &v).ok()?;
            writeln!(&mut out).ok()?;
            Some(out)
        }
        TextType::Xml => {
            let mut reader = Reader::from_reader(input);
            let config = reader.config_mut();
            config.trim_text(true);
            config.enable_all_checks(false);

            let mut out = Vec::with_capacity(input.len() * 2);
            let mut writer = Writer::new_with_indent(&mut out, b' ', 2);
            loop {
                let event = reader.read_event().ok()?;
                if matches!(event, Event::Eof) {
                    break;
                }
                writer.write_event(event).ok()?;
            }
            writeln!(&mut out).ok()?;
            Some(out)
        }
        _ => None,
    }
}

fn stream_to_stdout<R: io::Read>(r: &mut R, no_pager: bool) -> io::Result<()> {
    // If the pager is not disabled and stdout is a tty, stream to less.
    if !no_pager && *IS_STDOUT_TTY {
        // Ensure less is in the PATH.
        if let Some(path) = which("less") {
            return stream_to_pager(r, &path);
        }
    }

    // Otherwise stream to stdout directly.
    let mut stdout = io::stdout();
    io::copy(r, &mut stdout)?;
    stdout.flush()
}

fn stream_to_pager<R: io::Read>(r: &mut R, path: &Path) -> io::Result<()> {
    let mut child = process::Command::new(path)
        .arg("-FIRX")
        .stdin(Stdio::piped())
        .spawn()?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("unable to stream body to pager"))?;

    io::copy(r, &mut stdin)?;
    stdin.flush()?;
    drop(stdin);

    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other("unable to stream body to less"))
    }
}

fn which(name: &str) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths).find_map(|dir| {
            let path = dir.join(name);
            if path.is_file() {
                Some(path)
            } else {
                None
            }
        })
    })
}
