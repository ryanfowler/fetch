use std::{
    env,
    fs::{self, File},
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process::{self, ExitCode, Stdio},
    time::Duration,
};

use lazy_static::lazy_static;
use mime::Mime;
use quick_xml::{events::Event, Reader, Writer};
use reqwest::{
    blocking,
    header::{HeaderMap, HeaderValue, CONTENT_LENGTH, CONTENT_TYPE},
    Method,
};
use termcolor::{BufferedStandardStream, Color, ColorChoice, ColorSpec, WriteColor};

use crate::{
    body::Body,
    editor,
    error::Error,
    format::{self, format_request},
    highlight::highlight,
    http,
    image::Image,
    progress::ProgressReader,
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
            let mut w = BufferedStandardStream::stderr(ColorChoice::Auto);
            _ = w.set_color(ColorSpec::new().set_bold(true).set_fg(Some(Color::Red)));
            _ = w.write_all("Error".as_bytes());
            _ = w.reset();
            _ = writeln!(&mut w, ": {err}");
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

fn fetch_inner(cli: Cli) -> Result<bool, Error> {
    let mut req = create_request(&cli)?;

    // Print request info if necessary.
    let v = Verbosity::new(&cli);
    if v > Verbosity::Verbose || cli.dry_run {
        let mut stderr = BufferedStandardStream::stderr(ColorChoice::Auto);
        format_request(&mut stderr, &req)?;
        if cli.dry_run {
            if let Some(body) = req.body_mut() {
                // TODO(ryanfowler): This can be optimized to not have to read
                // the whole request body into memory.
                let raw = body.buffer()?;
                writeln!(&mut stderr)?;
                stderr.write_all(raw)?;
            }
            // Dry-run, so we can return now.
            return Ok(true);
        } else {
            writeln!(&mut stderr)?;
        }
    }

    let res = req.send()?;
    let version = res.version();
    let status = res.status();
    let is_success = (200..400).contains(&status.as_u16());

    if v > Verbosity::Silent {
        let mut stderr = BufferedStandardStream::stderr(ColorChoice::Auto);
        format::format_headers(&mut stderr, version, status, res.headers(), v)?;
    }

    // Write to a file if, specified.
    if let Some(output) = cli.output {
        let mut file = fs::File::create(output)?;
        let size = res.content_length();
        let reader = res.into_reader()?;
        let mut reader = ProgressReader::new(reader, size, matches!(v, Verbosity::Silent));
        io::copy(&mut reader, &mut file)?;
        file.sync_all()?;
        return Ok(is_success);
    }

    if *IS_STDOUT_TTY {
        // Stream response body to stdout.
        if let Some(content_type) = get_content_type(res.headers()) {
            // TODO(ryanfowler): Limit body before reading it all.
            let mut buf = Vec::with_capacity(1024);
            res.into_reader()?.read_to_end(&mut buf)?;
            match content_type {
                ContentType::Text(text_type) => {
                    if let Some(formatted) = format_text(&buf, text_type) {
                        buf = formatted;
                    }
                    if let Some(highlighted) = highlight(&buf, text_type) {
                        buf = highlighted;
                    }
                    stream_to_stdout(&mut &buf[..], cli.no_pager)?;
                    Ok(is_success)
                }
                ContentType::Image(_image) => {
                    if let Some(img) = Image::new(&buf) {
                        img.write_to_stdout()?;
                        Ok(is_success)
                    } else {
                        Err(Error::new("unable to parse image"))
                    }
                }
            }
        } else {
            stream_to_stdout(&mut res.into_reader()?, cli.no_pager)?;
            Ok(is_success)
        }
    } else {
        // stdout is not a tty, use a ProgressReader.
        let size = res.content_length();
        let reader = res.into_reader()?;
        let mut reader = ProgressReader::new(reader, size, matches!(v, Verbosity::Silent));
        stream_to_stdout(&mut reader, cli.no_pager)?;
        Ok(is_success)
    }
}

fn create_request(cli: &Cli) -> Result<http::Request, Error> {
    let mut builder = http::RequestBuilder::new(&cli.url)
        .with_method(cli.method.as_deref())
        .with_headers(&cli.header)
        .with_basic(cli.basic.as_deref())
        .with_bearer(cli.bearer.as_deref())
        .with_proxy(cli.proxy.as_deref())
        .with_query(&cli.query)
        .with_timeout(duration_from_f64(cli.timeout))
        .with_version(cli.http);

    // Parse out sigv4 parameters.
    let mut sigv4: Option<http::SigV4> = None;
    if let Some(raw) = &cli.aws_sigv4 {
        sigv4 = Some(http::SigV4::parse(raw)?);
    }

    // Parse any request body. Only one of these can be defined, as per the
    // clap group they belong to.
    let content_type = get_cli_content_type(cli);
    builder = builder.with_content_type(content_type.as_deref());
    if !cli.form.is_empty() {
        let data = cli
            .form
            .iter()
            .map(|v| {
                if let Some((key, val)) = v.split_once('=') {
                    (key, val)
                } else {
                    (v.as_str(), "")
                }
            })
            .collect::<Vec<_>>();
        builder = builder.with_body(Some(Body::new_form(&data)?));
    }
    if !cli.multipart.is_empty() {
        let mut form = blocking::multipart::Form::new();
        for v in &cli.multipart {
            let (key, val) = if let Some((key, val)) = v.split_once('=') {
                (key, val)
            } else {
                (v.as_str(), "")
            };
            if let Some(file) = val.strip_prefix('@') {
                form = form.file(key.to_owned(), file)?;
            } else {
                form = form.text(key.to_owned(), val.to_owned());
            }
        }
        builder = builder.with_multipart(Some(form));
    }
    if let Some(data) = &cli.data {
        if let Some(path) = data.strip_prefix('@') {
            // Request body is a file path.
            let file = File::open(path)?;
            builder = builder.with_body(Some(Body::new_file(file)?));
        } else {
            // data is the raw request body.
            let data = data.to_owned().into_bytes();
            builder = builder.with_body(Some(data.into()));
        }
    }

    let mut req = builder.build()?;

    // Disallow sending a body with certain methods, as reqwest will
    // silently not send a body with these if the body is a type that
    // implements Read.
    if (req.body_mut().is_some() || cli.edit)
        && matches!(req.method(), &Method::GET | &Method::HEAD | &Method::TRACE)
    {
        return Err(Error::new(format!(
            "cannot include a body with a {} request",
            req.method(),
        )));
    }

    // Pull up an editor for the user to define the request body.
    if cli.edit {
        // If a body is already set, use that as the "placeholder" text in the
        // file to edit.
        let mut placeholder: Option<&[u8]> = None;
        if let Some(body) = req.body_mut() {
            let raw = body.buffer()?;
            placeholder = Some(raw);
        }

        let ext = get_cli_content_ext(cli);
        let body = editor::edit(placeholder, ext)?;
        let length_str = body.len().to_string();
        *req.body_mut() = Some(body.into());
        req.headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from_str(&length_str).unwrap());
    }

    // Sign the request, if necessary.
    if let Some(sigv4) = sigv4 {
        req.sign(sigv4)?;
    }

    Ok(req)
}

fn get_cli_content_type(cli: &Cli) -> Option<String> {
    if cli.json {
        Some("application/json".to_string())
    } else if cli.xml {
        Some("application/xml".to_string())
    } else if !cli.form.is_empty() {
        Some("application/x-www-form-urlencoded".to_string())
    } else {
        cli.data
            .as_ref()
            .and_then(|v| v.strip_prefix('@'))
            .and_then(|v| mime_guess::from_path(v).first())
            .map(|mimetype| mimetype.to_string())
    }
}

fn get_cli_content_ext(cli: &Cli) -> Option<&'static str> {
    if cli.json {
        Some(".json")
    } else if cli.xml {
        Some(".xml")
    } else {
        None
    }
}

#[derive(Copy, Clone, Debug)]
pub(crate) enum ContentType {
    Image(ImageType),
    Text(TextType),
}

#[derive(Copy, Clone, Debug)]
pub(crate) enum ImageType {
    Jpeg,
    Png,
    Tiff,
    Webp,
}

#[derive(Copy, Clone, Debug)]
pub(crate) enum TextType {
    Html,
    Json,
    JsonLines,
    Toml,
    Xml,
    Yaml,
}

impl TextType {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            TextType::Html => "html",
            TextType::Json => "json",
            TextType::JsonLines => "jsonlines",
            TextType::Toml => "toml",
            TextType::Xml => "xml",
            TextType::Yaml => "yaml",
        }
    }
}

fn get_content_type(headers: &HeaderMap) -> Option<ContentType> {
    let mt: Mime = headers.get(CONTENT_TYPE)?.to_str().ok()?.parse().ok()?;
    match (mt.type_(), mt.subtype().as_str()) {
        (mime::IMAGE, "jpeg") => Some(ContentType::Image(ImageType::Jpeg)),
        (mime::IMAGE, "png") => Some(ContentType::Image(ImageType::Png)),
        (mime::IMAGE, "tiff") => Some(ContentType::Image(ImageType::Tiff)),
        (mime::IMAGE, "webp") => Some(ContentType::Image(ImageType::Webp)),
        (_, "html") => Some(ContentType::Text(TextType::Html)),
        (_, "json") => Some(ContentType::Text(TextType::Json)),
        (_, "jsonlines") => Some(ContentType::Text(TextType::JsonLines)),
        (_, "toml") => Some(ContentType::Text(TextType::Toml)),
        (_, "xml") => Some(ContentType::Text(TextType::Xml)),
        (_, "x-yaml" | "yaml") => Some(ContentType::Text(TextType::Yaml)),
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

fn duration_from_f64(v: Option<f64>) -> Option<Duration> {
    v.and_then(|v| {
        if v <= 0.0 || v.is_infinite() {
            None
        } else {
            Some(Duration::from_secs_f64(v))
        }
    })
}
