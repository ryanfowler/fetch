use std::{
    env, fs,
    io::{self, IsTerminal, Read, Write},
    path::Path,
    process::ExitCode,
    time::Duration,
};

use reqwest::blocking::{Client, ClientBuilder};
use serde::Deserialize;
use termcolor::{BufferWriter, Color, ColorChoice, ColorSpec, WriteColor};

static TARGET: &str = env!("TARGET");
static VERSION: &str = env!("CARGO_PKG_VERSION");
static APP_STRING: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

type Error = Box<dyn std::error::Error>;

pub(crate) fn update(timeout: Option<f64>) -> ExitCode {
    let writer = BufferWriter::stderr(if io::stderr().is_terminal() {
        ColorChoice::Always
    } else {
        ColorChoice::Never
    });

    if let Err(err) = update_in_place(&writer, timeout) {
        let _ = write_error(&writer, &err.to_string());
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(target_os = "windows")]
fn update_in_place(_writer: &BufferWriter, _timeout: Option<f64>) -> Result<(), Error> {
    Err("update functionality not supported for windows at this time".into())
}

#[cfg(not(target_os = "windows"))]
fn update_in_place(writer: &BufferWriter, timeout: Option<f64>) -> Result<(), Error> {
    let client = ClientBuilder::new()
        .use_rustls_tls()
        .timeout(duration_from_f64(timeout))
        .user_agent(APP_STRING)
        .build()?;

    let _ = write_info(writer, "fetching latest release version");
    let latest = get_latest_tag(&client)?;
    if latest.trim_start_matches('v') == VERSION {
        let msg = format!("\n  currently using the latest version (v{VERSION})");
        return write_raw(writer, &msg);
    }

    let _ = write_info(writer, &format!("downloading latest version ({latest})"));
    let reader = get_artifact_reader(&client, &latest)?;
    let temp_dir = tempfile::tempdir()?;
    unpack_artifact(temp_dir.path(), reader)?;

    let bin_path = env::current_exe()?;
    let src = temp_dir.path().join("fetch");
    fs::rename(src, bin_path)?;

    let msg = format!("\n  fetch successfully updated (v{VERSION} -> {latest})");
    write_raw(writer, &msg)
}

fn get_latest_tag(client: &Client) -> Result<String, Error> {
    #[derive(Deserialize)]
    struct Release {
        tag_name: String,
    }

    let res = client
        .get("https://api.github.com/repos/ryanfowler/fetch/releases/latest")
        .send()?;

    let status = res.status();
    if status != 200 {
        return Err(format!("fetching latest release: received status {status}").into());
    }

    let release: Release = res.json()?;
    Ok(release.tag_name)
}

fn get_artifact_reader(client: &Client, tag: &str) -> Result<impl Read, Error> {
    let url = format!(
        "https://github.com/ryanfowler/fetch/releases/download/{tag}/fetch-{tag}-{TARGET}.tar.gz"
    );
    let res = client.get(url).send()?;

    let status = res.status();
    if status != 200 {
        Err(format!("downloading artifact: received status {status}").into())
    } else {
        Ok(res)
    }
}

#[cfg(not(target_os = "windows"))]
fn unpack_artifact(temp_dir: &Path, r: impl Read) -> Result<(), io::Error> {
    let gz = flate2::read::GzDecoder::new(r);
    let mut archive = tar::Archive::new(gz);
    archive.unpack(temp_dir)
}

#[cfg(target_os = "windows")]
fn unpack_artifact(temp_dir: &Path, r: impl Read) -> Result<(), io::Error> {
    unimplemented!();
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

fn write_raw(writer: &BufferWriter, msg: &str) -> Result<(), Error> {
    let mut buf = writer.buffer();
    writeln!(&mut buf, "{msg}")?;
    Ok(writer.print(&buf)?)
}

fn write_info(writer: &BufferWriter, msg: &str) -> Result<(), Error> {
    let mut buf = writer.buffer();
    buf.set_color(ColorSpec::new().set_fg(Some(Color::Green)).set_bold(true))?;
    write!(buf, "info:")?;
    buf.reset()?;
    writeln!(&mut buf, " {msg}")?;
    Ok(writer.print(&buf)?)
}

fn write_error(writer: &BufferWriter, msg: &str) -> Result<(), Error> {
    let mut buf = writer.buffer();
    buf.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_bold(true))?;
    write!(&mut buf, "error:")?;
    buf.reset()?;
    writeln!(&mut buf, " {msg}")?;
    Ok(writer.print(&buf)?)
}
