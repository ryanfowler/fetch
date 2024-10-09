use std::{ops::Deref, path::PathBuf, process::ExitCode};

use clap::{ArgAction, Parser, ValueEnum};

mod aws_sigv4;
mod body;
mod editor;
mod error;
mod fetch;
mod format;
mod highlight;
mod http;
mod image;
mod progress;
mod theme;

fn main() -> ExitCode {
    fetch::fetch(Cli::parse())
}

#[derive(Debug, Parser)]
#[command(name = "fetch")]
#[command(disable_help_subcommand = true, about, version)]
struct Cli {
    /// The URL to make a request to
    #[command()]
    url: String,

    /// Sign the request using AWS signature V4
    #[arg(long, value_name = "REGION/SERVICE")]
    aws_sigv4: Option<String>,
    /// Enable HTTP basic authentication
    #[arg(long, value_name = "USER:PASS")]
    #[arg(conflicts_with = "aws_sigv4", conflicts_with = "bearer")]
    basic: Option<String>,
    /// Enable HTTP bearer authentication
    #[arg(long, value_name = "TOKEN")]
    #[arg(conflicts_with = "aws_sigv4", conflicts_with = "basic")]
    bearer: Option<String>,
    /// Send a request body
    #[arg(short, long, group = "body", value_name = "[@]VALUE")]
    data: Option<String>,
    /// Print out the request info and exit
    #[arg(long)]
    dry_run: bool,
    /// Use an editor to send a request body
    #[arg(short, long)]
    edit: bool,
    /// Send a form body
    #[arg(short, long, group = "body", value_name = "KEY=VALUE")]
    form: Vec<String>,
    /// Append headers to the request
    #[arg(short = 'H', long, value_name = "NAME:VALUE")]
    header: Vec<String>,
    /// Force the use of an HTTP version
    #[arg(long, value_name = "VERSION")]
    http: Option<Http>,
    /// Set the content-type to application/json
    #[arg(short, long, conflicts_with = "form", conflicts_with = "xml")]
    json: bool,
    /// HTTP method to use
    #[arg(short, long)]
    method: Option<String>,
    /// Avoid using a pager for displaying the response body
    #[arg(long)]
    no_pager: bool,
    /// Write the response body to a file
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Configure a proxy
    #[arg(long)]
    proxy: Option<String>,
    /// Append query parameters to the url
    #[arg(short, long, value_name = "KEY=VALUE")]
    query: Vec<String>,
    /// Avoid printing anything to stderr
    #[arg(short, long)]
    silent: bool,
    /// Timeout in seconds applied to the entire request
    #[arg(short, long)]
    timeout: Option<f64>,
    /// Verbosity of the command
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,
    /// Set the content-type to application/xml
    #[arg(short, long, conflicts_with = "form", conflicts_with = "json")]
    xml: bool,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Http {
    #[value(name = "1")]
    One,
    #[value(name = "2")]
    Two,
    // #[value(name = "3")]
    // Three,
}

impl Deref for Http {
    type Target = Self;

    fn deref(&self) -> &Self::Target {
        self
    }
}
