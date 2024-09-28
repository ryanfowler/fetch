use std::{ops::Deref, path::PathBuf, process::ExitCode};

use clap::{ArgAction, Parser, ValueEnum};

mod aws_sigv4;
mod error;
mod fetch;
mod format;
mod highlight;
mod http;
mod image;

static APP_STRING: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Parser)]
#[command(disable_help_subcommand = true, version)]
struct Cli {
    #[command()]
    url: String,

    #[arg(long)]
    aws_sigv4: Option<String>,
    #[arg(long)]
    dry_run: bool,
    #[arg(short = 'H', long)]
    header: Vec<String>,
    #[arg(long)]
    http: Option<Http>,
    #[arg(short, long)]
    method: Option<String>,
    #[arg(long)]
    no_pager: bool,
    #[arg(short, long)]
    output: Option<PathBuf>,
    #[arg(short, long)]
    query: Vec<String>,
    #[arg(short, long)]
    silent: bool,
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,
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

fn main() -> ExitCode {
    let cli = Cli::parse();
    // println!("{cli:?}");

    fetch::fetch(cli)
}
