use std::{path::PathBuf, process::ExitCode};

use clap::{ArgAction, Parser};

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
    dry_run: bool,
    #[arg(short = 'H', long)]
    header: Vec<String>,
    #[arg(short, long)]
    method: Option<String>,
    #[arg(long)]
    no_pager: bool,
    #[arg(short, long)]
    output: Option<PathBuf>,
    #[arg(short, long)]
    silent: bool,
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // println!("{cli:?}");

    fetch::fetch(cli)
}
