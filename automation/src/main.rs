use std::{io::Write, path::PathBuf};

use serde::Deserialize;

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() <= 1 {
        println!("Available commands are: ['install', 'view-updates']");
        std::process::exit(0);
    }

    match args[1].as_str() {
        "install" => install(),
        "view-updates" => view_updates(),
        arg => {
            println!("error: invalid command: {}", arg);
            std::process::exit(1);
        }
    }
}

static RAW_GRAMMARS: &str = include_str!("../../grammars.toml");

#[derive(Deserialize)]
struct Grammars {
    language: Vec<Language>,
}

#[derive(Deserialize)]
struct Language {
    name: String,
    files: Vec<String>,
    headers: Vec<String>,
    revision: String,
    repository: String,
}

fn install() {
    let grammars: Grammars = toml::from_str(RAW_GRAMMARS).unwrap();

    for language in &grammars.language {
        println!("info: installing grammar for {}", language.name);
        let headers = language.headers.iter();
        let license = ["LICENSE".to_string()];
        for file in language.files.iter().chain(headers).chain(license.iter()) {
            let url = format_url(&language.repository, &language.revision, file);
            let data = download(&url);
            let path: PathBuf = ["..", "grammars", &language.name, file].iter().collect();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let mut f = std::fs::File::create(path).unwrap();
            f.write_all(data.as_bytes()).unwrap();
            f.sync_all().unwrap();
        }
    }

    println!("info: all done!");
}

fn view_updates() {
    let grammars: Grammars = toml::from_str(RAW_GRAMMARS).unwrap();

    for lang in &grammars.language {
        let commit = get_latest_commit(&lang.repository);
        if lang.revision == commit {
            println!("{}: latest ({})", &lang.name, &lang.revision);
        } else {
            println!(
                "{}: update available ({} -> {})",
                &lang.name, &lang.revision, &commit
            );
        }
    }
}

fn format_url(repo: &str, revision: &str, file: &str) -> String {
    let url = repo.strip_prefix("https://github.com/").unwrap();
    format!(
        "https://raw.githubusercontent.com/{}/{}/{}",
        url, revision, file
    )
}

fn download(path: &str) -> String {
    let res = ureq::get(path).call().unwrap();
    if res.status() != 200 {
        println!("error: status: {}: {}", res.status(), path);
        std::process::exit(1);
    }
    res.into_string().unwrap()
}

fn get_latest_commit(repo: &str) -> String {
    let output = std::process::Command::new("git")
        .arg("ls-remote")
        .arg("--heads")
        .arg(repo)
        .arg("refs/heads/master")
        .output()
        .unwrap();

    if !output.status.success() {
        println!(
            "error: getting latest git commit for {}: {}",
            repo, output.status
        );
        std::process::exit(1);
    }

    let output = String::from_utf8(output.stdout).unwrap();
    output.split('\t').next().unwrap().to_string()
}
