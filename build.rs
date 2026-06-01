use std::env;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=Cargo.lock");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    println!("cargo:rerun-if-changed=.git/packed-refs");
    println!("cargo:rerun-if-changed=.git/refs/heads");
    println!("cargo:rerun-if-changed=.git/refs/tags");
    println!("cargo:rerun-if-env-changed=FETCH_VERSION");

    set_env(
        "FETCH_RUSTC_VERSION",
        command_output("rustc", &["--version"])
            .and_then(|version| rustc_release_version(&version).map(str::to_string)),
    );
    set_env("FETCH_VERSION", Some(build_version()));
    if let Ok(profile) = env::var("PROFILE") {
        println!("cargo:rustc-env=FETCH_BUILD_PROFILE={profile}");
    }

    if let Some(revision) = command_output("git", &["rev-parse", "HEAD"]) {
        println!("cargo:rustc-env=FETCH_VCS_REVISION={revision}");
        println!("cargo:rustc-env=FETCH_VCS=git");
    }
    set_env(
        "FETCH_VCS_TIME",
        command_output("git", &["log", "-1", "--format=%cI"]),
    );
    if let Some(status) = command_output("git", &["status", "--porcelain", "--untracked-files=no"])
    {
        println!(
            "cargo:rustc-env=FETCH_VCS_MODIFIED={}",
            if status.is_empty() { "false" } else { "true" }
        );
    }
}

fn set_env(key: &str, value: Option<String>) {
    if let Some(value) = value {
        println!("cargo:rustc-env={key}={value}");
    }
}

fn build_version() -> String {
    env::var("FETCH_VERSION")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            command_output(
                "git",
                &[
                    "describe",
                    "--tags",
                    "--exact-match",
                    "--match",
                    "v[0-9]*",
                    "HEAD",
                ],
            )
        })
        .or_else(|| {
            command_output(
                "git",
                &["describe", "--tags", "--long", "--match", "v[0-9]*"],
            )
        })
        .unwrap_or_else(|| "v0.0.0-dev".to_string())
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn rustc_release_version(version: &str) -> Option<&str> {
    version
        .strip_prefix("rustc ")?
        .split_whitespace()
        .next()
        .filter(|version| !version.is_empty())
}
