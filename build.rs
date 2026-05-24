use std::env;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=Cargo.lock");
    println!("cargo:rerun-if-changed=.git/HEAD");

    set_env(
        "FETCH_RUSTC_VERSION",
        command_output("rustc", &["--version"]),
    );
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
    if let Some(status) = command_output("git", &["status", "--porcelain"]) {
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

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
