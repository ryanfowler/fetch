#![cfg(not(windows))]

use std::fs;
use std::path::Path;

use flate2::Compression;
use flate2::write::GzEncoder;

use super::common::fetch_bin;

pub(crate) fn update_artifact_name(version: &str) -> String {
    let goos = if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        std::env::consts::OS
    };
    let goarch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    let suffix = if cfg!(target_os = "windows") {
        "zip"
    } else {
        "tar.gz"
    };
    format!("fetch-{version}-{goos}-{goarch}.{suffix}")
}

#[cfg(not(windows))]
pub(crate) fn make_update_artifact(version: &str) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let gz = GzEncoder::new(&mut out, Compression::fast());
        let mut tar = tar::Builder::new(gz);
        let script = format!("#!/bin/sh\necho 'fetch {version}'\n");
        let mut header = tar::Header::new_gnu();
        header.set_size(script.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        tar.append_data(&mut header, "fetch", script.as_bytes())
            .unwrap();
        let gz = tar.into_inner().unwrap();
        gz.finish().unwrap();
    }
    out
}

#[cfg(not(windows))]
pub(crate) fn update_artifact_checksum_line(name: &str, artifact: &[u8]) -> String {
    use sha2::{Digest as Sha2Digest, Sha256};

    let digest = Sha256::digest(artifact);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push(HEX[(byte >> 4) as usize] as char);
        hex.push(HEX[(byte & 0x0f) as usize] as char);
    }
    format!("{hex}  {name}\n")
}

#[cfg(not(windows))]
pub(crate) fn install_update_launcher(path: &Path) {
    let source = fetch_bin();
    if fs::hard_link(&source, path).is_err() {
        fs::copy(&source, path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(path, perms).unwrap();
        }
    }
}
