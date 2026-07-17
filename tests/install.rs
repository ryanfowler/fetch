#![cfg(unix)]

use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

const NEW_FETCH: &str =
    "#!/bin/sh\nif [ \"${1:-}\" = --version ]; then\n  echo 'fetch test'\n  exit 0\nfi\n";

struct InstallerFixture {
    _temp: TempDir,
    archive: PathBuf,
    checksum: PathBuf,
    home: PathBuf,
    install_dir: PathBuf,
    mock_bin: PathBuf,
}

impl InstallerFixture {
    fn new(fail_stage_copy: bool) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let payload = temp.path().join("payload");
        let archive = temp.path().join("fetch.tar.gz");
        let checksum = temp.path().join("fetch.tar.gz.sha256");
        let home = temp.path().join("home");
        let install_dir = temp.path().join("install");
        let mock_bin = temp.path().join("bin");
        fs::create_dir_all(&payload).unwrap();
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&install_dir).unwrap();
        fs::create_dir_all(&mock_bin).unwrap();
        write_executable(&payload.join("fetch"), NEW_FETCH);

        let status = Command::new("tar")
            .args(["-czf"])
            .arg(&archive)
            .arg("-C")
            .arg(&payload)
            .arg("fetch")
            .status()
            .unwrap();
        assert!(status.success());

        let digest = Sha256::digest(fs::read(&archive).unwrap());
        let digest = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        fs::write(&checksum, format!("{digest}  fetch.tar.gz\n")).unwrap();

        write_executable(
            &mock_bin.join("curl"),
            r#"#!/bin/sh
out=""
url=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    out="$2"
    shift 2
  else
    url="$1"
    shift
  fi
done
if [ -z "$out" ]; then
  printf '%s\n' '{"tag_name":"vtest","assets":[]}'
elif [ "${url##*.}" = "sha256" ]; then
  command cat "$MOCK_CHECKSUM" > "$out"
else
  command cat "$MOCK_ARCHIVE" > "$out"
fi
"#,
        );
        write_executable(
            &mock_bin.join("jq"),
            r#"#!/bin/sh
case "$*" in
  *tag_name*) printf '%s\n' vtest ;;
  *)
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--arg" ] && [ "$2" = "name" ]; then
        printf 'https://example.invalid/%s\n' "$3"
        exit 0
      fi
      shift
    done
    ;;
esac
"#,
        );
        if fail_stage_copy {
            write_executable(
                &mock_bin.join("cp"),
                "#!/bin/sh\nprintf partial > \"$2\"\nexit 1\n",
            );
        }

        Self {
            _temp: temp,
            archive,
            checksum,
            home,
            install_dir,
            mock_bin,
        }
    }

    fn run(&self) -> Output {
        let path = format!(
            "{}:{}",
            self.mock_bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        Command::new("bash")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("install.sh"))
            .env("FETCH_INSTALL_DIR", &self.install_dir)
            .env("FETCH_INSTALL_COMPLETIONS", "0")
            .env("HOME", &self.home)
            .env("MOCK_ARCHIVE", &self.archive)
            .env("MOCK_CHECKSUM", &self.checksum)
            .env("PATH", path)
            .output()
            .unwrap()
    }

    fn staged_files(&self) -> Vec<PathBuf> {
        fs::read_dir(&self.install_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".fetch.install.")
            })
            .collect()
    }
}

#[test]
fn installer_atomically_replaces_existing_binary() {
    let fixture = InstallerFixture::new(false);
    fs::write(fixture.install_dir.join("fetch"), "old fetch\n").unwrap();

    let output = fixture.run();

    assert!(
        output.status.success(),
        "installer failed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        fs::read_to_string(fixture.install_dir.join("fetch")).unwrap(),
        NEW_FETCH
    );
    assert!(fixture.staged_files().is_empty());
}

#[test]
fn staging_failure_preserves_existing_binary() {
    let fixture = InstallerFixture::new(true);
    let installed = fixture.install_dir.join("fetch");
    fs::write(&installed, "old fetch\n").unwrap();

    let output = fixture.run();

    assert!(!output.status.success());
    assert_eq!(fs::read_to_string(installed).unwrap(), "old fetch\n");
    assert!(fixture.staged_files().is_empty());
    assert!(String::from_utf8_lossy(&output.stdout).contains("unable to stage fetch"));
}

#[test]
fn directory_destination_is_rejected_and_staging_is_cleaned_up() {
    let fixture = InstallerFixture::new(false);
    let installed = fixture.install_dir.join("fetch");
    fs::create_dir(&installed).unwrap();

    let output = fixture.run();

    assert!(!output.status.success());
    assert!(installed.is_dir());
    assert_eq!(fs::read_dir(installed).unwrap().count(), 0);
    assert!(fixture.staged_files().is_empty());
    assert!(String::from_utf8_lossy(&output.stdout).contains("is a directory"));
}

#[test]
fn symlink_to_directory_destination_is_rejected_and_staging_is_cleaned_up() {
    let fixture = InstallerFixture::new(false);
    let destination = fixture.install_dir.join("destination");
    let installed = fixture.install_dir.join("fetch");
    fs::create_dir(&destination).unwrap();
    symlink(&destination, &installed).unwrap();

    let output = fixture.run();

    assert!(!output.status.success());
    assert!(
        fs::symlink_metadata(&installed)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_dir(destination).unwrap().count(), 0);
    assert!(fixture.staged_files().is_empty());
    assert!(String::from_utf8_lossy(&output.stdout).contains("is a directory"));
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}
