mod archive;
mod client;
mod install;
mod lock;
mod schedule;

use archive::{
    download_artifact, download_checksum, fetch_filename, goarch, goos, release_artifact,
    unpack_artifact_from_file, verify_artifact_checksum,
};
use client::{UpdateClient, latest_release};
use install::{can_replace_file, create_update_temp_dir, current_exe, self_replace};
use lock::{acquire_update_lock_with_timeout, update_lock_wait_timeout};
use schedule::{cache_dir, record_last_attempt_time};

use crate::cli::Cli;
use crate::core;
use crate::error::FetchError;

pub use install::maybe_run_self_delete_helper;
pub(crate) use schedule::maybe_spawn_auto_update;

pub async fn execute(cli: &Cli) -> Result<i32, FetchError> {
    crate::tls::install_default_crypto_provider();
    let client = UpdateClient::new(cli)?;

    let cache_dir = cache_dir()?;
    let lock_timeout = update_lock_wait_timeout(client.timeout);
    let _lock = acquire_update_lock_with_timeout(
        &cache_dir,
        true,
        cli.silent,
        cli.color.as_deref(),
        lock_timeout,
    )?
    .ok_or_else(|| FetchError::Message("unable to acquire update lock".to_string()))?;
    let result = update_inner(&client, cli.silent, cli.color.as_deref(), cli.dry_run).await;
    record_last_attempt_time(&cache_dir);
    result?;
    Ok(0)
}

async fn update_inner(
    client: &UpdateClient,
    silent: bool,
    color: Option<&str>,
    dry_run: bool,
) -> Result<(), FetchError> {
    let exe_path = current_exe()?;
    if !can_replace_file(&exe_path) {
        return Err(format!(
            "the current process does not have write permission to '{}'",
            exe_path.display()
        )
        .into());
    }
    let version = core::version();

    write_update_status(silent, color, "Fetching latest release...\n");
    let latest = latest_release(client).await?;

    if latest.tag_name == version {
        write_update_status_line(
            silent,
            color,
            format_args!("Already using the latest version ({}).", latest.tag_name),
        );
        return Ok(());
    }

    if dry_run {
        write_update_status_line(
            silent,
            color,
            format_args!("Update available: {version} -> {}", latest.tag_name),
        );
        return Ok(());
    }

    let release_artifact = release_artifact(&latest).ok_or_else(|| {
        FetchError::Message(format!(
            "no release artifact and checksum found for {}/{}",
            goos(),
            goarch()
        ))
    })?;
    write_update_status(
        silent,
        color,
        format_args!("Downloading {}\n\n", latest.tag_name),
    );

    let checksum = download_checksum(client, release_artifact.checksum_url).await?;

    let temp_dir = create_update_temp_dir()?;
    let archive_path = temp_dir.path().join("artifact");
    let actual_checksum =
        download_artifact(client, release_artifact.archive_url, &archive_path, silent).await?;
    verify_artifact_checksum(release_artifact.archive_name, &actual_checksum, &checksum)?;

    let unpack_dir = temp_dir.path().join("unpacked");
    std::fs::create_dir(&unpack_dir)?;
    let archive_name = release_artifact.archive_name.to_string();
    let archive_path_owned = archive_path.clone();
    let unpack_dir_owned = unpack_dir.clone();
    tokio::task::spawn_blocking(move || {
        unpack_artifact_from_file(&archive_name, &archive_path_owned, &unpack_dir_owned)
    })
    .await
    .map_err(|e| FetchError::Runtime(format!("extraction task failed: {e}")))??;

    let src = unpack_dir.join(fetch_filename());
    let replace_result = self_replace(&exe_path, &src);
    replace_result?;

    write_update_success(silent, color, version, &latest.tag_name);
    Ok(())
}

fn write_update_success(silent: bool, color: Option<&str>, old_version: &str, new_version: &str) {
    if silent {
        return;
    }
    let mut printer = core::Printer::stderr(color);
    write_update_success_to(&mut printer, old_version, new_version);
    core::flush_stderr(printer);
}

fn write_update_success_to(printer: &mut core::Printer, old_version: &str, new_version: &str) {
    core::write_status_line_no_flush(
        printer,
        format_args!("Updated fetch: {old_version} -> {new_version}"),
    );
    let compare_ref = changelog_compare_ref(old_version);
    if !compare_ref.is_empty() {
        printer.push('\n');
        core::write_status_line_no_flush(
            printer,
            format_args!(
                "Changelog: https://github.com/ryanfowler/fetch/compare/{compare_ref}...{new_version}"
            ),
        );
    }
}

fn write_update_status(silent: bool, color: Option<&str>, message: impl std::fmt::Display) {
    if !silent {
        core::write_status_with_color(message, color);
    }
}

fn write_update_status_line(silent: bool, color: Option<&str>, message: impl std::fmt::Display) {
    if !silent {
        core::write_status_line_with_color(message, color);
    }
}

fn changelog_compare_ref(old_version: &str) -> String {
    if is_version_tag(old_version) {
        old_version.to_string()
    } else {
        vcs_revision().unwrap_or_default()
    }
}

fn is_version_tag(value: &str) -> bool {
    if value.len() < 6 || !value.starts_with('v') {
        return false;
    }

    let mut dots = 0;
    let bytes = value.as_bytes();
    for i in 1..bytes.len() {
        match bytes[i] {
            b'.' => {
                if i == 1 || i == bytes.len() - 1 || bytes[i - 1] == b'.' {
                    return false;
                }
                dots += 1;
            }
            b'0'..=b'9' => {}
            _ => return false,
        }
    }
    dots == 2
}

fn vcs_revision() -> Option<String> {
    option_env!("FETCH_VCS_REVISION").and_then(|value| {
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    })
}

fn unique_suffix() -> String {
    format!("{:032x}", rand::random::<u128>())
}

#[cfg(test)]
pub(super) mod test_support {
    use std::io::{BufRead, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use std::time::Duration;

    use crate::output::progress::ProgressPrinter;

    #[cfg(unix)]
    use flate2::Compression;
    #[cfg(unix)]
    use flate2::write::GzEncoder;
    #[cfg(unix)]
    use tar::{Builder, Header};

    #[derive(Clone)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    pub(super) fn memory_printer() -> (ProgressPrinter, Arc<Mutex<Vec<u8>>>) {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        (
            ProgressPrinter::new(SharedBuffer(buffer.clone()), false),
            buffer,
        )
    }

    pub(super) fn start_artifact_response(
        headers: Vec<(&'static str, String)>,
        chunks: Vec<Vec<u8>>,
    ) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let join = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                    break;
                }
            }

            write!(stream, "HTTP/1.1 200 OK\r\nConnection: close\r\n").unwrap();
            for (name, value) in headers {
                write!(stream, "{name}: {value}\r\n").unwrap();
            }
            write!(stream, "\r\n").unwrap();
            for chunk in chunks {
                stream.write_all(&chunk).unwrap();
            }
        });
        (url, join)
    }

    fn read_request_line_and_headers(stream: &mut std::net::TcpStream) -> String {
        let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                break;
            }
        }
        request_line
    }

    pub(super) fn start_update_proxy(body: &'static str) -> (String, JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let join = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request_line = read_request_line_and_headers(&mut stream);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
            request_line
        });
        (url, join)
    }

    pub(super) fn start_slow_redirect_response(
        first_delay: Duration,
        final_delay: Duration,
    ) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let join = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = read_request_line_and_headers(&mut stream);
                std::thread::sleep(first_delay);
                let _ = write!(
                    stream,
                    "HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
            }
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = read_request_line_and_headers(&mut stream);
                std::thread::sleep(final_delay);
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                );
            }
        });
        (url, join)
    }

    #[cfg(unix)]
    pub(super) fn create_tar_gz(entries: &[(&str, &[u8], u32, bool)]) -> Vec<u8> {
        let mut data = Vec::new();
        {
            let encoder = GzEncoder::new(&mut data, Compression::default());
            let mut builder = Builder::new(encoder);
            for (name, content, mode, is_dir) in entries {
                let mut header = Header::new_old();
                let name_bytes = name.as_bytes();
                header.as_old_mut().name[..name_bytes.len()].copy_from_slice(name_bytes);
                header.set_mode(*mode);
                header.set_size(if *is_dir { 0 } else { content.len() as u64 });
                if *is_dir {
                    header.set_entry_type(tar::EntryType::Directory);
                }
                header.set_cksum();
                if *is_dir {
                    builder.append(&header, &[][..]).unwrap();
                } else {
                    builder.append(&header, *content).unwrap();
                }
            }
            builder.finish().unwrap();
        }
        data
    }

    pub(super) fn create_zip(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let cursor = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        for (name, content, is_dir) in entries {
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .unix_permissions(if *is_dir { 0o755 } else { 0o644 });
            if *is_dir {
                writer.add_directory(*name, options).unwrap();
            } else {
                writer.start_file(*name, options).unwrap();
                writer.write_all(content).unwrap();
            }
        }
        writer.finish().unwrap().into_inner()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_version_tag() {
        let tests = [
            ("v1.2.3", true),
            ("v0.0.0", true),
            ("v10.20.30", true),
            ("v100.200.300", true),
            ("v(dev)", false),
            ("v0.0.0-20231215164305-abcdef123456", false),
            ("1.2.3", false),
            ("v1.2", false),
            ("v1.2.3.4", false),
            ("v.1.2", false),
            ("v1..2", false),
            ("v1.2.", false),
            ("", false),
            ("v", false),
            ("vx.y.z", false),
            ("v1.2.3-rc1", false),
            ("v1.2.3+meta", false),
        ];

        for (input, want) in tests {
            assert_eq!(is_version_tag(input), want, "is_version_tag({input:?})");
        }
    }

    #[test]
    fn update_success_renders_through_printer() {
        let mut printer = core::Printer::new(false);
        write_update_success_to(&mut printer, "v1.2.3", "v1.2.4");

        assert_eq!(
            printer.into_string().unwrap(),
            "Updated fetch: v1.2.3 -> v1.2.4\n\nChangelog: https://github.com/ryanfowler/fetch/compare/v1.2.3...v1.2.4\n"
        );
    }
}
