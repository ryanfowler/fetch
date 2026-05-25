use std::env;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use reqwest::header::{CONTENT_TYPE, HeaderMap};

use crate::error::FetchError;

use super::RequestBody;

pub(crate) fn edit_request_body(
    headers: &HeaderMap,
    body: RequestBody,
) -> Result<RequestBody, FetchError> {
    let editor = find_editor().ok_or("unable to find an editor")?;
    edit_request_body_with_editor(headers, body, editor)
}

fn edit_request_body_with_editor(
    headers: &HeaderMap,
    body: RequestBody,
    editor: Vec<String>,
) -> Result<RequestBody, FetchError> {
    let content_type = body
        .as_ref()
        .and_then(|(_, content_type)| content_type.clone());
    let input = body.map(|(bytes, _)| bytes).unwrap_or_default();
    let edited = edit_bytes_with_editor(headers, &input, editor)?;
    Ok(Some((edited, content_type)))
}

fn edit_bytes_with_editor(
    headers: &HeaderMap,
    input: &[u8],
    editor: Vec<String>,
) -> Result<Vec<u8>, FetchError> {
    let extension = extension_for_content_type(headers);
    let temp = TempEditFile::create(extension, input)?;
    let path = temp.path_string();

    let mut argv = editor;
    argv.push(path.clone());
    let status = Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|err| FetchError::Message(format!("failed to start editor: {err}")))?;

    if !status.success() {
        return Err(FetchError::Message(format!(
            "editor failed with exit code: {}",
            status.code().unwrap_or(-1)
        )));
    }

    let buf = std::fs::read(&path)?;
    if buf.is_empty() {
        return Err(FetchError::Message(
            "aborting request due to empty request body after editing".to_string(),
        ));
    }
    Ok(buf)
}

fn extension_for_content_type(headers: &HeaderMap) -> &'static str {
    match headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    {
        Some("application/json") => ".json",
        Some("application/xml") | Some("text/xml") => ".xml",
        _ => "",
    }
}

fn find_editor() -> Option<Vec<String>> {
    find_editor_with_env(|name| env::var_os(name).and_then(os_string_to_string))
}

fn find_editor_with_env<F>(mut get_env: F) -> Option<Vec<String>>
where
    F: FnMut(&str) -> Option<String>,
{
    for name in ["VISUAL", "EDITOR"] {
        if let Some(value) = get_env(name)
            && !value.is_empty()
        {
            let args = parse_editor_args(&value);
            if !args.is_empty() {
                return Some(args);
            }
        }
    }

    for name in ["vim", "vi", "nano", "notepad.exe"] {
        if let Some(path) = look_path(name) {
            return Some(vec![path.to_string_lossy().into_owned()]);
        }
    }
    None
}

fn os_string_to_string(value: OsString) -> Option<String> {
    value.into_string().ok()
}

fn parse_editor_args(value: &str) -> Vec<String> {
    let value = value.trim();
    if value.is_empty() {
        return Vec::new();
    }

    if look_path(value).is_some() {
        return vec![value.to_string()];
    }

    if let Some(args) = parse_editor_executable_prefix(value) {
        return args;
    }

    split_args(value)
}

fn parse_editor_executable_prefix(value: &str) -> Option<Vec<String>> {
    let bytes = value.as_bytes();
    for idx in (0..bytes.len()).rev() {
        if bytes[idx] != b' ' && bytes[idx] != b'\t' {
            continue;
        }
        let name = value[..idx].trim();
        if name.is_empty() || look_path(name).is_none() {
            continue;
        }
        let mut args = vec![name.to_string()];
        args.extend(split_args(&value[idx + 1..]));
        return Some(args);
    }
    None
}

fn split_args(value: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut cur = Vec::new();
    let bytes = value.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        let ch = bytes[idx];
        match ch {
            b' ' | b'\t' => {
                if !cur.is_empty() {
                    args.push(String::from_utf8_lossy(&cur).into_owned());
                    cur.clear();
                }
                idx += 1;
            }
            b'\'' | b'"' => {
                let quote = ch;
                idx += 1;
                while idx < bytes.len() && bytes[idx] != quote {
                    cur.push(bytes[idx]);
                    idx += 1;
                }
                if idx < bytes.len() {
                    idx += 1;
                }
            }
            _ => {
                cur.push(ch);
                idx += 1;
            }
        }
    }
    if !cur.is_empty() {
        args.push(String::from_utf8_lossy(&cur).into_owned());
    }
    args
}

fn look_path(command: &str) -> Option<PathBuf> {
    let path = Path::new(command);
    if is_explicit_path(command, path) {
        return is_executable(path).then(|| path.to_path_buf());
    }

    let paths = env::var_os("PATH")?;
    for dir in env::split_paths(&paths) {
        for candidate in command_candidates(&dir, command) {
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

fn is_explicit_path(command: &str, path: &Path) -> bool {
    path.is_absolute() || command.contains('/') || command.contains('\\')
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    let Ok(metadata) = path.metadata() else {
        return false;
    };
    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
}

#[cfg(windows)]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(not(any(unix, windows)))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(windows)]
fn command_candidates(dir: &Path, command: &str) -> Vec<PathBuf> {
    let path = Path::new(command);
    if path.extension().is_some() {
        return vec![dir.join(command)];
    }
    let pathext = env::var_os("PATHEXT")
        .and_then(os_string_to_string)
        .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".to_string());
    pathext
        .split(';')
        .filter(|ext| !ext.is_empty())
        .map(|ext| dir.join(format!("{command}{ext}")))
        .collect()
}

#[cfg(not(windows))]
fn command_candidates(dir: &Path, command: &str) -> Vec<PathBuf> {
    vec![dir.join(command)]
}

struct TempEditFile {
    path: PathBuf,
}

impl TempEditFile {
    fn create(extension: &str, input: &[u8]) -> Result<Self, FetchError> {
        let dir = env::temp_dir();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for idx in 0..1000 {
            let filename = format!(
                "fetch.{}.{}.{}{}",
                std::process::id(),
                stamp,
                idx,
                extension
            );
            let path = dir.join(filename);
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            opts.mode(0o600);
            let file = opts.open(&path);
            let mut file = match file {
                Ok(file) => file,
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(err.into()),
            };
            file.write_all(input)?;
            drop(file);
            let path = absolute_path(path)?;
            return Ok(Self { path });
        }
        Err(FetchError::Message(
            "unable to create temporary edit file".to_string(),
        ))
    }

    fn path_string(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }
}

impl Drop for TempEditFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn absolute_path(path: PathBuf) -> Result<PathBuf, FetchError> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(env::current_dir()?.join(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;

    #[test]
    fn test_split_args() {
        let tests = [
            ("simple command", "vim", vec!["vim"]),
            ("command with flag", "code --wait", vec!["code", "--wait"]),
            (
                "command with multiple flags",
                "nvim -f --clean",
                vec!["nvim", "-f", "--clean"],
            ),
            (
                "double quoted path",
                r#""/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code" --wait"#,
                vec![
                    "/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code",
                    "--wait",
                ],
            ),
            (
                "single quoted path",
                r#"'/usr/local/my editor/bin/edit' -w"#,
                vec!["/usr/local/my editor/bin/edit", "-w"],
            ),
            ("extra whitespace", "  vim   -f  ", vec!["vim", "-f"]),
            (
                "tabs as separators",
                "vim\t-f\t--clean",
                vec!["vim", "-f", "--clean"],
            ),
            ("empty string", "", vec![]),
            ("only whitespace", "   ", vec![]),
            ("quoted empty string arg", r#"vim """#, vec!["vim"]),
            (
                "mixed quotes",
                r#"'/path/to/my editor' "--wait""#,
                vec!["/path/to/my editor", "--wait"],
            ),
            (
                "adjacent quotes and text",
                r#"vim --"clean""#,
                vec!["vim", "--clean"],
            ),
            ("unclosed quote", r#""vim --wait"#, vec!["vim --wait"]),
        ];

        for (name, input, want) in tests {
            assert_eq!(split_args(input), want, "{name}");
        }
    }

    #[test]
    fn test_find_editor() {
        let got = find_editor_with_env(|name| match name {
            "VISUAL" => Some("code --wait".to_string()),
            "EDITOR" => Some("vim".to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!(got, vec!["code", "--wait"]);

        let got = find_editor_with_env(|name| match name {
            "VISUAL" => Some(String::new()),
            "EDITOR" => Some("nvim -f".to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!(got, vec!["nvim", "-f"]);

        let got = find_editor_with_env(|name| match name {
            "VISUAL" => Some(String::new()),
            "EDITOR" => Some(r#""/usr/local/my app/bin/edit" --wait"#.to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!(got, vec!["/usr/local/my app/bin/edit", "--wait"]);

        let dir = tempfile::tempdir().unwrap();
        let editor_dir = dir.path().join("editor path");
        std::fs::create_dir(&editor_dir).unwrap();
        let editor = editor_dir.join(if cfg!(windows) {
            "edit-tool.exe"
        } else {
            "edit-tool"
        });
        std::fs::write(&editor, []).unwrap();
        make_executable(&editor);

        let got = find_editor_with_env(|name| match name {
            "VISUAL" => Some(String::new()),
            "EDITOR" => Some(editor.to_string_lossy().into_owned()),
            _ => None,
        })
        .unwrap();
        assert_eq!(got, vec![editor.to_string_lossy().into_owned()]);

        let got = find_editor_with_env(|name| match name {
            "VISUAL" => Some(String::new()),
            "EDITOR" => Some(format!("{} --wait", editor.display())),
            _ => None,
        })
        .unwrap();
        assert_eq!(
            got,
            vec![editor.to_string_lossy().into_owned(), "--wait".to_string()]
        );
    }

    #[test]
    fn content_type_extensions_match_go_edit_tempfile_policy() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        assert_eq!(extension_for_content_type(&headers), ".json");

        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/xml"));
        assert_eq!(extension_for_content_type(&headers), ".xml");

        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/xml"));
        assert_eq!(extension_for_content_type(&headers), ".xml");

        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        assert_eq!(extension_for_content_type(&headers), "");
    }

    #[cfg(unix)]
    #[test]
    fn temp_edit_file_is_user_readable_only() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempEditFile::create(".json", br#"{"token":"secret"}"#).unwrap();

        let mode = std::fs::metadata(&temp.path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn edit_request_body_uses_existing_body_and_preserves_content_type() {
        let dir = tempfile::tempdir().unwrap();
        let editor = write_script(
            dir.path(),
            "editor",
            r#"#!/bin/sh
printf '%s' '{"edited":true}' > "$1"
"#,
        );
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let body = edit_request_body_with_editor(
            &headers,
            Some((
                br#"{"template":true}"#.to_vec(),
                Some("application/json".to_string()),
            )),
            vec![editor.to_string_lossy().into_owned()],
        )
        .unwrap()
        .unwrap();

        assert_eq!(body.0, br#"{"edited":true}"#);
        assert_eq!(body.1.as_deref(), Some("application/json"));
    }

    #[cfg(unix)]
    #[test]
    fn edit_request_body_rejects_empty_body_after_editing() {
        let dir = tempfile::tempdir().unwrap();
        let editor = write_script(dir.path(), "editor", "#!/bin/sh\n: > \"$1\"\n");
        let err = edit_request_body_with_editor(
            &HeaderMap::new(),
            Some((b"template".to_vec(), None)),
            vec![editor.to_string_lossy().into_owned()],
        )
        .unwrap_err()
        .to_string();

        assert_eq!(
            err,
            "aborting request due to empty request body after editing"
        );
    }

    #[cfg(unix)]
    #[test]
    fn edit_request_body_reports_editor_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let editor = write_script(dir.path(), "editor", "#!/bin/sh\nexit 7\n");
        let err = edit_request_body_with_editor(
            &HeaderMap::new(),
            Some((b"template".to_vec(), None)),
            vec![editor.to_string_lossy().into_owned()],
        )
        .unwrap_err()
        .to_string();

        assert_eq!(err, "editor failed with exit code: 7");
    }

    #[cfg(unix)]
    fn write_script(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        make_executable(&path);
        path
    }

    #[cfg(unix)]
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    #[cfg(not(unix))]
    fn make_executable(_path: &Path) {}
}
