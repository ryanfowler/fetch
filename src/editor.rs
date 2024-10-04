use std::{
    env,
    ffi::OsStr,
    fs,
    io::{Seek, Write},
    process::Command,
};

use crate::error::Error;

pub(crate) fn edit(placeholder: Option<&[u8]>, extension: Option<&str>) -> Result<Vec<u8>, Error> {
    let editor = get_editor().ok_or_else(|| Error::new("unable to find an editor"))?;

    let mut file = if let Some(ext) = extension {
        tempfile::NamedTempFile::with_suffix(ext)
    } else {
        tempfile::NamedTempFile::new()
    }?;

    if let Some(placeholder) = placeholder {
        file.write_all(placeholder)?;
        file.rewind()?;
    }

    run_editor(&editor, file.path())?;

    let buf = fs::read(file.path())?;
    Ok(buf)
}

fn get_editor() -> Option<String> {
    if let Ok(editor) = env::var("VISUAL") {
        return Some(editor);
    }
    if let Ok(editor) = env::var("EDITOR") {
        return Some(editor);
    }
    ["vim", "vi", "nano", "notepad.exe"]
        .iter()
        .find_map(|v| which(v))
}

fn which(name: &str) -> Option<String> {
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths).find_map(|dir| {
            let path = dir.join(name);
            if path.is_file() {
                Some(name.to_string())
            } else {
                None
            }
        })
    })
}

fn run_editor(editor: &str, path: impl AsRef<OsStr>) -> Result<(), Error> {
    let status = Command::new(editor).arg(path).status()?;
    if status.success() {
        Ok(())
    } else {
        let msg = if let Some(code) = status.code() {
            format!("editor exited with status: {code}")
        } else {
            "editor was unsuccessful".to_string()
        };
        Err(Error::new(msg))
    }
}
