use std::env;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Protocol {
    Block,
    Inline,
    Kitty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Emulator {
    Unknown,
    Alacritty,
    Apple,
    Ghostty,
    Hyper,
    Iterm2,
    Kitty,
    Konsole,
    Mintty,
    Tmux,
    Vscode,
    WezTerm,
    Windows,
    Zellij,
}

impl Emulator {
    fn protocol(self) -> Protocol {
        match self {
            Self::Alacritty
            | Self::Apple
            | Self::Tmux
            | Self::Unknown
            | Self::Vscode
            | Self::Windows
            | Self::Zellij => Protocol::Block,
            Self::Hyper | Self::Iterm2 | Self::Mintty | Self::WezTerm => Protocol::Inline,
            Self::Ghostty | Self::Kitty | Self::Konsole => Protocol::Kitty,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TerminalSize {
    pub(crate) cols: u32,
    pub(crate) rows: u32,
    pub(crate) width_px: u32,
    pub(crate) height_px: u32,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RenderOptions {
    pub(crate) size: TerminalSize,
    pub(crate) protocol: Protocol,
    pub(crate) true_color: bool,
}

pub(crate) fn detect_protocol() -> Protocol {
    detect_emulator().protocol()
}

pub(crate) fn supports_true_color() -> bool {
    supports_true_color_with_env(|name| env::var(name).ok(), cfg!(windows))
}

fn supports_true_color_with_env(get: impl Fn(&str) -> Option<String>, is_windows: bool) -> bool {
    let colorterm = get("COLORTERM").unwrap_or_default();
    colorterm.eq_ignore_ascii_case("truecolor")
        || colorterm.eq_ignore_ascii_case("24bit")
        || (is_windows
            && (get_non_empty(&get, "WT_SESSION").is_some()
                || get("ConEmuANSI").as_deref() == Some("ON")))
}

fn detect_emulator() -> Emulator {
    detect_emulator_with_env(|name| env::var(name).ok())
}

fn detect_emulator_with_env(get: impl Fn(&str) -> Option<String> + Copy) -> Emulator {
    if get_non_empty(&get, "ZELLIJ").is_some() {
        return Emulator::Zellij;
    }
    detect_program_var(get)
        .or_else(|| detect_term_var(get))
        .or_else(|| detect_custom_var(get))
        .unwrap_or(Emulator::Unknown)
}

fn get_non_empty(get: &impl Fn(&str) -> Option<String>, name: &str) -> Option<String> {
    get(name).filter(|value| !value.is_empty())
}

fn detect_program_var(get: impl Fn(&str) -> Option<String>) -> Option<Emulator> {
    match get("TERM_PROGRAM").as_deref() {
        Some("Apple_Terminal") => Some(Emulator::Apple),
        Some("ghostty") => Some(Emulator::Ghostty),
        Some("Hyper") => Some(Emulator::Hyper),
        Some("iTerm.app") => Some(Emulator::Iterm2),
        Some("mintty") => Some(Emulator::Mintty),
        Some("tmux") => Some(Emulator::Tmux),
        Some("vscode") => Some(Emulator::Vscode),
        Some("WezTerm") => Some(Emulator::WezTerm),
        _ => None,
    }
}

fn detect_term_var(get: impl Fn(&str) -> Option<String>) -> Option<Emulator> {
    match get("TERM").as_deref() {
        Some("alacritty") => Some(Emulator::Alacritty),
        Some("xterm-ghostty") => Some(Emulator::Ghostty),
        Some("xterm-kitty") => Some(Emulator::Kitty),
        _ => None,
    }
}

fn detect_custom_var(get: impl Fn(&str) -> Option<String>) -> Option<Emulator> {
    if get_non_empty(&get, "GHOSTTY_BIN_DIR").is_some() {
        Some(Emulator::Ghostty)
    } else if get_non_empty(&get, "ITERM_SESSION_ID").is_some() {
        Some(Emulator::Iterm2)
    } else if get_non_empty(&get, "KITTY_PID").is_some() {
        Some(Emulator::Kitty)
    } else if get_non_empty(&get, "KONSOLE_VERSION").is_some() {
        Some(Emulator::Konsole)
    } else if get_non_empty(&get, "VSCODE_INJECTION").is_some() {
        Some(Emulator::Vscode)
    } else if get_non_empty(&get, "WEZTERM_EXECUTABLE").is_some() {
        Some(Emulator::WezTerm)
    } else if get_non_empty(&get, "WT_SESSION").is_some() {
        Some(Emulator::Windows)
    } else {
        None
    }
}

#[cfg(unix)]
pub(crate) fn terminal_size() -> std::io::Result<TerminalSize> {
    let mut ws = std::mem::MaybeUninit::<libc::winsize>::zeroed();
    let rc = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, ws.as_mut_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let ws = unsafe { ws.assume_init() };
    Ok(TerminalSize {
        cols: u32::from(ws.ws_col),
        rows: u32::from(ws.ws_row),
        width_px: u32::from(ws.ws_xpixel),
        height_px: u32::from(ws.ws_ypixel),
    })
}

#[cfg(not(unix))]
pub(crate) fn terminal_size() -> std::io::Result<TerminalSize> {
    let cols = env::var("COLUMNS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let rows = env::var("LINES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    if cols == 0 || rows == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "terminal size unavailable",
        ));
    }
    Ok(TerminalSize {
        cols,
        rows,
        width_px: 0,
        height_px: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supports_true_color_matches_go_environment_policy() {
        let env = |pairs: &[(&str, &str)], is_windows| {
            supports_true_color_with_env(
                |name| {
                    pairs
                        .iter()
                        .find_map(|(key, value)| (*key == name).then(|| (*value).to_string()))
                },
                is_windows,
            )
        };

        assert!(env(&[("COLORTERM", "truecolor")], false));
        assert!(env(&[("COLORTERM", "24bit")], false));
        assert!(env(&[("COLORTERM", "TRUECOLOR")], false));
        assert!(!env(&[("COLORTERM", "256color")], false));
        assert!(!env(&[("WT_SESSION", "1")], false));
        assert!(!env(&[("ConEmuANSI", "ON")], false));
        assert!(env(&[("WT_SESSION", "1")], true));
        assert!(!env(&[("WT_SESSION", "")], true));
        assert!(env(&[("ConEmuANSI", "ON")], true));
        assert!(!env(&[("ConEmuANSI", "on")], true));
    }

    #[test]
    fn detect_emulator_ignores_empty_environment_values() {
        let pairs = [
            ("TERM", "xterm-kitty"),
            ("TERM_PROGRAM", ""),
            ("ZELLIJ", ""),
            ("GHOSTTY_BIN_DIR", ""),
            ("ITERM_SESSION_ID", ""),
            ("KITTY_PID", ""),
            ("KONSOLE_VERSION", ""),
            ("VSCODE_INJECTION", ""),
            ("WEZTERM_EXECUTABLE", ""),
            ("WT_SESSION", ""),
        ];
        let get = |name: &str| -> Option<String> {
            pairs
                .iter()
                .find_map(|(key, value)| (*key == name).then(|| (*value).to_string()))
        };

        assert_eq!(detect_emulator_with_env(get), Emulator::Kitty);
    }

    #[test]
    fn emulator_detection_protocol_mapping_matches_go() {
        assert_eq!(Emulator::Iterm2.protocol(), Protocol::Inline);
        assert_eq!(Emulator::WezTerm.protocol(), Protocol::Inline);
        assert_eq!(Emulator::Kitty.protocol(), Protocol::Kitty);
        assert_eq!(Emulator::Ghostty.protocol(), Protocol::Kitty);
        assert_eq!(Emulator::Apple.protocol(), Protocol::Block);
    }
}
