use std::env;

use super::Protocol;

#[derive(Copy, Clone, Debug)]
pub(crate) enum Emulator {
    Alacritty,
    Apple,
    Ghostty,
    Hyper,
    Iterm2,
    Kitty,
    Konsole,
    Mintty,
    Tmux,
    Unknown,
    VSCode,
    WezTerm,
    Windows,
    Zellij,
}

impl Emulator {
    pub(crate) fn detect() -> Self {
        if env::var_os("ZELLIJ").is_some() {
            return Self::Zellij;
        }

        if let Some(emulator) = Self::detect_term_program_var() {
            return emulator;
        }

        if let Some(emulator) = Self::detect_term_var() {
            return emulator;
        }

        if let Some(emulator) = Self::detect_custom_var() {
            return emulator;
        }

        Self::Unknown
    }

    fn detect_term_program_var() -> Option<Emulator> {
        let values = [
            ("Apple_Terminal", Self::Apple),
            ("ghostty", Self::Ghostty),
            ("Hyper", Self::Hyper),
            ("iTerm.app", Self::Iterm2),
            ("mintty", Self::Mintty),
            ("tmux", Self::Tmux),
            ("vscode", Self::VSCode),
            ("WezTerm", Self::WezTerm),
        ];

        if let Ok(var) = env::var("TERM_PROGRAM") {
            for (value, emulator) in values.into_iter() {
                if var.as_str() == value {
                    return Some(emulator);
                }
            }
        }

        None
    }

    fn detect_term_var() -> Option<Emulator> {
        let values = [
            ("alacritty", Self::Alacritty),
            ("xterm-ghostty", Self::Ghostty),
            ("xterm-kitty", Self::Kitty),
        ];

        if let Ok(var) = env::var("TERM") {
            for (value, emulator) in values.into_iter() {
                if var.as_str() == value {
                    return Some(emulator);
                }
            }
        }
        None
    }

    fn detect_custom_var() -> Option<Emulator> {
        let values = [
            ("GHOSTTY_BIN_DIR", Self::Ghostty),
            ("ITERM_SESSION_ID", Self::Iterm2),
            ("KITTY_PID", Self::Kitty),
            ("KONSOLE_VERSION", Self::Konsole),
            ("VSCODE_INJECTION", Self::VSCode),
            ("WEZTERM_EXECUTABLE", Self::WezTerm),
            ("WT_SESSION", Self::Windows),
        ];

        for (var, emulator) in values.into_iter() {
            if env::var_os(var).is_some() {
                return Some(emulator);
            }
        }
        None
    }

    pub(crate) fn supported_protocol(&self) -> Protocol {
        match self {
            Emulator::Alacritty => Protocol::Block,
            Emulator::Apple => Protocol::Block,
            Emulator::Ghostty => Protocol::Kitty,
            Emulator::Hyper => Protocol::InlineImages,
            Emulator::Iterm2 => Protocol::InlineImages,
            Emulator::Kitty => Protocol::Kitty,
            Emulator::Konsole => Protocol::Kitty,
            Emulator::Mintty => Protocol::InlineImages,
            Emulator::Tmux => Protocol::Block,
            Emulator::Unknown => Protocol::Block,
            Emulator::VSCode => Protocol::Block,
            Emulator::WezTerm => Protocol::InlineImages,
            Emulator::Windows => Protocol::Block,
            Emulator::Zellij => Protocol::Block,
        }
    }
}
