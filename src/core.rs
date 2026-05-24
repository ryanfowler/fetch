use std::fmt;
use std::io::IsTerminal;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    Unknown,
    Auto,
    On,
    Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Unknown,
    Auto,
    Off,
    On,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsInteractiveMode {
    Auto,
    On,
    Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Default,
    Http1,
    Http2,
    Http3,
}

impl HttpVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http1 => "HTTP/1.1",
            Self::Http2 => "HTTP/2.0",
            Self::Http3 => "HTTP/3.0",
            Self::Default => "",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageSetting {
    Unknown,
    Auto,
    Native,
    Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verbosity {
    Silent,
    Normal,
    Verbose,
    ExtraVerbose,
    Debug,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyVal<T> {
    pub key: String,
    pub val: T,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalSize {
    pub cols: usize,
    pub rows: usize,
    pub width_px: usize,
    pub height_px: usize,
}

pub fn cut_trimmed<'a>(s: &'a str, sep: &str) -> Option<(&'a str, &'a str)> {
    let (key, val) = s.split_once(sep)?;
    Some((key.trim(), val.trim()))
}

pub fn color_enabled(setting: Option<&str>, is_terminal: bool) -> bool {
    match setting {
        Some("on") => true,
        Some("off") => false,
        _ => is_terminal,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sequence {
    Reset,
    Bold,
    Dim,
    Italic,
    Underline,
    Black,
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    White,
    Default,
}

impl Sequence {
    pub fn code(self) -> &'static str {
        match self {
            Self::Reset => "0",
            Self::Bold => "1",
            Self::Dim => "2",
            Self::Italic => "3",
            Self::Underline => "4",
            Self::Black => "30",
            Self::Red => "31",
            Self::Green => "32",
            Self::Yellow => "33",
            Self::Blue => "34",
            Self::Magenta => "35",
            Self::Cyan => "36",
            Self::White => "37",
            Self::Default => "39",
        }
    }

    pub fn ansi(self) -> String {
        format!("\x1b[{}m", self.code())
    }
}

#[derive(Debug, Clone)]
pub struct Printer {
    buf: Vec<u8>,
    use_color: bool,
}

impl Printer {
    pub fn new(use_color: bool) -> Self {
        Self {
            buf: Vec::new(),
            use_color,
        }
    }

    pub fn with_color_setting(setting: Option<&str>, is_terminal: bool) -> Self {
        Self::new(color_enabled(setting, is_terminal))
    }

    pub fn stderr(setting: Option<&str>) -> Self {
        Self::with_color_setting(setting, std::io::stderr().is_terminal())
    }

    pub fn stdout(setting: Option<&str>) -> Self {
        Self::with_color_setting(setting, std::io::stdout().is_terminal())
    }

    pub fn use_color(&self) -> bool {
        self.use_color
    }

    pub fn set(&mut self, sequence: Sequence) {
        if self.use_color {
            self.buf.extend_from_slice(b"\x1b[");
            self.buf.extend_from_slice(sequence.code().as_bytes());
            self.buf.push(b'm');
        }
    }

    pub fn reset(&mut self) {
        self.set(Sequence::Reset);
    }

    pub fn push(&mut self, ch: char) {
        let mut buf = [0; 4];
        self.push_str(ch.encode_utf8(&mut buf));
    }

    pub fn push_str(&mut self, value: &str) {
        self.buf.extend_from_slice(value.as_bytes());
    }

    pub fn write_styled(&mut self, value: &str, styles: &[Sequence]) {
        if self.use_color {
            for style in styles {
                self.set(*style);
            }
            self.push_str(value);
            self.reset();
        } else {
            self.push_str(value);
        }
    }

    pub fn write_request_prefix(&mut self) {
        self.write_styled("> ", &[Sequence::Dim]);
    }

    pub fn write_response_prefix(&mut self) {
        self.write_styled("< ", &[Sequence::Dim]);
    }

    pub fn write_info_prefix(&mut self) {
        self.write_styled("* ", &[Sequence::Dim]);
    }

    pub fn write_error_label(&mut self) {
        self.write_styled("error", &[Sequence::Red, Sequence::Bold]);
    }

    pub fn write_warning_label(&mut self) {
        self.write_styled("warning", &[Sequence::Bold, Sequence::Yellow]);
    }

    pub fn discard(&mut self) {
        self.buf.clear();
    }

    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn into_string(self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.buf)
    }

    pub fn flush_to(&mut self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
        writer.write_all(&self.buf)?;
        self.buf.clear();
        Ok(())
    }
}

pub fn write_error_msg_no_flush(printer: &mut Printer, err: impl fmt::Display) {
    printer.write_error_label();
    printer.push_str(": ");
    printer.push_str(&err.to_string());
    printer.push_str("\n");
}

pub fn write_warning_msg_no_flush(printer: &mut Printer, msg: impl fmt::Display) {
    printer.write_warning_label();
    printer.push_str(": ");
    printer.push_str(&msg.to_string());
    printer.push_str("\n");
}

impl std::io::Write for Printer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl std::fmt::Write for Printer {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.push_str(s);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct PrinterHandle {
    stderr: Printer,
    stdout: Printer,
}

impl PrinterHandle {
    pub fn new(
        color_setting: Option<&str>,
        stderr_is_terminal: bool,
        stdout_is_terminal: bool,
    ) -> Self {
        Self {
            stderr: Printer::with_color_setting(color_setting, stderr_is_terminal),
            stdout: Printer::with_color_setting(color_setting, stdout_is_terminal),
        }
    }

    pub fn stderr(&mut self) -> &mut Printer {
        &mut self.stderr
    }

    pub fn stdout(&mut self) -> &mut Printer {
        &mut self.stdout
    }
}

pub fn write_styled_to_string(out: &mut String, value: &str, styles: &[Sequence], use_color: bool) {
    if use_color {
        for style in styles {
            out.push_str(&style.ansi());
        }
        out.push_str(value);
        out.push_str(&Sequence::Reset.ansi());
    } else {
        out.push_str(value);
    }
}

pub fn terminal_cols() -> usize {
    terminal_size().map(|size| size.cols).unwrap_or(0)
}

#[cfg(unix)]
pub fn terminal_size() -> Option<TerminalSize> {
    let mut size = std::mem::MaybeUninit::<libc::winsize>::zeroed();
    // SAFETY: ioctl initializes the winsize struct when it succeeds.
    let rc = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, size.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }
    // SAFETY: ioctl returned success, so the winsize value was initialized.
    let size = unsafe { size.assume_init() };
    Some(TerminalSize {
        cols: usize::from(size.ws_col),
        rows: usize::from(size.ws_row),
        width_px: usize::from(size.ws_xpixel),
        height_px: usize::from(size.ws_ypixel),
    })
}

#[cfg(windows)]
pub fn terminal_size() -> Option<TerminalSize> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Console::{
        CONSOLE_SCREEN_BUFFER_INFO, GetConsoleScreenBufferInfo,
    };

    let handle = std::io::stdout().as_raw_handle();
    let mut info = std::mem::MaybeUninit::<CONSOLE_SCREEN_BUFFER_INFO>::zeroed();
    // SAFETY: GetConsoleScreenBufferInfo initializes info when it succeeds.
    let ok = unsafe { GetConsoleScreenBufferInfo(handle as _, info.as_mut_ptr()) };
    if ok == 0 {
        return None;
    }
    // SAFETY: GetConsoleScreenBufferInfo returned success, so info is initialized.
    let info = unsafe { info.assume_init() };
    Some(TerminalSize {
        cols: usize::try_from(info.srWindow.Right - info.srWindow.Left + 1).unwrap_or(0),
        rows: usize::try_from(info.srWindow.Bottom - info.srWindow.Top + 1).unwrap_or(0),
        width_px: 0,
        height_px: 0,
    })
}

#[cfg(not(any(unix, windows)))]
pub fn terminal_size() -> Option<TerminalSize> {
    None
}

const DEFAULT_VERSION: &str = concat!("v", env!("CARGO_PKG_VERSION"));

pub fn version() -> &'static str {
    option_env!("FETCH_VERSION").unwrap_or(DEFAULT_VERSION)
}

pub fn user_agent() -> String {
    format!("fetch/{}", version())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn color_enabled_matches_go_auto_policy() {
        assert!(color_enabled(Some("on"), false));
        assert!(color_enabled(Some("on"), true));
        assert!(!color_enabled(Some("off"), true));
        assert!(!color_enabled(Some("off"), false));
        assert!(color_enabled(None, true));
        assert!(!color_enabled(None, false));
        assert!(color_enabled(Some("auto"), true));
        assert!(!color_enabled(Some("auto"), false));
    }

    #[test]
    fn printer_writes_sequences_only_when_color_is_enabled() {
        let mut printer = Printer::new(true);
        printer.write_styled("ok", &[Sequence::Green, Sequence::Bold]);
        assert_eq!(printer.into_string().unwrap(), "\x1b[32m\x1b[1mok\x1b[0m");

        let mut printer = Printer::new(false);
        printer.write_styled("ok", &[Sequence::Green, Sequence::Bold]);
        assert_eq!(printer.into_string().unwrap(), "ok");
    }

    #[test]
    fn printer_flush_and_discard_manage_the_buffer() {
        let mut printer = Printer::new(false);
        printer.push_str("hello");
        let mut flushed = Vec::new();
        printer.flush_to(&mut flushed).unwrap();
        assert_eq!(flushed, b"hello");
        assert!(printer.bytes().is_empty());

        printer.push_str("unused");
        printer.discard();
        assert!(printer.bytes().is_empty());
    }

    #[test]
    fn printer_handle_uses_per_target_color_policy() {
        let mut handle = PrinterHandle::new(Some("auto"), true, false);
        handle.stderr().write_styled("err", &[Sequence::Red]);
        handle.stdout().write_styled("out", &[Sequence::Green]);

        assert_eq!(
            String::from_utf8(handle.stderr.bytes().to_vec()).unwrap(),
            "\x1b[31merr\x1b[0m"
        );
        assert_eq!(
            String::from_utf8(handle.stdout.bytes().to_vec()).unwrap(),
            "out"
        );
    }

    #[test]
    fn error_and_warning_helpers_match_go_label_styles() {
        let mut printer = Printer::new(true);
        write_error_msg_no_flush(&mut printer, "bad");
        assert_eq!(
            printer.into_string().unwrap(),
            "\x1b[31m\x1b[1merror\x1b[0m: bad\n"
        );

        let mut printer = Printer::new(true);
        write_warning_msg_no_flush(&mut printer, "careful");
        assert_eq!(
            printer.into_string().unwrap(),
            "\x1b[1m\x1b[33mwarning\x1b[0m: careful\n"
        );

        let mut printer = Printer::new(false);
        write_error_msg_no_flush(&mut printer, "bad");
        write_warning_msg_no_flush(&mut printer, "careful");
        assert_eq!(
            printer.into_string().unwrap(),
            "error: bad\nwarning: careful\n"
        );
    }
}
