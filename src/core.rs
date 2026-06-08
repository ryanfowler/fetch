use std::fmt;
use std::io::{IsTerminal, Write};
use std::sync::OnceLock;

pub const DEFAULT_ACCEPT_HEADER: &str = "application/json, */*;q=0.5";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    Unknown,
    Auto,
    On,
    Off,
}

impl Color {
    pub fn from_setting(setting: Option<&str>) -> Self {
        match setting {
            Some("on") => Self::On,
            Some("off") => Self::Off,
            Some("auto") | None => Self::Auto,
            Some(_) => Self::Unknown,
        }
    }

    pub fn enabled(self, is_terminal: bool) -> bool {
        match self {
            Self::On => true,
            Self::Off => false,
            Self::Auto | Self::Unknown => is_terminal,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Unknown,
    Auto,
    Off,
    On,
}

impl Format {
    pub fn from_setting(setting: Option<&str>) -> Self {
        match setting {
            Some("on") => Self::On,
            Some("off") => Self::Off,
            Some("auto") | None => Self::Auto,
            Some(_) => Self::Unknown,
        }
    }

    pub fn enabled(self, is_terminal: bool) -> bool {
        match self {
            Self::On => true,
            Self::Off => false,
            Self::Auto | Self::Unknown => is_terminal,
        }
    }
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
    External,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stdio {
    stdin_is_terminal: bool,
    stderr_is_terminal: bool,
    stdout_is_terminal: bool,
}

impl Stdio {
    fn new(stdin_is_terminal: bool, stderr_is_terminal: bool, stdout_is_terminal: bool) -> Self {
        Self {
            stdin_is_terminal,
            stderr_is_terminal,
            stdout_is_terminal,
        }
    }

    fn detect() -> Self {
        Self::new(
            std::io::stdin().is_terminal(),
            std::io::stderr().is_terminal(),
            std::io::stdout().is_terminal(),
        )
    }

    pub fn stdin_is_terminal(self) -> bool {
        self.stdin_is_terminal
    }

    pub fn stderr_is_terminal(self) -> bool {
        self.stderr_is_terminal
    }

    pub fn stdout_is_terminal(self) -> bool {
        self.stdout_is_terminal
    }

    pub fn all_terminal(self) -> bool {
        self.stdin_is_terminal && self.stderr_is_terminal && self.stdout_is_terminal
    }

    pub fn stderr_color(self, setting: Option<&str>) -> bool {
        color_enabled(setting, self.stderr_is_terminal)
    }

    pub fn stdout_color(self, setting: Option<&str>) -> bool {
        color_enabled(setting, self.stdout_is_terminal)
    }

    pub fn stderr_printer(self, setting: Option<&str>) -> Printer {
        Printer::with_color_setting(setting, self.stderr_is_terminal)
    }

    pub fn stdout_printer(self, setting: Option<&str>) -> Printer {
        Printer::with_color_setting(setting, self.stdout_is_terminal)
    }

    pub fn printer_handle(self, setting: Option<&str>) -> PrinterHandle {
        PrinterHandle::new(setting, self.stderr_is_terminal, self.stdout_is_terminal)
    }
}

static STDIO: OnceLock<Stdio> = OnceLock::new();

pub fn stdio() -> Stdio {
    *STDIO.get_or_init(Stdio::detect)
}

pub fn cut_trimmed<'a>(s: &'a str, sep: &str) -> Option<(&'a str, &'a str)> {
    let (key, val) = s.split_once(sep)?;
    Some((key.trim(), val.trim()))
}

pub fn color_enabled(setting: Option<&str>, is_terminal: bool) -> bool {
    Color::from_setting(setting).enabled(is_terminal)
}

pub fn format_enabled(setting: Option<&str>, is_terminal: bool) -> bool {
    Format::from_setting(setting).enabled(is_terminal)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdoutWriteStatus {
    Open,
    Closed,
}

pub fn is_broken_pipe(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::BrokenPipe
}

pub fn stdout_write_status(result: std::io::Result<()>) -> std::io::Result<StdoutWriteStatus> {
    match result {
        Ok(()) => Ok(StdoutWriteStatus::Open),
        Err(err) if is_broken_pipe(&err) => Ok(StdoutWriteStatus::Closed),
        Err(err) => Err(err),
    }
}

pub fn write_stdout(bytes: impl AsRef<[u8]>) -> std::io::Result<StdoutWriteStatus> {
    let mut stdout = std::io::stdout().lock();
    stdout_write_status(stdout.write_all(bytes.as_ref()))
}

pub fn bytes_appear_printable(bytes: &[u8]) -> bool {
    let mut preview = bytes;
    if bytes.len() > 1024 {
        preview = &bytes[..1024];
    }
    if preview.contains(&0) {
        return false;
    }

    let mut safe = 0usize;
    let mut total = 0usize;
    let mut remaining = preview;
    while !remaining.is_empty() {
        match std::str::from_utf8(remaining) {
            Ok(valid) => {
                for ch in valid.chars() {
                    total += 1;
                    if ch.is_whitespace() || !ch.is_control() || ch == '\x1b' {
                        safe += 1;
                    }
                }
                break;
            }
            Err(err) => {
                let valid_up_to = err.valid_up_to();
                if valid_up_to > 0 {
                    let valid = std::str::from_utf8(&remaining[..valid_up_to])
                        .expect("valid prefix reported by utf8 error");
                    for ch in valid.chars() {
                        total += 1;
                        if ch.is_whitespace() || !ch.is_control() || ch == '\x1b' {
                            safe += 1;
                        }
                    }
                }
                if err.error_len().is_none() {
                    break;
                }
                total += 1;
                remaining = &remaining[valid_up_to + err.error_len().unwrap()..];
            }
        }
    }

    total == 0 || (safe as f64 / total as f64) >= 0.9
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
        stdio().stderr_printer(setting)
    }

    pub fn stdout(setting: Option<&str>) -> Self {
        stdio().stdout_printer(setting)
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

pub fn write_warning_separator_no_flush(printer: &mut Printer) {
    printer.push('\n');
}

pub fn write_status_msg_no_flush(printer: &mut Printer, msg: impl fmt::Display) {
    printer.push_str(&msg.to_string());
}

pub fn write_status_line_no_flush(printer: &mut Printer, msg: impl fmt::Display) {
    write_status_msg_no_flush(printer, msg);
    printer.push('\n');
}

pub fn write_status_with_color(msg: impl fmt::Display, color: Option<&str>) {
    let mut printer = Printer::stderr(color);
    write_status_msg_no_flush(&mut printer, msg);
    flush_stderr(printer);
}

pub fn write_status_line_with_color(msg: impl fmt::Display, color: Option<&str>) {
    let mut printer = Printer::stderr(color);
    write_status_line_no_flush(&mut printer, msg);
    flush_stderr(printer);
}

pub fn flush_stderr(mut printer: Printer) {
    let mut stderr = std::io::stderr();
    let _ = printer.flush_to(&mut stderr);
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
    pub fn stdio(color_setting: Option<&str>) -> Self {
        stdio().printer_handle(color_setting)
    }

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

pub fn version() -> &'static str {
    option_env!("FETCH_VERSION").unwrap_or("v0.0.0-dev")
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
    fn format_enabled_matches_go_auto_policy() {
        assert!(format_enabled(Some("on"), false));
        assert!(format_enabled(Some("on"), true));
        assert!(!format_enabled(Some("off"), true));
        assert!(!format_enabled(Some("off"), false));
        assert!(format_enabled(None, true));
        assert!(!format_enabled(None, false));
        assert!(format_enabled(Some("auto"), true));
        assert!(!format_enabled(Some("auto"), false));
    }

    #[test]
    fn stdout_write_status_treats_broken_pipe_as_closed() {
        let err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "stdout closed");

        assert_eq!(
            stdout_write_status(Err(err)).unwrap(),
            StdoutWriteStatus::Closed
        );
        assert_eq!(
            stdout_write_status(Ok(())).unwrap(),
            StdoutWriteStatus::Open
        );
    }

    #[test]
    fn stdio_builds_target_specific_printers() {
        let stdio = Stdio::new(true, false, true);
        assert!(stdio.stdin_is_terminal());
        assert!(!stdio.stderr_is_terminal());
        assert!(stdio.stdout_is_terminal());
        assert!(!stdio.all_terminal());

        let mut stderr = stdio.stderr_printer(Some("auto"));
        stderr.write_styled("err", &[Sequence::Red]);
        assert_eq!(stderr.into_string().unwrap(), "err");

        let mut stdout = stdio.stdout_printer(Some("auto"));
        stdout.write_styled("out", &[Sequence::Green]);
        assert_eq!(stdout.into_string().unwrap(), "\x1b[32mout\x1b[0m");
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

    #[test]
    fn warning_separator_separates_warnings_from_following_output() {
        let mut printer = Printer::new(false);
        write_warning_msg_no_flush(&mut printer, "one");
        write_warning_msg_no_flush(&mut printer, "two");
        write_warning_separator_no_flush(&mut printer);
        printer.push_str("next\n");

        assert_eq!(
            printer.into_string().unwrap(),
            "warning: one\nwarning: two\n\nnext\n"
        );
    }

    #[test]
    fn status_helpers_write_plain_text_without_labels() {
        let mut printer = Printer::new(false);
        write_status_msg_no_flush(&mut printer, "Fetching latest release...\n");
        write_status_line_no_flush(
            &mut printer,
            format_args!("Updated fetch: {} -> {}", "v1", "v2"),
        );

        assert_eq!(
            printer.into_string().unwrap(),
            "Fetching latest release...\nUpdated fetch: v1 -> v2\n"
        );
    }
}
