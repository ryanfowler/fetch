use std::io::{self, Read, Write};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use futures_util::{Sink, SinkExt, Stream, StreamExt};
use tokio::sync::mpsc as tokio_mpsc;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

use crate::error::FetchError;
use crate::format::json;

use super::websocket_error;

pub const PROMPT: &str = "❯ ";
const MIN_ROWS: usize = 5;
const READ_BUF_SIZE: usize = 256;
const STDIN_CHAN_BUF: usize = 64;
const MAX_MESSAGES: usize = 10_000;
const STATUS_GAP_ROWS: usize = 1;

#[derive(Debug, Default)]
pub struct LineEditor {
    buf: Vec<char>,
    pos: usize,
}

impl LineEditor {
    pub fn insert(&mut self, ch: char) {
        self.buf.insert(self.pos, ch);
        self.pos += 1;
    }

    pub fn backspace(&mut self) -> bool {
        if self.pos == 0 {
            return false;
        }
        self.pos -= 1;
        self.buf.remove(self.pos);
        true
    }

    pub fn delete(&mut self) -> bool {
        if self.pos >= self.buf.len() {
            return false;
        }
        self.buf.remove(self.pos);
        true
    }

    pub fn move_left(&mut self) -> bool {
        if self.pos == 0 {
            return false;
        }
        self.pos -= 1;
        true
    }

    pub fn move_right(&mut self) -> bool {
        if self.pos >= self.buf.len() {
            return false;
        }
        self.pos += 1;
        true
    }

    pub fn home(&mut self) {
        self.pos = 0;
    }

    pub fn end(&mut self) {
        self.pos = self.buf.len();
    }

    pub fn clear_line(&mut self) {
        self.buf.clear();
        self.pos = 0;
    }

    pub fn delete_word(&mut self) {
        if self.pos == 0 {
            return;
        }
        while self.pos > 0 && self.buf[self.pos - 1] == ' ' {
            self.pos -= 1;
            self.buf.remove(self.pos);
        }
        while self.pos > 0 && self.buf[self.pos - 1] != ' ' {
            self.pos -= 1;
            self.buf.remove(self.pos);
        }
    }

    pub fn submit(&mut self) -> String {
        let text = self.text();
        self.clear_line();
        text
    }

    pub fn text(&self) -> String {
        self.buf.iter().collect()
    }

    pub fn set_text(&mut self, text: &str) {
        self.buf = text.chars().collect();
        self.pos = self.buf.len();
    }

    pub fn position(&self) -> usize {
        self.pos
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageEntry {
    arrow: Option<&'static str>,
    data: Option<Vec<u8>>,
    binary_len: usize,
}

impl MessageEntry {
    pub fn text(arrow: &'static str, data: impl Into<Vec<u8>>) -> Self {
        Self {
            arrow: Some(arrow),
            data: Some(data.into()),
            binary_len: 0,
        }
    }

    pub fn binary(len: usize) -> Self {
        Self {
            arrow: None,
            data: None,
            binary_len: len,
        }
    }
}

#[derive(Debug)]
pub struct InteractiveMode {
    editor: LineEditor,
    rows: usize,
    cols: usize,
    next_row: usize,
    status: String,
    messages: Vec<MessageEntry>,
    format_json: bool,
    color_json: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub enum InputAction {
    Send(String),
    Cancel,
}

impl InteractiveMode {
    pub fn new(cols: usize, format_json: bool) -> Self {
        Self::new_with_color(cols, format_json, false)
    }

    pub fn new_with_color(cols: usize, format_json: bool, color_json: bool) -> Self {
        Self {
            editor: LineEditor::default(),
            rows: 0,
            cols,
            next_row: 0,
            status: "connected".to_string(),
            messages: Vec::new(),
            format_json,
            color_json,
        }
    }

    pub fn editor(&self) -> &LineEditor {
        &self.editor
    }

    pub fn editor_mut(&mut self) -> &mut LineEditor {
        &mut self.editor
    }

    pub fn setup_screen<W: Write>(
        &mut self,
        out: &mut W,
        rows: usize,
        cols: usize,
        initial_cursor_row: usize,
    ) -> io::Result<()> {
        let first_setup = self.rows == 0;

        self.rows = rows;
        self.cols = cols;

        let scroll_end = self.scroll_end();
        if self.next_row == 0 {
            self.next_row = 1;
        }
        if self.next_row > scroll_end {
            self.next_row = scroll_end;
        }

        if !first_setup {
            write!(out, "\x1b[r")?;
            for row in 1..=rows {
                write!(out, "\x1b[{row};1H\x1b[2K")?;
            }
            self.next_row = 1;
        }

        if first_setup {
            let mut cursor_row = initial_cursor_row.max(1);
            if cursor_row >= scroll_end {
                let shift = cursor_row - scroll_end + 2;
                write!(out, "\x1b[{rows};1H")?;
                for _ in 0..shift {
                    writeln!(out)?;
                }
                cursor_row = cursor_row.saturating_sub(shift);
            }

            if cursor_row > 0 {
                self.next_row = (cursor_row + 1).min(scroll_end);
            }

            for row in self.next_row..=rows {
                write!(out, "\x1b[{row};1H\x1b[2K")?;
            }
        }

        write!(out, "\x1b[1;{scroll_end}r")?;
        self.draw_status(out)?;
        self.draw_separator(out, rows)?;

        if !first_setup {
            self.replay_messages(out)?;
        }

        self.draw_input_line(out)
    }

    pub fn teardown_screen<W: Write>(&mut self, out: &mut W) -> io::Result<()> {
        if self.rows == 0 {
            return Ok(());
        }
        write!(out, "\x1b[r")?;
        for row in [
            self.rows.saturating_sub(2),
            self.rows.saturating_sub(1),
            self.rows,
        ] {
            if row > 0 {
                write!(out, "\x1b[{row};1H\x1b[2K")?;
            }
        }
        let exit_row = self.next_row.min(self.scroll_end() + 1);
        write!(out, "\x1b[{exit_row};1H")
    }

    pub fn render_sent_message<W: Write>(&mut self, out: &mut W, data: &[u8]) -> io::Result<()> {
        self.render_message(out, "→", data)
    }

    pub fn render_received_message<W: Write>(
        &mut self,
        out: &mut W,
        data: &[u8],
    ) -> io::Result<()> {
        self.render_message(out, "←", data)
    }

    pub fn render_binary_indicator<W: Write>(&mut self, out: &mut W, len: usize) -> io::Result<()> {
        self.messages.push(MessageEntry::binary(len));
        self.truncate_messages();
        self.write_binary(out, len)?;
        self.draw_input_line(out)
    }

    pub fn set_status<W: Write>(
        &mut self,
        out: &mut W,
        status: impl Into<String>,
    ) -> io::Result<()> {
        self.status = status.into();
        self.draw_status(out)
    }

    pub fn handle_input<W: Write>(
        &mut self,
        out: &mut W,
        buf: &[u8],
    ) -> io::Result<(Vec<u8>, Vec<InputAction>)> {
        let mut actions = Vec::new();
        let mut index = 0;
        while index < buf.len() {
            let byte = buf[index];

            if byte == 0x1b {
                let consumed = self.handle_escape(&buf[index..]);
                if consumed == 0 {
                    return Ok((buf[index..].to_vec(), actions));
                }
                self.draw_input_line(out)?;
                index += consumed;
                continue;
            }

            match byte {
                0x03 | 0x04 => {
                    actions.push(InputAction::Cancel);
                    return Ok((Vec::new(), actions));
                }
                0x0d => {
                    let text = self.editor.submit();
                    self.draw_input_line(out)?;
                    if !text.is_empty() {
                        actions.push(InputAction::Send(text));
                    }
                    index += 1;
                    continue;
                }
                0x7f | 0x08 => {
                    self.editor.backspace();
                    self.draw_input_line(out)?;
                    index += 1;
                    continue;
                }
                0x01 => {
                    self.editor.home();
                    self.draw_input_line(out)?;
                    index += 1;
                    continue;
                }
                0x05 => {
                    self.editor.end();
                    self.draw_input_line(out)?;
                    index += 1;
                    continue;
                }
                0x15 => {
                    self.editor.clear_line();
                    self.draw_input_line(out)?;
                    index += 1;
                    continue;
                }
                0x17 => {
                    self.editor.delete_word();
                    self.draw_input_line(out)?;
                    index += 1;
                    continue;
                }
                _ => {}
            }

            if byte >= 0x20 {
                let Some(width) = utf8_sequence_width(byte) else {
                    index += 1;
                    continue;
                };
                if index + width > buf.len() {
                    return Ok((buf[index..].to_vec(), actions));
                }
                let Ok(text) = std::str::from_utf8(&buf[index..index + width]) else {
                    index += 1;
                    continue;
                };
                let ch = text.chars().next().expect("non-empty UTF-8 sequence");
                self.editor.insert(ch);
                self.draw_input_line(out)?;
                index += width;
                continue;
            }

            index += 1;
        }
        Ok((Vec::new(), actions))
    }

    pub fn note_send_success<W: Write>(&mut self, out: &mut W, data: &[u8]) -> io::Result<()> {
        self.status = format!("sent {} bytes", data.len());
        self.draw_status(out)?;
        self.render_sent_message(out, data)
    }

    pub fn note_send_failure<W: Write>(
        &mut self,
        out: &mut W,
        text: &str,
        err: impl std::fmt::Display,
    ) -> io::Result<()> {
        self.status = format!("send failed: {err}");
        self.editor.set_text(text);
        self.draw_status(out)?;
        self.draw_input_line(out)
    }

    pub fn handle_escape(&mut self, buf: &[u8]) -> usize {
        if buf.len() < 2 {
            return 0;
        }
        if buf[1] != b'[' {
            return 1;
        }
        if buf.len() < 3 {
            return 0;
        }

        match buf[2] {
            b'C' => {
                self.editor.move_right();
                3
            }
            b'D' => {
                self.editor.move_left();
                3
            }
            b'H' => {
                self.editor.home();
                3
            }
            b'F' => {
                self.editor.end();
                3
            }
            b'3' => {
                if buf.len() < 4 {
                    return 0;
                }
                if buf[3] == b'~' {
                    self.editor.delete();
                    4
                } else {
                    3
                }
            }
            _ => {
                for (index, byte) in buf.iter().enumerate().skip(2) {
                    if (0x40..=0x7e).contains(byte) {
                        return index + 1;
                    }
                }
                0
            }
        }
    }

    pub fn message_row_count(&self, msg: &MessageEntry) -> Result<usize, FetchError> {
        let Some(data) = msg.data.as_deref() else {
            return Ok(1);
        };
        let arrow = msg.arrow.unwrap_or("←");
        let prefix_width = display_width(&format!("{arrow} "));
        let width = self.cols.saturating_sub(prefix_width).max(1);
        Ok(wrap_display_lines(&self.format_message(data)?, width).len())
    }

    pub fn format_message(&self, data: &[u8]) -> Result<String, FetchError> {
        if self.format_json && serde_json::from_slice::<serde_json::Value>(data).is_ok() {
            let mut formatted = crate::core::Printer::new(self.color_json);
            if json::format_json_line_to(data, &mut formatted).is_ok() {
                let formatted = formatted.into_bytes();
                let text = String::from_utf8_lossy(&formatted);
                return Ok(if self.color_json {
                    text.trim_end_matches('\n').to_string()
                } else {
                    sanitize_message_text(text.trim_end_matches('\n'))
                });
            }
        }
        Ok(sanitize_message_text(&String::from_utf8_lossy(data)))
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    pub fn cols(&self) -> usize {
        self.cols
    }

    pub fn next_row(&self) -> usize {
        self.next_row
    }

    pub fn is_screen_tall_enough(rows: usize) -> bool {
        rows >= MIN_ROWS
    }

    fn render_message<W: Write>(
        &mut self,
        out: &mut W,
        arrow: &'static str,
        data: &[u8],
    ) -> io::Result<()> {
        self.messages.push(MessageEntry::text(arrow, data));
        self.truncate_messages();
        self.write_message(out, arrow, data)?;
        self.draw_input_line(out)
    }

    fn replay_messages<W: Write>(&mut self, out: &mut W) -> io::Result<()> {
        if self.messages.is_empty() {
            return Ok(());
        }

        let scroll_end = self.scroll_end();
        let mut start = self.messages.len();
        let mut used = 0;
        for index in (0..self.messages.len()).rev() {
            let rows = self
                .message_row_count(&self.messages[index])
                .map_err(io::Error::other)?;
            if used + rows > scroll_end && start != self.messages.len() {
                break;
            }
            used += rows;
            start = index;
        }

        let replay = self.messages[start..].to_vec();
        for message in replay {
            if let Some(data) = message.data {
                self.write_message(out, message.arrow.unwrap_or("←"), &data)?;
            } else {
                self.write_binary(out, message.binary_len)?;
            }
        }
        Ok(())
    }

    fn draw_separator<W: Write>(&self, out: &mut W, row: usize) -> io::Result<()> {
        write!(out, "\x1b[{row};1H\x1b[2K\x1b[90m")?;
        for _ in 0..self.cols {
            write!(out, "─")?;
        }
        write!(out, "\x1b[0m")
    }

    fn draw_status<W: Write>(&self, out: &mut W) -> io::Result<()> {
        if self.rows < 2 {
            return Ok(());
        }
        let row = self.rows - 2;
        let status = sanitize_message_text(&self.status).replace('\n', " ");
        let status = fit_display_width(&status, self.cols);
        write!(out, "\x1b[{row};1H\x1b[2K\x1b[90m{status}\x1b[0m")
    }

    fn draw_input_line<W: Write>(&self, out: &mut W) -> io::Result<()> {
        if self.rows < 1 {
            return Ok(());
        }
        let input_row = self.rows - 1;
        let text = self.editor.text();
        let pos = self.editor.position();
        let available = self.cols.saturating_sub(display_width(PROMPT)).max(1);
        let runes: Vec<char> = text.chars().collect();

        let width_to_cursor = runes
            .iter()
            .take(pos)
            .map(|ch| char_display_width(*ch).max(1))
            .sum::<usize>();
        let mut display_start = 0;
        if width_to_cursor >= available {
            let mut width = 0;
            for index in (0..pos).rev() {
                width += char_display_width(runes[index]).max(1);
                if width >= available {
                    display_start = index + 1;
                    break;
                }
            }
        }

        let mut cursor_col = display_width(PROMPT);
        for ch in runes.iter().take(pos).skip(display_start) {
            cursor_col += char_display_width(*ch).max(1);
        }

        write!(out, "\x1b[{input_row};1H\x1b[2K")?;
        write!(out, "\x1b[1m{PROMPT}\x1b[0m")?;

        let mut displayed_width = 0;
        for ch in runes.iter().skip(display_start) {
            let char_width = char_display_width(*ch).max(1);
            if displayed_width + char_width > available {
                break;
            }
            write!(out, "{ch}")?;
            displayed_width += char_width;
        }

        write!(out, "\x1b[{input_row};{}H", cursor_col + 1)
    }

    fn write_message<W: Write>(
        &mut self,
        out: &mut W,
        arrow: &'static str,
        data: &[u8],
    ) -> io::Result<()> {
        let prefix = format!("{arrow} ");
        let continuation = "  ";
        let width = self.cols.saturating_sub(display_width(&prefix)).max(1);
        let formatted = self.format_message(data).map_err(io::Error::other)?;
        let lines = wrap_display_lines(&formatted, width);
        for (index, line) in lines.iter().enumerate() {
            self.write_physical_line(out)?;
            if index == 0 {
                write!(out, "\x1b[2m{prefix}\x1b[0m")?;
            } else {
                write!(out, "{continuation}")?;
            }
            write!(out, "{line}")?;
        }
        Ok(())
    }

    fn write_binary<W: Write>(&mut self, out: &mut W, len: usize) -> io::Result<()> {
        self.write_physical_line(out)?;
        write!(out, "\x1b[2m← [binary {len} bytes]\x1b[0m")
    }

    fn write_physical_line<W: Write>(&mut self, out: &mut W) -> io::Result<()> {
        let scroll_end = self.scroll_end();
        if self.next_row <= scroll_end {
            let row = self.next_row;
            write!(out, "\x1b[{row};1H\x1b[2K")?;
            self.next_row += 1;
        } else {
            write!(out, "\x1b[{scroll_end};1H\n\x1b[2K")?;
        }
        Ok(())
    }

    fn scroll_end(&self) -> usize {
        self.rows.saturating_sub(3 + STATUS_GAP_ROWS).max(1)
    }

    fn truncate_messages(&mut self) {
        if self.messages.len() > MAX_MESSAGES {
            let keep_from = self.messages.len() - MAX_MESSAGES;
            self.messages.drain(..keep_from);
        }
    }
}

pub async fn run_terminal<S>(
    stream: S,
    initial_message: Option<&[u8]>,
    format_json: bool,
    color_json: bool,
    rows: usize,
    cols: usize,
) -> Result<(), FetchError>
where
    S: Stream<Item = Result<Message, WsError>> + Sink<Message, Error = WsError> + Unpin,
{
    let _raw = RawTerminal::enter()?;
    let mut stdout = io::stdout();
    let (input_tx, mut input_rx) = tokio_mpsc::channel(STDIN_CHAN_BUF);
    spawn_stdin_reader(input_tx);

    let mut mode = InteractiveMode::new_with_color(cols, format_json, color_json);
    let (initial_row, mut pending) = detect_cursor_row_async(&mut input_rx, &mut stdout).await?;
    mode.setup_screen(&mut stdout, rows, cols, initial_row)?;
    stdout.flush()?;

    let (mut sink, mut source) = stream.split();
    let mut resize_interval = tokio::time::interval(Duration::from_millis(250));
    resize_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    resize_interval.tick().await;

    if let Some(data) = initial_message.filter(|data| !data.is_empty()) {
        if let Err(err) = send_text(&mut sink, data).await {
            teardown(&mut mode, &mut stdout)?;
            return Err(err);
        }
        mode.render_sent_message(&mut stdout, data)?;
        stdout.flush()?;
    }

    loop {
        tokio::select! {
            raw = input_rx.recv() => {
                let Some(raw) = raw else {
                    teardown(&mut mode, &mut stdout)?;
                    return Ok(());
                };
                pending.extend_from_slice(&raw);
                let (rest, actions) = mode.handle_input(&mut stdout, &pending)?;
                pending = rest;
                stdout.flush()?;
                for action in actions {
                    match action {
                        InputAction::Cancel => {
                            teardown(&mut mode, &mut stdout)?;
                            let _ = sink.send(Message::Close(None)).await;
                            return Ok(());
                        }
                        InputAction::Send(text) => {
                            let data = text.as_bytes().to_vec();
                            match send_text(&mut sink, &data).await {
                                Ok(()) => mode.note_send_success(&mut stdout, &data)?,
                                Err(err) => mode.note_send_failure(&mut stdout, &text, err)?,
                            }
                            stdout.flush()?;
                        }
                    }
                }
            }
            message = source.next() => {
                let Some(message) = message else {
                    teardown(&mut mode, &mut stdout)?;
                    return Ok(());
                };
                match message.map_err(websocket_error)? {
                    Message::Text(text) => mode.render_received_message(&mut stdout, text.as_str().as_bytes())?,
                    Message::Binary(bytes) => mode.render_binary_indicator(&mut stdout, bytes.len())?,
                    Message::Close(_) => {
                        teardown(&mut mode, &mut stdout)?;
                        return Ok(());
                    }
                    Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
                }
                stdout.flush()?;
            }
            _ = resize_interval.tick() => {
                if let Some(size) = crate::core::terminal_size() {
                    if !InteractiveMode::is_screen_tall_enough(size.rows) {
                        teardown(&mut mode, &mut stdout)?;
                        let _ = sink.send(Message::Close(None)).await;
                        return Ok(());
                    }
                    if size.rows != mode.rows() || size.cols != mode.cols() {
                        mode.setup_screen(&mut stdout, size.rows, size.cols, 0)?;
                        stdout.flush()?;
                    }
                }
            }
        }
    }
}

async fn send_text<S>(sink: &mut S, data: &[u8]) -> Result<(), FetchError>
where
    S: Sink<Message, Error = WsError> + Unpin,
{
    sink.send(Message::Text(
        String::from_utf8_lossy(data).into_owned().into(),
    ))
    .await
    .map_err(websocket_error)
}

fn spawn_stdin_reader(tx: tokio_mpsc::Sender<Vec<u8>>) {
    thread::spawn(move || {
        let mut stdin = io::stdin();
        let mut buf = [0_u8; READ_BUF_SIZE];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => return,
                Ok(n) => {
                    if tx.blocking_send(buf[..n].to_vec()).is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    });
}

async fn detect_cursor_row_async<W: Write>(
    input_rx: &mut tokio_mpsc::Receiver<Vec<u8>>,
    out: &mut W,
) -> io::Result<(usize, Vec<u8>)> {
    write!(out, "\x1b[6n")?;
    out.flush()?;

    let mut captured = Vec::new();
    let deadline = tokio::time::sleep(Duration::from_secs(1));
    tokio::pin!(deadline);

    loop {
        let (row, remaining, ok) = extract_cursor_row(&captured);
        if ok {
            return Ok((row.max(1), remaining));
        }

        tokio::select! {
            raw = input_rx.recv() => {
                let Some(raw) = raw else {
                    return Ok((1, captured));
                };
                captured.extend_from_slice(&raw);
            }
            _ = &mut deadline => {
                return Ok((1, captured));
            }
        }
    }
}

fn teardown<W: Write>(mode: &mut InteractiveMode, out: &mut W) -> io::Result<()> {
    mode.teardown_screen(out)?;
    out.flush()
}

fn utf8_sequence_width(byte: u8) -> Option<usize> {
    match byte {
        0x00..=0x7f => Some(1),
        0xc2..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf4 => Some(4),
        _ => None,
    }
}

#[cfg(unix)]
struct RawTerminal {
    saved: libc::termios,
    active: bool,
}

#[cfg(unix)]
impl RawTerminal {
    fn enter() -> io::Result<Self> {
        let fd = libc::STDIN_FILENO;
        let mut saved = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: tcgetattr initializes saved when it returns success.
        let rc = unsafe { libc::tcgetattr(fd, saved.as_mut_ptr()) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: tcgetattr returned success, so saved is initialized.
        let saved = unsafe { saved.assume_init() };
        let mut raw = saved;
        // SAFETY: cfmakeraw mutates a valid termios struct.
        unsafe { libc::cfmakeraw(&mut raw) };
        // SAFETY: tcsetattr reads a valid termios struct.
        let rc = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            saved,
            active: true,
        })
    }

    fn restore(&mut self) {
        if self.active {
            // SAFETY: self.saved was captured from tcgetattr for stdin.
            let _ = unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.saved) };
            self.active = false;
        }
    }
}

#[cfg(windows)]
struct RawTerminal {
    handle: windows_sys::Win32::Foundation::HANDLE,
    saved: u32,
    active: bool,
}

#[cfg(windows)]
impl RawTerminal {
    fn enter() -> io::Result<Self> {
        use windows_sys::Win32::System::Console::{
            ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
            ENABLE_VIRTUAL_TERMINAL_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE,
            SetConsoleMode,
        };

        // SAFETY: GetStdHandle does not require additional invariants.
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut saved = 0;
        // SAFETY: saved points to writable memory.
        if unsafe { GetConsoleMode(handle, &mut saved) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let raw = (saved & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT))
            | ENABLE_VIRTUAL_TERMINAL_INPUT;
        // SAFETY: handle is a console input handle and raw is a console mode bitset.
        if unsafe { SetConsoleMode(handle, raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            handle,
            saved,
            active: true,
        })
    }

    fn restore(&mut self) {
        if self.active {
            use windows_sys::Win32::System::Console::SetConsoleMode;
            // SAFETY: handle and saved were captured from GetConsoleMode.
            let _ = unsafe { SetConsoleMode(self.handle, self.saved) };
            self.active = false;
        }
    }
}

#[cfg(not(any(unix, windows)))]
struct RawTerminal;

#[cfg(not(any(unix, windows)))]
impl RawTerminal {
    fn enter() -> io::Result<Self> {
        Ok(Self)
    }

    fn restore(&mut self) {}
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        self.restore();
    }
}

pub fn parse_cursor_row(resp: &[u8]) -> usize {
    let Some(start) = resp.iter().position(|byte| *byte == b'[') else {
        return 1;
    };
    let Some(semi) = resp.iter().position(|byte| *byte == b';') else {
        return 1;
    };
    if start >= semi {
        return 1;
    }
    std::str::from_utf8(&resp[start + 1..semi])
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1)
}

pub fn extract_cursor_row(buf: &[u8]) -> (usize, Vec<u8>, bool) {
    for i in 0..buf.len() {
        if buf[i] != 0x1b || i + 1 >= buf.len() || buf[i + 1] != b'[' {
            continue;
        }

        let mut j = i + 2;
        while j < buf.len() && buf[j].is_ascii_digit() {
            j += 1;
        }
        if j == i + 2 || j >= buf.len() || buf[j] != b';' {
            continue;
        }
        j += 1;

        let col_start = j;
        while j < buf.len() && buf[j].is_ascii_digit() {
            j += 1;
        }
        if j == col_start || j >= buf.len() || buf[j] != b'R' {
            continue;
        }

        let row = parse_cursor_row(&buf[i..=j]);
        let mut remaining = Vec::with_capacity(buf.len().saturating_sub(j - i + 1));
        remaining.extend_from_slice(&buf[..i]);
        remaining.extend_from_slice(&buf[j + 1..]);
        return (row, remaining, true);
    }

    (0, buf.to_vec(), false)
}

pub fn detect_cursor_row(input: &mpsc::Receiver<Vec<u8>>) -> (usize, Vec<u8>) {
    detect_cursor_row_with_timeout(input, Duration::from_secs(1))
}

pub fn detect_cursor_row_with_timeout(
    input: &mpsc::Receiver<Vec<u8>>,
    timeout: Duration,
) -> (usize, Vec<u8>) {
    let mut captured = Vec::new();
    loop {
        let (row, remaining, ok) = extract_cursor_row(&captured);
        if ok {
            return (row.max(1), remaining);
        }

        match input.recv_timeout(timeout) {
            Ok(raw) => captured.extend_from_slice(&raw),
            Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => {
                return (1, captured);
            }
        }
    }
}

pub fn sanitize_message_text(text: &str) -> String {
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut out = String::new();
    for ch in text.chars() {
        match ch {
            '\n' => out.push('\n'),
            '\t' => out.push_str("    "),
            '\x1b' => out.push_str(r"\x1b"),
            ch if ch.is_control() => {
                let value = ch as u32;
                if value <= 0xff {
                    out.push_str(&format!(r"\x{value:02x}"));
                } else {
                    out.push_str(&format!("{ch:?}"));
                }
            }
            ch => out.push(ch),
        }
    }
    out
}

pub fn wrap_display_lines(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    for part in text.split('\n') {
        if part.is_empty() {
            lines.push(String::new());
            continue;
        }

        let mut line = String::new();
        let mut line_width = 0;
        let mut index = 0;
        while index < part.len() {
            if let Some((sequence, next)) = ansi_csi_sequence(part, index) {
                line.push_str(sequence);
                index = next;
                continue;
            }

            let ch = part[index..]
                .chars()
                .next()
                .expect("index is inside string bounds");
            let char_width = char_display_width(ch).max(1);
            if line_width > 0 && line_width + char_width > width {
                lines.push(std::mem::take(&mut line));
                line_width = 0;
            }
            line.push(ch);
            line_width += char_width;
            index += ch.len_utf8();
        }
        lines.push(line);
    }

    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

pub fn fit_display_width(text: &str, width: usize) -> String {
    if width < 1 {
        return String::new();
    }
    let mut out = String::new();
    let mut used = 0;
    for ch in text.chars() {
        let char_width = char_display_width(ch).max(1);
        if used + char_width > width {
            break;
        }
        out.push(ch);
        used += char_width;
    }
    out
}

fn display_width(text: &str) -> usize {
    let mut width = 0;
    let mut index = 0;
    while index < text.len() {
        if let Some((_, next)) = ansi_csi_sequence(text, index) {
            index = next;
            continue;
        }
        let ch = text[index..]
            .chars()
            .next()
            .expect("index is inside string bounds");
        width += char_display_width(ch).max(1);
        index += ch.len_utf8();
    }
    width
}

fn ansi_csi_sequence(text: &str, start: usize) -> Option<(&str, usize)> {
    let bytes = text.as_bytes();
    if bytes.get(start) != Some(&b'\x1b') || bytes.get(start + 1) != Some(&b'[') {
        return None;
    }

    for index in start + 2..bytes.len() {
        if (0x40..=0x7e).contains(&bytes[index]) {
            return Some((&text[start..=index], index + 1));
        }
    }
    None
}

fn char_display_width(ch: char) -> usize {
    if ch == '\n' || ch == '\r' {
        return 0;
    }
    if is_wide(ch) { 2 } else { 1 }
}

fn is_wide(ch: char) -> bool {
    matches!(
        ch as u32,
        0x1100..=0x115f
            | 0x2329..=0x232a
            | 0x2e80..=0xa4cf
            | 0xac00..=0xd7a3
            | 0xf900..=0xfaff
            | 0xfe10..=0xfe19
            | 0xfe30..=0xfe6f
            | 0xff00..=0xff60
            | 0xffe0..=0xffe6
            | 0x1f300..=0x1f64f
            | 0x1f900..=0x1f9ff
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_line_editor_insert() {
        let mut editor = LineEditor::default();
        editor.insert('h');
        editor.insert('i');

        assert_eq!(editor.text(), "hi");
        assert_eq!(editor.position(), 2);
    }

    #[test]
    fn test_line_editor_backspace() {
        let mut editor = LineEditor::default();
        editor.insert('a');
        editor.insert('b');
        editor.insert('c');

        assert!(editor.backspace());
        assert_eq!(editor.text(), "ab");

        editor.home();
        assert!(!editor.backspace());
    }

    #[test]
    fn test_line_editor_delete() {
        let mut editor = LineEditor::default();
        editor.insert('a');
        editor.insert('b');
        editor.insert('c');
        editor.home();

        assert!(editor.delete());
        assert_eq!(editor.text(), "bc");

        editor.end();
        assert!(!editor.delete());
    }

    #[test]
    fn test_line_editor_movement() {
        let mut editor = LineEditor::default();
        editor.insert('a');
        editor.insert('b');
        editor.insert('c');

        assert!(editor.move_left());
        assert_eq!(editor.position(), 2);

        editor.home();
        assert_eq!(editor.position(), 0);
        assert!(!editor.move_left());

        editor.end();
        assert_eq!(editor.position(), 3);
        assert!(!editor.move_right());

        editor.home();
        assert!(editor.move_right());
        assert_eq!(editor.position(), 1);
    }

    #[test]
    fn test_line_editor_clear_line() {
        let mut editor = LineEditor::default();
        editor.insert('a');
        editor.insert('b');
        editor.clear_line();

        assert_eq!(editor.text(), "");
        assert_eq!(editor.position(), 0);
    }

    #[test]
    fn test_line_editor_delete_word() {
        let mut editor = LineEditor::default();
        for ch in "hello world".chars() {
            editor.insert(ch);
        }

        editor.delete_word();
        assert_eq!(editor.text(), "hello ");

        editor.delete_word();
        assert_eq!(editor.text(), "");

        editor.delete_word();
        assert_eq!(editor.text(), "");
    }

    #[test]
    fn test_line_editor_submit() {
        let mut editor = LineEditor::default();
        for ch in "test".chars() {
            editor.insert(ch);
        }

        assert_eq!(editor.submit(), "test");
        assert_eq!(editor.text(), "");
        assert_eq!(editor.position(), 0);
    }

    #[test]
    fn test_line_editor_unicode() {
        let mut editor = LineEditor::default();
        editor.insert('日');
        editor.insert('本');
        editor.insert('語');

        assert_eq!(editor.text(), "日本語");
        editor.move_left();
        editor.backspace();
        assert_eq!(editor.text(), "日語");
    }

    #[test]
    fn test_line_editor_insert_middle() {
        let mut editor = LineEditor::default();
        editor.insert('a');
        editor.insert('c');
        editor.move_left();
        editor.insert('b');

        assert_eq!(editor.text(), "abc");
        assert_eq!(editor.position(), 2);
    }

    #[test]
    fn test_handle_escape_arrows() {
        let mut mode = InteractiveMode::new(80, false);
        mode.editor_mut().insert('a');
        mode.editor_mut().insert('b');
        mode.editor_mut().insert('c');

        assert_eq!(mode.handle_escape(&[0x1b, b'[', b'D']), 3);
        assert_eq!(mode.editor().position(), 2);

        assert_eq!(mode.handle_escape(&[0x1b, b'[', b'C']), 3);
        assert_eq!(mode.editor().position(), 3);

        assert_eq!(mode.handle_escape(&[0x1b, b'[', b'H']), 3);
        assert_eq!(mode.editor().position(), 0);

        assert_eq!(mode.handle_escape(&[0x1b, b'[', b'F']), 3);
        assert_eq!(mode.editor().position(), 3);
    }

    #[test]
    fn test_handle_escape_delete() {
        let mut mode = InteractiveMode::new(80, false);
        mode.editor_mut().insert('a');
        mode.editor_mut().insert('b');
        mode.editor_mut().home();

        assert_eq!(mode.handle_escape(&[0x1b, b'[', b'3', b'~']), 4);
        assert_eq!(mode.editor().text(), "b");
    }

    #[test]
    fn test_handle_escape_incomplete() {
        let mut mode = InteractiveMode::new(80, false);

        assert_eq!(mode.handle_escape(&[0x1b]), 0);
        assert_eq!(mode.handle_escape(&[0x1b, b'[']), 0);
        assert_eq!(mode.handle_escape(&[0x1b, b'[', b'3']), 0);
    }

    #[test]
    fn test_sanitize_message_text() {
        let got = sanitize_message_text("ok\x1b[31m\r\nbad\x00\tend");
        let want = r"ok\x1b[31m".to_string() + "\n" + r"bad\x00    end";

        assert_eq!(got, want);
    }

    #[test]
    fn test_wrap_display_lines() {
        let cases = [
            ("wraps ascii", "abcdef", 3, vec!["abc", "def"]),
            ("preserves explicit newlines", "ab\ncd", 8, vec!["ab", "cd"]),
            (
                "wide runes count as two cells",
                "日本語",
                4,
                vec!["日本", "語"],
            ),
            (
                "ansi sgr sequences do not count toward width",
                "\x1b[34mabc\x1b[0mdef",
                3,
                vec!["\x1b[34mabc\x1b[0m", "def"],
            ),
        ];

        for (name, input, width, want) in cases {
            assert_eq!(wrap_display_lines(input, width), want, "{name}");
        }
    }

    #[test]
    fn test_interactive_message_row_count() {
        let mode = InteractiveMode::new(7, false);

        let msg = MessageEntry::text("←", b"abcdef");
        assert_eq!(mode.message_row_count(&msg).unwrap(), 2);

        let msg = MessageEntry::text("←", b"ab\ncd");
        assert_eq!(mode.message_row_count(&msg).unwrap(), 2);

        let msg = MessageEntry::binary(10);
        assert_eq!(mode.message_row_count(&msg).unwrap(), 1);
    }

    #[test]
    fn test_extract_cursor_row() {
        let cases = [
            (
                "plain dsr response",
                b"\x1b[12;34R".as_slice(),
                12,
                Vec::new(),
                true,
            ),
            (
                "bytes before and after dsr are preserved",
                b"abc\x1b[7;9Rxyz".as_slice(),
                7,
                b"abcxyz".to_vec(),
                true,
            ),
            (
                "non-dsr bytes are left untouched",
                b"hello".as_slice(),
                0,
                b"hello".to_vec(),
                false,
            ),
            (
                "incomplete dsr stays buffered",
                b"\x1b[12;".as_slice(),
                0,
                b"\x1b[12;".to_vec(),
                false,
            ),
        ];

        for (name, input, want_row, want_rest, want_found) in cases {
            let (row, rest, found) = extract_cursor_row(input);
            assert_eq!(row, want_row, "{name}");
            assert_eq!(rest, want_rest, "{name}");
            assert_eq!(found, want_found, "{name}");
        }
    }

    #[test]
    fn test_detect_cursor_row() {
        let (tx, rx) = mpsc::channel();
        tx.send(b"x".to_vec()).unwrap();
        tx.send(b"\x1b[23;45Ry".to_vec()).unwrap();
        drop(tx);

        let (row, pending) = detect_cursor_row(&rx);

        assert_eq!(row, 23);
        assert_eq!(pending, b"xy");
    }

    #[test]
    fn test_detect_cursor_row_closed_input_falls_back_to_row_1() {
        let (_tx, rx) = mpsc::channel();

        let (row, pending) = detect_cursor_row_with_timeout(&rx, Duration::from_millis(1));

        assert_eq!(row, 1);
        assert!(pending.is_empty());
    }

    #[test]
    fn test_detect_cursor_row_timeout_preserves_buffered_bytes() {
        let (tx, rx) = mpsc::channel();
        tx.send(b"typed".to_vec()).unwrap();

        let (row, pending) = detect_cursor_row_with_timeout(&rx, Duration::from_millis(1));

        assert_eq!(row, 1);
        assert_eq!(pending, b"typed");
    }

    #[test]
    fn fit_display_width_respects_wide_runes() {
        assert_eq!(fit_display_width("abc", 2), "ab");
        assert_eq!(fit_display_width("日本語", 4), "日本");
        assert_eq!(fit_display_width("日本語", 3), "日");
        assert_eq!(fit_display_width("abc", 0), "");
    }

    #[test]
    fn screen_min_rows_matches_go_interactive_boundary() {
        assert!(!InteractiveMode::is_screen_tall_enough(4));
        assert!(InteractiveMode::is_screen_tall_enough(5));
    }

    #[test]
    fn setup_screen_draws_scroll_region_status_separator_and_prompt() {
        let mut mode = InteractiveMode::new(10, false);
        let mut out = Vec::new();

        mode.setup_screen(&mut out, 8, 10, 1).unwrap();
        let out = String::from_utf8(out).unwrap();

        assert!(out.contains("\x1b[1;4r"), "{out:?}");
        assert!(out.contains("\x1b[6;1H\x1b[2K\x1b[90mconnected\x1b[0m"));
        assert!(out.contains("\x1b[8;1H\x1b[2K\x1b[90m──────────\x1b[0m"));
        assert!(out.contains("\x1b[7;1H\x1b[2K\x1b[1m❯ \x1b[0m"));
        assert_eq!(mode.rows(), 8);
        assert_eq!(mode.cols(), 10);
        assert_eq!(mode.next_row(), 2);
    }

    #[test]
    fn setup_screen_pushes_bottom_cursor_content_into_scrollback() {
        let mut mode = InteractiveMode::new(10, false);
        let mut out = Vec::new();

        mode.setup_screen(&mut out, 8, 10, 7).unwrap();
        let out = String::from_utf8(out).unwrap();

        assert!(out.contains("\x1b[8;1H\n\n\n\n\n"), "{out:?}");
        assert_eq!(mode.next_row(), 3);
    }

    #[test]
    fn render_messages_wraps_lines_and_redraws_prompt() {
        let mut mode = InteractiveMode::new(7, false);
        let mut out = Vec::new();
        mode.setup_screen(&mut out, 8, 7, 1).unwrap();
        out.clear();

        mode.render_received_message(&mut out, b"abcdef").unwrap();
        let out = String::from_utf8(out).unwrap();

        assert!(out.contains("\x1b[2m← \x1b[0mabcde"), "{out:?}");
        assert!(out.contains("  f"), "{out:?}");
        assert!(out.contains("\x1b[7;1H\x1b[2K\x1b[1m❯ \x1b[0m"));
    }

    #[test]
    fn render_binary_indicator_matches_go_shape() {
        let mut mode = InteractiveMode::new(20, false);
        let mut out = Vec::new();
        mode.setup_screen(&mut out, 8, 20, 1).unwrap();
        out.clear();

        mode.render_binary_indicator(&mut out, 42).unwrap();
        let out = String::from_utf8(out).unwrap();

        assert!(out.contains("\x1b[2m← [binary 42 bytes]\x1b[0m"));
    }

    #[test]
    fn set_status_sanitizes_and_truncates_to_terminal_width() {
        let mut mode = InteractiveMode::new(8, false);
        let mut out = Vec::new();
        mode.setup_screen(&mut out, 8, 8, 1).unwrap();
        out.clear();

        mode.set_status(&mut out, "ok\x1b[31m\nvery long").unwrap();
        let out = String::from_utf8(out).unwrap();

        assert!(out.contains(r"ok\x1b[3"), "{out:?}");
        assert!(!out.contains('\n'));
    }

    #[test]
    fn teardown_screen_resets_scroll_region_and_clears_chrome() {
        let mut mode = InteractiveMode::new(10, false);
        let mut out = Vec::new();
        mode.setup_screen(&mut out, 8, 10, 1).unwrap();
        out.clear();

        mode.teardown_screen(&mut out).unwrap();
        let out = String::from_utf8(out).unwrap();

        assert!(out.starts_with("\x1b[r"), "{out:?}");
        assert!(out.contains("\x1b[6;1H\x1b[2K"));
        assert!(out.contains("\x1b[7;1H\x1b[2K"));
        assert!(out.contains("\x1b[8;1H\x1b[2K"));
    }

    #[test]
    fn format_message_formats_json_when_enabled() {
        let mode = InteractiveMode::new(80, true);
        let formatted = mode.format_message(br#"{"ok":true}"#).unwrap();

        assert_eq!(formatted, r#"{ "ok": true }"#);
    }

    #[test]
    fn format_message_colors_json_when_enabled() {
        let mode = InteractiveMode::new_with_color(80, true, true);
        let formatted = mode.format_message(br#"{"ok":"yes"}"#).unwrap();

        assert!(formatted.contains("\"\x1b[34m\x1b[1mok\x1b[0m\""));
        assert!(formatted.contains("\"\x1b[32myes\x1b[0m\""));
    }

    #[test]
    fn handle_input_submits_text_messages_on_enter() {
        let mut mode = InteractiveMode::new(20, false);
        let mut out = Vec::new();
        mode.setup_screen(&mut out, 8, 20, 1).unwrap();
        out.clear();

        let (rest, actions) = mode.handle_input(&mut out, b"hi\r").unwrap();

        assert!(rest.is_empty());
        assert_eq!(actions, vec![InputAction::Send("hi".to_string())]);
        assert_eq!(mode.editor().text(), "");
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("\x1b[7;1H\x1b[2K\x1b[1m❯ \x1b[0m"));
    }

    #[test]
    fn handle_input_preserves_incomplete_utf8_until_next_read() {
        let mut mode = InteractiveMode::new(20, false);
        let mut out = Vec::new();
        mode.setup_screen(&mut out, 8, 20, 1).unwrap();
        out.clear();

        let (mut pending, actions) = mode.handle_input(&mut out, &[0xe6, 0x97]).unwrap();
        assert_eq!(pending, vec![0xe6, 0x97]);
        assert!(actions.is_empty());
        assert_eq!(mode.editor().text(), "");

        pending.push(0xa5);
        let (pending, actions) = mode.handle_input(&mut out, &pending).unwrap();
        assert!(pending.is_empty());
        assert!(actions.is_empty());
        assert_eq!(mode.editor().text(), "日");
    }

    #[test]
    fn handle_input_ctrl_c_requests_cancel() {
        let mut mode = InteractiveMode::new(20, false);
        let mut out = Vec::new();

        let (rest, actions) = mode.handle_input(&mut out, &[0x03]).unwrap();

        assert!(rest.is_empty());
        assert_eq!(actions, vec![InputAction::Cancel]);
    }

    #[test]
    fn send_success_updates_status_and_renders_sent_message() {
        let mut mode = InteractiveMode::new(20, false);
        let mut out = Vec::new();
        mode.setup_screen(&mut out, 8, 20, 1).unwrap();
        out.clear();

        mode.note_send_success(&mut out, b"hello").unwrap();
        let out = String::from_utf8(out).unwrap();

        assert!(out.contains("\x1b[6;1H\x1b[2K\x1b[90msent 5 bytes\x1b[0m"));
        assert!(out.contains("\x1b[2m→ \x1b[0mhello"));
    }

    #[test]
    fn send_failure_restores_editor_text_and_status() {
        let mut mode = InteractiveMode::new(24, false);
        let mut out = Vec::new();
        mode.setup_screen(&mut out, 8, 24, 1).unwrap();
        out.clear();

        mode.note_send_failure(&mut out, "retry me", "closed")
            .unwrap();
        let out = String::from_utf8(out).unwrap();

        assert_eq!(mode.editor().text(), "retry me");
        assert!(out.contains("send failed: closed"));
        assert!(out.contains("❯ \x1b[0mretry me"));
    }
}
