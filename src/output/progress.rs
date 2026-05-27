use std::io::{Read, Write};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::core::{Printer, Sequence};

const BOLD: Sequence = Sequence::Bold;
const DIM: Sequence = Sequence::Dim;
const ITALIC: Sequence = Sequence::Italic;
const GREEN: Sequence = Sequence::Green;

#[derive(Clone)]
pub struct ProgressPrinter {
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    use_color: bool,
}

impl ProgressPrinter {
    pub fn new<W>(writer: W, use_color: bool) -> Self
    where
        W: Write + Send + 'static,
    {
        Self {
            writer: Arc::new(Mutex::new(Box::new(writer))),
            use_color,
        }
    }

    pub fn stderr(color_setting: Option<&str>) -> Self {
        Self::new(
            std::io::stderr(),
            crate::core::stdio().stderr_color(color_setting),
        )
    }

    pub fn stderr_with_color(use_color: bool) -> Self {
        Self::new(std::io::stderr(), use_color)
    }

    fn render(&self, output: &str) {
        let Ok(mut writer) = self.writer.lock() else {
            return;
        };
        let _ = writer.write_all(output.as_bytes());
        let _ = writer.flush();
    }

    fn output_printer(&self) -> Printer {
        Printer::new(self.use_color)
    }

    fn render_printer(&self, printer: Printer) {
        let output = printer
            .into_string()
            .expect("progress output is valid UTF-8");
        self.render(&output);
    }

    #[cfg(test)]
    fn memory(use_color: bool) -> (Self, Arc<Mutex<Vec<u8>>>) {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        (Self::new(SharedBuffer(buffer.clone()), use_color), buffer)
    }
}

// FormatSize converts bytes to a human-readable string.
pub fn format_size(bytes: i64) -> String {
    const UNITS: &[u8] = b"KMGTPE";
    const UNIT: i64 = 1024;

    if bytes < UNIT {
        return format!("{bytes}B");
    }

    let mut div = UNIT;
    let mut exp = 0usize;
    let mut n = bytes / UNIT;
    while n >= 1000 {
        div *= UNIT;
        exp += 1;
        n /= UNIT;
    }

    if exp >= UNITS.len() {
        return "NaN".to_string();
    }

    let value = bytes as f64 / div as f64;
    format!("{value:.1}{}B", UNITS[exp] as char)
}

pub fn format_progress_duration(duration: Duration) -> String {
    if duration < Duration::from_secs(1) {
        format!("{:.1}ms", duration.as_secs_f64() * 1000.0)
    } else if duration < Duration::from_secs(60) {
        format!("{:.1}s", duration.as_secs_f64())
    } else if duration < Duration::from_secs(60 * 60) {
        format!("{:.1}m", duration.as_secs_f64() / 60.0)
    } else {
        format!("{:.1}h", duration.as_secs_f64() / 3600.0)
    }
}

pub fn write_final_progress(
    printer: &ProgressPrinter,
    bytes_read: i64,
    duration: Duration,
    to_clear: i32,
    path: &str,
) {
    let mut out = printer.output_printer();
    if to_clear >= 0 {
        out.push('\r');
    }

    out.push_str("Downloaded ");
    out.write_styled(&format_size(bytes_read), &[BOLD]);
    out.push_str(" in ");
    out.write_styled(&format_progress_duration(duration), &[ITALIC]);

    out.push_str(" to '");
    out.write_styled(path, &[DIM]);
    out.push('\'');

    let padding = (to_clear - path.len() as i32).max(0) as usize;
    push_repeat(&mut out, ' ', padding);
    out.push('\n');

    printer.render_printer(out);
}

pub fn emit_native_progress(printer: &ProgressPrinter, state: i32, percent: i64) {
    let percent = percent.clamp(0, 100);
    printer.render(&format!("\x1b]9;4;{state};{percent}\x1b\\"));
}

pub fn clear_line(printer: &ProgressPrinter, width: usize) {
    let mut out = String::new();
    out.push('\r');
    out.extend(std::iter::repeat_n(' ', width));
    out.push('\r');
    printer.render(&out);
}

pub struct Bar<R> {
    reader: R,
    counter: BarCounter,
}

impl<R> Bar<R> {
    pub fn new(reader: R, printer: ProgressPrinter, total_bytes: i64) -> Self {
        Self::new_with_on_render(
            reader,
            printer,
            total_bytes,
            None::<Box<dyn FnMut(i64) + Send>>,
        )
    }

    pub fn new_with_on_render<F>(
        reader: R,
        printer: ProgressPrinter,
        total_bytes: i64,
        on_render: Option<F>,
    ) -> Self
    where
        F: FnMut(i64) + Send + 'static,
    {
        Self {
            reader,
            counter: BarCounter::new_with_on_render(printer, total_bytes, on_render),
        }
    }

    pub fn stop(&mut self) -> (i64, Duration) {
        self.counter.stop()
    }
}

impl<R> Drop for Bar<R> {
    fn drop(&mut self) {
        self.counter.stop_thread();
    }
}

impl<R: Read> Read for Bar<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.reader.read(buf)?;
        self.counter.add(n as i64);
        Ok(n)
    }
}

pub struct BarCounter {
    bytes_read: Arc<AtomicI64>,
    start: Instant,
    stop_tx: Option<mpsc::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

impl BarCounter {
    pub fn new(printer: ProgressPrinter, total_bytes: i64) -> Self {
        Self::new_with_on_render(printer, total_bytes, None::<Box<dyn FnMut(i64) + Send>>)
    }

    pub fn new_with_on_render<F>(
        printer: ProgressPrinter,
        total_bytes: i64,
        on_render: Option<F>,
    ) -> Self
    where
        F: FnMut(i64) + Send + 'static,
    {
        let bytes_read = Arc::new(AtomicI64::new(0));
        let thread_bytes_read = bytes_read.clone();
        let (stop_tx, stop_rx) = mpsc::channel();
        let mut on_render =
            on_render.map(|callback| Box::new(callback) as Box<dyn FnMut(i64) + Send>);

        let handle = thread::spawn(move || {
            loop {
                match stop_rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                        render_bar(&printer, &thread_bytes_read, total_bytes, &mut on_render);
                        return;
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        render_bar(&printer, &thread_bytes_read, total_bytes, &mut on_render);
                    }
                }
            }
        });

        Self {
            bytes_read,
            start: Instant::now(),
            stop_tx: Some(stop_tx),
            handle: Some(handle),
        }
    }

    pub fn add(&self, bytes: i64) {
        if bytes > 0 {
            self.bytes_read.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    pub fn stop(&mut self) -> (i64, Duration) {
        self.stop_thread();
        (
            self.bytes_read.load(Ordering::Relaxed),
            self.start.elapsed(),
        )
    }

    fn stop_thread(&mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for BarCounter {
    fn drop(&mut self) {
        self.stop_thread();
    }
}

pub struct Spinner<R> {
    reader: R,
    counter: SpinnerCounter,
}

impl<R> Spinner<R> {
    pub fn new(reader: R, printer: ProgressPrinter) -> Self {
        Self::new_with_on_start(reader, printer, None::<Box<dyn FnOnce() + Send>>)
    }

    pub fn new_with_on_start<F>(reader: R, printer: ProgressPrinter, on_start: Option<F>) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        Self {
            reader,
            counter: SpinnerCounter::new_with_on_start(printer, on_start),
        }
    }

    pub fn stop(&mut self) -> (i64, Duration) {
        self.counter.stop()
    }
}

impl<R> Drop for Spinner<R> {
    fn drop(&mut self) {
        self.counter.stop_thread();
    }
}

impl<R: Read> Read for Spinner<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.reader.read(buf)?;
        self.counter.add(n as i64);
        Ok(n)
    }
}

pub struct SpinnerCounter {
    bytes_read: Arc<AtomicI64>,
    start: Instant,
    stop_tx: Option<mpsc::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

impl SpinnerCounter {
    pub fn new(printer: ProgressPrinter) -> Self {
        Self::new_with_on_start(printer, None::<Box<dyn FnOnce() + Send>>)
    }

    pub fn new_with_on_start<F>(printer: ProgressPrinter, on_start: Option<F>) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        let bytes_read = Arc::new(AtomicI64::new(0));
        let thread_bytes_read = bytes_read.clone();
        let (stop_tx, stop_rx) = mpsc::channel();
        let mut on_start = on_start.map(|callback| Box::new(callback) as Box<dyn FnOnce() + Send>);

        let handle = thread::spawn(move || {
            if let Some(callback) = on_start.take() {
                callback();
            }

            let mut position = 0i64;
            loop {
                match stop_rx.recv_timeout(Duration::from_millis(50)) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                        render_spinner(&printer, &thread_bytes_read, position);
                        return;
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        render_spinner(&printer, &thread_bytes_read, position);
                        position += 1;
                    }
                }
            }
        });

        Self {
            bytes_read,
            start: Instant::now(),
            stop_tx: Some(stop_tx),
            handle: Some(handle),
        }
    }

    pub fn add(&self, bytes: i64) {
        if bytes > 0 {
            self.bytes_read.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    pub fn stop(&mut self) -> (i64, Duration) {
        self.stop_thread();
        (
            self.bytes_read.load(Ordering::Relaxed),
            self.start.elapsed(),
        )
    }

    fn stop_thread(&mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for SpinnerCounter {
    fn drop(&mut self) {
        self.stop_thread();
    }
}

fn render_bar(
    printer: &ProgressPrinter,
    bytes_read: &AtomicI64,
    total_bytes: i64,
    on_render: &mut Option<Box<dyn FnMut(i64) + Send>>,
) {
    const BAR_WIDTH: i64 = 30;

    let bytes_read = bytes_read.load(Ordering::Relaxed);
    let percentage = if total_bytes == 0 {
        0
    } else {
        ((bytes_read as i128 * 100) / total_bytes as i128) as i64
    };
    let completed_width = (BAR_WIDTH * percentage / 100).clamp(0, BAR_WIDTH) as usize;

    if let Some(callback) = on_render.as_mut() {
        callback(percentage);
    }

    let mut out = printer.output_printer();
    out.push('\r');

    out.set(BOLD);
    out.push('[');
    out.set(GREEN);
    push_repeat(&mut out, '=', completed_width);
    out.reset();
    push_repeat(
        &mut out,
        ' ',
        (BAR_WIDTH as usize).saturating_sub(completed_width),
    );
    out.set(BOLD);
    out.push_str("] ");

    let pct = percentage.to_string();
    push_repeat(&mut out, ' ', 3usize.saturating_sub(pct.len()));
    out.push_str(&pct);
    out.push('%');
    out.reset();

    out.push_str(" (");
    let size = format_size(bytes_read);
    push_repeat(&mut out, ' ', 7usize.saturating_sub(size.len()));
    out.push_str(&size);
    out.push_str(" / ");
    out.push_str(&format_size(total_bytes));
    out.push(')');

    printer.render_printer(out);
}

fn render_spinner(printer: &ProgressPrinter, bytes_read: &AtomicI64, position: i64) {
    const WIDTH: i64 = 20;

    let position = position % (WIDTH * 2);
    let (value, offset) = if position < WIDTH {
        ("=>", position as usize)
    } else {
        ("<=", (WIDTH * 2 - position - 1) as usize)
    };

    let mut out = printer.output_printer();
    out.push('\r');
    out.set(BOLD);
    out.push('[');
    push_repeat(&mut out, ' ', offset);
    out.set(GREEN);
    out.push_str(value);
    out.reset();
    push_repeat(&mut out, ' ', (WIDTH as usize).saturating_sub(offset + 1));
    out.set(BOLD);
    out.push(']');
    out.reset();

    out.push(' ');
    let size = format_size(bytes_read.load(Ordering::Relaxed));
    push_repeat(&mut out, ' ', 7usize.saturating_sub(size.len()));
    out.push_str(&size);

    printer.render_printer(out);
}

fn push_repeat(out: &mut Printer, ch: char, count: usize) {
    for _ in 0..count {
        out.push(ch);
    }
}

#[cfg(test)]
#[derive(Clone)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

#[cfg(test)]
impl Write for SharedBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn test_printer() -> ProgressPrinter {
        ProgressPrinter::memory(false).0
    }

    #[test]
    fn test_format_size() {
        let tests = [
            (0, "0B"),
            (1, "1B"),
            (512, "512B"),
            (1023, "1023B"),
            (1024, "1.0KB"),
            (1536, "1.5KB"),
            (10240, "10.0KB"),
            (1048576, "1.0MB"),
            (1572864, "1.5MB"),
            (1073741824, "1.0GB"),
            (1099511627776, "1.0TB"),
            (1125899906842624, "1.0PB"),
            (1152921504606846976, "1.0EB"),
        ];

        for (bytes, want) in tests {
            assert_eq!(format_size(bytes), want, "FormatSize({bytes})");
        }
    }

    #[test]
    fn test_format_size_boundaries() {
        let tests = [
            ("just under 1KB", 1023, "1023B"),
            ("exactly 1KB", 1024, "1.0KB"),
            ("just under 1MB", 1048575, "1.0MB"),
            ("exactly 1MB", 1048576, "1.0MB"),
            ("999KB", 999 * 1024, "999.0KB"),
            ("1000KB promotes to MB", 1000 * 1024, "1.0MB"),
        ];

        for (name, bytes, want) in tests {
            assert_eq!(format_size(bytes), want, "{name}");
        }
    }

    #[test]
    fn test_bar_read_passthrough() {
        let data = b"hello, world!".to_vec();
        let reader = std::io::Cursor::new(data.clone());
        let printer = test_printer();
        let mut bar = Bar::new(reader, printer, data.len() as i64);

        let mut got = Vec::new();
        bar.read_to_end(&mut got).unwrap();
        assert_eq!(got, data);

        let (bytes_read, _) = bar.stop();
        assert_eq!(bytes_read, data.len() as i64);
    }

    #[test]
    fn test_bar_read_large_data() {
        let data = vec![b'x'; 100_000];
        let reader = std::io::Cursor::new(data.clone());
        let printer = test_printer();
        let mut bar = Bar::new(reader, printer, data.len() as i64);

        let mut got = Vec::new();
        bar.read_to_end(&mut got).unwrap();
        assert_eq!(got.len(), data.len());

        let (bytes_read, _) = bar.stop();
        assert_eq!(bytes_read, data.len() as i64);
    }

    #[test]
    fn test_bar_on_render_callback() {
        let data = vec![b'x'; 1024];
        let reader = std::io::Cursor::new(data.clone());
        let printer = test_printer();
        let called = Arc::new(AtomicBool::new(false));
        let callback_called = called.clone();

        let mut bar = Bar::new_with_on_render(
            reader,
            printer,
            data.len() as i64,
            Some(move |pct| {
                callback_called.store(true, Ordering::SeqCst);
                assert!((0..=100).contains(&pct), "percentage out of range: {pct}");
            }),
        );
        let mut got = Vec::new();
        bar.read_to_end(&mut got).unwrap();
        bar.stop();

        assert!(
            called.load(Ordering::SeqCst),
            "onRender callback was never called"
        );
    }

    #[test]
    fn test_spinner_read_passthrough() {
        let data = b"spinner test data".to_vec();
        let reader = std::io::Cursor::new(data.clone());
        let printer = test_printer();
        let mut spinner = Spinner::new(reader, printer);

        let mut got = Vec::new();
        spinner.read_to_end(&mut got).unwrap();
        assert_eq!(got, data);

        let (bytes_read, _) = spinner.stop();
        assert_eq!(bytes_read, data.len() as i64);
    }

    #[test]
    fn test_spinner_on_start_callback() {
        let data = b"test".to_vec();
        let reader = std::io::Cursor::new(data);
        let printer = test_printer();
        let called = Arc::new(AtomicBool::new(false));
        let callback_called = called.clone();

        let mut spinner = Spinner::new_with_on_start(
            reader,
            printer,
            Some(move || {
                callback_called.store(true, Ordering::SeqCst);
            }),
        );
        let mut got = Vec::new();
        spinner.read_to_end(&mut got).unwrap();
        spinner.stop();

        assert!(
            called.load(Ordering::SeqCst),
            "onStart callback was never called"
        );
    }

    #[test]
    fn test_bar_empty_read() {
        let reader = std::io::Cursor::new(Vec::<u8>::new());
        let printer = test_printer();
        let mut bar = Bar::new(reader, printer, 1);

        let mut got = Vec::new();
        bar.read_to_end(&mut got).unwrap();
        assert!(
            got.is_empty(),
            "expected empty read, got {} bytes",
            got.len()
        );

        let (bytes_read, _) = bar.stop();
        assert_eq!(bytes_read, 0);
    }

    #[test]
    fn test_spinner_empty_read() {
        let reader = std::io::Cursor::new(Vec::<u8>::new());
        let printer = test_printer();
        let mut spinner = Spinner::new(reader, printer);

        let mut got = Vec::new();
        spinner.read_to_end(&mut got).unwrap();
        assert!(
            got.is_empty(),
            "expected empty read, got {} bytes",
            got.len()
        );

        let (bytes_read, _) = spinner.stop();
        assert_eq!(bytes_read, 0);
    }

    #[test]
    fn render_shapes_match_go_without_color() {
        let (printer, buffer) = ProgressPrinter::memory(false);
        let bytes_read = AtomicI64::new(13);
        render_bar(&printer, &bytes_read, 13, &mut None);
        assert_eq!(
            String::from_utf8(buffer.lock().unwrap().clone()).unwrap(),
            "\r[==============================] 100% (    13B / 13B)"
        );

        let (printer, buffer) = ProgressPrinter::memory(false);
        let bytes_read = AtomicI64::new(17);
        render_spinner(&printer, &bytes_read, 0);
        assert_eq!(
            String::from_utf8(buffer.lock().unwrap().clone()).unwrap(),
            "\r[=>                   ]     17B"
        );
    }

    #[test]
    fn render_shapes_use_core_sequences_with_color() {
        let (printer, buffer) = ProgressPrinter::memory(true);
        let bytes_read = AtomicI64::new(13);
        render_bar(&printer, &bytes_read, 13, &mut None);
        let output = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();

        assert!(output.contains(&Sequence::Bold.ansi()), "{output:?}");
        assert!(output.contains(&Sequence::Green.ansi()), "{output:?}");
        assert!(output.contains(&Sequence::Reset.ansi()), "{output:?}");
    }

    #[test]
    fn bar_counter_renders_and_tracks_manual_progress() {
        let (printer, buffer) = ProgressPrinter::memory(false);
        let mut counter = BarCounter::new(printer, 13);

        counter.add(5);
        counter.add(8);
        let (bytes_read, _) = counter.stop();

        assert_eq!(bytes_read, 13);
        assert_eq!(
            String::from_utf8(buffer.lock().unwrap().clone()).unwrap(),
            "\r[==============================] 100% (    13B / 13B)"
        );
    }

    #[test]
    fn spinner_counter_renders_and_tracks_manual_progress() {
        let (printer, buffer) = ProgressPrinter::memory(false);
        let mut counter = SpinnerCounter::new(printer);

        counter.add(17);
        let (bytes_read, _) = counter.stop();

        assert_eq!(bytes_read, 17);
        assert_eq!(
            String::from_utf8(buffer.lock().unwrap().clone()).unwrap(),
            "\r[=>                   ]     17B"
        );
    }

    #[test]
    fn format_progress_duration_matches_go_fetch_progress() {
        assert_eq!(
            format_progress_duration(Duration::from_micros(1500)),
            "1.5ms"
        );
        assert_eq!(
            format_progress_duration(Duration::from_millis(1500)),
            "1.5s"
        );
        assert_eq!(format_progress_duration(Duration::from_secs(90)), "1.5m");
        assert_eq!(
            format_progress_duration(Duration::from_secs(90 * 60)),
            "1.5h"
        );
    }

    #[test]
    fn final_progress_summary_shape_without_color() {
        let (printer, buffer) = ProgressPrinter::memory(false);

        write_final_progress(&printer, 13, Duration::from_millis(1500), 20, "/tmp/file");

        assert_eq!(
            String::from_utf8(buffer.lock().unwrap().clone()).unwrap(),
            "\rDownloaded 13B in 1.5s to '/tmp/file'           \n"
        );
    }

    #[test]
    fn native_progress_clamps_percent_like_go() {
        let (printer, buffer) = ProgressPrinter::memory(false);

        emit_native_progress(&printer, 1, 125);
        emit_native_progress(&printer, 1, -5);

        assert_eq!(
            String::from_utf8(buffer.lock().unwrap().clone()).unwrap(),
            "\x1b]9;4;1;100\x1b\\\x1b]9;4;1;0\x1b\\"
        );
    }
}
