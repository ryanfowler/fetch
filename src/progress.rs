use std::{
    io::{self, Write},
    time::Duration,
};

use indicatif::{ProgressBar, ProgressStyle};

use crate::fetch::IS_STDERR_TTY;

pub(crate) struct ProgressReader<R> {
    inner: R,
    progress: ProgressBar,
    has_err: bool,
}

impl<R> ProgressReader<R> {
    pub(crate) fn new(r: R, size: Option<u64>, hidden: bool) -> Self {
        if *IS_STDERR_TTY {
            console::set_colors_enabled(true);
        }
        let progress = if hidden {
            ProgressBar::hidden()
        } else if let Some(size) = size {
            ProgressBar::new(size).with_style(
                ProgressStyle::with_template(
                    "{bar:40.cyan/blue} {bytes}/{total_bytes:.bold} [{elapsed}]",
                )
                .unwrap(),
            )
        } else {
            let progress = ProgressBar::new_spinner().with_style(
                ProgressStyle::with_template(" {spinner:.blue} {bytes:.bold} [{elapsed}]")
                    .unwrap()
                    .tick_strings(&["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷", "⣿"]),
            );
            progress.enable_steady_tick(Duration::from_millis(100));
            progress
        };

        // Call tick to print the progress bar to stderr.
        progress.tick();

        Self {
            inner: r,
            progress,
            has_err: false,
        }
    }
}

impl<R: io::Read> io::Read for ProgressReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let res = self.inner.read(buf);
        if res.is_err() {
            self.has_err = true;
        }
        let len = res?;
        self.progress.inc(len as u64);
        Ok(len)
    }
}

impl<R> Drop for ProgressReader<R> {
    fn drop(&mut self) {
        if self.has_err {
            self.progress.abandon();
            _ = io::stderr().write_all("\n\n".as_bytes());
        } else {
            self.progress.finish();
        }
    }
}
