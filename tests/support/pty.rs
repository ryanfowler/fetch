#![cfg(unix)]

use std::fs;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use std::os::fd::{FromRawFd, RawFd};

pub(crate) struct PtyPair {
    pub(crate) master: fs::File,
    pub(crate) slave: fs::File,
}

pub(crate) struct PtyCapture {
    pub(crate) file: fs::File,
    pub(crate) buffer: Arc<Mutex<Vec<u8>>>,
    pub(crate) done: mpsc::Receiver<()>,
}

pub(crate) fn open_pty(rows: u16, cols: u16, xpixel: u16, ypixel: u16) -> PtyPair {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    #[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
    let winsize = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: xpixel,
        ws_ypixel: ypixel,
    };
    #[cfg(not(all(target_os = "linux", not(target_env = "uclibc"))))]
    let mut winsize = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: xpixel,
        ws_ypixel: ypixel,
    };
    #[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
    let winsize_ptr = &winsize;
    #[cfg(not(all(target_os = "linux", not(target_env = "uclibc"))))]
    let winsize_ptr = &mut winsize;
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            winsize_ptr,
        )
    };
    assert_eq!(rc, 0, "openpty failed");
    PtyPair {
        master: unsafe { fs::File::from_raw_fd(master) },
        slave: unsafe { fs::File::from_raw_fd(slave) },
    }
}

pub(crate) fn start_pty_capture(file: &fs::File) -> PtyCapture {
    let mut read_file = file.try_clone().unwrap();
    let write_file = file.try_clone().unwrap();
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let buffer_for_thread = Arc::clone(&buffer);
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut responded = false;
        let mut chunk = [0_u8; 1024];
        loop {
            match read_file.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    let needs_cursor_response = {
                        let mut buf = buffer_for_thread.lock().unwrap();
                        buf.extend_from_slice(&chunk[..n]);
                        !responded && buf.windows(4).any(|w| w == b"\x1b[6n")
                    };
                    if needs_cursor_response {
                        responded = true;
                        let mut writer = write_file.try_clone().unwrap();
                        let _ = writer.write_all(b"\x1b[1;1R");
                    }
                }
                Err(_) => break,
            }
        }
        let _ = tx.send(());
    });
    PtyCapture {
        file: file.try_clone().unwrap(),
        buffer,
        done: rx,
    }
}

impl PtyCapture {
    pub(crate) fn output(&self) -> String {
        String::from_utf8_lossy(&self.buffer.lock().unwrap()).into_owned()
    }

    pub(crate) fn wait_for(&self, want: &str, timeout: Duration) {
        let start = Instant::now();
        loop {
            if self.output().contains(want) {
                return;
            }
            assert!(
                start.elapsed() < timeout,
                "timed out waiting for PTY output {want:?}; output:\n{}",
                self.output()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub(crate) fn close(self) {
        drop(self.file);
        let _ = self.done.recv_timeout(Duration::from_secs(1));
    }
}

pub(crate) fn configure_pty_child(cmd: &mut Command, slave: &fs::File) {
    use std::os::unix::process::CommandExt;
    cmd.stdin(Stdio::from(slave.try_clone().unwrap()));
    cmd.stdout(Stdio::from(slave.try_clone().unwrap()));
    cmd.stderr(Stdio::from(slave.try_clone().unwrap()));
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(0 as RawFd, libc::TIOCSCTTY as libc::c_ulong, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}
