use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

pub(crate) const PARTIAL_REPLAY_BODY_PREFIX_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub(crate) struct TestRequest {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) headers: HashMap<String, String>,
    pub(crate) header_lines: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl TestRequest {
    pub(crate) fn header(&self, name: &str) -> String {
        self.headers
            .get(&name.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn header_values(&self, name: &str) -> Vec<String> {
        self.header_lines
            .iter()
            .filter(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
            .collect()
    }

    pub(crate) fn body_string(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

pub(crate) struct TestResponse {
    pub(crate) status: u16,
    pub(crate) reason: &'static str,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
    pub(crate) h2_reset: Option<h2::Reason>,
}

impl TestResponse {
    pub(crate) fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 200,
            reason: "OK",
            headers: Vec::new(),
            body: body.into(),
            h2_reset: None,
        }
    }

    pub(crate) fn status(status: u16, reason: &'static str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            reason,
            headers: Vec::new(),
            body: body.into(),
            h2_reset: None,
        }
    }

    pub(crate) fn h2_reset(reason: h2::Reason) -> Self {
        Self {
            status: 200,
            reason: "OK",
            headers: Vec::new(),
            body: Vec::new(),
            h2_reset: Some(reason),
        }
    }

    pub(crate) fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

pub(crate) struct TestServer {
    pub(crate) url: String,
    pub(crate) requests: Arc<Mutex<Vec<TestRequest>>>,
    request_notify: mpsc::Receiver<()>,
    shutdown: Option<mpsc::Sender<()>>,
    join: Option<thread::JoinHandle<()>>,
}

pub(crate) struct PartialBodyReplayServer {
    pub(crate) url: String,
    pub(crate) requests: Arc<Mutex<Vec<TestRequest>>>,
    pub(crate) join: Option<thread::JoinHandle<()>>,
}

impl TestServer {
    pub(crate) fn start(
        handler: impl Fn(TestRequest) -> TestResponse + Send + Sync + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        listener
            .set_nonblocking(true)
            .expect("set test listener nonblocking");
        let url = format!("http://{}", listener.local_addr().expect("local addr"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let handler = Arc::new(handler);
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let (notify_tx, notify_rx) = mpsc::channel();
        let request_log = Arc::clone(&requests);
        let join = thread::spawn(move || {
            loop {
                if shutdown_rx.try_recv().is_ok() {
                    break;
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let handler = Arc::clone(&handler);
                        let request_log = Arc::clone(&request_log);
                        let notify = notify_tx.clone();
                        thread::spawn(move || {
                            let mut writer = stream.try_clone().expect("clone response stream");
                            let mut reader = BufReader::new(stream);
                            while let Some(req) = read_request(&mut reader) {
                                let close = req.header("connection").eq_ignore_ascii_case("close");
                                request_log.lock().unwrap().push(req.clone());
                                let _ = notify.send(());
                                let resp = handler(req);
                                write_response(&mut writer, resp);
                                if close {
                                    break;
                                }
                            }
                        });
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            url,
            requests,
            request_notify: notify_rx,
            shutdown: Some(shutdown_tx),
            join: Some(join),
        }
    }

    pub(crate) fn requests(&self) -> Vec<TestRequest> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl PartialBodyReplayServer {
    pub(crate) fn start(
        status: u16,
        reason: &'static str,
        headers: Vec<(&'static str, &'static str)>,
        final_body: &'static str,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind partial body server");
        listener
            .set_nonblocking(true)
            .expect("set partial body listener nonblocking");
        let url = format!("http://{}", listener.local_addr().expect("local addr"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let request_log = Arc::clone(&requests);
        let next_request = Arc::new(Mutex::new(0_usize));
        let (done_tx, done_rx) = mpsc::channel();
        let join = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline && done_rx.try_recv().is_err() {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let request_log = Arc::clone(&request_log);
                        let next_request = Arc::clone(&next_request);
                        let headers = headers.clone();
                        let done_tx = done_tx.clone();
                        thread::spawn(move || {
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                            let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                            let reader_stream = stream.try_clone().expect("clone request stream");
                            let mut reader = BufReader::new(reader_stream);
                            let Some(req) = read_request(&mut reader) else {
                                return;
                            };
                            request_log.lock().unwrap().push(req);
                            let request_index = {
                                let mut next = next_request.lock().unwrap();
                                let index = *next;
                                *next += 1;
                                index
                            };
                            if request_index == 0 {
                                let _ = write!(stream, "HTTP/1.1 {status} {reason}\r\n");
                                for (name, value) in &headers {
                                    let _ = write!(stream, "{name}: {value}\r\n");
                                }
                                let _ = write!(
                                    stream,
                                    "Content-Length: 1073741824\r\nConnection: close\r\n\r\n"
                                );
                                let body = vec![b'x'; PARTIAL_REPLAY_BODY_PREFIX_BYTES];
                                let _ = stream.write_all(&body);
                                let _ = stream.flush();

                                let deadline = Instant::now() + Duration::from_secs(3);
                                let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
                                let mut buf = [0_u8; 1024];
                                while Instant::now() < deadline {
                                    match stream.read(&mut buf) {
                                        Ok(0) => break,
                                        Ok(_) => {}
                                        Err(err)
                                            if matches!(
                                                err.kind(),
                                                std::io::ErrorKind::WouldBlock
                                                    | std::io::ErrorKind::TimedOut
                                            ) => {}
                                        Err(_) => break,
                                    }
                                }
                            } else {
                                write_response(
                                    &mut stream,
                                    TestResponse::ok(final_body).header("Connection", "close"),
                                );
                                let _ = done_tx.send(());
                            }
                            let _ = stream.shutdown(Shutdown::Both);
                        });
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            url,
            requests,
            join: Some(join),
        }
    }

    pub(crate) fn requests(&self) -> Vec<TestRequest> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for PartialBodyReplayServer {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

pub(crate) fn read_request(reader: &mut impl BufRead) -> Option<TestRequest> {
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).ok()? == 0 {
        return None;
    }
    let request_line = request_line.trim_end_matches(['\r', '\n']);
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let _version = parts.next()?.to_string();

    let mut headers = HashMap::new();
    let mut header_lines = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            return None;
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            header_lines.push((name.clone(), value.clone()));
            headers.insert(name, value);
        }
    }

    let mut body = Vec::new();
    if headers
        .get("transfer-encoding")
        .is_some_and(|v| v.eq_ignore_ascii_case("chunked"))
    {
        loop {
            let mut size_line = String::new();
            reader.read_line(&mut size_line).ok()?;
            let size = usize::from_str_radix(size_line.trim(), 16).ok()?;
            if size == 0 {
                let mut trailer_end = String::new();
                reader.read_line(&mut trailer_end).ok()?;
                break;
            }
            let start = body.len();
            body.resize(start + size, 0);
            reader.read_exact(&mut body[start..]).ok()?;
            let mut crlf = [0; 2];
            reader.read_exact(&mut crlf).ok()?;
        }
    } else {
        let content_length = headers
            .get("content-length")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        if content_length > 0 {
            body.resize(content_length, 0);
            reader.read_exact(&mut body).ok()?;
        }
    }

    Some(TestRequest {
        method,
        path,
        headers,
        header_lines,
        body,
    })
}

pub(crate) fn write_response(stream: &mut impl Write, resp: TestResponse) {
    let mut headers = resp.headers;
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-length"))
    {
        headers.push(("Content-Length".to_string(), resp.body.len().to_string()));
    }
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("connection"))
    {
        headers.push(("Connection".to_string(), "keep-alive".to_string()));
    }
    let _ = write!(stream, "HTTP/1.1 {} {}\r\n", resp.status, resp.reason);
    for (name, value) in headers {
        let _ = write!(stream, "{name}: {value}\r\n");
    }
    let _ = write!(stream, "\r\n");
    let _ = stream.write_all(&resp.body);
    let _ = stream.flush();
}

pub(crate) fn wait_for_requests(server: &TestServer, count: usize) -> Vec<TestRequest> {
    let start = Instant::now();
    while server.requests().len() < count {
        let remaining = Duration::from_secs(2).saturating_sub(start.elapsed());
        if remaining.is_zero() {
            let requests = server.requests();
            panic!(
                "timed out waiting for {count} requests; got {}",
                requests.len()
            );
        }
        let _ = server.request_notify.recv_timeout(remaining);
    }
    server.requests()
}
