use std::io::{self, Read};

use reqwest::blocking;

use crate::error::Error;

pub(crate) struct Body {
    pub(crate) data: Data,
    pub(crate) content_type: Option<&'static str>,
}

impl Body {
    pub(crate) fn new_form(form: &[(&str, &str)]) -> Result<Self, Error> {
        let body = serde_urlencoded::to_string(form).map_err(|e| Error::new(e.to_string()))?;
        Ok(Self {
            data: body.into(),
            content_type: Some("application/x-www-form-urlencoded"),
        })
    }
}

#[allow(dead_code)]
pub(crate) enum Data {
    Buffer(Vec<u8>),
    Reader(Box<dyn Read + Send + 'static>),
}

#[allow(dead_code)]
impl Data {
    fn from_reader(r: impl Read + Send + 'static) -> Self {
        Self::Reader(Box::new(r))
    }
}

impl From<Vec<u8>> for Data {
    fn from(value: Vec<u8>) -> Self {
        Self::Buffer(value)
    }
}

impl From<String> for Data {
    fn from(value: String) -> Self {
        Self::Buffer(value.into_bytes())
    }
}

impl From<Data> for blocking::Body {
    fn from(value: Data) -> Self {
        match value {
            Data::Buffer(buf) => buf.into(),
            Data::Reader(r) => blocking::Body::new(r),
        }
    }
}

#[allow(dead_code)]
pub(crate) enum LimitedRead<R: Read> {
    Buffer(Vec<u8>),
    Reader(Wrapped<R>),
}

pub(crate) struct Wrapped<R: Read> {
    reader: R,
    buf: Vec<u8>,
    pos: usize,
}

#[allow(dead_code)]
impl<R: Read> Wrapped<R> {
    fn new(reader: R, buf: Vec<u8>) -> Self {
        Self {
            reader,
            buf,
            pos: 0,
        }
    }
}

impl<R: Read> Read for Wrapped<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos < self.buf.len() {
            let n = Read::read(&mut &self.buf[self.pos..], buf)?;
            self.pos += n;
            Ok(n)
        } else {
            self.reader.read(buf)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrapped() {
        let mut r = Wrapped::new(" world!".as_bytes(), "hello,".as_bytes().to_vec());
        let mut out = String::new();
        r.read_to_string(&mut out).expect("no error");
        assert_eq!(out, "hello, world!");
    }
}
