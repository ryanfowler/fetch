use std::{
    fs,
    io::{self, Read},
    os::unix::fs::MetadataExt,
};

use reqwest::blocking;

use crate::error::Error;

pub(crate) enum Body {
    Buffer(Vec<u8>),
    File((fs::File, Option<u64>)),
}

impl Body {
    pub(crate) fn new_form(form: &[(&str, &str)]) -> Result<Self, Error> {
        let body = serde_urlencoded::to_string(form).map_err(|e| Error::new(e.to_string()))?;
        Ok(body.into())
    }

    pub(crate) fn new_file(f: fs::File) -> Result<Self, Error> {
        let size = f.metadata()?.size();
        Ok(Self::File((f, Some(size))))
    }
}

impl From<Vec<u8>> for Body {
    fn from(value: Vec<u8>) -> Self {
        Self::Buffer(value)
    }
}

impl From<String> for Body {
    fn from(value: String) -> Self {
        Self::Buffer(value.into_bytes())
    }
}

impl From<Body> for blocking::Body {
    fn from(value: Body) -> Self {
        match value {
            Body::Buffer(buf) => buf.into(),
            Body::File((f, size)) => {
                if let Some(size) = size {
                    blocking::Body::sized(f, size)
                } else {
                    blocking::Body::new(f)
                }
            }
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
