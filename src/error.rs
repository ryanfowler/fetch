use std::{
    error::Error as _,
    fmt::{self, Write},
};

use image::ImageError;
use reqwest::header::{InvalidHeaderName, InvalidHeaderValue};
use url::ParseError;

#[derive(Debug)]
pub(crate) struct Error {
    msg: String,
    src: Option<Box<dyn std::error::Error + 'static>>,
}

impl Error {
    pub(crate) fn new<S: ToString>(msg: S) -> Self {
        Self {
            msg: msg.to_string(),
            src: None,
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.src.as_deref()
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl From<fmt::Error> for Error {
    fn from(value: fmt::Error) -> Self {
        Self {
            msg: value.to_string(),
            src: Some(Box::new(value)),
        }
    }
}

impl From<jiff::Error> for Error {
    fn from(value: jiff::Error) -> Self {
        Self {
            msg: value.to_string(),
            src: Some(Box::new(value)),
        }
    }
}

impl From<ParseError> for Error {
    fn from(value: ParseError) -> Self {
        Self {
            msg: format!("parsing url: {value}"),
            src: Some(Box::new(value)),
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(value: reqwest::Error) -> Self {
        let mut msg = value.to_string();
        if let Some(inner) = value.source() {
            _ = msg.write_str(": ");
            _ = msg.write_str(&inner.to_string());
        }
        Self {
            msg,
            src: Some(Box::new(value)),
        }
    }
}

impl From<InvalidHeaderName> for Error {
    fn from(value: InvalidHeaderName) -> Self {
        Self {
            msg: value.to_string(),
            src: Some(Box::new(value)),
        }
    }
}

impl From<InvalidHeaderValue> for Error {
    fn from(value: InvalidHeaderValue) -> Self {
        Self {
            msg: value.to_string(),
            src: Some(Box::new(value)),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self {
            msg: value.to_string(),
            src: Some(Box::new(value)),
        }
    }
}

impl From<ImageError> for Error {
    fn from(value: ImageError) -> Self {
        Self {
            msg: value.to_string(),
            src: Some(Box::new(value)),
        }
    }
}
