use std::error::Error as StdError;
use std::fmt;

use crate::error::FetchError;

mod body;
mod client;
mod h3;
mod proxy;

pub(crate) use body::{Body, BodyDeadline, Response, read_body_frame};
pub(crate) use client::{
    Client, ClientBuilder, RequestBuilder, basic_auth_header_value, extract_url_basic_auth,
    redirect,
};
pub(crate) use h3::AutoHttp3Config;
pub(crate) use proxy::{NoProxy, Proxy};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ErrorKind {
    Request,
    Connect,
    Timeout,
    Body,
}

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    message: String,
    source: Option<Box<dyn StdError + Send + Sync>>,
}

impl Error {
    pub(super) fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            source: None,
        }
    }

    pub(super) fn with_source(
        kind: ErrorKind,
        message: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    pub(super) fn request(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Request, message)
    }

    pub(super) fn connect(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Connect, message)
    }

    pub(super) fn timeout(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Timeout, message)
    }

    pub(super) fn body(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Body, message)
    }

    pub(super) fn body_source(source: impl StdError + Send + Sync + 'static) -> Self {
        let message = source.to_string();
        Self::with_source(ErrorKind::Body, message, source)
    }

    pub(super) fn from_fetch(kind: ErrorKind, err: FetchError) -> Self {
        let message = err.to_string();
        let kind = if message.starts_with("request timed out after ") {
            ErrorKind::Timeout
        } else {
            kind
        };
        Self::new(kind, message)
    }

    pub(crate) fn is_timeout(&self) -> bool {
        self.kind == ErrorKind::Timeout
    }

    pub(crate) fn is_connect(&self) -> bool {
        self.kind == ErrorKind::Connect
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}

#[cfg(test)]
mod tests;
