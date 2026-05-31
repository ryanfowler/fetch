use std::fmt;

use http::header::HeaderMap;
use percent_encoding::percent_decode_str;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Code(pub i32);

impl Code {
    pub const OK: Self = Self(0);
    pub const CANCELED: Self = Self(1);
    pub const UNKNOWN: Self = Self(2);
    pub const INVALID_ARGUMENT: Self = Self(3);
    pub const DEADLINE_EXCEEDED: Self = Self(4);
    pub const NOT_FOUND: Self = Self(5);
    pub const ALREADY_EXISTS: Self = Self(6);
    pub const PERMISSION_DENIED: Self = Self(7);
    pub const RESOURCE_EXHAUSTED: Self = Self(8);
    pub const FAILED_PRECONDITION: Self = Self(9);
    pub const ABORTED: Self = Self(10);
    pub const OUT_OF_RANGE: Self = Self(11);
    pub const UNIMPLEMENTED: Self = Self(12);
    pub const INTERNAL: Self = Self(13);
    pub const UNAVAILABLE: Self = Self(14);
    pub const DATA_LOSS: Self = Self(15);
    pub const UNAUTHENTICATED: Self = Self(16);

    pub fn name(self) -> String {
        match self.0 {
            0 => "OK".to_string(),
            1 => "CANCELED".to_string(),
            2 => "UNKNOWN".to_string(),
            3 => "INVALID_ARGUMENT".to_string(),
            4 => "DEADLINE_EXCEEDED".to_string(),
            5 => "NOT_FOUND".to_string(),
            6 => "ALREADY_EXISTS".to_string(),
            7 => "PERMISSION_DENIED".to_string(),
            8 => "RESOURCE_EXHAUSTED".to_string(),
            9 => "FAILED_PRECONDITION".to_string(),
            10 => "ABORTED".to_string(),
            11 => "OUT_OF_RANGE".to_string(),
            12 => "UNIMPLEMENTED".to_string(),
            13 => "INTERNAL".to_string(),
            14 => "UNAVAILABLE".to_string(),
            15 => "DATA_LOSS".to_string(),
            16 => "UNAUTHENTICATED".to_string(),
            other => format!("CODE({other})"),
        }
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub code: Code,
    pub message: String,
}

impl Status {
    pub fn ok(&self) -> bool {
        self.code == Code::OK
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.message.is_empty() {
            write!(f, "grpc error: {}", self.code)
        } else {
            write!(f, "grpc error: {}: {}", self.code, self.message)
        }
    }
}

impl std::error::Error for Status {}

pub fn parse_status(grpc_status: &str, grpc_message: &str) -> Status {
    let code = grpc_status
        .parse::<i32>()
        .map(Code)
        .unwrap_or(Code::UNKNOWN);
    let message = if grpc_message.is_empty() {
        String::new()
    } else {
        percent_decode_str(grpc_message)
            .decode_utf8()
            .map(|decoded| decoded.into_owned())
            .unwrap_or_else(|_| grpc_message.to_string())
    };
    Status { code, message }
}

pub fn from_headers(headers: &HeaderMap) -> Option<Status> {
    let status = headers.get("grpc-status")?.to_str().ok()?;
    let message = headers
        .get("grpc-message")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    Some(parse_status(status, message))
}

pub fn from_headers_or_trailers(headers: &HeaderMap, trailers: &HeaderMap) -> Option<Status> {
    from_headers(trailers).or_else(|| from_headers(headers))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::HeaderValue;

    #[test]
    fn test_code_string() {
        let cases = [
            (Code::OK, "OK"),
            (Code::CANCELED, "CANCELED"),
            (Code::UNKNOWN, "UNKNOWN"),
            (Code::INVALID_ARGUMENT, "INVALID_ARGUMENT"),
            (Code::DEADLINE_EXCEEDED, "DEADLINE_EXCEEDED"),
            (Code::NOT_FOUND, "NOT_FOUND"),
            (Code::ALREADY_EXISTS, "ALREADY_EXISTS"),
            (Code::PERMISSION_DENIED, "PERMISSION_DENIED"),
            (Code::RESOURCE_EXHAUSTED, "RESOURCE_EXHAUSTED"),
            (Code::FAILED_PRECONDITION, "FAILED_PRECONDITION"),
            (Code::ABORTED, "ABORTED"),
            (Code::OUT_OF_RANGE, "OUT_OF_RANGE"),
            (Code::UNIMPLEMENTED, "UNIMPLEMENTED"),
            (Code::INTERNAL, "INTERNAL"),
            (Code::UNAVAILABLE, "UNAVAILABLE"),
            (Code::DATA_LOSS, "DATA_LOSS"),
            (Code::UNAUTHENTICATED, "UNAUTHENTICATED"),
            (Code(100), "CODE(100)"),
        ];

        for (code, want) in cases {
            assert_eq!(code.to_string(), want);
        }
    }

    #[test]
    fn test_status_error() {
        let cases = [
            (
                "OK status",
                Status {
                    code: Code::OK,
                    message: String::new(),
                },
                "grpc error: OK",
                true,
            ),
            (
                "error with message",
                Status {
                    code: Code::NOT_FOUND,
                    message: "resource not found".to_string(),
                },
                "grpc error: NOT_FOUND: resource not found",
                false,
            ),
            (
                "error without message",
                Status {
                    code: Code::INTERNAL,
                    message: String::new(),
                },
                "grpc error: INTERNAL",
                false,
            ),
        ];

        for (name, status, want, want_ok) in cases {
            assert_eq!(status.to_string(), want, "{name}");
            assert_eq!(status.ok(), want_ok, "{name}");
        }
    }

    #[test]
    fn test_parse_status() {
        let cases = [
            ("OK", "0", "", Code::OK, ""),
            (
                "NotFound with message",
                "5",
                "not found",
                Code::NOT_FOUND,
                "not found",
            ),
            (
                "invalid status string",
                "invalid",
                "some message",
                Code::UNKNOWN,
                "some message",
            ),
            (
                "empty status string",
                "",
                "error occurred",
                Code::UNKNOWN,
                "error occurred",
            ),
            (
                "Unauthenticated",
                "16",
                "invalid token",
                Code::UNAUTHENTICATED,
                "invalid token",
            ),
            (
                "percent-encoded message",
                "13",
                "bad%20thing%3A%20no%20tokens",
                Code::INTERNAL,
                "bad thing: no tokens",
            ),
            (
                "invalid percent-encoded message",
                "13",
                "bad%zzmessage",
                Code::INTERNAL,
                "bad%zzmessage",
            ),
        ];

        for (name, grpc_status, grpc_message, want_code, want_message) in cases {
            let status = parse_status(grpc_status, grpc_message);
            assert_eq!(status.code, want_code, "{name}");
            assert_eq!(status.message, want_message, "{name}");
        }
    }

    #[test]
    fn from_headers_parses_status_metadata() {
        let mut headers = HeaderMap::new();
        headers.insert("grpc-status", HeaderValue::from_static("13"));
        headers.insert("grpc-message", HeaderValue::from_static("oh%20no%21"));

        let status = from_headers(&headers).unwrap();

        assert_eq!(status.code, Code::INTERNAL);
        assert_eq!(status.message, "oh no!");
        assert_eq!(status.to_string(), "grpc error: INTERNAL: oh no!");
    }

    #[test]
    fn from_headers_returns_ok_status() {
        let mut headers = HeaderMap::new();
        headers.insert("grpc-status", HeaderValue::from_static("0"));

        let status = from_headers(&headers).unwrap();

        assert!(status.ok());
    }

    #[test]
    fn from_headers_or_trailers_prefers_trailers() {
        let mut headers = HeaderMap::new();
        headers.insert("grpc-status", HeaderValue::from_static("13"));
        headers.insert("grpc-message", HeaderValue::from_static("header failure"));
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));

        let status = from_headers_or_trailers(&headers, &trailers).unwrap();

        assert!(status.ok());
    }

    #[test]
    fn from_headers_or_trailers_falls_back_to_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("grpc-status", HeaderValue::from_static("5"));

        let status = from_headers_or_trailers(&headers, &HeaderMap::new()).unwrap();

        assert_eq!(status.code, Code::NOT_FOUND);
    }
}
