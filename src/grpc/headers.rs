use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};

use crate::grpc::encoding;

pub const PROTO_CONTENT_TYPE: &str = "application/grpc+proto";

pub fn apply_standard_headers(headers: &mut HeaderMap) {
    headers.insert(ACCEPT, HeaderValue::from_static(PROTO_CONTENT_TYPE));
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(PROTO_CONTENT_TYPE));
    headers.insert(
        HeaderName::from_static("te"),
        HeaderValue::from_static("trailers"),
    );
    headers.insert(
        HeaderName::from_static("grpc-accept-encoding"),
        HeaderValue::from_static(encoding::ACCEPT_ENCODING),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_headers_match_grpc_defaults() {
        let mut headers = HeaderMap::new();

        apply_standard_headers(&mut headers);

        assert_eq!(headers[ACCEPT], PROTO_CONTENT_TYPE);
        assert_eq!(headers[CONTENT_TYPE], PROTO_CONTENT_TYPE);
        assert_eq!(headers["te"], "trailers");
        assert_eq!(headers["grpc-accept-encoding"], encoding::ACCEPT_ENCODING);
    }
}
