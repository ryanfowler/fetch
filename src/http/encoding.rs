use super::*;

pub(super) fn apply_accept_encoding(
    headers: &mut HeaderMap,
    cli: &Cli,
    method: &Method,
) -> CompressionMode {
    let compression = CompressionMode::from_cli(cli);
    let Some(accept_encoding) = compression.accept_encoding() else {
        return CompressionMode::Off;
    };
    if method == Method::HEAD || headers.contains_key(ACCEPT_ENCODING) {
        return CompressionMode::Off;
    }
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static(accept_encoding));
    compression
}

#[cfg(test)]
pub(super) fn decode_response_bytes(
    compression: CompressionMode,
    headers: &HeaderMap,
    bytes: &[u8],
) -> Result<Vec<u8>, FetchError> {
    if compression == CompressionMode::Off {
        return Ok(bytes.to_vec());
    }

    let Some(encodings) = content_encoding_decoders(headers, compression) else {
        return Ok(bytes.to_vec());
    };

    let mut decoded = bytes.to_vec();
    for encoding in encodings {
        decoded = match encoding.as_str() {
            "br" => decode_brotli(&decoded)?,
            "gzip" => decode_gzip(&decoded)?,
            "zstd" => decode_zstd(&decoded)?,
            "aws-chunked" => decoded,
            _ => unreachable!("unsupported encodings are filtered"),
        };
    }
    Ok(decoded)
}

pub(super) fn decoded_async_response_reader(
    mut reader: AsyncReadBox,
    compression: CompressionMode,
    headers: &HeaderMap,
) -> Result<AsyncReadBox, FetchError> {
    if compression == CompressionMode::Off {
        return Ok(reader);
    }

    let Some(encodings) = content_encoding_decoders(headers, compression) else {
        return Ok(reader);
    };

    for encoding in encodings {
        reader = match encoding.as_str() {
            "br" => Box::pin(AsyncPrefixedReadError {
                prefix: "br",
                inner: AsyncBrotliDecoder::new(tokio::io::BufReader::new(reader)),
            }),
            "gzip" => Box::pin(AsyncPrefixedReadError {
                prefix: "gzip",
                inner: AsyncGzipDecoder::new(tokio::io::BufReader::new(reader)),
            }),
            "zstd" => Box::pin(AsyncPrefixedReadError {
                prefix: "zstd",
                inner: AsyncZstdDecoder::new(tokio::io::BufReader::new(reader)),
            }),
            "aws-chunked" => reader,
            _ => unreachable!("unsupported encodings are filtered"),
        };
    }
    Ok(reader)
}

pub(super) fn output_progress_total_bytes(
    compression: CompressionMode,
    headers: &HeaderMap,
    content_length: Option<i64>,
) -> Option<i64> {
    if compression != CompressionMode::Off
        && content_encoding_decoders(headers, compression)
            .is_some_and(|decoders| !decoders.is_empty())
    {
        None
    } else {
        content_length
    }
}

pub(super) struct AsyncPrefixedReadError<R> {
    prefix: &'static str,
    inner: R,
}

impl<R: AsyncRead + Unpin> AsyncRead for AsyncPrefixedReadError<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let prefix = self.prefix;
        Pin::new(&mut self.inner)
            .poll_read(cx, buf)
            .map_err(|err| std::io::Error::new(err.kind(), format!("{prefix}: {err}")))
    }
}

pub(super) fn content_encoding_decoders(
    headers: &HeaderMap,
    compression: CompressionMode,
) -> Option<Vec<String>> {
    let encodings = content_encodings(headers);
    let mut decoders = Vec::with_capacity(encodings.len());
    for encoding in encodings.into_iter().rev() {
        if compression.decodes(&encoding) {
            decoders.push(encoding);
        } else {
            return None;
        }
    }
    Some(decoders)
}

pub(super) fn content_encodings(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(http::header::CONTENT_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

#[cfg(test)]
pub(super) fn decode_gzip(bytes: &[u8]) -> Result<Vec<u8>, FetchError> {
    let mut decoder = GzDecoder::new(bytes);
    let mut decoded = Vec::new();
    decoder
        .read_to_end(&mut decoded)
        .map_err(|err| FetchError::Message(format!("gzip: {err}")))?;
    Ok(decoded)
}

#[cfg(test)]
pub(super) fn decode_brotli(bytes: &[u8]) -> Result<Vec<u8>, FetchError> {
    let mut decoder = brotli::Decompressor::new(bytes, 4096);
    let mut decoded = Vec::new();
    decoder
        .read_to_end(&mut decoded)
        .map_err(|err| FetchError::Message(format!("br: {err}")))?;
    Ok(decoded)
}

#[cfg(test)]
pub(super) fn decode_zstd(bytes: &[u8]) -> Result<Vec<u8>, FetchError> {
    zstd::stream::decode_all(bytes).map_err(|err| FetchError::Message(format!("zstd: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    use clap::Parser;
    use flate2::Compression;
    use flate2::write::GzEncoder;

    fn gzip_encode(data: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn brotli_encode(data: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::new();
        {
            let mut encoder = brotli::CompressorWriter::new(&mut encoded, 4096, 5, 22);
            encoder.write_all(data).unwrap();
        }
        encoded
    }

    fn zstd_encode(data: &[u8]) -> Vec<u8> {
        zstd::stream::encode_all(data, 0).unwrap()
    }

    #[test]
    fn content_encodings_splits_multiple_header_values() {
        let mut headers = HeaderMap::new();
        headers.append(
            http::header::CONTENT_ENCODING,
            HeaderValue::from_static("gzip"),
        );
        headers.append(
            http::header::CONTENT_ENCODING,
            HeaderValue::from_static("zstd, aws-chunked"),
        );

        assert_eq!(content_encodings(&headers), ["gzip", "zstd", "aws-chunked"]);
    }

    #[test]
    fn apply_accept_encoding_uses_requested_compression_mode() {
        for (args, expected_mode, expected_header) in [
            (
                vec!["fetch", "https://example.com"],
                CompressionMode::Auto,
                Some("gzip, br, zstd"),
            ),
            (
                vec!["fetch", "--compress", "br", "https://example.com"],
                CompressionMode::Brotli,
                Some("br"),
            ),
            (
                vec!["fetch", "--compress", "brotli", "https://example.com"],
                CompressionMode::Brotli,
                Some("br"),
            ),
            (
                vec!["fetch", "--compress", "gzip", "https://example.com"],
                CompressionMode::Gzip,
                Some("gzip"),
            ),
            (
                vec!["fetch", "--compress", "zstd", "https://example.com"],
                CompressionMode::Zstd,
                Some("zstd"),
            ),
            (
                vec!["fetch", "--compress", "off", "https://example.com"],
                CompressionMode::Off,
                None,
            ),
        ] {
            let cli = Cli::try_parse_from(args).unwrap();
            let mut headers = HeaderMap::new();

            let mode = apply_accept_encoding(&mut headers, &cli, &Method::GET);

            assert_eq!(mode, expected_mode);
            assert_eq!(
                headers
                    .get(ACCEPT_ENCODING)
                    .and_then(|value| value.to_str().ok()),
                expected_header
            );
        }
    }

    #[test]
    fn apply_accept_encoding_skips_head_and_custom_header() {
        let cli = Cli::try_parse_from(["fetch", "https://example.com"]).unwrap();
        let mut headers = HeaderMap::new();
        assert_eq!(
            apply_accept_encoding(&mut headers, &cli, &Method::HEAD),
            CompressionMode::Off
        );
        assert!(!headers.contains_key(ACCEPT_ENCODING));

        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("br"));
        assert_eq!(
            apply_accept_encoding(&mut headers, &cli, &Method::GET),
            CompressionMode::Off
        );
        assert_eq!(headers.get(ACCEPT_ENCODING).unwrap(), "br");
    }

    #[test]
    fn decodes_stacked_content_encoding_in_reverse_order() {
        let data = b"this is stacked encoded data";
        let body = zstd_encode(&gzip_encode(data));
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_ENCODING,
            HeaderValue::from_static("gzip, zstd"),
        );

        let decoded = decode_response_bytes(CompressionMode::Auto, &headers, &body).unwrap();

        assert_eq!(decoded, data);
    }

    #[test]
    fn decodes_brotli_content_encoding() {
        let data = b"this is brotli encoded data";
        let body = brotli_encode(data);
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_ENCODING,
            HeaderValue::from_static("br"),
        );

        let decoded = decode_response_bytes(CompressionMode::Brotli, &headers, &body).unwrap();

        assert_eq!(decoded, data);
    }

    #[test]
    fn decodes_aws_chunked_plus_gzip() {
        let data = b"this is gzip encoded data";
        let body = gzip_encode(data);
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_ENCODING,
            HeaderValue::from_static("aws-chunked, gzip"),
        );

        let decoded = decode_response_bytes(CompressionMode::Auto, &headers, &body).unwrap();

        assert_eq!(decoded, data);
    }

    #[test]
    fn compression_mode_only_decodes_requested_algorithm() {
        let data = b"this is gzip encoded data";
        let body = gzip_encode(data);
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_ENCODING,
            HeaderValue::from_static("gzip"),
        );

        let decoded = decode_response_bytes(CompressionMode::Gzip, &headers, &body).unwrap();
        assert_eq!(decoded, data);

        let decoded = decode_response_bytes(CompressionMode::Brotli, &headers, &body).unwrap();
        assert_eq!(decoded, body);

        let decoded = decode_response_bytes(CompressionMode::Zstd, &headers, &body).unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn leaves_unsupported_stacked_content_encoding_untouched() {
        let body = b"not decoded";
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_ENCODING,
            HeaderValue::from_static("deflate, gzip"),
        );

        let decoded = decode_response_bytes(CompressionMode::Auto, &headers, body).unwrap();

        assert_eq!(decoded, body);
    }

    #[test]
    fn skips_decoding_when_encoding_was_not_requested_by_fetch() {
        let data = b"this stays gzip encoded";
        let body = gzip_encode(data);
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_ENCODING,
            HeaderValue::from_static("gzip"),
        );

        let decoded = decode_response_bytes(CompressionMode::Off, &headers, &body).unwrap();

        assert_eq!(decoded, body);
    }

    #[test]
    fn output_progress_omits_total_for_decoded_content_encoding() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_ENCODING,
            HeaderValue::from_static("gzip"),
        );

        assert_eq!(
            output_progress_total_bytes(CompressionMode::Auto, &headers, Some(10)),
            None
        );
    }

    #[test]
    fn output_progress_keeps_total_when_written_length_matches_wire_length() {
        let content_length = Some(10);
        assert_eq!(
            output_progress_total_bytes(CompressionMode::Auto, &HeaderMap::new(), content_length),
            content_length
        );

        let mut compressed_headers = HeaderMap::new();
        compressed_headers.insert(
            http::header::CONTENT_ENCODING,
            HeaderValue::from_static("gzip"),
        );
        assert_eq!(
            output_progress_total_bytes(CompressionMode::Off, &compressed_headers, content_length),
            content_length
        );

        let mut unsupported_headers = HeaderMap::new();
        unsupported_headers.insert(
            http::header::CONTENT_ENCODING,
            HeaderValue::from_static("deflate"),
        );
        assert_eq!(
            output_progress_total_bytes(
                CompressionMode::Auto,
                &unsupported_headers,
                content_length
            ),
            content_length
        );
    }

    #[test]
    fn gzip_decoder_errors_are_prefixed() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_ENCODING,
            HeaderValue::from_static("gzip"),
        );

        let err = decode_response_bytes(CompressionMode::Auto, &headers, b"not gzip").unwrap_err();

        assert!(err.to_string().contains("gzip:"));
    }

    #[test]
    fn brotli_decoder_errors_are_prefixed() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_ENCODING,
            HeaderValue::from_static("br"),
        );

        let err =
            decode_response_bytes(CompressionMode::Auto, &headers, b"not brotli").unwrap_err();

        assert!(err.to_string().contains("br:"));
    }
}
