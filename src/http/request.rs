use super::*;
use futures_util::TryStreamExt;
use std::io::Cursor;

pub(crate) type RequestBody = Option<RequestBodyPayload>;
pub(crate) type MaterializedRequestBody = Option<(Vec<u8>, Option<String>)>;

const DRY_RUN_BODY_PREVIEW_BYTES: usize = 1024;

#[derive(Debug, Clone)]
pub(crate) struct RequestBodyPayload {
    pub(super) source: RequestBodySource,
    pub(super) content_type: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) enum RequestBodySource {
    Bytes(Bytes),
    File {
        path: String,
        len: u64,
    },
    Stdin,
    Multipart(multipart::Multipart),
    GrpcJsonStream {
        source: Box<RequestBodySource>,
        desc: prost_reflect::MessageDescriptor,
    },
}

impl RequestBodyPayload {
    pub(crate) fn from_bytes(bytes: Vec<u8>, content_type: Option<String>) -> Self {
        Self {
            source: RequestBodySource::Bytes(Bytes::from(bytes)),
            content_type,
        }
    }

    pub(crate) fn from_grpc_json_stream(
        body: RequestBodyPayload,
        desc: prost_reflect::MessageDescriptor,
        content_type: Option<String>,
    ) -> Self {
        Self {
            source: RequestBodySource::GrpcJsonStream {
                source: Box::new(body.source),
                desc,
            },
            content_type,
        }
    }
}

pub(super) fn print_dry_run_body(cli: &Cli, body: &RequestBody) -> Result<(), FetchError> {
    let Some(body) = body else {
        return Ok(());
    };
    if cli.verbose < 2 {
        let mut printer = core::Printer::stderr(cli.color.as_deref());
        core::write_status_line_no_flush(&mut printer, "");
        core::flush_stderr(printer);
    }
    let preview = dry_run_body_preview(body, DRY_RUN_BODY_PREVIEW_BYTES)?;
    if !is_printable(&preview.bytes) {
        print_dry_run_binary_warning(cli);
        if preview.truncated {
            print_dry_run_truncation_warning(cli, DRY_RUN_BODY_PREVIEW_BYTES);
        }
        return Ok(());
    }

    let mut stderr = std::io::stderr();
    stderr.write_all(&preview.bytes)?;
    if preview.truncated {
        if !preview.bytes.ends_with(b"\n") {
            stderr.write_all(b"\n")?;
        }
        print_dry_run_truncation_warning(cli, DRY_RUN_BODY_PREVIEW_BYTES);
    }
    Ok(())
}

fn print_dry_run_binary_warning(cli: &Cli) {
    let mut printer = core::Printer::stderr(cli.color.as_deref());
    core::write_warning_msg_no_flush(&mut printer, "the request body appears to be binary");
    core::flush_stderr(printer);
}

fn print_dry_run_truncation_warning(cli: &Cli, limit: usize) {
    let mut printer = core::Printer::stderr(cli.color.as_deref());
    core::write_warning_msg_no_flush(
        &mut printer,
        format!("the request body preview was truncated after {limit} bytes"),
    );
    core::flush_stderr(printer);
}

pub(super) fn build_request(
    client: &Client,
    method: Method,
    url: Url,
    mut headers: HeaderMap,
    body: RequestBody,
    cli: &Cli,
    authorization: RequestAuthorization<'_>,
) -> Result<RequestBuilder, FetchError> {
    if let Some(len) = inferred_request_body_content_len(&headers, &body)? {
        headers.insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&len.to_string())
                .expect("content length is a valid header value"),
        );
    }
    let mut req = client.request(method, url).headers(headers);
    if let Some(version) = transport_request_version_for_cli(cli)? {
        req = req.version(version);
    }

    if let Some(body) = body {
        req = req.body(request_body_to_transport_body(body)?);
    }

    match authorization {
        RequestAuthorization::Cli => {
            let mut authorization_headers = HeaderMap::new();
            apply_builder_authorization_headers(&mut authorization_headers, cli, None)?;
            req = req.headers(authorization_headers);
        }
        RequestAuthorization::Digest(auth) => {
            let mut authorization_headers = HeaderMap::new();
            apply_builder_authorization_headers(&mut authorization_headers, cli, Some(auth))?;
            req = req.headers(authorization_headers);
        }
        RequestAuthorization::None => {}
    }

    Ok(req)
}

pub(super) fn apply_request_timeout(
    mut req: RequestBuilder,
    request_timeout: Option<Duration>,
    request_start: Instant,
) -> Result<RequestBuilder, FetchError> {
    if let Some(timeout) = TimeoutBudget::started_at(request_timeout, request_start).remaining()? {
        let timeout_message = request_timeout
            .map(request_timeout_message)
            .unwrap_or_else(|| request_timeout_message(timeout));
        req = req.timeout_with_message(timeout, timeout_message);
    }
    Ok(req)
}

pub(super) enum RequestAuthorization<'a> {
    Cli,
    Digest(&'a str),
    None,
}

pub(crate) fn apply_builder_authorization_headers(
    headers: &mut HeaderMap,
    cli: &Cli,
    authorization: Option<&str>,
) -> Result<(), FetchError> {
    if let Some(auth) = authorization {
        let value = HeaderValue::from_str(auth)
            .map_err(|err| FetchError::Message(format!("invalid authorization header: {err}")))?;
        headers.insert(http::header::AUTHORIZATION, value);
    } else if let Some(auth) = basic_header(cli.basic.as_deref())? {
        let value = HeaderValue::from_str(&auth)
            .map_err(|err| FetchError::Message(format!("invalid authorization header: {err}")))?;
        headers.insert(http::header::AUTHORIZATION, value);
    }
    if let Some(token) = cli.bearer.as_deref() {
        let value = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|err| FetchError::Message(format!("invalid bearer token: {err}")))?;
        headers.insert(http::header::AUTHORIZATION, value);
    }
    Ok(())
}

pub(super) fn transport_request_version_for_cli(
    cli: &Cli,
) -> Result<Option<http::Version>, FetchError> {
    let version = crate::cli::selected_http_version(cli).map_err(FetchError::Message)?;
    Ok(match effective_http_version(cli, version) {
        Some(HttpVersion::Http1) => Some(http::Version::HTTP_11),
        Some(HttpVersion::Http2) => Some(http::Version::HTTP_2),
        Some(HttpVersion::Http3) => Some(http::Version::HTTP_3),
        None => None,
    })
}

pub(super) struct DigestRetryContext<'a> {
    pub(super) client: &'a Client,
    pub(super) client_build: &'a client::ClientBuildContext<'a>,
    pub(super) method: Method,
    pub(super) headers: HeaderMap,
    pub(super) body: RequestBody,
    pub(super) cli: &'a Cli,
    pub(super) redirect_statuses: Vec<StatusCode>,
    pub(super) strip_entity_headers: bool,
    pub(super) auth_allowed: bool,
}

pub(super) async fn apply_digest_challenge(
    response: Response,
    context: DigestRetryContext<'_>,
    credentials: Option<&(String, String)>,
) -> Result<Response, FetchError> {
    let Some((username, password)) = credentials else {
        return Ok(response);
    };
    if response.status() != StatusCode::UNAUTHORIZED {
        return Ok(response);
    }
    if !context.auth_allowed {
        return Ok(response);
    }

    let challenge = digest::find_digest_challenge(
        response
            .headers()
            .get_all(WWW_AUTHENTICATE)
            .iter()
            .filter_map(|value| value.to_str().ok()),
    );
    let Some(challenge) = challenge else {
        return Ok(response);
    };
    let challenge = digest::parse_challenge(&challenge).map_err(digest_challenge_error)?;

    let challenged_url = response.url().clone();
    let (challenged_method, challenged_body) =
        digest_challenged_request(context.method, context.body, &context.redirect_statuses);
    let auth = match digest::response(
        challenged_method.as_str(),
        &request_target(&challenged_url),
        &challenge,
        username,
        password,
    ) {
        Ok(auth) => auth,
        Err(err) => return Err(digest_challenge_error(err)),
    };
    ensure_request_body_replayable(&challenged_body, "digest authentication")?;
    let mut challenged_headers = context.headers;
    if context.strip_entity_headers {
        strip_entity_headers_for_bodyless_redirect(&mut challenged_headers);
    }

    let retry_before_drain = digest_retry_before_drain(&response);
    let retry_client;
    let client = if retry_before_drain {
        retry_client =
            client::build_client_for_url(context.cli, &challenged_url, context.client_build)
                .await?;
        &retry_client.client
    } else {
        context.client
    };
    let retry_request = build_request(
        client,
        challenged_method,
        challenged_url,
        challenged_headers,
        challenged_body,
        context.cli,
        RequestAuthorization::Digest(&auth),
    )?;
    let retry_request = apply_request_timeout(
        retry_request,
        context.client_build.request_timeout,
        context.client_build.request_start,
    )?;

    if retry_before_drain {
        let retry_response: Result<Response, FetchError> =
            retry_request.send().await.map_err(Into::into);
        drop(response);
        retry_response
    } else {
        drain_response_body_bounded(response).await;
        retry_request.send().await.map_err(Into::into)
    }
}

pub(super) fn digest_challenge_error(err: digest::DigestError) -> FetchError {
    let prefix = match err {
        digest::DigestError::UnsupportedAlgorithm(_) | digest::DigestError::UnsupportedQop(_) => {
            "unsupported"
        }
        digest::DigestError::NotDigest | digest::DigestError::MissingRequiredParameter => "invalid",
    };
    FetchError::Runtime(format!("{prefix} digest authentication challenge: {err}"))
}

pub(super) fn digest_retry_before_drain(response: &Response) -> bool {
    if response_body_exceeds_discard_bound(response) {
        return true;
    }

    #[cfg(windows)]
    {
        !response_connection_close(response)
    }

    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(windows)]
pub(super) fn response_connection_close(response: &Response) -> bool {
    response
        .headers()
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("close"))
}

pub(super) fn digest_challenged_request(
    original_method: Method,
    original_body: RequestBody,
    redirect_statuses: &[StatusCode],
) -> (Method, RequestBody) {
    let mut method = original_method;
    let mut body = original_body;

    for status in redirect_statuses {
        match *status {
            StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND | StatusCode::SEE_OTHER => {
                if method != Method::GET && method != Method::HEAD {
                    method = Method::GET;
                }
                body = None;
            }
            StatusCode::TEMPORARY_REDIRECT | StatusCode::PERMANENT_REDIRECT => {}
            _ => {}
        }
    }

    (method, body)
}

pub(super) fn digest_credentials(
    value: Option<&str>,
) -> Result<Option<(String, String)>, FetchError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let Some((username, password)) = value.split_once(':') else {
        return Err("digest format must be <USERNAME:PASSWORD>".into());
    };
    Ok(Some((username.to_string(), password.to_string())))
}

pub(crate) fn aws_config(value: Option<&str>) -> Result<Option<aws_sigv4::Config>, FetchError> {
    value
        .map(aws_sigv4::parse_config)
        .transpose()
        .map_err(|err| FetchError::Message(err.to_string()))
}

pub(super) fn aws_unsigned_payload(cli: &Cli, config: &aws_sigv4::Config) -> bool {
    config.service == "s3" && cli.data.as_deref() == Some("@-") && !cli.data_is_literal
}

pub(crate) fn apply_aws_sigv4(
    cli: &Cli,
    method: &str,
    url: &Url,
    headers: &mut HeaderMap,
    body: &RequestBody,
    config: &aws_sigv4::Config,
) -> Result<(), FetchError> {
    let unsigned_payload = aws_unsigned_payload(cli, config);
    let body_bytes = request_body_bytes(body);
    let content_sha256 = HeaderName::from_static("x-amz-content-sha256");
    if body_bytes.is_none() && !unsigned_payload && !headers.contains_key(&content_sha256) {
        let hash = request_body_sha256_hex(body)?;
        headers.insert(
            content_sha256,
            HeaderValue::from_str(&hash)
                .map_err(|err| FetchError::Message(format!("invalid AWS payload hash: {err}")))?,
        );
    }
    aws_sigv4::sign(
        method,
        url,
        headers,
        body_bytes,
        config,
        time::OffsetDateTime::now_utc(),
        unsigned_payload,
    )
    .map_err(|err| FetchError::Message(err.to_string()))
}

pub(crate) fn request_body_sha256_hex(body: &RequestBody) -> Result<String, FetchError> {
    let Some(body) = body else {
        return hex_sha256_stream(std::io::empty());
    };
    let mut hasher = Sha256::new();
    match &body.source {
        RequestBodySource::Bytes(bytes) => hasher.update(bytes),
        RequestBodySource::File { path, .. } => {
            hash_reader(&mut hasher, std::fs::File::open(path)?)?;
        }
        RequestBodySource::Multipart(multipart) => {
            let mut writer = Sha256Writer(&mut hasher);
            multipart
                .write_to(&mut writer)
                .map_err(|err| FetchError::Message(err.to_string()))?;
        }
        RequestBodySource::GrpcJsonStream { source, desc } => {
            if request_body_source_uses_stdin(source) {
                return Err(FetchError::Message(
                    "AWS SigV4 cannot sign a streaming stdin request body unless x-amz-content-sha256 is set or S3 unsigned payload is used".to_string(),
                ));
            }
            let bytes = request_body_source_to_bytes((**source).clone())?;
            let framed = proto::stream_json_to_grpc_frames(&bytes, desc)
                .map_err(|err| FetchError::Message(err.to_string()))?;
            hasher.update(framed);
        }
        RequestBodySource::Stdin => {
            return Err(FetchError::Message(
                "AWS SigV4 cannot sign a streaming stdin request body unless x-amz-content-sha256 is set or S3 unsigned payload is used".to_string(),
            ));
        }
    }
    Ok(hex_encode(hasher.finalize().as_slice()))
}

pub(super) fn hash_reader(hasher: &mut Sha256, mut reader: impl Read) -> Result<(), FetchError> {
    let mut buf = [0_u8; 8192];
    loop {
        let len = reader.read(&mut buf)?;
        if len == 0 {
            return Ok(());
        }
        hasher.update(&buf[..len]);
    }
}

pub(super) fn hex_sha256_stream(reader: impl Read) -> Result<String, FetchError> {
    let mut hasher = Sha256::new();
    hash_reader(&mut hasher, reader)?;
    Ok(hex_encode(hasher.finalize().as_slice()))
}

pub(super) struct Sha256Writer<'a>(&'a mut Sha256);

impl Write for Sha256Writer<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub(crate) fn request_body_bytes(body: &RequestBody) -> Option<&[u8]> {
    match body.as_ref().map(|body| &body.source) {
        Some(RequestBodySource::Bytes(bytes)) => Some(bytes.as_ref()),
        _ => None,
    }
}

pub(crate) fn request_body_content_len(body: &RequestBody) -> Result<Option<u64>, FetchError> {
    match body.as_ref() {
        None => Ok(None),
        Some(RequestBodyPayload {
            source: RequestBodySource::Bytes(bytes),
            ..
        }) => Ok(Some(bytes.len() as u64)),
        Some(RequestBodyPayload {
            source: RequestBodySource::File { len, .. },
            ..
        }) => Ok(Some(*len)),
        Some(RequestBodyPayload {
            source: RequestBodySource::Multipart(multipart),
            ..
        }) => multipart
            .content_len()
            .map(Some)
            .map_err(|err| FetchError::Message(err.to_string())),
        Some(RequestBodyPayload {
            source: RequestBodySource::Stdin,
            ..
        }) => Ok(None),
        Some(RequestBodyPayload {
            source: RequestBodySource::GrpcJsonStream { .. },
            ..
        }) => Ok(None),
    }
}

pub(super) fn inferred_request_body_content_len(
    headers: &HeaderMap,
    body: &RequestBody,
) -> Result<Option<u64>, FetchError> {
    if headers.contains_key(CONTENT_LENGTH) || headers.contains_key(TRANSFER_ENCODING) {
        return Ok(None);
    }
    request_body_content_len(body)
}

pub(crate) fn request_body_to_transport_body(body: RequestBodyPayload) -> Result<Body, FetchError> {
    match body.source {
        RequestBodySource::Bytes(bytes) => Ok(Body::from(bytes)),
        RequestBodySource::File { path, .. } => {
            let file = std::fs::File::open(&path)?;
            Ok(Body::from(tokio::fs::File::from_std(file)))
        }
        RequestBodySource::Stdin => Ok(Body::wrap_stream(ReaderStream::new(tokio::io::stdin()))),
        RequestBodySource::Multipart(multipart) => Ok(Body::wrap_stream(multipart.stream())),
        RequestBodySource::GrpcJsonStream { source, desc } => match *source {
            RequestBodySource::Stdin => Ok(Body::wrap_stream(
                proto::stdin_json_to_grpc_frame_stream(desc),
            )),
            source => {
                let reader = request_body_source_to_async_reader(source)?;
                Ok(Body::wrap_stream(proto::json_reader_to_grpc_frame_stream(
                    reader, desc,
                )))
            }
        },
    }
}

pub(crate) fn request_body_source_to_async_reader(
    source: RequestBodySource,
) -> Result<AsyncReadBox, FetchError> {
    match source {
        RequestBodySource::Bytes(bytes) => Ok(Box::pin(Cursor::new(bytes))),
        RequestBodySource::File { path, .. } => {
            let file = std::fs::File::open(&path)?;
            Ok(Box::pin(tokio::fs::File::from_std(file)))
        }
        RequestBodySource::Stdin => Ok(Box::pin(tokio::io::stdin())),
        RequestBodySource::Multipart(multipart) => Ok(Box::pin(StreamReader::new(
            multipart
                .stream()
                .map_err(|err| std::io::Error::other(err.to_string())),
        ))),
        RequestBodySource::GrpcJsonStream { source, desc } => {
            let reader = request_body_source_to_async_reader(*source)?;
            Ok(Box::pin(StreamReader::new(
                proto::json_reader_to_grpc_frame_stream(reader, desc),
            )))
        }
    }
}

pub(crate) fn request_body_into_bytes(
    body: RequestBody,
) -> Result<MaterializedRequestBody, FetchError> {
    let Some(body) = body else {
        return Ok(None);
    };
    let content_type = body.content_type.clone();
    let bytes = request_body_source_to_bytes(body.source)?;
    Ok(Some((bytes, content_type)))
}

pub(crate) fn request_body_into_bytes_limited(
    body: RequestBody,
    max_bytes: usize,
    limit_error: &str,
) -> Result<MaterializedRequestBody, FetchError> {
    let Some(body) = body else {
        return Ok(None);
    };
    let content_type = body.content_type.clone();
    let bytes = request_body_source_to_bytes_limited(body.source, max_bytes, limit_error)?;
    Ok(Some((bytes, content_type)))
}

pub(crate) fn request_body_source_to_bytes(
    source: RequestBodySource,
) -> Result<Vec<u8>, FetchError> {
    match source {
        RequestBodySource::Bytes(bytes) => Ok(bytes.to_vec()),
        RequestBodySource::File { path, .. } => Ok(std::fs::read(path)?),
        RequestBodySource::Stdin => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            Ok(buf)
        }
        RequestBodySource::Multipart(multipart) => multipart
            .open()
            .map_err(|err| FetchError::Message(err.to_string())),
        RequestBodySource::GrpcJsonStream { source, desc } => {
            let bytes = request_body_source_to_bytes(*source)?;
            proto::stream_json_to_grpc_frames(&bytes, &desc)
                .map_err(|err| FetchError::Message(err.to_string()))
        }
    }
}

fn request_body_source_to_bytes_limited(
    source: RequestBodySource,
    max_bytes: usize,
    limit_error: &str,
) -> Result<Vec<u8>, FetchError> {
    match source {
        RequestBodySource::Bytes(bytes) => {
            ensure_materialized_len(bytes.len(), max_bytes, limit_error)?;
            Ok(bytes.to_vec())
        }
        RequestBodySource::File { path, len } => {
            ensure_materialized_len_u64(len, max_bytes, limit_error)?;
            let file = std::fs::File::open(path)?;
            read_to_end_limited(file, max_bytes, limit_error)
        }
        RequestBodySource::Stdin => {
            let stdin = std::io::stdin();
            read_to_end_limited(stdin.lock(), max_bytes, limit_error)
        }
        RequestBodySource::Multipart(multipart) => {
            ensure_materialized_len_u64(
                multipart
                    .content_len()
                    .map_err(|err| FetchError::Message(err.to_string()))?,
                max_bytes,
                limit_error,
            )?;
            let mut out = Vec::new();
            multipart
                .write_to(LimitedBytesWriter {
                    out: &mut out,
                    limit: max_bytes,
                    limit_error,
                })
                .map_err(|err| FetchError::Message(err.to_string()))?;
            Ok(out)
        }
        RequestBodySource::GrpcJsonStream { source, desc } => {
            let bytes = request_body_source_to_bytes_limited(*source, max_bytes, limit_error)?;
            let framed = proto::stream_json_to_grpc_frames(&bytes, &desc)
                .map_err(|err| FetchError::Message(err.to_string()))?;
            ensure_materialized_len(framed.len(), max_bytes, limit_error)?;
            Ok(framed)
        }
    }
}

fn read_to_end_limited<R: Read>(
    reader: R,
    max_bytes: usize,
    limit_error: &str,
) -> Result<Vec<u8>, FetchError> {
    let mut out = Vec::new();
    let read_limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    reader.take(read_limit).read_to_end(&mut out)?;
    ensure_materialized_len(out.len(), max_bytes, limit_error)?;
    Ok(out)
}

fn ensure_materialized_len(
    len: usize,
    max_bytes: usize,
    limit_error: &str,
) -> Result<(), FetchError> {
    if len > max_bytes {
        return Err(FetchError::Message(limit_error.to_string()));
    }
    Ok(())
}

fn ensure_materialized_len_u64(
    len: u64,
    max_bytes: usize,
    limit_error: &str,
) -> Result<(), FetchError> {
    if len > u64::try_from(max_bytes).unwrap_or(u64::MAX) {
        return Err(FetchError::Message(limit_error.to_string()));
    }
    Ok(())
}

struct LimitedBytesWriter<'a> {
    out: &'a mut Vec<u8>,
    limit: usize,
    limit_error: &'a str,
}

impl Write for LimitedBytesWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self
            .out
            .len()
            .checked_add(buf.len())
            .is_none_or(|len| len > self.limit)
        {
            return Err(std::io::Error::other(self.limit_error.to_string()));
        }
        self.out.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct DryRunBodyPreview {
    bytes: Vec<u8>,
    truncated: bool,
}

fn dry_run_body_preview(
    body: &RequestBodyPayload,
    limit: usize,
) -> Result<DryRunBodyPreview, FetchError> {
    dry_run_source_preview(&body.source, limit)
}

fn dry_run_source_preview(
    source: &RequestBodySource,
    limit: usize,
) -> Result<DryRunBodyPreview, FetchError> {
    match source {
        RequestBodySource::Bytes(bytes) => Ok(DryRunBodyPreview {
            bytes: bytes.slice(..bytes.len().min(limit)).to_vec(),
            truncated: bytes.len() > limit,
        }),
        RequestBodySource::File { path, len } => Ok(DryRunBodyPreview {
            bytes: read_file_prefix(path, limit)?,
            truncated: *len > u64::try_from(limit).unwrap_or(u64::MAX),
        }),
        RequestBodySource::Stdin => read_prefix_preview(std::io::stdin().lock(), limit),
        RequestBodySource::Multipart(multipart) => {
            let (bytes, truncated) = multipart
                .preview(limit)
                .map_err(|err| FetchError::Message(err.to_string()))?;
            Ok(DryRunBodyPreview { bytes, truncated })
        }
        RequestBodySource::GrpcJsonStream { source, desc } => {
            grpc_json_stream_dry_run_preview(source, desc, limit)
        }
    }
}

fn read_prefix_preview<R: Read>(reader: R, limit: usize) -> Result<DryRunBodyPreview, FetchError> {
    let read_limit = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let mut limited = reader.take(read_limit);
    let mut bytes = Vec::new();
    limited.read_to_end(&mut bytes)?;
    let truncated = bytes.len() > limit;
    bytes.truncate(limit);
    Ok(DryRunBodyPreview { bytes, truncated })
}

fn grpc_json_stream_dry_run_preview(
    source: &RequestBodySource,
    desc: &prost_reflect::MessageDescriptor,
    limit: usize,
) -> Result<DryRunBodyPreview, FetchError> {
    let input = dry_run_source_preview(source, limit)?;
    if input.truncated {
        return Ok(DryRunBodyPreview {
            bytes: vec![0],
            truncated: true,
        });
    }
    let framed = proto::stream_json_to_grpc_frames(&input.bytes, desc)
        .map_err(|err| FetchError::Message(err.to_string()))?;
    Ok(DryRunBodyPreview {
        bytes: framed.iter().copied().take(limit).collect(),
        truncated: framed.len() > limit,
    })
}

#[cfg(test)]
pub(crate) fn request_body_preview(body: &RequestBodyPayload) -> Result<Vec<u8>, FetchError> {
    dry_run_body_preview(body, DRY_RUN_BODY_PREVIEW_BYTES).map(|preview| preview.bytes)
}

pub(super) fn apply_body_content_type(headers: &mut HeaderMap, body: &RequestBody) {
    let Some(RequestBodyPayload {
        content_type: Some(content_type),
        ..
    }) = body.as_ref()
    else {
        return;
    };
    if !headers.contains_key(CONTENT_TYPE)
        && let Ok(value) = HeaderValue::from_str(content_type)
    {
        headers.insert(CONTENT_TYPE, value);
    }
}

pub(super) fn apply_ranges(headers: &mut HeaderMap, ranges: &[String]) {
    if ranges.is_empty() {
        return;
    }
    headers.insert(
        RANGE,
        HeaderValue::from_str(&format!("bytes={}", ranges.join(", ")))
            .expect("range is a valid header value"),
    );
}

pub(crate) fn request_body(cli: &Cli) -> Result<RequestBody, FetchError> {
    if !cli.multipart.is_empty() {
        let multipart = multipart::Multipart::from_cli_fields(&cli.multipart)
            .map_err(|err| FetchError::Message(err.to_string()))?
            .expect("non-empty multipart input creates multipart body");
        multipart
            .content_len()
            .map_err(|err| FetchError::Message(err.to_string()))?;
        let content_type = multipart.content_type();
        return Ok(Some(RequestBodyPayload {
            source: RequestBodySource::Multipart(multipart),
            content_type: Some(content_type),
        }));
    }
    if let Some(value) = cli.data.as_deref() {
        if let Some(bytes) = &cli.data_literal_bytes {
            return Ok(Some(RequestBodyPayload {
                source: RequestBodySource::Bytes(Bytes::copy_from_slice(bytes)),
                content_type: None,
            }));
        }
        if cli.data_is_literal {
            return Ok(Some(RequestBodyPayload {
                source: RequestBodySource::Bytes(Bytes::copy_from_slice(value.as_bytes())),
                content_type: None,
            }));
        }
        let (source, content_type) = body_value_source(value, true)?;
        return Ok(Some(RequestBodyPayload {
            source,
            content_type,
        }));
    }
    if let Some(value) = cli.json.as_deref() {
        let (source, _) = body_value_source(value, false)?;
        return Ok(Some(RequestBodyPayload {
            source,
            content_type: Some("application/json".to_string()),
        }));
    }
    if let Some(value) = cli.xml.as_deref() {
        let (source, _) = body_value_source(value, false)?;
        return Ok(Some(RequestBodyPayload {
            source,
            content_type: Some("application/xml".to_string()),
        }));
    }
    if !cli.form.is_empty() {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for raw in &cli.form {
            let (key, val) = raw.split_once('=').unwrap_or((raw, ""));
            serializer.append_pair(key.trim(), val);
        }
        return Ok(Some(RequestBodyPayload {
            source: RequestBodySource::Bytes(Bytes::from(serializer.finish().into_bytes())),
            content_type: Some("application/x-www-form-urlencoded".to_string()),
        }));
    }
    Ok(None)
}

pub(super) fn body_value_source(
    value: &str,
    detect_content_type: bool,
) -> Result<(RequestBodySource, Option<String>), FetchError> {
    if value == "@-" {
        return Ok((
            RequestBodySource::Stdin,
            detect_content_type.then(|| "application/octet-stream".to_string()),
        ));
    }
    if let Some(path) = value.strip_prefix('@') {
        let expanded = crate::fileutil::expand_home(path);
        let metadata = std::fs::metadata(&expanded).map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                FetchError::Message(format!("file '{path}' does not exist"))
            } else {
                err.into()
            }
        })?;
        if metadata.is_dir() {
            return Err(format!("file '{path}' is a directory").into());
        }
        let content_type = if detect_content_type {
            Some(detect_body_file_content_type(&expanded)?)
        } else {
            None
        };
        return Ok((
            RequestBodySource::File {
                path: expanded.to_string_lossy().into_owned(),
                len: metadata.len(),
            },
            content_type,
        ));
    }
    Ok((
        RequestBodySource::Bytes(Bytes::copy_from_slice(value.as_bytes())),
        detect_content_type.then(|| sniff_content_type_like_go(value.as_bytes())),
    ))
}

pub(super) fn detect_body_file_content_type(path: &Path) -> Result<String, FetchError> {
    if let Some(content_type) = content_type::request_content_type_for_path(path) {
        return Ok(content_type.to_string());
    }
    Ok(sniff_content_type_like_go(&read_file_prefix(path, 512)?))
}

pub(super) fn read_file_prefix(
    path: impl AsRef<Path>,
    limit: usize,
) -> Result<Vec<u8>, FetchError> {
    let mut file = std::fs::File::open(path)?;
    let mut out = vec![0_u8; limit];
    let len = file.read(&mut out)?;
    out.truncate(len);
    Ok(out)
}

pub(super) fn sniff_content_type_like_go(body: &[u8]) -> String {
    let sniff = &body[..body.len().min(512)];
    if sniff.starts_with(b"\xFF\xD8\xFF") {
        return "image/jpeg".to_string();
    }
    if sniff.starts_with(b"\x89PNG\r\n\x1A\n") {
        return "image/png".to_string();
    }
    if sniff.starts_with(b"GIF87a") || sniff.starts_with(b"GIF89a") {
        return "image/gif".to_string();
    }
    if sniff.len() >= 12 && &sniff[..4] == b"RIFF" && &sniff[8..12] == b"WEBP" {
        return "image/webp".to_string();
    }
    if sniff.starts_with(b"%PDF-") {
        return "application/pdf".to_string();
    }
    if sniff.starts_with(b"PK\x03\x04")
        || sniff.starts_with(b"PK\x05\x06")
        || sniff.starts_with(b"PK\x07\x08")
    {
        return "application/zip".to_string();
    }
    if looks_like_html(sniff) {
        return "text/html; charset=utf-8".to_string();
    }
    if is_text_like_go(sniff) {
        "text/plain; charset=utf-8".to_string()
    } else {
        "application/octet-stream".to_string()
    }
}

pub(super) fn looks_like_html(bytes: &[u8]) -> bool {
    let trimmed = trim_ascii_whitespace(bytes);
    let lower = String::from_utf8_lossy(trimmed).to_ascii_lowercase();
    [
        "<!doctype html",
        "<html",
        "<head",
        "<script",
        "<iframe",
        "<h1",
        "<div",
        "<font",
        "<table",
        "<a",
        "<style",
        "<title",
        "<body",
        "<br",
        "<p",
    ]
    .iter()
    .any(|tag| lower.starts_with(tag))
}

pub(super) fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map(|idx| idx + 1)
        .unwrap_or(start);
    &bytes[start..end]
}

pub(super) fn is_text_like_go(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| {
        matches!(*byte, b'\t' | b'\n' | b'\x0c' | b'\r') || (*byte >= 0x20 && *byte != 0x7f)
    })
}

pub(crate) fn basic_header(value: Option<&str>) -> Result<Option<String>, FetchError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if !value.contains(':') {
        return Err("basic format must be <USERNAME:PASSWORD>".into());
    }
    let encoded = base64::engine::general_purpose::STANDARD.encode(value.as_bytes());
    Ok(Some(format!("Basic {encoded}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    use clap::Parser;

    #[test]
    fn request_body_data_detects_go_style_content_type() {
        let cli = Cli::try_parse_from(["fetch", "--data", "hello", "https://example.com"]).unwrap();
        let body = request_body_into_bytes(request_body(&cli).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(body.0, b"hello");
        assert_eq!(body.1.as_deref(), Some("text/plain; charset=utf-8"));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.json");
        std::fs::write(&path, br#"{"ok":true}"#).unwrap();
        let cli = Cli::try_parse_from([
            "fetch",
            "--data",
            &format!("@{}", path.display()),
            "https://example.com",
        ])
        .unwrap();
        let body = request_body_into_bytes(request_body(&cli).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(body.0, br#"{"ok":true}"#);
        assert_eq!(body.1.as_deref(), Some("application/json"));
    }

    #[test]
    fn request_body_form_preserves_value_spaces_after_equals() {
        let cli =
            Cli::try_parse_from(["fetch", "--form", "message= hello ", "https://example.com"])
                .unwrap();
        let body = request_body_into_bytes(request_body(&cli).unwrap())
            .unwrap()
            .unwrap();

        assert_eq!(body.0, b"message=+hello+");
        assert_eq!(body.1.as_deref(), Some("application/x-www-form-urlencoded"));
    }

    #[test]
    fn request_body_file_errors_match_go_cli_surface() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.txt");
        let cli = Cli::try_parse_from([
            "fetch",
            "--data",
            &format!("@{}", missing.display()),
            "https://example.com",
        ])
        .unwrap();
        let err = request_body(&cli).unwrap_err().to_string();
        assert_eq!(err, format!("file '{}' does not exist", missing.display()));

        let cli = Cli::try_parse_from([
            "fetch",
            "--data",
            &format!("@{}", dir.path().display()),
            "https://example.com",
        ])
        .unwrap();
        let err = request_body(&cli).unwrap_err().to_string();
        assert_eq!(
            err,
            format!("file '{}' is a directory", dir.path().display())
        );
    }

    #[cfg(unix)]
    #[test]
    fn request_body_propagates_multipart_header_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evil\nname.txt");
        std::fs::write(&path, b"payload").unwrap();
        let cli = Cli::try_parse_from([
            "fetch",
            "--multipart",
            &format!("file=@{}", path.display()),
            "https://example.com",
        ])
        .unwrap();

        let err = request_body(&cli).unwrap_err().to_string();

        assert!(err.contains("invalid multipart filename"));
    }

    #[test]
    fn digest_credentials_require_username_password() {
        assert_eq!(
            digest_credentials(Some("user:pass")).unwrap(),
            Some(("user".to_string(), "pass".to_string()))
        );
        assert_eq!(
            digest_credentials(Some(" user : pass ")).unwrap(),
            Some((" user ".to_string(), " pass ".to_string()))
        );
        assert!(digest_credentials(Some("nocolon")).is_err());
        assert_eq!(digest_credentials(None).unwrap(), None);
    }

    #[test]
    fn digest_challenge_after_redirect_uses_go_redirect_method_and_body() {
        let original_body = Some(RequestBodyPayload::from_bytes(
            b"payload".to_vec(),
            Some("text/plain".to_string()),
        ));

        let (method, body) = digest_challenged_request(
            Method::POST,
            original_body.clone(),
            &[StatusCode::SEE_OTHER],
        );
        assert_eq!(method, Method::GET);
        assert!(body.is_none());

        let (method, body) = digest_challenged_request(
            Method::POST,
            original_body.clone(),
            &[StatusCode::TEMPORARY_REDIRECT],
        );
        assert_eq!(method, Method::POST);
        assert_eq!(request_body_bytes(&body), Some(b"payload".as_slice()));

        let (method, body) = digest_challenged_request(
            Method::HEAD,
            original_body,
            &[StatusCode::MOVED_PERMANENTLY],
        );
        assert_eq!(method, Method::HEAD);
        assert!(body.is_none());
    }

    #[test]
    fn basic_header_preserves_credential_spaces() {
        assert_eq!(
            basic_header(Some(" user : pass ")).unwrap(),
            Some("Basic IHVzZXIgOiBwYXNzIA==".to_string())
        );
        assert!(basic_header(Some("nocolon")).is_err());
        assert_eq!(basic_header(None).unwrap(), None);
    }

    #[test]
    fn owned_request_body_clone_replays_without_go_temp_spool() {
        let body = Some(RequestBodyPayload::from_bytes(
            b"hello".to_vec(),
            Some("text/plain".to_string()),
        ));
        let first = request_body_bytes(&body).unwrap().to_vec();
        let replay = body.clone();

        assert_eq!(first, b"hello");
        assert_eq!(request_body_bytes(&replay).unwrap(), b"hello");
    }

    #[test]
    fn grpc_request_body_frames_empty_and_raw_bodies() {
        let empty = proto::grpc_request_body(None, None).unwrap();
        let empty = request_body_into_bytes(empty).unwrap().unwrap();
        assert_eq!(empty.0, crate::grpc::framing::frame(&[], false).unwrap());
        assert_eq!(empty.1.as_deref(), Some("application/grpc+proto"));

        let framed = proto::grpc_request_body(
            Some(RequestBodyPayload::from_bytes(b"hello".to_vec(), None)),
            None,
        )
        .unwrap();
        let framed = request_body_into_bytes(framed).unwrap().unwrap();
        assert_eq!(
            framed.0,
            crate::grpc::framing::frame(b"hello", false).unwrap()
        );
    }

    #[test]
    fn grpc_request_body_rejects_oversized_file_before_reading() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large.bin");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(crate::grpc::framing::MAX_MESSAGE_SIZE as u64 + 1)
            .unwrap();
        let body = Some(RequestBodyPayload {
            source: RequestBodySource::File {
                path: path.display().to_string(),
                len: crate::grpc::framing::MAX_MESSAGE_SIZE as u64 + 1,
            },
            content_type: None,
        });

        let err = proto::grpc_request_body(body, None).unwrap_err();

        assert_eq!(
            err.to_string(),
            format!(
                "gRPC request body exceeds maximum of {} bytes",
                crate::grpc::framing::MAX_MESSAGE_SIZE
            )
        );
    }
}
