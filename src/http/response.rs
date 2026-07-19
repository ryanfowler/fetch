use super::*;

mod formatters;
mod metadata;
mod stdout;
mod stream;

pub(super) use formatters::{
    should_retry_sse_without_compression, should_retry_sse_without_compression_for_method,
};
pub(super) use stream::{drain_response_body_bounded, response_body_exceeds_discard_bound};

use formatters::{
    format_stdout_bytes, should_stream_formatted_grpc_stdout,
    should_stream_formatted_ndjson_stdout, should_stream_formatted_sse_stdout,
    stream_response_to_formatted_grpc_stdout, stream_response_to_formatted_ndjson_stdout,
    stream_response_to_formatted_sse_stdout,
};
use metadata::{
    body_duration, check_grpc_status, exit_code, finalize_streamed_response,
    handle_clipboard_outcome, print_response_metadata, print_timing,
};
use stdout::{StdoutBody, stdout_stream_target, write_stdout_bytes};
use stream::{
    read_decoded_article_body_limited, read_decoded_response_body_limited,
    stream_response_to_discard, stream_response_to_output, stream_response_to_stdout,
};

#[allow(clippy::too_many_arguments)]
pub(super) async fn finish_response(
    cli: &Cli,
    response: Response,
    compression: CompressionMode,
    timing: Option<AttemptTiming>,
    grpc_method: Option<&prost_reflect::MethodDescriptor>,
    har_recorder: Option<&crate::har::Recorder>,
    har_destination: Option<crate::har::Destination>,
    har_started: SystemTime,
) -> Result<i32, FetchError> {
    let response_timing = timing.and_then(AttemptTiming::response_timing);
    let status = response.status();
    let headers = response.headers().clone();
    let response_meta = har_recorder.map(|_| crate::har::ResponseMeta {
        status: status.as_u16(),
        status_text: status.canonical_reason().unwrap_or_default().to_string(),
        redirect_url: headers
            .get(LOCATION)
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
            .unwrap_or_default(),
        content_type: headers
            .get(CONTENT_TYPE)
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
            .unwrap_or_default(),
        headers,
        version: response.version(),
        remote_ip: response.remote_addr().map(|addr| addr.ip().to_string()),
        timing: response_timing,
        started: har_started,
    });
    let result = finish_response_output(
        cli,
        response,
        compression,
        response_timing,
        grpc_method,
        har_recorder.map(crate::har::Recorder::response_capture),
    )
    .await;
    let code = result?;
    if let (Some(recorder), Some(destination), Some(meta)) =
        (har_recorder, har_destination, response_meta)
    {
        let bytes = recorder.serialize(meta)?;
        destination.commit(&bytes)?;
    }
    Ok(code)
}

async fn finish_response_output(
    cli: &Cli,
    response: Response,
    compression: CompressionMode,
    response_timing: Option<ResponseTiming>,
    grpc_method: Option<&prost_reflect::MethodDescriptor>,
    har_capture: Option<crate::har::Capture>,
) -> Result<i32, FetchError> {
    let status = response.status();
    print_response_metadata(cli, &response);
    let response_headers = response.headers().clone();
    let response_url = response.url().clone();
    let response_content_length = response
        .content_length()
        .and_then(|len| i64::try_from(len).ok());
    let output_progress_total =
        output_progress_total_bytes(compression, &response_headers, response_content_length);
    let method_is_head = cli.method().eq_ignore_ascii_case("HEAD");
    let stdio = core::stdio();

    if cli.discard {
        let body_start = Instant::now();
        let streamed = stream_response_to_discard(
            response,
            response_headers.clone(),
            compression,
            har_capture,
        )
        .await?;
        return Ok(finalize_streamed_response(
            cli,
            status,
            &response_headers,
            response_timing,
            method_is_head,
            body_start,
            streamed,
        ));
    }

    let resolved_output = output::resolve_output_path(
        cli.output.as_deref(),
        cli.remote_name,
        cli.remote_header_name,
        &response_url,
        &response_headers,
    )
    .map_err(|err| FetchError::Message(err.to_string()))?;
    if let Some(warning) = &resolved_output.warning {
        write_warning(cli, warning);
    }
    if let (Some(har), Some(response_output)) =
        (cli.har.as_deref(), resolved_output.path.as_deref())
        && output::destinations_conflict(har, response_output)
    {
        return Err(FetchError::Message(
            "flags '--har' and response output cannot use the same path".into(),
        ));
    }
    if cli.article {
        return finish_article_response(
            cli,
            response,
            response_headers,
            response_url,
            compression,
            status,
            response_timing,
            method_is_head,
            resolved_output.path.as_deref(),
            har_capture,
        )
        .await;
    }
    if let Some(path) = resolved_output.path {
        let progress = if cli.silent {
            output::WriteProgress::disabled()
        } else {
            output::WriteProgress::stdio(cli.color.as_deref(), output_progress_total)
        };
        let body_start = Instant::now();
        let streamed = stream_response_to_output(
            response,
            response_headers.clone(),
            compression,
            path,
            cli.clobber,
            progress,
            cli.copy,
            har_capture,
        )
        .await?;
        return Ok(finalize_streamed_response(
            cli,
            status,
            &response_headers,
            response_timing,
            method_is_head,
            body_start,
            streamed,
        ));
    }

    let body_start = Instant::now();
    let stdout_is_terminal = stdio.stdout_is_terminal();
    if should_stream_formatted_sse_stdout(cli, &response_headers, stdout_is_terminal) {
        let use_color = stdio.stdout_color(cli.color.as_deref());
        let streamed = stream_response_to_formatted_sse_stdout(
            response,
            response_headers.clone(),
            compression,
            cli.copy,
            use_color,
            har_capture,
        )
        .await?;
        return Ok(finalize_streamed_response(
            cli,
            status,
            &response_headers,
            response_timing,
            method_is_head,
            body_start,
            streamed,
        ));
    }
    if should_stream_formatted_ndjson_stdout(cli, &response_headers, stdout_is_terminal) {
        let use_color = stdio.stdout_color(cli.color.as_deref());
        let streamed = stream_response_to_formatted_ndjson_stdout(
            response,
            response_headers.clone(),
            compression,
            cli.copy,
            use_color,
            har_capture,
        )
        .await?;
        return Ok(finalize_streamed_response(
            cli,
            status,
            &response_headers,
            response_timing,
            method_is_head,
            body_start,
            streamed,
        ));
    }
    if should_stream_formatted_grpc_stdout(cli, &response_headers, stdout_is_terminal) {
        let use_color = stdio.stdout_color(cli.color.as_deref());
        let streamed = stream_response_to_formatted_grpc_stdout(
            response,
            response_headers.clone(),
            compression,
            cli.copy,
            grpc_method.map(|method| method.output()),
            use_color,
            har_capture,
        )
        .await?;
        return Ok(finalize_streamed_response(
            cli,
            status,
            &response_headers,
            response_timing,
            method_is_head,
            body_start,
            streamed,
        ));
    }
    if let Some(target) = stdout_stream_target(cli, &response_headers, stdout_is_terminal) {
        let streamed = stream_response_to_stdout(
            cli,
            response,
            response_headers.clone(),
            compression,
            cli.copy,
            target,
            stdout_is_terminal,
            har_capture,
        )
        .await?;
        return Ok(finalize_streamed_response(
            cli,
            status,
            &response_headers,
            response_timing,
            method_is_head,
            body_start,
            streamed,
        ));
    }

    let (bytes, trailers) = read_decoded_response_body_limited(
        response,
        response_headers.clone(),
        compression,
        har_capture,
    )
    .await?;
    let body_duration = body_duration(method_is_head, bytes.as_ref(), body_start);
    if cli.copy {
        handle_clipboard_outcome(cli, clipboard::copy_bytes(&bytes));
    }
    let stdout_body = format_stdout_bytes(
        cli,
        &response_headers,
        &bytes,
        grpc_method.map(|method| method.output()),
    )?;
    write_stdout_bytes(cli, &stdout_body)?;
    print_timing(cli, response_timing, body_duration);

    let code = exit_code(status.as_u16(), cli.ignore_status);
    Ok(check_grpc_status(cli, &response_headers, &trailers, code))
}

#[allow(clippy::too_many_arguments)]
async fn finish_article_response(
    cli: &Cli,
    response: Response,
    response_headers: HeaderMap,
    response_url: url::Url,
    compression: CompressionMode,
    status: StatusCode,
    response_timing: Option<ResponseTiming>,
    method_is_head: bool,
    output_path: Option<&str>,
    har_capture: Option<crate::har::Capture>,
) -> Result<i32, FetchError> {
    let body_start = Instant::now();
    let (bytes, trailers) = read_decoded_article_body_limited(
        response,
        response_headers.clone(),
        compression,
        har_capture,
    )
    .await?;
    let body_duration = body_duration(method_is_head, &bytes, body_start);

    let input_kind = article_response_content_kind(&response_headers, &bytes);
    if input_kind == ArticleInputKind::Unsupported {
        let content_type = stdout::response_header_content_type_label(&response_headers);
        return Err(FetchError::Message(format!(
            "response content type '{content_type}' is not supported with '--article'; try again without '--article'"
        )));
    }

    let raw_content_type = response_headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    let (_, charset) = content_type::get_content_type(raw_content_type);
    let text = formatters::transcode_bytes(&bytes, &charset);
    let text = String::from_utf8_lossy(&text);
    let article = match input_kind {
        ArticleInputKind::Html => {
            crate::format::article::extract_markdown(&text, response_url.as_str())
                .map_err(FetchError::Message)?
        }
        ArticleInputKind::Markdown => {
            crate::format::article::add_url_frontmatter(&text, response_url.as_str())
        }
        ArticleInputKind::Unsupported => unreachable!("unsupported article input returned above"),
    };

    if cli.copy {
        handle_clipboard_outcome(cli, clipboard::copy_bytes(&article));
    }

    if let Some(path) = output_path {
        let progress = if cli.silent {
            output::WriteProgress::disabled()
        } else {
            output::WriteProgress::stdio(
                cli.color.as_deref(),
                Some(i64::try_from(article.len()).unwrap_or(i64::MAX)),
            )
        };
        output::write_output_with_progress(path, &article, cli.clobber, progress)
            .await
            .map_err(|err| FetchError::Message(err.to_string()))?;
    } else {
        let stdout_is_terminal = core::stdio().stdout_is_terminal();
        let rendered = if core::format_enabled(cli.format.as_deref(), stdout_is_terminal) {
            let use_color = core::color_enabled(cli.color.as_deref(), stdout_is_terminal);
            let mut out = core::Printer::new(use_color);
            if markdown::format_markdown_to(&article, &mut out).is_ok() {
                out.into_bytes()
            } else {
                article.clone()
            }
        } else {
            article.clone()
        };
        write_stdout_bytes(
            cli,
            &StdoutBody {
                bytes: rendered,
                content_type: ContentType::Markdown,
                content_type_label: "text/markdown; charset=utf-8".to_string(),
            },
        )?;
    }

    print_timing(cli, response_timing, body_duration);
    let code = exit_code(status.as_u16(), cli.ignore_status);
    Ok(check_grpc_status(cli, &response_headers, &trailers, code))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArticleInputKind {
    Html,
    Markdown,
    Unsupported,
}

fn article_response_content_kind(headers: &HeaderMap, bytes: &[u8]) -> ArticleInputKind {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    if content_type::get_content_type(content_type).0 == ContentType::Markdown {
        return ArticleInputKind::Markdown;
    }

    let declared_html = content_type
        .and_then(|value| value.parse::<mime::Mime>().ok())
        .is_some_and(|mime| {
            (mime.type_() == mime::TEXT && mime.subtype() == mime::HTML)
                || (mime.type_() == mime::APPLICATION && mime.subtype().as_str() == "xhtml")
        });
    if declared_html || content_type::sniff_content_type(bytes) == ContentType::Html {
        ArticleInputKind::Html
    } else {
        ArticleInputKind::Unsupported
    }
}
