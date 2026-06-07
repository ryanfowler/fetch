use super::*;

mod formatters;
mod metadata;
mod stdout;
mod stream;

pub(super) use formatters::should_retry_sse_without_compression;
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
use stdout::{stdout_stream_target, write_stdout_bytes};
use stream::{
    read_decoded_response_body_limited, stream_response_to_discard, stream_response_to_output,
    stream_response_to_stdout,
};

pub(super) async fn finish_response(
    cli: &Cli,
    response: Response,
    compression: CompressionMode,
    timing: Option<AttemptTiming>,
    grpc_method: Option<&prost_reflect::MethodDescriptor>,
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
    let response_timing = timing.and_then(AttemptTiming::response_timing);
    let stdio = core::stdio();

    if cli.discard {
        let body_start = Instant::now();
        let streamed =
            stream_response_to_discard(response, response_headers.clone(), compression).await?;
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

    let output_path = output::resolve_output_path(
        cli.output.as_deref(),
        cli.remote_name,
        cli.remote_header_name,
        &response_url,
        &response_headers,
    )
    .map_err(|err| FetchError::Message(err.to_string()))?;
    if let Some(path) = output_path {
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
        let streamed = stream_response_to_formatted_grpc_stdout(
            response,
            response_headers.clone(),
            compression,
            cli.copy,
            grpc_method.map(|method| method.output()),
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

    let (bytes, trailers) =
        read_decoded_response_body_limited(response, response_headers.clone(), compression).await?;
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
