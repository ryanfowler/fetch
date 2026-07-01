use super::*;

use super::stream::StreamedOutput;

pub(super) fn finalize_streamed_response(
    cli: &Cli,
    status: StatusCode,
    response_headers: &HeaderMap,
    response_timing: Option<ResponseTiming>,
    method_is_head: bool,
    body_start: Instant,
    streamed: StreamedOutput,
) -> i32 {
    handle_optional_clipboard_outcome(cli, streamed.clipboard);
    let body_duration = body_duration_from_len(method_is_head, streamed.bytes_written, body_start);
    print_timing(cli, response_timing, body_duration);

    let code = exit_code(status.as_u16(), cli.ignore_status);
    check_grpc_status(cli, response_headers, &streamed.trailers, code)
}

pub(super) fn handle_optional_clipboard_outcome(
    cli: &Cli,
    outcome: Option<clipboard::CopyOutcome>,
) {
    if let Some(outcome) = outcome {
        handle_clipboard_outcome(cli, outcome);
    }
}

pub(super) fn handle_clipboard_outcome(cli: &Cli, outcome: clipboard::CopyOutcome) {
    match outcome {
        clipboard::CopyOutcome::Copied { .. } => {}
        other => write_warning(cli, &other.to_string()),
    }
}

pub(super) fn body_duration(
    method_is_head: bool,
    bytes: &[u8],
    start: Instant,
) -> Option<Duration> {
    body_duration_from_len(
        method_is_head,
        i64::try_from(bytes.len()).unwrap_or(i64::MAX),
        start,
    )
}

fn body_duration_from_len(method_is_head: bool, len: i64, start: Instant) -> Option<Duration> {
    if method_is_head || len == 0 {
        None
    } else {
        Some(start.elapsed())
    }
}

pub(super) fn print_timing(cli: &Cli, timing: Option<ResponseTiming>, body: Option<Duration>) {
    if !cli.timing || cli.silent {
        return;
    }
    let Some(mut timing) = timing else {
        return;
    };
    timing.body = body;
    let mut printer = core::stdio().stderr_printer(cli.color.as_deref());
    timing::render_waterfall_to(timing, &mut printer);
    let _ = printer.flush_to(&mut std::io::stderr());
}

pub(super) fn check_grpc_status(
    cli: &Cli,
    headers: &HeaderMap,
    trailers: &HeaderMap,
    exit_code: i32,
) -> i32 {
    if !cli.grpc {
        return exit_code;
    }
    let Some(status) = grpc_status::from_headers_or_trailers(headers, trailers) else {
        return exit_code;
    };
    if status.ok() {
        return exit_code;
    }
    if !cli.silent {
        write_error_with_color(status, cli.color.as_deref());
    }
    if exit_code == 0 { 1 } else { exit_code }
}

pub(super) fn print_response_metadata(cli: &Cli, response: &Response) {
    if cli.silent {
        return;
    }

    let status = response.status();
    let mut printer = core::Printer::stderr(cli.color.as_deref());
    if cli.verbose >= 2 {
        printer.write_response_prefix();
    }
    printer.write_styled(version_label(response.version()), &[core::Sequence::Dim]);
    printer.push_str(" ");
    let status_color = color_for_status(status.as_u16());
    printer.write_styled(
        &status.as_u16().to_string(),
        &[status_color, core::Sequence::Bold],
    );
    let reason = status.canonical_reason().unwrap_or("");
    if !reason.is_empty() {
        printer.push_str(" ");
        printer.write_styled(reason, &[status_color]);
    }
    printer.push_str("\n");

    if cli.verbose > 0 {
        let mut lines = header_lines(response.headers());
        if cli.sort_headers {
            sort_header_lines(&mut lines);
        }
        for (name, value) in lines {
            if cli.verbose >= 2 {
                printer.write_response_prefix();
            }
            printer.write_styled(&name, &[core::Sequence::Bold, core::Sequence::Cyan]);
            printer.push_str(": ");
            printer.push_str(&value);
            printer.push_str("\n");
        }
    }
    if cli.verbose >= 2 {
        printer.write_response_prefix();
    }
    printer.push_str("\n");
    core::flush_stderr(printer);
}

pub(super) fn exit_code(status: u16, ignore_status: bool) -> i32 {
    if ignore_status || (200..400).contains(&status) {
        0
    } else if (400..500).contains(&status) {
        4
    } else if (500..600).contains(&status) {
        5
    } else {
        6
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use clap::Parser;

    #[test]
    fn finalize_streamed_response_checks_grpc_status_from_trailers() {
        let cli = Cli::try_parse_from([
            "fetch",
            "--grpc",
            "--silent",
            "https://example.com/test.Service/Get",
        ])
        .unwrap();
        let headers = HeaderMap::new();
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("7"));
        let streamed = StreamedOutput {
            trailers,
            bytes_written: 12,
            clipboard: None,
        };

        let code = finalize_streamed_response(
            &cli,
            StatusCode::OK,
            &headers,
            None,
            false,
            Instant::now(),
            streamed,
        );

        assert_eq!(code, 1);
    }

    #[test]
    fn exit_code_maps_status_classes() {
        assert_eq!(exit_code(200, false), 0);
        assert_eq!(exit_code(302, false), 0);
        assert_eq!(exit_code(404, false), 4);
        assert_eq!(exit_code(503, false), 5);
        assert_eq!(exit_code(999, false), 6);
        assert_eq!(exit_code(404, true), 0);
    }
}
