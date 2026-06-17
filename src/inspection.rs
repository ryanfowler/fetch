use crate::cli::Cli;

pub(crate) fn append_shared_ignored_request_flags(cli: &Cli, ignored: &mut Vec<&'static str>) {
    if cli.data.is_some() || cli.json.is_some() || cli.xml.is_some() {
        ignored.push("--data/--json/--xml");
    }
    if !cli.form.is_empty() {
        ignored.push("--form");
    }
    if !cli.multipart.is_empty() {
        ignored.push("--multipart");
    }
    if cli.grpc {
        ignored.push("--grpc");
    }
    if cli.grpc_describe.is_some() {
        ignored.push("--grpc-describe");
    }
    if cli.grpc_list {
        ignored.push("--grpc-list");
    }
    if cli.proto_desc.is_some() {
        ignored.push("--proto-desc");
    }
    if !cli.proto_files.is_empty() {
        ignored.push("--proto-file");
    }
    if !cli.proto_imports.is_empty() {
        ignored.push("--proto-import");
    }
    if cli.output.is_some() {
        ignored.push("--output");
    }
    if cli.remote_name {
        ignored.push("--remote-name");
    }
    if cli.remote_header_name {
        ignored.push("--remote-header-name");
    }
    if cli.copy {
        ignored.push("--copy");
    }
    if cli.clobber {
        ignored.push("--clobber");
    }
    if cli.method.is_some() {
        ignored.push("--method");
    }
    if !cli.headers.is_empty() {
        ignored.push("--header");
    }
    if !cli.query.is_empty() {
        ignored.push("--query");
    }
    if cli.edit {
        ignored.push("--edit");
    }
    if cli.session.is_some() {
        ignored.push("--session");
    }
    if cli.retry() > 0 {
        ignored.push("--retry");
    }
    if cli.retry_delay.is_some() {
        ignored.push("--retry-delay");
    }
    if cli.redirects.is_some() {
        ignored.push("--redirects");
    }
    if !cli.ranges.is_empty() {
        ignored.push("--range");
    }
    if cli.timing {
        ignored.push("--timing");
    }
    if cli.proxy.is_some() {
        ignored.push("--proxy");
    }
    if cli.discard {
        ignored.push("--discard");
    }
    if cli.unix.is_some() {
        ignored.push("--unix");
    }
}

pub(crate) fn append_shared_ignored_auth_flags(cli: &Cli, ignored: &mut Vec<&'static str>) {
    if cli.bearer.is_some() {
        ignored.push("--bearer");
    }
    if cli.basic.is_some() {
        ignored.push("--basic");
    }
    if cli.digest.is_some() {
        ignored.push("--digest");
    }
    if cli.aws_sigv4.is_some() {
        ignored.push("--aws-sigv4");
    }
}

pub(crate) fn append_shared_ignored_response_flags(cli: &Cli, ignored: &mut Vec<&'static str>) {
    if cli.compress.is_some() || cli.no_encode {
        ignored.push("--compress/--no-encode");
    }
    if cli.format.is_some() {
        ignored.push("--format");
    }
    if cli.image.is_some() {
        ignored.push("--image");
    }
    if cli.pager.is_some() {
        ignored.push("--pager");
    }
    if cli.ignore_status {
        ignored.push("--ignore-status");
    }
    if cli.sort_headers {
        ignored.push("--sort-headers");
    }
    if cli.ws_interactive.is_some() {
        ignored.push("--ws-interactive");
    }
    if cli.ws_message_mode.is_some() {
        ignored.push("--ws-message-mode");
    }
    if cli.dry_run {
        ignored.push("--dry-run");
    }
}
