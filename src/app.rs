use clap::{ColorChoice, CommandFactory, Parser};
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Read;

use crate::cli::{Cli, from_curl};
use crate::core;
use crate::error::{FetchError, write_cli_error_with_color, write_runtime_error_with_color};

const CURL_DEFAULT_MAX_REDIRECTS: usize = 50;
const MAX_MATERIALIZED_CURL_DATA_BYTES: usize = 16 * 1024 * 1024;

pub async fn main_entry() -> i32 {
    crate::tls::install_default_crypto_provider();

    if let Some(code) = crate::update::maybe_run_self_delete_helper() {
        return code;
    }

    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            return handle_parse_error(
                err,
                color_setting_from_args(std::env::args().skip(1)).as_deref(),
            );
        }
    };

    let signal_color = cli.color.clone();
    let mut run = Box::pin(run(cli));
    tokio::select! {
        result = &mut run => match result {
            Ok(code) => code,
            Err(err) => {
                write_runtime_error_with_color(err.error, err.color.as_deref());
                1
            }
        },
        message = shutdown_signal_message() => {
            write_runtime_error_with_color(FetchError::Runtime(message), signal_color.as_deref());
            1
        }
    }
}

#[cfg(unix)]
async fn shutdown_signal_message() -> String {
    use tokio::signal::unix::{SignalKind, signal};

    let mut interrupt = signal(SignalKind::interrupt()).ok();
    let mut hangup = signal(SignalKind::hangup()).ok();
    let mut terminate = signal(SignalKind::terminate()).ok();

    tokio::select! {
        _ = recv_signal(&mut interrupt) => "received signal: interrupt".to_string(),
        _ = recv_signal(&mut hangup) => "received signal: hangup".to_string(),
        _ = recv_signal(&mut terminate) => "received signal: terminated".to_string(),
    }
}

#[cfg(unix)]
async fn recv_signal(signal: &mut Option<tokio::signal::unix::Signal>) {
    if let Some(signal) = signal.as_mut() {
        let _ = signal.recv().await;
    } else {
        std::future::pending::<()>().await;
    }
}

#[cfg(not(unix))]
async fn shutdown_signal_message() -> String {
    let _ = tokio::signal::ctrl_c().await;
    "received signal: interrupt".to_string()
}

fn handle_parse_error(err: clap::Error, color: Option<&str>) -> i32 {
    if err.exit_code() == 0 {
        let _ = err.print();
        return 0;
    }

    write_cli_error_with_color(format_parse_error_message(&err), color);
    1
}

fn color_setting_from_args(args: impl IntoIterator<Item = String>) -> Option<String> {
    let mut args = args.into_iter().peekable();
    while let Some(arg) = args.next() {
        if arg == "--" {
            return None;
        }
        if let Some(value) = arg.strip_prefix("--color=") {
            return Some(value.to_string());
        }
        if arg == "--color" {
            return args.peek().cloned();
        }
    }
    None
}

fn format_parse_error_message(err: &clap::Error) -> String {
    let msg = err.to_string();
    let msg = msg.trim().strip_prefix("error: ").unwrap_or(msg.trim());
    let first_line = msg.lines().next().unwrap_or(msg).trim();

    if let Some(flag) = unknown_flag_from_clap_message(first_line) {
        return format!("unknown flag '{flag}'");
    }
    if let Some(flag) = required_arg_flag_from_clap_message(first_line) {
        return format!("argument required for flag '{flag}'");
    }
    if let Some((flag, value, usage)) = invalid_value_from_clap_message(first_line) {
        return format!("invalid value '{value}' for option '{flag}': {usage}");
    }
    if let Some(flag) = no_args_flag_from_clap_message(first_line) {
        return format!("flag '{flag}' does not take any arguments");
    }
    if let Some((first, second)) = exclusive_flags_from_clap_message(first_line) {
        return format!("flags '{first}' and '{second}' cannot be used together");
    }

    first_line.to_string()
}

fn unknown_flag_from_clap_message(msg: &str) -> Option<&str> {
    let rest = msg.strip_prefix("unexpected argument '")?;
    let (arg, _) = rest.split_once('\'')?;
    if arg.starts_with('-') {
        Some(arg)
    } else {
        None
    }
}

fn required_arg_flag_from_clap_message(msg: &str) -> Option<String> {
    let rest = msg.strip_prefix("a value is required for '")?;
    let (spec, _) = rest.split_once('\'')?;
    Some(flag_name_from_spec(spec))
}

fn no_args_flag_from_clap_message(msg: &str) -> Option<String> {
    if !msg.starts_with("unexpected value ") {
        return None;
    }
    let (_, rest) = msg.split_once(" for '")?;
    let (spec, _) = rest.split_once('\'')?;
    Some(flag_name_from_spec(spec))
}

fn exclusive_flags_from_clap_message(msg: &str) -> Option<(String, String)> {
    let rest = msg.strip_prefix("the argument '")?;
    let (first, rest) = rest.split_once("' cannot be used")?;
    let (_, rest) = rest.split_once("with '")?;
    let (second, _) = rest.split_once('\'')?;
    Some((flag_name_from_spec(first), flag_name_from_spec(second)))
}

fn invalid_value_from_clap_message(msg: &str) -> Option<(String, String, &'static str)> {
    let rest = msg.strip_prefix("invalid value '")?;
    let (value, rest) = rest.split_once('\'')?;
    let (_, rest) = rest.split_once(" for '")?;
    let (spec, _) = rest.split_once('\'')?;
    let flag = flag_name_from_spec(spec);
    if flag == "--pager" || flag == "--ws-interactive" {
        return Some((flag, value.to_string(), "must be one of [auto, on, off]"));
    }
    if flag == "--color" || flag == "--format" {
        return Some((flag, value.to_string(), "must be one of [auto, off, on]"));
    }
    if flag == "--retry" || flag == "--redirects" {
        return Some((flag, value.to_string(), "must be a non-negative integer"));
    }
    if flag == "--connect-timeout" || flag == "--retry-delay" || flag == "--timeout" {
        return Some((flag, value.to_string(), "must be a non-negative number"));
    }
    None
}

fn flag_name_from_spec(spec: &str) -> String {
    spec.split_whitespace().next().unwrap_or(spec).to_string()
}

#[derive(Debug)]
struct RuntimeErrorWithColor {
    error: FetchError,
    color: Option<String>,
}

impl std::fmt::Display for RuntimeErrorWithColor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

async fn run(mut cli: Cli) -> Result<i32, RuntimeErrorWithColor> {
    match run_inner(&mut cli).await {
        Ok(code) => Ok(code),
        Err(error) => Err(RuntimeErrorWithColor {
            error,
            color: cli.color.clone(),
        }),
    }
}

async fn run_inner(cli: &mut Cli) -> Result<i32, FetchError> {
    if let Some(shell) = cli.complete.as_deref() {
        let output =
            crate::cli::completion::output(shell, &cli.extra_args).map_err(FetchError::Message)?;
        core::write_stdout(output)?;
        return Ok(0);
    }

    normalize_extra_args(cli)?;

    if cli.help || cli.version || cli.buildinfo {
        crate::config::apply_best_effort(cli);
        if cli.help {
            print_help(cli)?;
            return Ok(0);
        }
        if cli.version {
            core::write_stdout(format!("fetch {}\n", core::version()))?;
            return Ok(0);
        }
        if cli.buildinfo {
            print_build_info(cli)?;
            return Ok(0);
        }
    }

    let direct_cli_sources = DirectCliSources::capture(cli);

    apply_from_curl(cli)?;
    let config_path = crate::config::apply(cli)?;
    crate::config::validate(cli)?;
    crate::cli::parse_http_version(cli.http.as_deref()).map_err(FetchError::Message)?;
    crate::cli::normalize_range_values(&mut cli.ranges).map_err(FetchError::Message)?;
    validate_proto_schema_files(cli)?;
    validate_client_certificate_flags(cli, direct_cli_sources)?;
    validate_auth_credentials(cli)?;
    print_config_debug(cli, config_path.as_deref());

    if cli.update {
        return crate::update::execute(cli).await;
    }

    if cli.remote_header_name && !cli.remote_name {
        return Err("flag '--remote-header-name' requires '--remote-name'".into());
    }

    if cli.url.is_none() && cli.has_grpc_discovery() && !cli.has_proto_schema() {
        return Err("<URL> must be provided unless --proto-file or --proto-desc is set".into());
    }
    if cli.url.is_none() && !cli.has_grpc_discovery() {
        return Err("<URL> must be provided".into());
    }

    if let Some(value) = cli.auto_update.as_deref() {
        crate::update::maybe_spawn_auto_update(value);
    }

    if cli.inspect_dns {
        return crate::dns::inspect::execute(cli).await;
    }

    if cli.inspect_tls {
        return crate::tls::inspect::execute(cli).await;
    }

    let is_websocket = cli
        .url
        .as_deref()
        .map(crate::websocket::is_websocket_url)
        .unwrap_or(false);
    if !is_websocket && cli.ws_interactive.is_some() {
        return Err("'--ws-interactive' requires a ws:// or wss:// URL".into());
    }
    if !is_websocket && cli.ws_message_mode.is_some() {
        return Err("'--ws-message-mode' requires a ws:// or wss:// URL".into());
    }
    if is_websocket {
        validate_websocket_exclusives(cli)?;
        return crate::websocket::execute(cli).await;
    }

    if cli.has_grpc_discovery() {
        return crate::grpc::reflection::execute_discovery(cli).await;
    }

    crate::http::execute(cli).await
}

fn normalize_extra_args(cli: &mut Cli) -> Result<(), FetchError> {
    if cli.extra_args.is_empty() {
        return Ok(());
    }
    if cli.url.is_none() {
        cli.url = Some(cli.extra_args.remove(0));
    }
    if let Some(arg) = cli.extra_args.first() {
        return Err(format!("unexpected argument: {arg:?}").into());
    }
    Ok(())
}

fn validate_proto_schema_files(cli: &Cli) -> Result<(), FetchError> {
    if let Some(path) = cli.proto_desc.as_deref() {
        check_file_exists(path)?;
    }
    for path in crate::proto::proto_file_paths(&cli.proto_files) {
        check_file_exists(&path)?;
    }
    for path in &cli.proto_imports {
        check_file_exists(path)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectCliSources {
    cert: bool,
    key: bool,
}

impl DirectCliSources {
    fn capture(cli: &Cli) -> Self {
        Self {
            cert: cli.cert.is_some(),
            key: cli.key.is_some(),
        }
    }
}

fn validate_client_certificate_flags(
    cli: &Cli,
    sources: DirectCliSources,
) -> Result<(), FetchError> {
    if sources.key && cli.cert.is_none() {
        return Err("flag '--key' requires '--cert'".into());
    }
    Ok(())
}

fn validate_auth_credentials(cli: &mut Cli) -> Result<(), FetchError> {
    if let Some(value) = cli.basic.take() {
        cli.basic = Some(validate_user_password_option("basic", &value)?);
    }
    if let Some(value) = cli.digest.take() {
        cli.digest = Some(validate_user_password_option("digest", &value)?);
    }
    Ok(())
}

fn print_config_debug(cli: &Cli, path: Option<&std::path::Path>) {
    if cli.silent || cli.verbose < 3 {
        return;
    }
    let Some(path) = path else {
        return;
    };

    let mut printer = core::Printer::stderr(cli.color.as_deref());
    printer.write_info_prefix();
    printer.write_styled("Config", &[core::Sequence::Bold, core::Sequence::Yellow]);
    printer.push_str(": '");
    printer.write_styled(&path.display().to_string(), &[core::Sequence::Dim]);
    printer.push_str("'\n");
    printer.write_info_prefix();
    printer.push('\n');
    let mut stderr = std::io::stderr();
    let _ = printer.flush_to(&mut stderr);
}

fn validate_user_password_option(option: &str, value: &str) -> Result<String, FetchError> {
    if !value.contains(':') {
        return Err(format!(
            "invalid value '{value}' for option '--{option}': format must be <USERNAME:PASSWORD>"
        )
        .into());
    }
    Ok(value.to_string())
}

fn check_file_exists(path: &str) -> Result<(), FetchError> {
    match std::fs::metadata(path) {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            Err(format!("file '{path}' does not exist").into())
        }
        Err(err) => Err(err.into()),
    }
}

fn print_help(cli: &Cli) -> Result<(), FetchError> {
    let mut command = Cli::command().color(clap_color_choice(cli.color.as_deref()));
    command.print_help()?;
    core::write_stdout(b"\n")?;
    Ok(())
}

fn clap_color_choice(color: Option<&str>) -> ColorChoice {
    match color {
        Some("on") => ColorChoice::Always,
        Some("off") => ColorChoice::Never,
        _ => ColorChoice::Auto,
    }
}

fn apply_from_curl(cli: &mut Cli) -> Result<(), FetchError> {
    let Some(command) = cli.from_curl.clone() else {
        return Ok(());
    };

    validate_from_curl_exclusives(cli)?;
    let parsed = from_curl::parse(&command)?;
    let mut url = apply_proto_restriction(&parsed.url, &parsed.allowed_proto)?;

    cli.method = if parsed.method.is_empty() {
        None
    } else {
        Some(parsed.method.clone())
    };

    for header in &parsed.headers {
        cli.headers
            .push(format!("{}: {}", header.name, header.value));
    }
    if !parsed.user_agent.is_empty() {
        cli.headers
            .push(format!("User-Agent: {}", parsed.user_agent));
    }
    if !parsed.referer.is_empty() {
        cli.headers.push(format!("Referer: {}", parsed.referer));
    }
    if !parsed.cookie.is_empty() {
        cli.headers.push(format!("Cookie: {}", parsed.cookie));
    }

    if !parsed.data_values.is_empty() {
        if !parsed.get_flag
            && let Some(value) = streaming_curl_data_value(&parsed.data_values)
        {
            cli.data = Some(value.to_string());
            cli.data_is_literal = false;
            cli.data_literal_bytes = None;
            if !parsed.has_content_type {
                cli.headers
                    .push("Content-Type: application/x-www-form-urlencoded".to_string());
            }
        } else {
            let data = materialize_curl_data(&parsed.data_values)?;
            if parsed.get_flag {
                append_raw_query(&mut url, &String::from_utf8_lossy(&data));
            } else {
                cli.data = Some(String::from_utf8_lossy(&data).into_owned());
                cli.data_is_literal = true;
                cli.data_literal_bytes = Some(data);
                if !parsed.has_content_type {
                    cli.headers
                        .push("Content-Type: application/x-www-form-urlencoded".to_string());
                }
            }
        }
    }

    if !parsed.upload_file.is_empty() {
        cli.data = Some(format!("@{}", parsed.upload_file));
        cli.data_is_literal = false;
        cli.data_literal_bytes = None;
    }

    for field in &parsed.form_fields {
        cli.multipart
            .push(format!("{}={}", field.name, field.value));
    }

    if !parsed.basic_auth.is_empty() {
        if !parsed.basic_auth.contains(':') {
            return Err("invalid basic auth format, expected USER:PASS".into());
        }
        if parsed.digest_auth {
            cli.digest = Some(parsed.basic_auth.clone());
        } else {
            cli.basic = Some(parsed.basic_auth.clone());
        }
    }
    if !parsed.bearer.is_empty() {
        cli.bearer = Some(parsed.bearer.clone());
    }
    if !parsed.aws_sigv4.is_empty() {
        cli.aws_sigv4 = Some(parse_aws_sigv4(&parsed.aws_sigv4)?);
    }

    if !parsed.output.is_empty() {
        cli.output = Some(parsed.output.clone());
    }
    cli.remote_name = parsed.remote_name;
    cli.remote_header_name = parsed.remote_header_name;

    if parsed.insecure {
        cli.insecure = true;
    }
    if !parsed.tls_version.is_empty() {
        cli.min_tls = Some(parsed.tls_version.clone());
    }
    if !parsed.tls_max_version.is_empty() {
        cli.max_tls = Some(parsed.tls_max_version.clone());
    }
    if !parsed.ca_cert.is_empty() {
        cli.ca_cert.push(parsed.ca_cert.clone());
    }
    if !parsed.cert.is_empty() {
        cli.cert = Some(parsed.cert.clone());
    }
    if !parsed.key.is_empty() {
        cli.key = Some(parsed.key.clone());
    }

    cli.redirects = Some(if parsed.follow_redirects {
        if parsed.max_redirects_set {
            usize::try_from(parsed.max_redirects).unwrap_or(usize::MAX)
        } else {
            CURL_DEFAULT_MAX_REDIRECTS
        }
    } else {
        0
    });
    if parsed.timeout > 0.0 {
        cli.timeout = Some(parsed.timeout);
    }
    if parsed.connect_timeout > 0.0 {
        cli.connect_timeout = Some(parsed.connect_timeout);
    }
    if !parsed.proxy.is_empty() {
        cli.proxy = Some(parsed.proxy.clone());
    }
    if !parsed.unix_socket.is_empty() {
        cli.unix = Some(parsed.unix_socket.clone());
    }
    if !parsed.doh_url.is_empty() {
        cli.dns_server = Some(parsed.doh_url.clone());
    }
    if parsed.retry > 0 {
        cli.retry = Some(parsed.retry);
    }
    if parsed.retry_delay > 0.0 {
        cli.retry_delay = Some(parsed.retry_delay);
    }
    cli.ranges.extend(parsed.ranges.iter().cloned());

    match parsed.http_version.as_str() {
        "1.0" | "1.1" => cli.http = Some("1".to_string()),
        "2" => cli.http = Some("2".to_string()),
        "3" => cli.http = Some("3".to_string()),
        _ => {}
    }

    cli.verbose = cli.verbose.saturating_add(parsed.verbose);
    if parsed.silent {
        cli.silent = true;
    }

    cli.url = Some(url);
    cli.from_curl = None;
    Ok(())
}

fn streaming_curl_data_value(values: &[from_curl::DataValue]) -> Option<&str> {
    let [value] = values else {
        return None;
    };
    if value.is_raw || value.is_urlencode {
        return None;
    }
    value.value.starts_with('@').then_some(value.value.as_str())
}

fn validate_from_curl_exclusives(cli: &Cli) -> Result<(), FetchError> {
    if cli.url.is_some() {
        return Err("'--from-curl' and a URL argument cannot be used together".into());
    }

    let conflicting_flag = if cli.method.is_some() {
        Some("method")
    } else if !cli.headers.is_empty() {
        Some("header")
    } else if cli.data.is_some() {
        Some("data")
    } else if cli.json.is_some() {
        Some("json")
    } else if cli.xml.is_some() {
        Some("xml")
    } else if !cli.form.is_empty() {
        Some("form")
    } else if !cli.multipart.is_empty() {
        Some("multipart")
    } else if cli.basic.is_some() {
        Some("basic")
    } else if cli.bearer.is_some() {
        Some("bearer")
    } else if cli.digest.is_some() {
        Some("digest")
    } else if cli.aws_sigv4.is_some() {
        Some("aws-sigv4")
    } else if cli.output.is_some() {
        Some("output")
    } else if cli.remote_name {
        Some("remote-name")
    } else if cli.remote_header_name {
        Some("remote-header-name")
    } else if !cli.ranges.is_empty() {
        Some("range")
    } else if cli.unix.is_some() {
        Some("unix")
    } else if cli.timeout.is_some() {
        Some("timeout")
    } else if cli.connect_timeout.is_some() {
        Some("connect-timeout")
    } else if cli.redirects.is_some() {
        Some("redirects")
    } else if cli.proxy.is_some() {
        Some("proxy")
    } else if cli.insecure {
        Some("insecure")
    } else if cli.max_tls.is_some() {
        Some("max-tls")
    } else if cli.min_tls.is_some() {
        Some("min-tls")
    } else if cli.tls.is_some() {
        Some("tls")
    } else if cli.http.is_some() {
        Some("http")
    } else if cli.cert.is_some() {
        Some("cert")
    } else if cli.key.is_some() {
        Some("key")
    } else if !cli.ca_cert.is_empty() {
        Some("ca-cert")
    } else if cli.dns_server.is_some() {
        Some("dns-server")
    } else if cli.retry.is_some() {
        Some("retry")
    } else if cli.retry_delay.is_some() {
        Some("retry-delay")
    } else if cli.grpc {
        Some("grpc")
    } else if cli.grpc_describe.is_some() {
        Some("grpc-describe")
    } else if cli.grpc_list {
        Some("grpc-list")
    } else if !cli.query.is_empty() {
        Some("query")
    } else {
        None
    };

    if let Some(flag) = conflicting_flag {
        return Err(format!("'--from-curl' and '--{flag}' cannot be used together").into());
    }
    Ok(())
}

fn validate_websocket_exclusives(cli: &Cli) -> Result<(), FetchError> {
    let scheme = cli
        .url
        .as_deref()
        .and_then(|url| url.split_once("://").map(|(scheme, _)| scheme))
        .unwrap_or("ws")
        .to_ascii_lowercase();
    if let Some(version) =
        crate::cli::parse_http_version(cli.http.as_deref()).map_err(FetchError::Message)?
        && version != crate::cli::HttpVersion::Http1
    {
        return Err(format!(
            "WebSocket requires HTTP/1.1; {} is not supported",
            version.label()
        )
        .into());
    }
    let conflicting_flag = if cli.clobber {
        Some("clobber")
    } else if cli.copy {
        Some("copy")
    } else if cli.discard {
        Some("discard")
    } else if cli.digest.is_some() {
        Some("digest")
    } else if cli.edit {
        Some("edit")
    } else if !cli.form.is_empty() {
        Some("form")
    } else if cli.grpc {
        Some("grpc")
    } else if cli.grpc_describe.is_some() {
        Some("grpc-describe")
    } else if cli.grpc_list {
        Some("grpc-list")
    } else if !cli.multipart.is_empty() {
        Some("multipart")
    } else if cli.output.is_some() {
        Some("output")
    } else if cli.remote_header_name {
        Some("remote-header-name")
    } else if cli.remote_name {
        Some("remote-name")
    } else if cli.retry() > 0 {
        Some("retry")
    } else if cli.retry_delay.is_some() {
        Some("retry-delay")
    } else if cli.xml.is_some() {
        Some("xml")
    } else if scheme == "ws" && cli.insecure {
        Some("insecure")
    } else if scheme == "ws" && cli.max_tls.is_some() {
        Some("max-tls")
    } else if scheme == "ws" && cli.min_tls.is_some() {
        Some("min-tls")
    } else if scheme == "ws" && cli.tls.is_some() {
        Some("tls")
    } else if scheme == "ws" && cli.cert.is_some() {
        Some("cert")
    } else if scheme == "ws" && cli.key.is_some() {
        Some("key")
    } else if scheme == "ws" && !cli.ca_cert.is_empty() {
        Some("ca-cert")
    } else {
        None
    };

    if let Some(flag) = conflicting_flag {
        return Err(
            format!("'{scheme}://' scheme and '--{flag}' flag cannot be used together").into(),
        );
    }

    if cli.ws_interactive.is_some()
        && !cli
            .url
            .as_deref()
            .map(crate::websocket::is_websocket_url)
            .unwrap_or(false)
    {
        return Err("'--ws-interactive' requires a ws:// or wss:// URL".into());
    }
    if cli.ws_message_mode.is_some()
        && !cli
            .url
            .as_deref()
            .map(crate::websocket::is_websocket_url)
            .unwrap_or(false)
    {
        return Err("'--ws-message-mode' requires a ws:// or wss:// URL".into());
    }
    Ok(())
}

fn apply_proto_restriction(raw_url: &str, allowed_proto: &str) -> Result<String, FetchError> {
    if allowed_proto.is_empty() {
        return Ok(raw_url.to_string());
    }

    let (allow_http, allow_https) = from_curl::parse_allowed_proto(allowed_proto);
    if let Some((scheme, _rest)) = raw_url.split_once("://") {
        match scheme {
            "http" if !allow_http => {
                return Err(
                    format!("protocol 'http' not allowed by --proto {allowed_proto:?}").into(),
                );
            }
            "https" if !allow_https => {
                return Err(
                    format!("protocol 'https' not allowed by --proto {allowed_proto:?}").into(),
                );
            }
            _ => return Ok(raw_url.to_string()),
        }
    }

    if !allow_http && !allow_https {
        return Err(format!(
            "protocols 'http' and 'https' not allowed by --proto {allowed_proto:?}"
        )
        .into());
    }

    if allow_https && !allow_http {
        Ok(format!("https://{raw_url}"))
    } else if allow_http && !allow_https {
        Ok(format!("http://{raw_url}"))
    } else {
        Ok(raw_url.to_string())
    }
}

fn materialize_curl_data(values: &[from_curl::DataValue]) -> Result<Vec<u8>, FetchError> {
    let mut out = Vec::new();
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            append_materialized_curl_bytes(&mut out, b"&")?;
        }
        if value.is_raw {
            append_materialized_curl_bytes(&mut out, value.value.as_bytes())?;
        } else if value.is_urlencode {
            append_url_encode_from_value(&value.value, &mut out)?;
        } else {
            append_body_value(&value.value, &mut out)?;
        }
    }
    Ok(out)
}

fn append_body_value(value: &str, out: &mut Vec<u8>) -> Result<(), FetchError> {
    if value == "@-" {
        let stdin = std::io::stdin();
        return append_materialized_curl_reader(stdin.lock(), out);
    }
    if let Some(path) = value.strip_prefix('@') {
        let file = std::fs::File::open(expand_home(path))?;
        return append_materialized_curl_reader(file, out);
    }
    append_materialized_curl_bytes(out, value.as_bytes())
}

fn append_url_encode_from_value(value: &str, out: &mut Vec<u8>) -> Result<(), FetchError> {
    if let Some(path) = value.strip_prefix('@') {
        return append_url_encoded_file(path, out);
    }

    if let Some((name, path)) = value.split_once('@')
        && !name.is_empty()
    {
        append_materialized_curl_bytes(out, name.as_bytes())?;
        append_materialized_curl_bytes(out, b"=")?;
        return append_url_encoded_file(path, out);
    }

    append_query_escaped_bytes(value.as_bytes(), out)
}

fn append_url_encoded_file(path: &str, out: &mut Vec<u8>) -> Result<(), FetchError> {
    let file = std::fs::File::open(expand_home(path))?;
    append_query_escaped_reader(file, out)
}

fn append_query_escaped_reader(mut reader: impl Read, out: &mut Vec<u8>) -> Result<(), FetchError> {
    let mut buf = [0; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        append_query_escaped_bytes(&buf[..n], out)?;
    }
}

fn append_query_escaped_bytes(bytes: &[u8], out: &mut Vec<u8>) -> Result<(), FetchError> {
    for chunk in url::form_urlencoded::byte_serialize(bytes) {
        append_materialized_curl_bytes(out, chunk.as_bytes())?;
    }
    Ok(())
}

fn append_materialized_curl_reader(
    mut reader: impl Read,
    out: &mut Vec<u8>,
) -> Result<(), FetchError> {
    let mut buf = [0; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        append_materialized_curl_bytes(out, &buf[..n])?;
    }
}

fn append_materialized_curl_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), FetchError> {
    if out
        .len()
        .checked_add(bytes.len())
        .is_none_or(|len| len > MAX_MATERIALIZED_CURL_DATA_BYTES)
    {
        return Err(materialized_curl_data_limit_error());
    }
    out.extend_from_slice(bytes);
    Ok(())
}

fn materialized_curl_data_limit_error() -> FetchError {
    FetchError::Message(format!(
        "--from-curl data requires materializing more than {MAX_MATERIALIZED_CURL_DATA_BYTES} bytes; use a single -d @file/-d @- body for streaming input"
    ))
}

fn expand_home(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return format!("{}/{}", home.to_string_lossy(), rest);
    }
    path.to_string()
}

fn append_raw_query(url: &mut String, query: &str) {
    if query.is_empty() {
        return;
    }
    if url.contains('?') {
        url.push('&');
    } else {
        url.push('?');
    }
    url.push_str(query);
}

fn parse_aws_sigv4(value: &str) -> Result<String, FetchError> {
    let parts: Vec<&str> = value.split(':').collect();
    if parts.len() == 4 {
        let region = parts[2];
        let service = parts[3];
        if region.is_empty() || service.is_empty() {
            return Err(format!(
                "invalid aws-sigv4 format: region and service must be non-empty in {value:?}"
            )
            .into());
        }
        return Ok(format!("{region}/{service}"));
    }

    if let Some((region, service)) = value.split_once('/') {
        if region.is_empty() || service.is_empty() {
            return Err(format!(
                "invalid aws-sigv4 format: region and service must be non-empty in {value:?}"
            )
            .into());
        }
        return Ok(value.to_string());
    }

    Err(format!(
        "invalid aws-sigv4 format: {value:?}, expected 'aws:amz:REGION:SERVICE' or 'REGION/SERVICE'"
    )
    .into())
}

fn print_build_info(cli: &Cli) -> Result<(), FetchError> {
    let stdout_is_terminal = core::stdio().stdout_is_terminal();
    let output = build_info_output(cli, stdout_is_terminal)?;
    core::write_stdout(output)?;
    Ok(())
}

fn build_info_output(cli: &Cli, stdout_is_terminal: bool) -> Result<Vec<u8>, FetchError> {
    let encoded = build_info_json(cli.verbose > 0);
    if cli.format.as_deref() == Some("off") {
        return Ok(encoded);
    }

    let mut out = core::Printer::with_color_setting(cli.color.as_deref(), stdout_is_terminal);
    if crate::format::json::format_json_to(&encoded, &mut out).is_ok() {
        Ok(out.into_bytes())
    } else {
        Ok(newline_terminated(encoded))
    }
}

fn build_info_json(include_deps: bool) -> Vec<u8> {
    #[derive(Serialize)]
    struct BuildInfo {
        fetch: &'static str,
        rust: &'static str,
        #[serde(skip_serializing_if = "BTreeMap::is_empty")]
        settings: BTreeMap<&'static str, String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        deps: Option<BTreeMap<String, String>>,
    }

    let info = BuildInfo {
        fetch: core::version(),
        rust: option_env!("FETCH_RUSTC_VERSION").unwrap_or("unknown"),
        settings: build_settings(),
        deps: include_deps.then(cargo_lock_dependencies),
    };
    serde_json::to_vec(&info).expect("build info serializes")
}

fn build_settings() -> BTreeMap<&'static str, String> {
    let mut settings = BTreeMap::new();
    settings.insert("target_arch", std::env::consts::ARCH.to_string());
    settings.insert("target_os", std::env::consts::OS.to_string());
    insert_env(&mut settings, "profile", option_env!("FETCH_BUILD_PROFILE"));
    insert_env(&mut settings, "vcs", option_env!("FETCH_VCS"));
    insert_env(
        &mut settings,
        "vcs.modified",
        option_env!("FETCH_VCS_MODIFIED"),
    );
    insert_env(
        &mut settings,
        "vcs.revision",
        option_env!("FETCH_VCS_REVISION"),
    );
    insert_env(&mut settings, "vcs.time", option_env!("FETCH_VCS_TIME"));
    settings
}

fn insert_env(
    settings: &mut BTreeMap<&'static str, String>,
    key: &'static str,
    value: Option<&'static str>,
) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        settings.insert(key, value.to_string());
    }
}

fn cargo_lock_dependencies() -> BTreeMap<String, String> {
    let mut deps = BTreeMap::new();
    let mut name = None::<String>;
    let mut version = None::<String>;

    for line in include_str!("../Cargo.lock").lines() {
        let line = line.trim();
        if line == "[[package]]" {
            insert_dependency(&mut deps, &mut name, &mut version);
            continue;
        }
        if let Some(value) = line.strip_prefix("name = ") {
            name = parse_lock_string(value);
        } else if let Some(value) = line.strip_prefix("version = ") {
            version = parse_lock_string(value);
        }
    }
    insert_dependency(&mut deps, &mut name, &mut version);
    deps.remove(env!("CARGO_PKG_NAME"));
    deps
}

fn insert_dependency(
    deps: &mut BTreeMap<String, String>,
    name: &mut Option<String>,
    version: &mut Option<String>,
) {
    if let (Some(name), Some(version)) = (name.take(), version.take()) {
        deps.insert(name, version);
    }
}

fn parse_lock_string(value: &str) -> Option<String> {
    let value = value.strip_prefix('"')?;
    let (value, _) = value.split_once('"')?;
    Some(value.to_string())
}

fn newline_terminated(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.push(b'\n');
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn clap_parse_errors_are_rendered_like_go_parser() {
        let cases = [
            (
                Cli::try_parse_from(["fetch", "--bad"]).unwrap_err(),
                "unknown flag '--bad'",
            ),
            (
                Cli::try_parse_from(["fetch", "--output"]).unwrap_err(),
                "argument required for flag '--output'",
            ),
            (
                Cli::try_parse_from(["fetch", "--help=1"]).unwrap_err(),
                "flag '--help' does not take any arguments",
            ),
            (
                Cli::try_parse_from([
                    "fetch",
                    "--basic",
                    "user:pass",
                    "--bearer",
                    "token",
                    "https://example.com",
                ])
                .unwrap_err(),
                "flags '--basic' and '--bearer' cannot be used together",
            ),
            (
                Cli::try_parse_from(["fetch", "ws://example.com", "--ws-interactive", "maybe"])
                    .unwrap_err(),
                "invalid value 'maybe' for option '--ws-interactive': must be one of [auto, on, off]",
            ),
            (
                Cli::try_parse_from(["fetch", "--color", "always", "https://example.com"])
                    .unwrap_err(),
                "invalid value 'always' for option '--color': must be one of [auto, off, on]",
            ),
            (
                Cli::try_parse_from(["fetch", "--format", "pretty", "https://example.com"])
                    .unwrap_err(),
                "invalid value 'pretty' for option '--format': must be one of [auto, off, on]",
            ),
            (
                Cli::try_parse_from(["fetch", "--pager", "always", "https://example.com"])
                    .unwrap_err(),
                "invalid value 'always' for option '--pager': must be one of [auto, on, off]",
            ),
            (
                Cli::try_parse_from(["fetch", "--retry", "bad", "https://example.com"])
                    .unwrap_err(),
                "invalid value 'bad' for option '--retry': must be a non-negative integer",
            ),
            (
                Cli::try_parse_from(["fetch", "--retry", "-1", "https://example.com"]).unwrap_err(),
                "invalid value '-1' for option '--retry': must be a non-negative integer",
            ),
            (
                Cli::try_parse_from(["fetch", "--redirects", "-1", "https://example.com"])
                    .unwrap_err(),
                "invalid value '-1' for option '--redirects': must be a non-negative integer",
            ),
        ];

        for (err, want) in cases {
            assert_eq!(format_parse_error_message(&err), want);
        }
    }

    #[test]
    fn parse_error_color_setting_is_recovered_like_go_partial_app() {
        assert_eq!(
            color_setting_from_args(["--color".to_string(), "on".to_string()]).as_deref(),
            Some("on")
        );
        assert_eq!(
            color_setting_from_args(["--color=off".to_string()]).as_deref(),
            Some("off")
        );
        assert_eq!(
            color_setting_from_args(["--".to_string(), "--color".to_string(), "on".to_string()]),
            None
        );
    }

    #[test]
    fn from_curl_data_urlencode_file_preserves_non_utf8_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.txt");
        let named_path = dir.path().join("named.bin");
        std::fs::write(&path, b"hello \xff&=").unwrap();
        std::fs::write(&named_path, b"a \xff").unwrap();
        let command = format!(
            "curl --data-urlencode '@{}' --data-urlencode 'field@{}' https://example.com",
            path.display(),
            named_path.display()
        );
        let mut cli = Cli::try_parse_from(["fetch", "--from-curl", &command]).unwrap();

        apply_from_curl(&mut cli).unwrap();

        let expected = "hello+%FF%26%3D&field=a+%FF";
        assert_eq!(cli.data.as_deref(), Some(expected));
        assert!(cli.data_is_literal);
        assert_eq!(cli.data_literal_bytes.as_deref(), Some(expected.as_bytes()));
    }

    #[test]
    fn from_curl_single_file_data_uses_streaming_body_source() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.txt");
        std::fs::write(&path, b"streamed data").unwrap();
        let body_arg = format!("@{}", curl_test_path(&path));
        let command = format!("curl -d '{body_arg}' https://example.com");
        let mut cli = Cli::try_parse_from(["fetch", "--from-curl", &command]).unwrap();

        apply_from_curl(&mut cli).unwrap();

        assert_eq!(cli.data.as_deref(), Some(body_arg.as_str()));
        assert!(!cli.data_is_literal);
        assert_eq!(cli.data_literal_bytes, None);

        let body = crate::http::request_body(&cli).unwrap();
        assert_eq!(
            crate::http::request_body_content_len(&body),
            Some("streamed data".len() as u64)
        );
        assert!(crate::http::request_body_bytes(&body).is_none());
        assert_eq!(
            crate::http::request_body_preview(body.as_ref().unwrap()).unwrap(),
            b"streamed data"
        );
    }

    #[test]
    fn from_curl_composite_file_data_materialization_is_capped() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first.bin");
        let second = dir.path().join("second.bin");
        std::fs::File::create(&first)
            .unwrap()
            .set_len((MAX_MATERIALIZED_CURL_DATA_BYTES / 2 + 1) as u64)
            .unwrap();
        std::fs::File::create(&second)
            .unwrap()
            .set_len((MAX_MATERIALIZED_CURL_DATA_BYTES / 2 + 1) as u64)
            .unwrap();
        let command = format!(
            "curl -d '@{}' -d '@{}' https://example.com",
            curl_test_path(&first),
            curl_test_path(&second)
        );
        let mut cli = Cli::try_parse_from(["fetch", "--from-curl", &command]).unwrap();

        let err = apply_from_curl(&mut cli).unwrap_err().to_string();

        assert!(err.contains("--from-curl data requires materializing more than"));
        assert!(err.contains(&MAX_MATERIALIZED_CURL_DATA_BYTES.to_string()));
        assert!(err.contains("single -d @file/-d @- body"));
    }

    #[test]
    fn from_curl_get_data_appends_materialized_query() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.txt");
        std::fs::write(&path, "q=search&limit=10").unwrap();
        let command = format!("curl -G -d '@{}' https://example.com", path.display());
        let mut cli = Cli::try_parse_from(["fetch", "--from-curl", &command]).unwrap();

        apply_from_curl(&mut cli).unwrap();

        assert_eq!(cli.data, None);
        assert_eq!(
            cli.url.as_deref(),
            Some("https://example.com?q=search&limit=10")
        );
    }

    fn curl_test_path(path: &std::path::Path) -> String {
        path.to_string_lossy().replace('\\', "/")
    }

    #[test]
    fn from_curl_redirect_defaults_match_curl_application() {
        let cases = [
            ("curl https://example.com", Some(0)),
            ("curl --max-redirs 5 https://example.com", Some(0)),
            (
                "curl -L https://example.com",
                Some(CURL_DEFAULT_MAX_REDIRECTS),
            ),
            ("curl -L --max-redirs 5 https://example.com", Some(5)),
        ];

        for (command, want) in cases {
            let mut cli = Cli::try_parse_from(["fetch", "--from-curl", command]).unwrap();
            apply_from_curl(&mut cli).unwrap();
            assert_eq!(cli.redirects, want, "command: {command}");
        }
    }

    #[test]
    fn from_curl_exclusive_with_url_is_rejected() {
        let mut cli = Cli::try_parse_from([
            "fetch",
            "--from-curl",
            "curl https://example.com",
            "https://other.com",
        ])
        .unwrap();

        let err = apply_from_curl(&mut cli).unwrap_err().to_string();
        assert!(err.contains("cannot be used together"));
    }

    #[test]
    fn from_curl_proto_restriction_rejects_disallowed_scheme() {
        let mut cli = Cli::try_parse_from([
            "fetch",
            "--from-curl",
            "curl --proto '=https' http://example.com",
        ])
        .unwrap();

        let err = apply_from_curl(&mut cli).unwrap_err().to_string();
        assert!(err.contains("not allowed by --proto"));
    }

    #[test]
    fn from_curl_proto_restriction_rejects_schemeless_when_no_supported_scheme_is_allowed() {
        for command in [
            "curl --proto '=ftp' example.com",
            "curl --proto '=-http,-https' example.com",
        ] {
            let mut cli = Cli::try_parse_from(["fetch", "--from-curl", command]).unwrap();

            let err = apply_from_curl(&mut cli).unwrap_err().to_string();
            assert!(err.contains("protocols 'http' and 'https' not allowed by --proto"));
        }
    }

    #[test]
    fn from_curl_proto_restriction_defaults_schemeless_urls_to_allowed_scheme() {
        for (command, want_url) in [
            (
                "curl --proto '=https' example.com/path",
                "https://example.com/path",
            ),
            (
                "curl --proto '=http' example.com/path",
                "http://example.com/path",
            ),
        ] {
            let mut cli = Cli::try_parse_from(["fetch", "--from-curl", command]).unwrap();

            apply_from_curl(&mut cli).unwrap();

            assert_eq!(cli.url.as_deref(), Some(want_url));
        }
    }

    #[test]
    fn from_curl_aws_sigv4_credentials_are_not_loaded_during_parse() {
        let mut cli = Cli::try_parse_from([
            "fetch",
            "--from-curl",
            r#"curl --aws-sigv4 "aws:amz:us-east-1:s3" https://example.com"#,
        ])
        .unwrap();

        apply_from_curl(&mut cli).unwrap();

        assert_eq!(cli.aws_sigv4.as_deref(), Some("us-east-1/s3"));
    }

    #[test]
    fn basic_auth_parsing_preserves_spaces() {
        let mut cli =
            Cli::try_parse_from(["fetch", "--basic", " user : pass ", "http://example.com"])
                .unwrap();

        validate_auth_credentials(&mut cli).unwrap();

        assert_eq!(cli.basic.as_deref(), Some(" user : pass "));
    }

    #[test]
    fn basic_auth_invalid_format_matches_go_value_error() {
        let mut cli =
            Cli::try_parse_from(["fetch", "--basic", "nocolon", "http://example.com"]).unwrap();

        let err = validate_auth_credentials(&mut cli).unwrap_err().to_string();

        assert_eq!(
            err,
            "invalid value 'nocolon' for option '--basic': format must be <USERNAME:PASSWORD>"
        );
    }

    #[test]
    fn bearer_auth_parsing_keeps_token() {
        let cli =
            Cli::try_parse_from(["fetch", "--bearer", "mytoken", "http://example.com"]).unwrap();

        assert_eq!(cli.bearer.as_deref(), Some("mytoken"));
    }

    #[test]
    fn bearer_conflicts_with_basic_like_go() {
        let err = Cli::try_parse_from([
            "fetch",
            "--basic",
            "user:pass",
            "--bearer",
            "token",
            "http://example.com",
        ])
        .unwrap_err()
        .to_string();

        assert!(err.contains("cannot be used"));
    }

    #[test]
    fn digest_auth_parsing_preserves_spaces() {
        let mut cli =
            Cli::try_parse_from(["fetch", "--digest", " user : pass ", "http://example.com"])
                .unwrap();

        validate_auth_credentials(&mut cli).unwrap();

        assert_eq!(cli.digest.as_deref(), Some(" user : pass "));
    }

    #[test]
    fn from_curl_basic_auth_preserves_spaces() {
        let mut cli = Cli::try_parse_from([
            "fetch",
            "--from-curl",
            "curl -u ' user : pass ' https://example.com",
        ])
        .unwrap();

        apply_from_curl(&mut cli).unwrap();
        validate_auth_credentials(&mut cli).unwrap();

        assert_eq!(cli.basic.as_deref(), Some(" user : pass "));
    }

    #[test]
    fn websocket_scheme_exclusives_match_go_error_shape() {
        let cli = Cli::try_parse_from(["fetch", "ws://example.com", "--copy"]).unwrap();
        let err = validate_websocket_exclusives(&cli).unwrap_err().to_string();

        assert_eq!(
            err,
            "'ws://' scheme and '--copy' flag cannot be used together"
        );
    }

    #[test]
    fn websocket_rejects_digest_auth() {
        let cli =
            Cli::try_parse_from(["fetch", "wss://example.com", "--digest", "user:pass"]).unwrap();
        let err = validate_websocket_exclusives(&cli).unwrap_err().to_string();

        assert_eq!(
            err,
            "'wss://' scheme and '--digest' flag cannot be used together"
        );
    }

    #[test]
    fn websocket_rejects_non_http1_versions() {
        for http in ["2", "3"] {
            let cli = Cli::try_parse_from(["fetch", "ws://example.com", "--http", http]).unwrap();
            let err = validate_websocket_exclusives(&cli).unwrap_err().to_string();

            assert_eq!(
                err,
                format!("WebSocket requires HTTP/1.1; HTTP/{http}.0 is not supported")
            );
        }

        let cli = Cli::try_parse_from(["fetch", "ws://example.com", "--http", "1"]).unwrap();
        validate_websocket_exclusives(&cli).unwrap();
    }

    #[test]
    fn websocket_allows_network_options() {
        let cli =
            Cli::try_parse_from(["fetch", "wss://example.com", "--proxy", "http://proxy"]).unwrap();
        validate_websocket_exclusives(&cli).unwrap();

        let cli =
            Cli::try_parse_from(["fetch", "wss://example.com", "--dns-server", "1.1.1.1"]).unwrap();
        validate_websocket_exclusives(&cli).unwrap();
    }

    #[test]
    fn plain_websocket_rejects_tls_options() {
        let cli = Cli::try_parse_from(["fetch", "ws://example.com", "--insecure"]).unwrap();
        let err = validate_websocket_exclusives(&cli).unwrap_err().to_string();

        assert_eq!(
            err,
            "'ws://' scheme and '--insecure' flag cannot be used together"
        );
    }

    #[tokio::test]
    async fn websocket_interactive_requires_websocket_url() {
        let cli = Cli::try_parse_from(["fetch", "https://example.com", "--ws-interactive", "off"])
            .unwrap();
        let err = run(cli).await.unwrap_err().to_string();

        assert!(err.contains("requires a ws:// or wss:// URL"));
    }

    #[test]
    fn completion_extra_args_do_not_break_url_after_double_dash() {
        let mut cli = Cli::try_parse_from(["fetch", "--", "https://example.com"]).unwrap();

        normalize_extra_args(&mut cli).unwrap();

        assert_eq!(cli.url.as_deref(), Some("https://example.com"));
        assert!(cli.extra_args.is_empty());
    }

    #[test]
    fn non_completion_extra_args_report_go_style_unexpected_argument() {
        let mut cli = Cli::try_parse_from(["fetch", "https://example.com", "--", "extra"]).unwrap();

        let err = normalize_extra_args(&mut cli).unwrap_err().to_string();

        assert_eq!(err, "unexpected argument: \"extra\"");
    }

    #[test]
    fn key_without_cert_reports_go_style_required_flag() {
        let cli =
            Cli::try_parse_from(["fetch", "https://example.com", "--key", "client.key"]).unwrap();
        let sources = DirectCliSources::capture(&cli);

        let err = validate_client_certificate_flags(&cli, sources)
            .unwrap_err()
            .to_string();

        assert_eq!(err, "flag '--key' requires '--cert'");
    }

    #[test]
    fn direct_key_with_merged_cert_is_allowed() {
        let mut cli =
            Cli::try_parse_from(["fetch", "https://example.com", "--key", "client.key"]).unwrap();
        let sources = DirectCliSources::capture(&cli);
        cli.cert = Some("client.crt".to_string());

        validate_client_certificate_flags(&cli, sources).unwrap();
    }

    #[test]
    fn config_or_curl_key_without_direct_cert_does_not_trip_required_flag() {
        let mut cli = Cli::try_parse_from(["fetch", "https://example.com"]).unwrap();
        let sources = DirectCliSources::capture(&cli);
        cli.key = Some("client.key".to_string());

        validate_client_certificate_flags(&cli, sources).unwrap();
    }

    #[test]
    fn proto_desc_missing_file_reports_go_style_error() {
        let path = tempfile::tempdir().unwrap().path().join("missing.pb");
        let cli = Cli::try_parse_from([
            "fetch",
            "https://example.com/svc/Method",
            "--grpc",
            "--proto-desc",
            path.to_str().unwrap(),
        ])
        .unwrap();

        let err = validate_proto_schema_files(&cli).unwrap_err().to_string();
        assert_eq!(err, format!("file '{}' does not exist", path.display()));
    }

    #[test]
    fn proto_file_missing_file_reports_go_style_error() {
        let path = tempfile::tempdir().unwrap().path().join("missing.proto");
        let cli = Cli::try_parse_from([
            "fetch",
            "https://example.com/svc/Method",
            "--grpc",
            "--proto-file",
            path.to_str().unwrap(),
        ])
        .unwrap();

        let err = validate_proto_schema_files(&cli).unwrap_err().to_string();
        assert_eq!(err, format!("file '{}' does not exist", path.display()));
    }

    #[test]
    fn proto_file_supports_comma_separated_paths_like_go() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first.proto");
        let second = dir.path().join("second.proto");
        std::fs::write(&first, "syntax = \"proto3\";").unwrap();
        std::fs::write(&second, "syntax = \"proto3\";").unwrap();
        let value = format!("{},{}", first.display(), second.display());
        let cli = Cli::try_parse_from([
            "fetch",
            "https://example.com/svc/Method",
            "--grpc",
            "--proto-file",
            &value,
        ])
        .unwrap();

        validate_proto_schema_files(&cli).unwrap();
    }

    #[test]
    fn build_info_json_includes_rust_settings_without_dependencies_by_default() {
        let value: Value = serde_json::from_slice(&build_info_json(false)).unwrap();

        assert_eq!(value["fetch"], core::version());
        let rust = value["rust"].as_str().unwrap_or_default();
        assert!(!rust.contains("rustc"));
        assert!(!rust.contains(char::is_whitespace));
        assert_eq!(
            value["settings"]["target_os"].as_str().unwrap_or_default(),
            std::env::consts::OS
        );
        assert_eq!(
            value["settings"]["target_arch"]
                .as_str()
                .unwrap_or_default(),
            std::env::consts::ARCH
        );
        assert!(value.get("deps").is_none());
    }

    #[test]
    fn build_info_json_includes_dependencies_when_verbose() {
        let value: Value = serde_json::from_slice(&build_info_json(true)).unwrap();

        assert!(value["deps"]["hyper"].as_str().is_some());
    }

    #[test]
    fn build_info_output_matches_go_format_policy() {
        let default_cli = Cli::try_parse_from(["fetch", "--buildinfo"]).unwrap();
        let default_output = build_info_output(&default_cli, false).unwrap();
        let default_output = String::from_utf8(default_output).unwrap();
        assert!(default_output.starts_with("{\n"));
        assert!(default_output.contains("  \"fetch\": "));
        assert!(!default_output.contains("  \"deps\": "));
        assert!(default_output.ends_with('\n'));

        let off_cli = Cli::try_parse_from(["fetch", "--buildinfo", "--format", "off"]).unwrap();
        let off_output = build_info_output(&off_cli, false).unwrap();
        let off_output = String::from_utf8(off_output).unwrap();
        assert!(off_output.starts_with("{\"fetch\":"));
        assert!(!off_output.contains('\n'));
        assert!(!off_output.contains("\"deps\""));

        let color_cli = Cli::try_parse_from(["fetch", "--buildinfo", "--color", "on"]).unwrap();
        let color_output = build_info_output(&color_cli, false).unwrap();
        let color_output = String::from_utf8(color_output).unwrap();
        assert!(color_output.contains("\x1b["));

        let verbose_cli = Cli::try_parse_from(["fetch", "--buildinfo", "-v"]).unwrap();
        let verbose_output = build_info_output(&verbose_cli, false).unwrap();
        let verbose_output = String::from_utf8(verbose_output).unwrap();
        assert!(verbose_output.contains("  \"deps\": "));
    }
}
