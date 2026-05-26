use std::collections::HashMap;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use crate::cli::Cli;
use crate::error::FetchError;

#[derive(Clone, Debug, Default, PartialEq)]
struct ConfigValues {
    auto_update: Option<String>,
    ca_cert: Vec<String>,
    cert: Option<String>,
    color: Option<String>,
    compress: Option<String>,
    connect_timeout: Option<f64>,
    copy: Option<bool>,
    dns_server: Option<String>,
    format: Option<String>,
    headers: Vec<String>,
    http: Option<String>,
    ignore_status: Option<bool>,
    image: Option<String>,
    insecure: Option<bool>,
    key: Option<String>,
    max_tls: Option<String>,
    min_tls: Option<String>,
    pager: Option<String>,
    proxy: Option<String>,
    query: Vec<String>,
    redirects: Option<usize>,
    retry: Option<usize>,
    retry_delay: Option<f64>,
    session: Option<String>,
    silent: Option<bool>,
    sort_headers: Option<bool>,
    timeout: Option<f64>,
    timing: Option<bool>,
    verbosity: Option<u8>,
}

#[derive(Debug, Default, PartialEq)]
struct ConfigFile {
    global: ConfigValues,
    hosts: HashMap<String, ConfigValues>,
    path: PathBuf,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CliConfigSources {
    compress: bool,
    copy: bool,
    ignore_status: bool,
    insecure: bool,
    pager: bool,
    silent: bool,
    sort_headers: bool,
    timing: bool,
    verbosity: bool,
}

impl CliConfigSources {
    fn capture(cli: &Cli) -> Self {
        Self {
            compress: cli.compress.is_some() || cli.no_encode,
            copy: cli.copy,
            ignore_status: cli.ignore_status,
            insecure: cli.insecure,
            pager: cli.pager.is_some(),
            silent: cli.silent,
            sort_headers: cli.sort_headers,
            timing: cli.timing,
            verbosity: cli.verbose > 0,
        }
    }
}

pub fn apply(cli: &mut Cli) -> Result<Option<PathBuf>, FetchError> {
    let Some((path, contents)) = get_config_file(cli.config.as_deref())? else {
        return Ok(None);
    };

    let file = parse_file(&path, &contents).map_err(FetchError::Message)?;
    let sources = CliConfigSources::capture(cli);
    apply_file(cli, &file, sources);
    validate(cli)?;
    Ok(Some(file.path))
}

pub fn apply_best_effort(cli: &mut Cli) -> Option<PathBuf> {
    apply(cli).ok().flatten()
}

pub fn validate(cli: &Cli) -> Result<(), FetchError> {
    let min_tls = cli.min_tls.as_deref().or(cli.tls.as_deref());
    for (option, value) in [
        ("tls", cli.tls.as_deref()),
        ("min-tls", cli.min_tls.as_deref()),
        ("max-tls", cli.max_tls.as_deref()),
    ] {
        if let Some(value) = value {
            validate_cli_tls_value(option, value)?;
        }
    }
    if let Some(value) = cli.image.as_deref() {
        validate_cli_choice("image", value, &["auto", "external", "off"])?;
    }
    if let Some(value) = cli.compress.as_deref() {
        validate_cli_choice("compress", value, crate::cli::CompressionMode::VALUES)?;
    }
    if let Some(value) = cli.pager.as_deref() {
        validate_cli_choice("pager", value, crate::cli::PagerMode::VALUES)?;
    }
    if let Some(value) = cli.proxy.as_deref() {
        validate_proxy_value(value).map_err(|usage| {
            FetchError::Message(format!(
                "invalid value '{value}' for option '--proxy': {usage}"
            ))
        })?;
    }
    if let (Some(min_tls), Some(max_tls)) = (min_tls, cli.max_tls.as_deref())
        && tls_order(min_tls).expect("validated min tls")
            > tls_order(max_tls).expect("validated max tls")
    {
        return Err("min-tls must be less than or equal to max-tls".into());
    }
    if let Some(retry_count) = cli.retry {
        crate::http::total_attempts_for_retry(retry_count)?;
    }
    Ok(())
}

fn get_config_file(path: Option<&str>) -> Result<Option<(PathBuf, String)>, FetchError> {
    if let Some(path) = path {
        let path = absolute_path(expand_home(path))?;
        let contents = std::fs::read_to_string(&path)?;
        return Ok(Some((path, contents)));
    }

    for path in default_config_candidates(
        env::var_os("HOME").map(PathBuf::from),
        env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
        env::var_os("AppData").map(PathBuf::from),
        cfg!(windows),
    ) {
        if let Ok(contents) = std::fs::read_to_string(&path) {
            return Ok(Some((path, contents)));
        }
    }

    Ok(None)
}

fn default_config_candidates(
    home: Option<PathBuf>,
    xdg_config_home: Option<PathBuf>,
    app_data: Option<PathBuf>,
    is_windows: bool,
) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(path) = xdg_config_home {
        paths.push(path.join("fetch").join("config"));
    }
    if let Some(path) = home {
        paths.push(path.join(".config").join("fetch").join("config"));
    }
    if is_windows && let Some(path) = app_data {
        paths.push(path.join("fetch").join("config"));
    }
    paths
}

fn apply_file(cli: &mut Cli, file: &ConfigFile, sources: CliConfigSources) {
    let mut values = file.global.clone();
    if let Some(host_cfg) = cli
        .url
        .as_deref()
        .and_then(url_hostname)
        .and_then(|hostname| file.host_config(&hostname))
    {
        values.overlay(host_cfg);
    }

    if cli.auto_update.is_none() {
        cli.auto_update = values.auto_update;
    }
    prepend_vec(&mut cli.ca_cert, values.ca_cert);
    if cli.cert.is_none() {
        cli.cert = values.cert;
    }
    if cli.color.is_none() {
        cli.color = values.color;
    }
    if cli.compress.is_none() && !sources.compress {
        cli.compress = values.compress;
    }
    if cli.connect_timeout.is_none() {
        cli.connect_timeout = values.connect_timeout;
    }
    if !sources.copy {
        cli.copy = values.copy.unwrap_or(false);
    }
    if cli.dns_server.is_none() {
        cli.dns_server = values.dns_server;
    }
    if cli.format.is_none() {
        cli.format = values.format;
    }
    prepend_vec(&mut cli.headers, values.headers);
    if cli.http.is_none() {
        cli.http = values.http;
    }
    if !sources.ignore_status {
        cli.ignore_status = values.ignore_status.unwrap_or(false);
    }
    if cli.image.is_none() {
        cli.image = values.image;
    }
    if !sources.insecure {
        cli.insecure = values.insecure.unwrap_or(false);
    }
    if cli.key.is_none() {
        cli.key = values.key;
    }
    if cli.max_tls.is_none() {
        cli.max_tls = values.max_tls;
    }
    if cli.min_tls.is_none() && cli.tls.is_none() {
        cli.min_tls = values.min_tls;
    }
    if !sources.pager {
        cli.pager = values.pager;
    }
    if cli.proxy.is_none() {
        cli.proxy = values.proxy;
    }
    prepend_vec(&mut cli.query, values.query);
    if cli.redirects.is_none() {
        cli.redirects = values.redirects;
    }
    if cli.retry.is_none() {
        cli.retry = values.retry;
    }
    if cli.retry_delay.is_none() {
        cli.retry_delay = values.retry_delay;
    }
    if cli.session.is_none() {
        cli.session = values.session;
    }
    if !sources.silent {
        cli.silent = values.silent.unwrap_or(false);
    }
    if !sources.sort_headers {
        cli.sort_headers = values.sort_headers.unwrap_or(false);
    }
    if cli.timeout.is_none() {
        cli.timeout = values.timeout;
    }
    if !sources.timing {
        cli.timing = values.timing.unwrap_or(false);
    }
    if !sources.verbosity {
        cli.verbose = values.verbosity.unwrap_or(0);
    }
}

fn prepend_vec<T>(target: &mut Vec<T>, mut values: Vec<T>) {
    if values.is_empty() {
        return;
    }
    values.append(target);
    *target = values;
}

fn parse_file(path: &Path, contents: &str) -> Result<ConfigFile, String> {
    let mut file = ConfigFile {
        global: ConfigValues::default(),
        hosts: HashMap::new(),
        path: path.to_path_buf(),
    };
    let mut current_host: Option<String> = None;

    for (line_num, raw_line) in numbered_lines(contents) {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            let host = line[1..line.len() - 1].trim().to_ascii_lowercase();
            validate_host_section(path, line_num, &host)?;
            current_host = Some(host.clone());
            file.hosts.insert(host, ConfigValues::default());
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            return Err(file_error(
                path,
                line_num,
                &format!("invalid key/value pair '{line}'"),
            ));
        };
        let key = key.trim();
        let value = value.trim();
        let target = match current_host.as_deref() {
            Some(host) => file
                .hosts
                .get_mut(host)
                .expect("host section inserted before values"),
            None => &mut file.global,
        };
        set_value(path, line_num, target, key, value)?;
    }

    Ok(file)
}

fn validate_host_section(path: &Path, line_num: usize, host: &str) -> Result<(), String> {
    if host.is_empty() {
        return Err(file_error(path, line_num, "hostname cannot be empty"));
    }
    if host.contains('*') && (!host.starts_with("*.") || host.len() < 3 || host[2..].contains('*'))
    {
        return Err(file_error(
            path,
            line_num,
            &format!("invalid wildcard hostname '{host}': must be in the format '*.domain'"),
        ));
    }
    Ok(())
}

fn set_value(
    path: &Path,
    line_num: usize,
    config: &mut ConfigValues,
    key: &str,
    value: &str,
) -> Result<(), String> {
    match key {
        "auto-update" => config.auto_update = Some(validate_auto_update(path, line_num, value)?),
        "ca-cert" => {
            validate_file_option(path, line_num, || {
                crate::tls::validate_ca_certificate_file(value)
            })?;
            config.ca_cert.push(value.to_string());
        }
        "cert" => {
            validate_file_option(path, line_num, || {
                crate::tls::validate_client_certificate_file(value)
            })?;
            config.cert = Some(value.to_string());
        }
        "color" | "colour" => {
            validate_choice(path, line_num, "color", value, &["auto", "off", "on"])?;
            config.color = Some(value.to_string());
        }
        "compress" => {
            validate_choice(
                path,
                line_num,
                "compress",
                value,
                crate::cli::CompressionMode::VALUES,
            )?;
            config.compress = Some(value.to_string());
        }
        "connect-timeout" => {
            config.connect_timeout = Some(parse_duration_seconds(
                path,
                line_num,
                "connect-timeout",
                value,
                "must be a non-negative number",
            )?);
        }
        "copy" => config.copy = Some(parse_bool_value(path, line_num, "copy", value)?),
        "dns-server" => {
            validate_dns_server(path, line_num, value)?;
            config.dns_server = Some(value.to_string());
        }
        "format" => {
            validate_choice(path, line_num, "format", value, &["auto", "off", "on"])?;
            config.format = Some(value.to_string());
        }
        "header" => config.headers.push(parse_header(path, line_num, value)?),
        "http" => {
            validate_choice(path, line_num, "http", value, &["1", "2", "3"])?;
            config.http = Some(value.to_string());
        }
        "ignore-status" => {
            config.ignore_status = Some(parse_bool_value(path, line_num, "ignore-status", value)?);
        }
        "image" => {
            validate_choice(path, line_num, "image", value, &["auto", "external", "off"])?;
            config.image = Some(value.to_string());
        }
        "insecure" => config.insecure = Some(parse_bool_value(path, line_num, "insecure", value)?),
        "key" => {
            validate_file_option(path, line_num, || {
                crate::tls::validate_client_key_file(value)
            })?;
            config.key = Some(value.to_string());
        }
        "max-tls" => {
            validate_tls_value(path, line_num, "max-tls", value)?;
            if let Some(min_tls) = config.min_tls.as_deref()
                && tls_order(value) < tls_order(min_tls)
            {
                return Err(value_error(
                    path,
                    line_num,
                    "max-tls",
                    value,
                    "must be greater than or equal to min-tls",
                ));
            }
            config.max_tls = Some(value.to_string());
        }
        "min-tls" => {
            validate_tls_value(path, line_num, "min-tls", value)?;
            if let Some(max_tls) = config.max_tls.as_deref()
                && tls_order(value) > tls_order(max_tls)
            {
                return Err(value_error(
                    path,
                    line_num,
                    "min-tls",
                    value,
                    "must be less than or equal to max-tls",
                ));
            }
            config.min_tls = Some(value.to_string());
        }
        "no-encode" => {
            let no_encode = parse_bool_value(path, line_num, "no-encode", value)?;
            config.compress = Some(if no_encode { "off" } else { "auto" }.to_string());
        }
        "no-pager" => {
            let no_pager = parse_bool_value(path, line_num, "no-pager", value)?;
            config.pager = Some(if no_pager { "off" } else { "auto" }.to_string());
        }
        "pager" => {
            validate_choice(
                path,
                line_num,
                "pager",
                value,
                crate::cli::PagerMode::VALUES,
            )?;
            config.pager = Some(value.to_string());
        }
        "proxy" => {
            validate_proxy(path, line_num, value)?;
            config.proxy = Some(value.to_string());
        }
        "query" => config.query.push(parse_query(value)),
        "redirects" => {
            config.redirects = Some(parse_nonnegative_usize(path, line_num, "redirects", value)?);
        }
        "retry" => config.retry = Some(parse_nonnegative_usize(path, line_num, "retry", value)?),
        "retry-delay" => {
            config.retry_delay = Some(parse_duration_seconds(
                path,
                line_num,
                "retry-delay",
                value,
                "must be a non-negative number",
            )?);
        }
        "session" => {
            if !crate::session::is_valid_name(value) {
                return Err(value_error(
                    path,
                    line_num,
                    "session",
                    value,
                    "must contain only alphanumeric characters, hyphens, and underscores",
                ));
            }
            config.session = Some(value.to_string());
        }
        "silent" => config.silent = Some(parse_bool_value(path, line_num, "silent", value)?),
        "sort-headers" => {
            config.sort_headers = Some(parse_bool_value(path, line_num, "sort-headers", value)?);
        }
        "timeout" => {
            config.timeout = Some(parse_duration_seconds(
                path,
                line_num,
                "timeout",
                value,
                "must be a non-negative number",
            )?);
        }
        "timing" => config.timing = Some(parse_bool_value(path, line_num, "timing", value)?),
        "tls" => {
            validate_tls_value(path, line_num, "tls", value)?;
            if let Some(max_tls) = config.max_tls.as_deref()
                && tls_order(value) > tls_order(max_tls)
            {
                return Err(value_error(
                    path,
                    line_num,
                    "tls",
                    value,
                    "must be less than or equal to max-tls",
                ));
            }
            config.min_tls = Some(value.to_string());
        }
        "verbosity" => {
            let value = parse_nonnegative_u64(
                path,
                line_num,
                "verbosity",
                value,
                "must be a valid integer",
            )?;
            config.verbosity = Some(u8::try_from(value).unwrap_or(u8::MAX));
        }
        _ => {
            return Err(file_error(
                path,
                line_num,
                &format!("invalid option: '{key}'"),
            ));
        }
    }
    Ok(())
}

fn validate_file_option<F>(path: &Path, line_num: usize, validate: F) -> Result<(), String>
where
    F: FnOnce() -> Result<(), FetchError>,
{
    validate().map_err(|err| file_error(path, line_num, &err.to_string()))
}

fn validate_choice(
    path: &Path,
    line_num: usize,
    option: &str,
    value: &str,
    choices: &[&str],
) -> Result<(), String> {
    if choices.contains(&value) {
        return Ok(());
    }
    Err(value_error(
        path,
        line_num,
        option,
        value,
        &format!("must be one of [{}]", choices.join(", ")),
    ))
}

fn validate_tls_value(
    path: &Path,
    line_num: usize,
    option: &str,
    value: &str,
) -> Result<(), String> {
    if tls_order(value).is_some() {
        return Ok(());
    }
    Err(value_error(
        path,
        line_num,
        option,
        value,
        "must be one of [1.2, 1.3]",
    ))
}

fn validate_cli_tls_value(option: &str, value: &str) -> Result<(), FetchError> {
    if tls_order(value).is_some() {
        return Ok(());
    }
    Err(
        format!("invalid value '{value}' for option '--{option}': must be one of [1.2, 1.3]")
            .into(),
    )
}

fn validate_cli_choice(option: &str, value: &str, choices: &[&str]) -> Result<(), FetchError> {
    if choices.contains(&value) {
        return Ok(());
    }
    Err(format!(
        "invalid value '{value}' for option '--{option}': must be one of [{}]",
        choices.join(", ")
    )
    .into())
}

fn parse_bool_value(
    path: &Path,
    line_num: usize,
    option: &str,
    value: &str,
) -> Result<bool, String> {
    parse_bool_go(value)
        .ok_or_else(|| value_error(path, line_num, option, value, "must be a boolean"))
}

fn parse_bool_go(value: &str) -> Option<bool> {
    match value {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

fn validate_auto_update(path: &Path, line_num: usize, value: &str) -> Result<String, String> {
    if parse_bool_go(value).is_some() || crate::duration::parse_duration_interval(value).is_some() {
        Ok(value.to_string())
    } else {
        Err(value_error(
            path,
            line_num,
            "auto-update",
            value,
            "must be either a boolean or interval",
        ))
    }
}

fn parse_duration_seconds(
    path: &Path,
    line_num: usize,
    option: &str,
    value: &str,
    usage: &str,
) -> Result<f64, String> {
    let seconds = value
        .parse::<f64>()
        .map_err(|_| value_error(path, line_num, option, value, usage))?;
    if !seconds.is_finite() || !(0.0..=crate::http::MAX_DURATION_SECONDS).contains(&seconds) {
        return Err(value_error(path, line_num, option, value, usage));
    }
    Ok(seconds)
}

fn parse_nonnegative_usize(
    path: &Path,
    line_num: usize,
    option: &str,
    value: &str,
) -> Result<usize, String> {
    let parsed = parse_nonnegative_u64(
        path,
        line_num,
        option,
        value,
        "must be a non-negative integer",
    )?;
    usize::try_from(parsed).map_err(|_| {
        value_error(
            path,
            line_num,
            option,
            value,
            "must be a non-negative integer",
        )
    })
}

fn parse_nonnegative_u64(
    path: &Path,
    line_num: usize,
    option: &str,
    value: &str,
    usage: &str,
) -> Result<u64, String> {
    if value.starts_with('-') {
        return Err(value_error(path, line_num, option, value, usage));
    }
    let value_to_parse = value.strip_prefix('+').unwrap_or(value);
    if value_to_parse.is_empty() {
        return Err(value_error(path, line_num, option, value, usage));
    }
    value_to_parse
        .parse::<u64>()
        .map_err(|_| value_error(path, line_num, option, value, usage))
}

fn parse_header(path: &Path, line_num: usize, value: &str) -> Result<String, String> {
    let Some((name, val)) = value.split_once(':') else {
        return Err(header_value_error(path, line_num, value));
    };
    let name = name.trim();
    let val = val.trim();
    if name.is_empty() || !valid_header_name(name) {
        return Err(header_value_error(path, line_num, value));
    }
    Ok(format!("{name}: {val}"))
}

fn valid_header_name(name: &str) -> bool {
    name.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            )
    })
}

fn header_value_error(path: &Path, line_num: usize, value: &str) -> String {
    value_error(
        path,
        line_num,
        "header",
        value,
        "must be in the format NAME:VALUE with a valid non-empty header name",
    )
}

fn parse_query(value: &str) -> String {
    let (key, val) = value.split_once('=').unwrap_or((value, ""));
    format!("{}={}", key.trim(), val.trim())
}

fn validate_dns_server(path: &Path, line_num: usize, value: &str) -> Result<(), String> {
    if value.starts_with("https://") || value.starts_with("http://") {
        url::Url::parse(value).map_err(|_| {
            value_error(
                path,
                line_num,
                "dns-server",
                value,
                "unable to parse DoH URL",
            )
        })?;
        return Ok(());
    }

    let has_bracketed_port = value.matches(':').count() > 1 && value.starts_with('[');
    if value.matches(':').count() == 1 || has_bracketed_port {
        if value.parse::<SocketAddr>().is_ok() {
            return Ok(());
        }
        return Err(dns_server_value_error(path, line_num, value));
    }

    value
        .parse::<IpAddr>()
        .map(|_| ())
        .map_err(|_| dns_server_value_error(path, line_num, value))
}

fn dns_server_value_error(path: &Path, line_num: usize, value: &str) -> String {
    value_error(
        path,
        line_num,
        "dns-server",
        value,
        "must be in the format <IP[:PORT]>",
    )
}

fn validate_proxy(path: &Path, line_num: usize, value: &str) -> Result<(), String> {
    validate_proxy_value(value)
        .map_err(|message| value_error(path, line_num, "proxy", value, &message))
}

pub(crate) fn validate_proxy_value(value: &str) -> Result<(), String> {
    validate_go_url_parse_syntax(value).map_err(|message| format!("parse {value:?}: {message}"))
}

fn validate_go_url_parse_syntax(value: &str) -> Result<(), String> {
    if value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err("net/url: invalid control character in URL".to_string());
    }
    validate_url_escapes(value)?;

    let scheme_end = find_go_scheme_separator(value)?;
    if let Some(index) = scheme_end {
        let rest = &value[index + 1..];
        if let Some(after_slashes) = rest.strip_prefix("//") {
            validate_go_authority(split_go_authority(after_slashes))?;
        }
        return Ok(());
    }

    if let Some(after_slashes) = value.strip_prefix("//") {
        validate_go_authority(split_go_authority(after_slashes))?;
        return Ok(());
    }

    if !value.starts_with('/') {
        let first_segment = value.split(['/', '?', '#']).next().unwrap_or(value);
        if first_segment.contains(':') {
            return Err("first path segment in URL cannot contain colon".to_string());
        }
    }
    Ok(())
}

fn validate_url_escapes(value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                let end = (index + 3).min(bytes.len());
                let escape = String::from_utf8_lossy(&bytes[index..end]);
                return Err(format!("invalid URL escape \"{escape}\""));
            }
            index += 3;
            continue;
        }
        index += 1;
    }
    Ok(())
}

fn find_go_scheme_separator(value: &str) -> Result<Option<usize>, String> {
    let bytes = value.as_bytes();
    for (index, byte) in bytes.iter().copied().enumerate() {
        match byte {
            b':' => {
                if index == 0 {
                    return Err("missing protocol scheme".to_string());
                }
                if bytes[0].is_ascii_alphabetic()
                    && bytes[..index].iter().copied().all(is_go_scheme_char)
                {
                    return Ok(Some(index));
                }
                return Ok(None);
            }
            b'/' | b'?' | b'#' => return Ok(None),
            _ => {}
        }
    }
    Ok(None)
}

fn is_go_scheme_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
}

fn split_go_authority(rest: &str) -> &str {
    rest.split(['/', '?', '#']).next().unwrap_or(rest)
}

fn validate_go_authority(authority: &str) -> Result<(), String> {
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);
    if host_port.is_empty() {
        return Ok(());
    }

    if let Some(after_open) = host_port.strip_prefix('[') {
        let Some(close_index) = after_open.find(']') else {
            return Err("missing ']' in host".to_string());
        };
        let after_host = &after_open[close_index + 1..];
        if !valid_go_optional_port(after_host) {
            return Err(format!("invalid port \"{after_host}\" after host"));
        }
        return Ok(());
    }

    if let Some(colon_index) = host_port.find(':') {
        let port = &host_port[colon_index..];
        if !valid_go_optional_port(port) {
            return Err(format!("invalid port \"{port}\" after host"));
        }
    }
    Ok(())
}

fn valid_go_optional_port(port: &str) -> bool {
    port.is_empty()
        || port
            .strip_prefix(':')
            .is_some_and(|digits| digits.bytes().all(|byte| byte.is_ascii_digit()))
}

impl ConfigValues {
    fn overlay(&mut self, higher: &Self) {
        choose(&mut self.auto_update, &higher.auto_update);
        self.ca_cert.extend(higher.ca_cert.iter().cloned());
        choose(&mut self.cert, &higher.cert);
        choose(&mut self.color, &higher.color);
        choose(&mut self.compress, &higher.compress);
        choose(&mut self.connect_timeout, &higher.connect_timeout);
        choose(&mut self.copy, &higher.copy);
        choose(&mut self.dns_server, &higher.dns_server);
        choose(&mut self.format, &higher.format);
        self.headers.extend(higher.headers.iter().cloned());
        choose(&mut self.http, &higher.http);
        choose(&mut self.ignore_status, &higher.ignore_status);
        choose(&mut self.image, &higher.image);
        choose(&mut self.insecure, &higher.insecure);
        choose(&mut self.key, &higher.key);
        choose(&mut self.max_tls, &higher.max_tls);
        choose(&mut self.min_tls, &higher.min_tls);
        choose(&mut self.pager, &higher.pager);
        choose(&mut self.proxy, &higher.proxy);
        self.query.extend(higher.query.iter().cloned());
        choose(&mut self.redirects, &higher.redirects);
        choose(&mut self.retry, &higher.retry);
        choose(&mut self.retry_delay, &higher.retry_delay);
        choose(&mut self.session, &higher.session);
        choose(&mut self.silent, &higher.silent);
        choose(&mut self.sort_headers, &higher.sort_headers);
        choose(&mut self.timeout, &higher.timeout);
        choose(&mut self.timing, &higher.timing);
        choose(&mut self.verbosity, &higher.verbosity);
    }
}

fn choose<T: Clone>(target: &mut Option<T>, value: &Option<T>) {
    if value.is_some() {
        *target = value.clone();
    }
}

impl ConfigFile {
    fn host_config(&self, hostname: &str) -> Option<&ConfigValues> {
        if hostname.is_empty() {
            return None;
        }
        let hostname = hostname.to_ascii_lowercase();
        if let Some(config) = self.hosts.get(&hostname) {
            return Some(config);
        }

        let mut best = None;
        let mut best_len = 0;
        for (host, config) in &self.hosts {
            let Some(suffix) = host.strip_prefix('*') else {
                continue;
            };
            if hostname.ends_with(suffix) && suffix.len() > best_len {
                best = Some(config);
                best_len = suffix.len();
            }
        }
        best
    }
}

fn numbered_lines(contents: &str) -> Vec<(usize, &str)> {
    let mut lines = Vec::new();
    let mut rest = contents;
    let mut line_num = 1;
    while !rest.is_empty() {
        let Some(index) = rest.find(['\n', '\r']) else {
            lines.push((line_num, rest));
            break;
        };
        lines.push((line_num, &rest[..index]));
        let mut advance = 1;
        if rest.as_bytes()[index] == b'\r' && rest.as_bytes().get(index + 1).copied() == Some(b'\n')
        {
            advance = 2;
        }
        rest = &rest[index + advance..];
        line_num += 1;
    }
    lines
}

fn value_error(path: &Path, line_num: usize, option: &str, value: &str, usage: &str) -> String {
    file_error(
        path,
        line_num,
        &format!("invalid value '{value}' for option '{option}': {usage}"),
    )
}

fn file_error(path: &Path, line_num: usize, message: &str) -> String {
    format!(
        "config file '{}': line {line_num}: {message}",
        path.display()
    )
}

fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(path)
}

fn absolute_path(path: PathBuf) -> Result<PathBuf, FetchError> {
    if path.is_absolute() {
        return Ok(path);
    }
    Ok(env::current_dir()?.join(path))
}

fn url_hostname(raw: &str) -> Option<String> {
    if raw.contains("://") {
        return url::Url::parse(raw)
            .ok()
            .and_then(|url| url.host_str().map(ToOwned::to_owned));
    }

    let host = raw.split('/').next().unwrap_or(raw);
    let host = host.split('@').next_back().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn tls_order(value: &str) -> Option<u8> {
    match value {
        "1.0" => Some(10),
        "1.1" => Some(11),
        "1.2" => Some(12),
        "1.3" => Some(13),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::io::Write;

    #[test]
    fn parse_file_accepts_global_presentation_settings() {
        let path = PathBuf::from("test/config");
        let file = parse_file(&path, "color = off\nformat = on\n").unwrap();

        assert_eq!(file.global.color.as_deref(), Some("off"));
        assert_eq!(file.global.format.as_deref(), Some("on"));
    }

    #[test]
    fn parse_file_accepts_request_settings() {
        let path = PathBuf::from("test/config");
        let file = parse_file(
            &path,
            "
              timeout = 10
              compress = zstd
              connect-timeout = 0.5
              retry = 2
              retry-delay = 0
              redirects = 3
              header = X-Test:
              query = q
              http = 2
              ignore-status = true
              pager = off
              insecure = true
              session = abc_123
              sort-headers = true
              verbosity = 3
            ",
        )
        .unwrap();

        assert_eq!(file.global.timeout, Some(10.0));
        assert_eq!(file.global.compress.as_deref(), Some("zstd"));
        assert_eq!(file.global.connect_timeout, Some(0.5));
        assert_eq!(file.global.retry, Some(2));
        assert_eq!(file.global.retry_delay, Some(0.0));
        assert_eq!(file.global.redirects, Some(3));
        assert_eq!(file.global.headers, vec!["X-Test: "]);
        assert_eq!(file.global.query, vec!["q="]);
        assert_eq!(file.global.http.as_deref(), Some("2"));
        assert_eq!(file.global.ignore_status, Some(true));
        assert_eq!(file.global.pager.as_deref(), Some("off"));
        assert_eq!(file.global.insecure, Some(true));
        assert_eq!(file.global.session.as_deref(), Some("abc_123"));
        assert_eq!(file.global.sort_headers, Some(true));
        assert_eq!(file.global.verbosity, Some(3));
    }

    #[test]
    fn parse_file_validates_tls_pem_files_eagerly_like_go() {
        let path = PathBuf::from("test/config");
        let missing = tempfile::tempdir().unwrap().path().join("missing.pem");
        let err = parse_file(&path, &format!("cert = {}\n", missing.display())).unwrap_err();
        assert!(err.contains("config file 'test/config': line 1"));
        assert!(err.contains(&format!("file '{}' does not exist", missing.display())));

        let (_key_file, key_path) = write_temp_config_pem(
            b"-----BEGIN RSA PRIVATE KEY-----\nZmFrZQ==\n-----END RSA PRIVATE KEY-----\n",
        );
        let err = parse_file(&path, &format!("cert = {key_path}\n")).unwrap_err();
        assert!(err.contains("invalid client certificate"));
        assert!(err.contains("expected CERTIFICATE, got RSA PRIVATE KEY"));

        let (_cert_file, cert_path) = write_temp_config_pem(
            b"-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n",
        );
        let err = parse_file(&path, &format!("key = {cert_path}\n")).unwrap_err();
        assert!(err.contains("invalid client key"));
        assert!(err.contains("expected PRIVATE KEY, got CERTIFICATE"));

        let err = parse_file(&path, &format!("ca-cert = {key_path}\n")).unwrap_err();
        assert!(err.contains("invalid CA certificate"));
        assert!(err.contains("no certificates found"));

        let file = parse_file(&path, &format!("cert = {cert_path}\nkey = {key_path}\n",)).unwrap();
        assert_eq!(file.global.cert.as_deref(), Some(cert_path.as_str()));
        assert_eq!(file.global.key.as_deref(), Some(key_path.as_str()));
    }

    #[test]
    fn parse_file_rejects_invalid_format_value() {
        let path = PathBuf::from("test/config");
        let err = parse_file(&path, "format = nope\n").unwrap_err();

        assert!(err.contains("line 1"));
        assert!(err.contains("invalid value 'nope' for option 'format'"));
    }

    #[test]
    fn parse_file_rejects_invalid_compress_value() {
        let path = PathBuf::from("test/config");
        let err = parse_file(&path, "compress = deflate\n").unwrap_err();

        assert!(err.contains("line 1"));
        assert!(err.contains("invalid value 'deflate' for option 'compress'"));
        assert!(err.contains("must be one of [auto, br, brotli, gzip, zstd, off]"));
    }

    #[test]
    fn parse_file_maps_legacy_no_encode_to_compress_mode() {
        let path = PathBuf::from("test/config");
        let file = parse_file(&path, "no-encode = true\n").unwrap();
        assert_eq!(file.global.compress.as_deref(), Some("off"));

        let file = parse_file(&path, "no-encode = false\n").unwrap();
        assert_eq!(file.global.compress.as_deref(), Some("auto"));
    }

    #[test]
    fn parse_file_rejects_invalid_proxy_value_like_go() {
        let path = PathBuf::from("test/config");
        let err = parse_file(&path, "proxy = :bad\n").unwrap_err();

        assert!(err.contains("config file 'test/config': line 1"));
        assert!(err.contains("invalid value ':bad' for option 'proxy'"));

        let file = parse_file(&path, "proxy = proxy.example\n").unwrap();
        assert_eq!(file.global.proxy.as_deref(), Some("proxy.example"));

        let file = parse_file(&path, "proxy = http://\n").unwrap();
        assert_eq!(file.global.proxy.as_deref(), Some("http://"));

        let file = parse_file(&path, "proxy = http://host:\n").unwrap();
        assert_eq!(file.global.proxy.as_deref(), Some("http://host:"));

        for value in ["http://host:bad", "http://[::1", "proxy/%zz"] {
            let err = parse_file(&path, &format!("proxy = {value}\n")).unwrap_err();
            assert!(err.contains("invalid value"), "{value}: {err}");
            assert!(err.contains("for option 'proxy'"), "{value}: {err}");
        }
    }

    #[test]
    fn parse_header_matches_go_validation() {
        let path = PathBuf::from("test/config");
        let file = parse_file(&path, "header = X-Test: value\nheader = X-Empty:\n").unwrap();
        assert_eq!(file.global.headers, vec!["X-Test: value", "X-Empty: "]);

        for value in ["NoColon", ": value", "Bad Header: value"] {
            let err = parse_file(&path, &format!("header = {value}\n")).unwrap_err();
            assert!(err.contains("invalid value"));
            assert!(err.contains("must be in the format NAME:VALUE"));
        }
    }

    #[test]
    fn parse_retry_matches_go_validation() {
        let path = PathBuf::from("test/config");
        assert_eq!(
            parse_file(&path, "retry = 3\n").unwrap().global.retry,
            Some(3)
        );
        assert_eq!(
            parse_file(&path, "retry = +3\n").unwrap().global.retry,
            Some(3)
        );
        assert_eq!(
            parse_file(&path, "retry = 0\n").unwrap().global.retry,
            Some(0)
        );

        for value in ["-1", "abc"] {
            let err = parse_file(&path, &format!("retry = {value}\n")).unwrap_err();
            assert!(err.contains("invalid value"));
            assert!(err.contains("must be a non-negative integer"));
        }
    }

    #[test]
    fn validate_rejects_retry_count_that_cannot_add_initial_attempt() {
        let mut cli = Cli::try_parse_from([
            "fetch",
            "--retry",
            &usize::MAX.to_string(),
            "https://example.com",
        ])
        .unwrap();

        let err = validate(&cli).unwrap_err();

        assert_eq!(
            err.to_string(),
            format!(
                "invalid value '{}' for option '--retry': must be less than the maximum usize value",
                usize::MAX
            )
        );
        cli.retry = Some(usize::MAX - 1);
        validate(&cli).unwrap();
    }

    #[test]
    fn parse_duration_seconds_matches_go_validation() {
        let path = PathBuf::from("test/config");
        assert_eq!(
            parse_file(&path, "connect-timeout = 2.5\n")
                .unwrap()
                .global
                .connect_timeout,
            Some(2.5)
        );
        assert_eq!(
            parse_file(&path, "retry-delay = 0\n")
                .unwrap()
                .global
                .retry_delay,
            Some(0.0)
        );

        for key in ["timeout", "connect-timeout", "retry-delay"] {
            for value in ["-1", "abc", "NaN", "+Inf", "-Inf", "Inf", "1e100"] {
                let err = parse_file(&path, &format!("{key} = {value}\n")).unwrap_err();
                assert!(err.contains("invalid value"), "{key}={value}: {err}");
                assert!(
                    err.contains("must be a non-negative number"),
                    "{key}={value}: {err}"
                );
            }
        }
    }

    #[test]
    fn auto_update_validation_matches_duration_parser() {
        let path = PathBuf::from("test/config");
        for value in ["1.5h", "+30m", "1d"] {
            assert_eq!(
                parse_file(&path, &format!("auto-update = {value}\n"))
                    .unwrap()
                    .global
                    .auto_update,
                Some(value.to_string())
            );
        }

        let err = parse_file(&path, "auto-update = -1h\n").unwrap_err();
        assert!(err.contains("invalid value"), "{err}");
        assert!(
            err.contains("must be either a boolean or interval"),
            "{err}"
        );
    }

    #[test]
    fn parse_file_validates_wildcard_hostnames_like_go() {
        let path = PathBuf::from("test/config");
        let file = parse_file(&path, "[*.Example.com]\ninsecure = true\n").unwrap();
        assert_eq!(
            file.host_config("www.example.com")
                .and_then(|cfg| cfg.insecure),
            Some(true)
        );

        for host in ["*example.com", "*.", "*.*.com", "example.*.com"] {
            let err = parse_file(&path, &format!("[{host}]\ncolor = on\n")).unwrap_err();
            assert!(
                err.contains(&format!(
                    "invalid wildcard hostname '{}'",
                    host.to_ascii_lowercase()
                )),
                "{host}: {err}"
            );
            assert!(
                err.contains("must be in the format '*.domain'"),
                "{host}: {err}"
            );
        }
    }

    #[test]
    fn parse_file_rejects_invalid_key_value_pair_like_go() {
        let path = PathBuf::from("test/config");
        let err = parse_file(&path, "\ncolor = off\ninvalidline\n").unwrap_err();

        assert!(err.contains("line 3"));
        assert!(err.contains("invalid key/value pair 'invalidline'"));
    }

    #[test]
    fn parse_file_replaces_duplicate_host_sections_like_go() {
        let path = PathBuf::from("test/config");
        let file = parse_file(
            &path,
            "
              [api.example.com]
              header = X-Old: yes
              color = off

              [api.example.com]
              header = X-New: yes
              format = on
            ",
        )
        .unwrap();
        let cfg = file.host_config("api.example.com").unwrap();

        assert_eq!(cfg.headers, vec!["X-New: yes"]);
        assert_eq!(cfg.color, None);
        assert_eq!(cfg.format.as_deref(), Some("on"));
    }

    #[test]
    fn parse_file_accepts_successful_go_file_cases() {
        let path = PathBuf::from("test/config");
        let file = parse_file(
            &path,
            "
              timeout = 10
              tls = 1.2
              max-tls = 1.3

              [Example.com]
              insecure = true

              [anotherhost.com]
              ignore-status = true
            ",
        )
        .unwrap();

        assert_eq!(file.global.timeout, Some(10.0));
        assert_eq!(file.global.min_tls.as_deref(), Some("1.2"));
        assert_eq!(file.global.max_tls.as_deref(), Some("1.3"));
        assert_eq!(
            file.host_config("example.com").and_then(|cfg| cfg.insecure),
            Some(true)
        );
        assert_eq!(
            file.host_config("anotherhost.com")
                .and_then(|cfg| cfg.ignore_status),
            Some(true)
        );
    }

    #[test]
    fn validate_tls_flags_matches_go_cli_behavior() {
        let cli = Cli::try_parse_from(["fetch", "--tls", "1.2", "https://example.com"]).unwrap();
        validate(&cli).unwrap();

        let cli = Cli::try_parse_from([
            "fetch",
            "--min-tls",
            "1.2",
            "--max-tls",
            "1.3",
            "https://example.com",
        ])
        .unwrap();
        validate(&cli).unwrap();

        let cli = Cli::try_parse_from([
            "fetch",
            "--min-tls",
            "1.3",
            "--max-tls",
            "1.2",
            "https://example.com",
        ])
        .unwrap();
        let err = validate(&cli).unwrap_err();
        assert_eq!(
            err.to_string(),
            "min-tls must be less than or equal to max-tls"
        );

        let cli =
            Cli::try_parse_from(["fetch", "--min-tls", "1.4", "https://example.com"]).unwrap();
        let err = validate(&cli).unwrap_err();
        assert!(err.to_string().contains("invalid value '1.4'"));
        assert!(err.to_string().contains("--min-tls"));
    }

    #[test]
    fn validate_image_flag_matches_go_choices() {
        let cli =
            Cli::try_parse_from(["fetch", "--image", "external", "https://example.com"]).unwrap();
        validate(&cli).unwrap();

        let cli = Cli::try_parse_from(["fetch", "--image", "bad", "https://example.com"]).unwrap();
        let err = validate(&cli).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid value 'bad' for option '--image': must be one of [auto, external, off]"
        );
    }

    #[test]
    fn validate_proxy_flag_matches_go_cli_behavior() {
        let cli =
            Cli::try_parse_from(["fetch", "--proxy", "http://", "https://example.com"]).unwrap();
        validate(&cli).unwrap();

        let cli = Cli::try_parse_from(["fetch", "--proxy", ":bad", "https://example.com"]).unwrap();
        let err = validate(&cli).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid value ':bad' for option '--proxy': parse \":bad\": missing protocol scheme"
        );
    }

    #[test]
    fn host_config_prefers_exact_then_most_specific_wildcard() {
        let path = PathBuf::from("test/config");
        let file = parse_file(
            &path,
            "
              [*.example.com]
              color = off
              [*.api.example.com]
              color = on
              [api.example.com]
              format = on
            ",
        )
        .unwrap();

        assert_eq!(
            file.host_config("api.example.com")
                .and_then(|cfg| cfg.format.as_deref()),
            Some("on")
        );
        assert_eq!(
            file.host_config("API.Example.com")
                .and_then(|cfg| cfg.format.as_deref()),
            Some("on")
        );
        assert_eq!(
            file.host_config("v1.api.example.com")
                .and_then(|cfg| cfg.color.as_deref()),
            Some("on")
        );
        assert_eq!(
            file.host_config("V1.API.Example.com")
                .and_then(|cfg| cfg.color.as_deref()),
            Some("on")
        );
        assert_eq!(
            file.host_config("www.example.com")
                .and_then(|cfg| cfg.color.as_deref()),
            Some("off")
        );
        assert_eq!(
            file.host_config("a.b.example.com")
                .and_then(|cfg| cfg.color.as_deref()),
            Some("off")
        );
        assert!(file.host_config("example.com").is_none());
        assert!(file.host_config("other.com").is_none());
        assert!(file.host_config("").is_none());
        assert!(ConfigFile::default().host_config("example.com").is_none());
    }

    #[test]
    fn apply_file_does_not_override_cli_values() {
        let path = PathBuf::from("test/config");
        let file = parse_file(
            &path,
            "
              color = on
              compress = zstd
              format = on
              retry = 2
              retry-delay = 0.5
            ",
        )
        .unwrap();
        let mut cli = Cli::try_parse_from([
            "fetch",
            "--color",
            "off",
            "--compress",
            "gzip",
            "--format",
            "off",
            "--retry",
            "0",
            "--retry-delay",
            "1",
            "http://example.com",
        ])
        .unwrap();

        let sources = CliConfigSources::capture(&cli);
        apply_file(&mut cli, &file, sources);

        assert_eq!(cli.color.as_deref(), Some("off"));
        assert_eq!(cli.compress.as_deref(), Some("gzip"));
        assert_eq!(cli.format.as_deref(), Some("off"));
        assert_eq!(cli.retry, Some(0));
        assert_eq!(cli.retry_delay, Some(1.0));
    }

    #[test]
    fn apply_file_preserves_bool_and_count_sources_when_config_sets_false() {
        let path = PathBuf::from("test/config");
        let file = parse_file(
            &path,
            "
              copy = false
              ignore-status = false
              insecure = false
              no-encode = false
              pager = auto
              silent = false
              sort-headers = false
              timing = false
              verbosity = 0
            ",
        )
        .unwrap();
        let mut cli = Cli::try_parse_from([
            "fetch",
            "--copy",
            "--ignore-status",
            "--insecure",
            "--no-encode",
            "--pager",
            "off",
            "--silent",
            "--sort-headers",
            "--timing",
            "-vv",
            "http://example.com",
        ])
        .unwrap();

        let sources = CliConfigSources::capture(&cli);
        apply_file(&mut cli, &file, sources);

        assert!(cli.copy);
        assert!(cli.ignore_status);
        assert!(cli.insecure);
        assert!(cli.no_encode);
        assert_eq!(cli.pager.as_deref(), Some("off"));
        assert!(cli.silent);
        assert!(cli.sort_headers);
        assert!(cli.timing);
        assert_eq!(cli.verbose, 2);
    }

    #[test]
    fn apply_file_treats_tls_alias_as_cli_min_tls_source_like_go() {
        let path = PathBuf::from("test/config");
        let file = parse_file(
            &path,
            "
              min-tls = 1.2
              max-tls = 1.2
            ",
        )
        .unwrap();
        let mut cli = Cli::try_parse_from(["fetch", "--tls", "1.3", "http://example.com"]).unwrap();

        let sources = CliConfigSources::capture(&cli);
        apply_file(&mut cli, &file, sources);

        assert_eq!(cli.tls.as_deref(), Some("1.3"));
        assert_eq!(cli.min_tls.as_deref(), None);
        assert_eq!(cli.max_tls.as_deref(), Some("1.2"));
        let err = validate(&cli).unwrap_err();
        assert_eq!(
            err.to_string(),
            "min-tls must be less than or equal to max-tls"
        );
    }

    #[test]
    fn apply_file_uses_host_before_global_for_singletons() {
        let path = PathBuf::from("test/config");
        let file = parse_file(
            &path,
            "
              color = off
              format = off
              [api.example.com]
              color = on
            ",
        )
        .unwrap();
        let mut cli = Cli::try_parse_from(["fetch", "https://api.example.com"]).unwrap();

        let sources = CliConfigSources::capture(&cli);
        apply_file(&mut cli, &file, sources);

        assert_eq!(cli.color.as_deref(), Some("on"));
        assert_eq!(cli.format.as_deref(), Some("off"));
    }

    #[test]
    fn apply_file_orders_global_host_then_cli_for_repeated_values() {
        let path = PathBuf::from("test/config");
        let file = parse_file(
            &path,
            "
              header = X-Global: 1
              query = global=1
              [api.example.com]
              header = X-Host: 1
              query = host=1
            ",
        )
        .unwrap();
        let mut cli = Cli::try_parse_from([
            "fetch",
            "-H",
            "X-Cli: 1",
            "-q",
            "cli=1",
            "https://api.example.com",
        ])
        .unwrap();

        let sources = CliConfigSources::capture(&cli);
        apply_file(&mut cli, &file, sources);

        assert_eq!(cli.headers, vec!["X-Global: 1", "X-Host: 1", "X-Cli: 1"]);
        assert_eq!(cli.query, vec!["global=1", "host=1", "cli=1"]);
    }

    #[test]
    fn default_config_candidates_match_go_search_order() {
        let unix = default_config_candidates(
            Some(PathBuf::from("/home/me")),
            Some(PathBuf::from("/xdg")),
            Some(PathBuf::from("/appdata")),
            false,
        );
        assert_eq!(
            unix,
            vec![
                PathBuf::from("/xdg/fetch/config"),
                PathBuf::from("/home/me/.config/fetch/config"),
            ]
        );

        let windows = default_config_candidates(
            Some(PathBuf::from("C:/Users/me")),
            Some(PathBuf::from("C:/xdg")),
            Some(PathBuf::from("C:/AppData/Roaming")),
            true,
        );
        assert_eq!(
            windows,
            vec![
                PathBuf::from("C:/xdg/fetch/config"),
                PathBuf::from("C:/Users/me/.config/fetch/config"),
                PathBuf::from("C:/AppData/Roaming/fetch/config"),
            ]
        );
    }

    #[test]
    fn explicit_config_path_is_absolute_and_expands_home() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let path = expand_home_with_home("~/fetch.conf", Some(&home));
        assert_eq!(path, home.join("fetch.conf"));
    }

    fn expand_home_with_home(path: &str, home: Option<&Path>) -> PathBuf {
        if let Some(rest) = path.strip_prefix("~/")
            && let Some(home) = home
        {
            return home.join(rest);
        }
        PathBuf::from(path)
    }

    fn write_temp_config_pem(contents: &[u8]) -> (tempfile::NamedTempFile, String) {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(contents).unwrap();
        let path = file.path().to_string_lossy().into_owned();
        (file, path)
    }
}
