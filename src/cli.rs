use clap::{ArgAction, Parser};

pub mod completion;
pub mod from_curl;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpVersion {
    Http1,
    Http2,
    Http3,
}

impl HttpVersion {
    pub fn label(self) -> &'static str {
        match self {
            Self::Http1 => "HTTP/1.1",
            Self::Http2 => "HTTP/2.0",
            Self::Http3 => "HTTP/3.0",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompressionMode {
    Auto,
    Gzip,
    Zstd,
    Off,
}

impl CompressionMode {
    pub const VALUES: &[&str] = &["auto", "gzip", "zstd", "off"];

    pub fn from_cli(cli: &Cli) -> Self {
        if cli.no_encode {
            return Self::Off;
        }
        Self::from_value(cli.compress.as_deref().unwrap_or("auto"))
            .expect("compression mode is validated by clap/config")
    }

    pub fn from_value(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "gzip" => Some(Self::Gzip),
            "zstd" => Some(Self::Zstd),
            "off" => Some(Self::Off),
            _ => None,
        }
    }

    pub fn accept_encoding(self) -> Option<&'static str> {
        match self {
            Self::Auto => Some("gzip, zstd"),
            Self::Gzip => Some("gzip"),
            Self::Zstd => Some("zstd"),
            Self::Off => None,
        }
    }

    pub fn decodes(self, encoding: &str) -> bool {
        matches!(
            (self, encoding),
            (Self::Auto, "gzip" | "zstd" | "aws-chunked")
                | (Self::Gzip, "gzip" | "aws-chunked")
                | (Self::Zstd, "zstd" | "aws-chunked")
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PagerMode {
    Auto,
    On,
    Off,
}

impl PagerMode {
    pub const VALUES: &[&str] = &["auto", "on", "off"];

    pub fn from_cli(cli: &Cli) -> Self {
        Self::from_value(cli.pager.as_deref().unwrap_or("auto"))
            .expect("pager mode is validated by clap/config")
    }

    pub fn from_value(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "on" => Some(Self::On),
            "off" => Some(Self::Off),
            _ => None,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "fetch",
    about = "fetch is a modern HTTP(S) client for the command line",
    disable_help_flag = true,
    disable_version_flag = true
)]
pub struct Cli {
    #[arg(value_name = "URL", help = "The URL to make a request to")]
    pub url: Option<String>,

    #[arg(last = true, hide = true)]
    pub extra_args: Vec<String>,

    #[arg(long = "auto-update", value_name = "ENABLED|INTERVAL", hide = true)]
    pub auto_update: Option<String>,

    #[arg(
        long = "aws-sigv4",
        value_name = "REGION/SERVICE",
        conflicts_with_all = ["basic", "bearer", "digest"],
        help = "Sign the request using AWS signature V4"
    )]
    pub aws_sigv4: Option<String>,

    #[arg(
        long,
        value_name = "USER:PASS",
        conflicts_with_all = ["aws_sigv4", "bearer", "digest"],
        help = "Enable HTTP basic authentication"
    )]
    pub basic: Option<String>,

    #[arg(
        long,
        value_name = "TOKEN",
        conflicts_with_all = ["aws_sigv4", "basic", "digest"],
        help = "Enable HTTP bearer authentication"
    )]
    pub bearer: Option<String>,

    #[arg(long, help = "Print the build information")]
    pub buildinfo: bool,

    #[arg(long, value_name = "PATH", help = "CA certificate file path")]
    pub ca_cert: Vec<String>,

    #[arg(long, value_name = "PATH", help = "Client certificate for mTLS")]
    pub cert: Option<String>,

    #[arg(long, help = "Overwrite existing output file")]
    pub clobber: bool,

    #[arg(
        long,
        alias = "colour",
        value_name = "OPTION",
        value_parser = ["auto", "off", "on"],
        hide_possible_values = true,
        help = "Enable/disable color [auto, off, on]"
    )]
    pub color: Option<String>,

    #[arg(long, value_name = "SHELL", help = "Output shell completion")]
    pub complete: Option<String>,

    #[arg(
        long,
        value_name = "MODE",
        value_parser = ["auto", "gzip", "zstd", "off"],
        hide_possible_values = true,
        conflicts_with = "no_encode",
        help = "Compression mode [auto, gzip, zstd, off]"
    )]
    pub compress: Option<String>,

    #[arg(short = 'c', long, value_name = "PATH", help = "Path to config file")]
    pub config: Option<String>,

    #[arg(
        long = "connect-timeout",
        value_name = "SECONDS",
        allow_hyphen_values = true,
        help = "Timeout for connection establishment"
    )]
    pub connect_timeout: Option<f64>,

    #[arg(long, help = "Copy the response body to clipboard")]
    pub copy: bool,

    #[arg(
        short = 'd',
        long,
        value_name = "[@]VALUE",
        conflicts_with_all = ["form", "json", "multipart", "xml"],
        help = "Send a request body"
    )]
    pub data: Option<String>,

    #[arg(skip)]
    pub data_is_literal: bool,

    #[arg(skip)]
    pub data_literal_bytes: Option<Vec<u8>>,

    #[arg(
        long,
        value_name = "USER:PASS",
        conflicts_with_all = ["aws_sigv4", "basic", "bearer"],
        help = "Enable HTTP digest authentication"
    )]
    pub digest: Option<String>,

    #[arg(
        long,
        conflicts_with_all = ["copy", "output", "remote_name"],
        help = "Discard the response body"
    )]
    pub discard: bool,

    #[arg(
        long = "dns-server",
        value_name = "IP[:PORT]|URL",
        help = "DNS server IP or DoH URL"
    )]
    pub dns_server: Option<String>,

    #[arg(long = "dry-run", help = "Print out the request info and exit")]
    pub dry_run: bool,

    #[arg(short = 'e', long, help = "Use an editor to modify the request body")]
    pub edit: bool,

    #[arg(
        short = 'f',
        long,
        value_name = "KEY=VALUE",
        conflicts_with_all = ["data", "json", "multipart", "xml"],
        help = "Send a urlencoded form body"
    )]
    pub form: Vec<String>,

    #[arg(
        long,
        value_name = "OPTION",
        value_parser = ["auto", "off", "on"],
        hide_possible_values = true,
        help = "Enable/disable formatting [auto, off, on]"
    )]
    pub format: Option<String>,

    #[arg(
        long = "from-curl",
        value_name = "COMMAND",
        help = "Execute a curl command using fetch"
    )]
    pub from_curl: Option<String>,

    #[arg(long, help = "Enable gRPC mode")]
    pub grpc: bool,

    #[arg(
        long = "grpc-describe",
        value_name = "NAME",
        help = "Describe a gRPC service, method, or message"
    )]
    pub grpc_describe: Option<String>,

    #[arg(long = "grpc-list", help = "List available gRPC services")]
    pub grpc_list: bool,

    #[arg(
        short = 'H',
        long = "header",
        value_name = "NAME:VALUE",
        help = "Set headers for the request"
    )]
    pub headers: Vec<String>,

    #[arg(short = 'h', long, help = "Print help")]
    pub help: bool,

    #[arg(long, value_name = "VERSION", help = "HTTP version to use [1, 2, 3]")]
    pub http: Option<String>,

    #[arg(long = "ignore-status", help = "Exit code unaffected by HTTP status")]
    pub ignore_status: bool,

    #[arg(
        long,
        value_name = "OPTION",
        help = "Image rendering [auto,external,off]"
    )]
    pub image: Option<String>,

    #[arg(long, help = "Accept invalid TLS certs (!)")]
    pub insecure: bool,

    #[arg(long = "inspect-dns", help = "Inspect DNS resolution")]
    pub inspect_dns: bool,

    #[arg(long = "inspect-tls", help = "Inspect the TLS certificate chain")]
    pub inspect_tls: bool,

    #[arg(
        short = 'j',
        long,
        value_name = "[@]VALUE",
        conflicts_with_all = ["data", "form", "multipart", "xml"],
        help = "Send a JSON request body"
    )]
    pub json: Option<String>,

    #[arg(long, value_name = "PATH", help = "Client private key for mTLS")]
    pub key: Option<String>,

    #[arg(
        long = "max-tls",
        value_name = "VERSION",
        help = "Maximum TLS version [1.2, 1.3]"
    )]
    pub max_tls: Option<String>,

    #[arg(
        short = 'm',
        long = "method",
        short_alias = 'X',
        value_name = "METHOD",
        help = "HTTP method to use [default: GET]"
    )]
    pub method: Option<String>,

    #[arg(
        long = "min-tls",
        value_name = "VERSION",
        help = "Minimum TLS version [1.2, 1.3]"
    )]
    pub min_tls: Option<String>,

    #[arg(
        short = 'F',
        long,
        value_name = "NAME=[@]VALUE",
        conflicts_with_all = ["data", "form", "json", "xml"],
        help = "Send a multipart form body"
    )]
    pub multipart: Vec<String>,

    #[arg(long = "no-encode", hide = true)]
    pub no_encode: bool,

    #[arg(
        long,
        value_name = "MODE",
        value_parser = ["auto", "on", "off"],
        hide_possible_values = true,
        help = "Control pager use [auto, on, off]"
    )]
    pub pager: Option<String>,

    #[arg(
        short = 'o',
        long,
        value_name = "PATH",
        conflicts_with = "remote_name",
        help = "Write the response body to a file"
    )]
    pub output: Option<String>,

    #[arg(
        long = "proto-desc",
        value_name = "PATH",
        conflicts_with = "proto_files",
        help = "Pre-compiled descriptor set file"
    )]
    pub proto_desc: Option<String>,

    #[arg(
        long = "proto-file",
        value_name = "PATH",
        help = "Compile .proto file(s) via protoc"
    )]
    pub proto_files: Vec<String>,

    #[arg(
        long = "proto-import",
        value_name = "PATH",
        requires = "proto_files",
        help = "Import path for proto compilation"
    )]
    pub proto_imports: Vec<String>,

    #[arg(long, value_name = "PROXY", help = "Configure a proxy")]
    pub proxy: Option<String>,

    #[arg(
        short = 'q',
        long = "query",
        value_name = "KEY=VALUE",
        help = "Append query parameters to the url"
    )]
    pub query: Vec<String>,

    #[arg(
        short = 'r',
        long = "range",
        value_name = "RANGE",
        allow_hyphen_values = true,
        help = "Request a specific byte range"
    )]
    pub ranges: Vec<String>,

    #[arg(
        long,
        value_name = "NUM",
        allow_hyphen_values = true,
        help = "Maximum number of redirects"
    )]
    pub redirects: Option<usize>,

    #[arg(
        short = 'J',
        long = "remote-header-name",
        help = "Use content-disposition header filename"
    )]
    pub remote_header_name: bool,

    #[arg(
        short = 'O',
        long = "remote-name",
        alias = "output-current-dir",
        conflicts_with_all = ["discard", "output"],
        help = "Use URL path component as output filename"
    )]
    pub remote_name: bool,

    #[arg(
        long,
        value_name = "NUM",
        allow_hyphen_values = true,
        help = "Maximum number of retries [default: 0]"
    )]
    pub retry: Option<usize>,

    #[arg(
        long = "retry-delay",
        value_name = "SECONDS",
        allow_hyphen_values = true,
        help = "Initial delay between retries [default: 1]"
    )]
    pub retry_delay: Option<f64>,

    #[arg(
        short = 'S',
        long,
        value_name = "NAME",
        help = "Use a named session for cookies"
    )]
    pub session: Option<String>,

    #[arg(short = 's', long, help = "Print only errors to stderr")]
    pub silent: bool,

    #[arg(long = "sort-headers", help = "Sort displayed headers by name")]
    pub sort_headers: bool,

    #[arg(
        short = 't',
        long,
        value_name = "SECONDS",
        allow_hyphen_values = true,
        help = "Timeout applied to the request"
    )]
    pub timeout: Option<f64>,

    #[arg(short = 'T', long, help = "Display a timing waterfall chart")]
    pub timing: bool,

    #[arg(long, value_name = "VERSION", hide = true)]
    pub tls: Option<String>,

    #[arg(
        long,
        value_name = "PATH",
        help = "Make the request over a unix socket"
    )]
    pub unix: Option<String>,

    #[arg(long, help = "Update the fetch binary in place")]
    pub update: bool,

    #[arg(
        short = 'v',
        long = "verbose",
        action = ArgAction::Count,
        help = "Verbosity of the output"
    )]
    pub verbose: u8,

    #[arg(short = 'V', long, help = "Print version")]
    pub version: bool,

    #[arg(
        long = "ws-interactive",
        value_name = "MODE",
        value_parser = ["auto", "on", "off"],
        hide_possible_values = true,
        help = "WebSocket prompt mode [auto, on, off]"
    )]
    pub ws_interactive: Option<String>,

    #[arg(
        short = 'x',
        long,
        value_name = "[@]VALUE",
        conflicts_with_all = ["data", "form", "json", "multipart"],
        help = "Send an XML request body"
    )]
    pub xml: Option<String>,
}

impl Cli {
    pub fn method(&self) -> &str {
        self.method.as_deref().unwrap_or("GET")
    }

    pub fn has_grpc_discovery(&self) -> bool {
        self.grpc_list || self.grpc_describe.is_some()
    }

    pub fn has_proto_schema(&self) -> bool {
        !self.proto_files.is_empty() || self.proto_desc.is_some()
    }

    pub fn retry(&self) -> usize {
        self.retry.unwrap_or(0)
    }

    pub fn retry_delay(&self) -> f64 {
        self.retry_delay.unwrap_or(1.0)
    }
}

pub fn normalize_range_values(values: &mut [String]) -> Result<(), String> {
    for value in values {
        *value = normalize_range_value(value)?;
    }
    Ok(())
}

pub fn parse_http_version(value: Option<&str>) -> Result<Option<HttpVersion>, String> {
    match value {
        None => Ok(None),
        Some("1") => Ok(Some(HttpVersion::Http1)),
        Some("2") => Ok(Some(HttpVersion::Http2)),
        Some("3") => Ok(Some(HttpVersion::Http3)),
        Some(value) => Err(format!(
            "invalid value '{value}' for option '--http': must be one of [1, 2, 3]"
        )),
    }
}

fn normalize_range_value(value: &str) -> Result<String, String> {
    let value = value.trim();
    let Some((start, end)) = value.split_once('-') else {
        return Err(range_error(value, "invalid byte range"));
    };
    let start = start.trim();
    let end = end.trim();
    if start.is_empty() && end.is_empty() {
        return Err(range_error(value, "invalid byte range"));
    }
    if !is_valid_range_value(start) {
        return Err(range_error(
            value,
            &format!("invalid range start '{start}'"),
        ));
    }
    if !is_valid_range_value(end) {
        return Err(range_error(value, &format!("invalid range end '{end}'")));
    }
    Ok(format!("{start}-{end}"))
}

fn is_valid_range_value(value: &str) -> bool {
    value.bytes().all(|byte| byte.is_ascii_digit())
}

fn range_error(value: &str, usage: &str) -> String {
    format!("invalid value '{value}' for option '--range': {usage}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{ColorChoice, CommandFactory};

    #[test]
    fn help_output_includes_go_descriptions_and_stays_under_80_columns() {
        let mut command = Cli::command().color(ColorChoice::Never);
        let mut output = Vec::new();
        command.write_help(&mut output).unwrap();
        let help = String::from_utf8(output).unwrap();

        assert!(help.contains("[URL]  The URL to make a request to"));
        assert!(
            help.contains("--aws-sigv4 <REGION/SERVICE>  Sign the request using AWS signature V4")
        );
        assert!(
            help.contains(
                "--format <OPTION>             Enable/disable formatting [auto, off, on]"
            )
        );
        assert!(help.contains("--pager <MODE>                Control pager use [auto, on, off]"));
        assert!(help.contains("--sort-headers                Sort displayed headers by name"));
        assert!(
            help.contains("-m, --method <METHOD>             HTTP method to use [default: GET]")
        );
        assert!(
            help.contains("--ws-interactive <MODE>       WebSocket prompt mode [auto, on, off]")
        );

        for line in help.lines() {
            assert!(
                line.chars().count() <= 80,
                "help line exceeds 80 columns: {line:?}"
            );
        }
    }

    #[test]
    fn digest_auth_parsing() {
        let cli =
            Cli::try_parse_from(["fetch", "--digest", "user:pass", "http://example.com"]).unwrap();
        assert_eq!(cli.digest.as_deref(), Some("user:pass"));
    }

    #[test]
    fn digest_conflicts_with_basic() {
        let err = Cli::try_parse_from([
            "fetch",
            "--digest",
            "user:pass",
            "--basic",
            "user:pass",
            "http://example.com",
        ])
        .unwrap_err()
        .to_string();
        assert!(err.contains("cannot be used"));
    }

    #[test]
    fn aws_sigv4_credentials_are_not_loaded_during_parse() {
        let cli = Cli::try_parse_from([
            "fetch",
            "--aws-sigv4",
            "us-east-1/s3",
            "https://example.com",
        ])
        .unwrap();
        assert_eq!(cli.aws_sigv4.as_deref(), Some("us-east-1/s3"));
    }

    #[test]
    fn completion_parse_keeps_remaining_args_as_extra_args() {
        let cli = Cli::try_parse_from(["fetch", "--complete=bash", "--", "fetch", "--"]).unwrap();

        assert_eq!(cli.complete.as_deref(), Some("bash"));
        assert_eq!(cli.extra_args, vec!["fetch", "--"]);
    }

    #[test]
    fn range_flag_accepts_unsigned_byte_ranges() {
        let tests = [
            ("suffix", "-1023", vec!["-1023"]),
            ("open ended", "1023-", vec!["1023-"]),
            ("bounded", "0-1023", vec!["0-1023"]),
            ("trimmed", " 5 - 10 ", vec!["5-10"]),
        ];

        for (name, arg, want) in tests {
            let mut cli = Cli::try_parse_from(["fetch", "--range", arg]).unwrap();
            normalize_range_values(&mut cli.ranges).unwrap();
            assert_eq!(cli.ranges, want, "{name}");
        }
    }

    #[test]
    fn range_flag_rejects_signed_or_malformed_byte_ranges() {
        for arg in ["bad", "-", "5--1", "+5-10", "5-+10", "--1", "-+1"] {
            let mut cli = Cli::try_parse_from(["fetch", "--range", arg]).unwrap();
            let err = normalize_range_values(&mut cli.ranges).unwrap_err();
            assert!(err.contains("invalid"), "{arg}: {err}");
        }
    }

    #[test]
    fn range_flag_reports_invalid_range_end() {
        let mut cli = Cli::try_parse_from(["fetch", "--range", "5--1"]).unwrap();
        let err = normalize_range_values(&mut cli.ranges).unwrap_err();

        assert!(err.contains("invalid range end '-1'"));
    }

    #[test]
    fn timeout_flags_accept_negative_values_for_validation() {
        let cli = Cli::try_parse_from([
            "fetch",
            "--connect-timeout",
            "-1",
            "--timeout",
            "-2",
            "--retry-delay",
            "-3",
            "http://example.com",
        ])
        .unwrap();

        assert_eq!(cli.connect_timeout, Some(-1.0));
        assert_eq!(cli.timeout, Some(-2.0));
        assert_eq!(cli.retry_delay, Some(-3.0));
    }

    #[test]
    fn http_flag_accepts_go_supported_versions() {
        let tests = [
            ("1", Some(HttpVersion::Http1)),
            ("2", Some(HttpVersion::Http2)),
            ("3", Some(HttpVersion::Http3)),
        ];

        for (arg, want) in tests {
            let cli = Cli::try_parse_from(["fetch", "--http", arg, "http://example.com"]).unwrap();
            assert_eq!(parse_http_version(cli.http.as_deref()).unwrap(), want);
        }
    }

    #[test]
    fn http_flag_rejects_unknown_versions_like_go() {
        let cli = Cli::try_parse_from(["fetch", "--http", "1.1", "http://example.com"]).unwrap();
        let err = parse_http_version(cli.http.as_deref()).unwrap_err();

        assert_eq!(
            err,
            "invalid value '1.1' for option '--http': must be one of [1, 2, 3]"
        );
    }
}
