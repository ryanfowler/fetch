use thiserror::Error;

use crate::core::{self, Printer, Sequence};

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("{0}")]
    Message(String),
    #[error("{0}")]
    Runtime(String),
    #[error("{0}")]
    CertificateValidation(String),
    #[error("invalid value '{value}' for option '{option}'{usage_suffix}")]
    InvalidValue {
        option: String,
        value: String,
        usage: Option<String>,
        usage_suffix: InvalidValueUsageSuffix,
    },
    #[error("file '{0}' does not exist")]
    FileDoesNotExist(String),
    #[error("config file '{path}': line {line}: {message}")]
    ConfigFile {
        path: String,
        line: usize,
        message: Box<FetchError>,
    },
    #[error(transparent)]
    Transport(#[from] crate::http::transport::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Url(#[from] url::ParseError),
}

#[derive(Debug, Error)]
#[error("{0}")]
pub struct InvalidValueUsageSuffix(String);

impl From<&str> for FetchError {
    fn from(value: &str) -> Self {
        Self::from_message(value.to_string())
    }
}

impl From<String> for FetchError {
    fn from(value: String) -> Self {
        Self::from_message(value)
    }
}

impl FetchError {
    fn from_message(value: String) -> Self {
        if let Some(err) = parse_config_file_error(&value) {
            return err;
        }
        if let Some(err) = parse_invalid_value_error(&value) {
            return err;
        }
        if let Some(path) = parse_file_does_not_exist_error(&value) {
            return Self::FileDoesNotExist(path.to_string());
        }
        Self::Message(value)
    }

    pub fn invalid_value(
        option: impl Into<String>,
        value: impl Into<String>,
        usage: impl Into<String>,
    ) -> Self {
        Self::InvalidValue {
            option: option.into(),
            value: value.into(),
            usage: Some(usage.into()),
            usage_suffix: InvalidValueUsageSuffix(String::new()),
        }
        .with_usage_suffix()
    }

    fn with_usage_suffix(self) -> Self {
        match self {
            Self::InvalidValue {
                option,
                value,
                usage,
                ..
            } => {
                let suffix = usage
                    .as_ref()
                    .filter(|usage| !usage.is_empty())
                    .map(|usage| format!(": {usage}"))
                    .unwrap_or_default();
                Self::InvalidValue {
                    option,
                    value,
                    usage,
                    usage_suffix: InvalidValueUsageSuffix(suffix),
                }
            }
            other => other,
        }
    }

    pub fn print_to(&self, printer: &mut Printer) {
        match self {
            Self::InvalidValue {
                option,
                value,
                usage,
                ..
            } => {
                printer.push_str("invalid value '");
                printer.write_styled(value, &[Sequence::Yellow]);
                printer.push_str("' for option '");
                printer.write_styled(option, &[Sequence::Bold]);
                printer.push('\'');
                if let Some(usage) = usage.as_ref().filter(|usage| !usage.is_empty()) {
                    printer.push_str(": ");
                    printer.push_str(usage);
                }
            }
            Self::FileDoesNotExist(path) => {
                printer.push_str("file '");
                printer.write_styled(path, &[Sequence::Dim]);
                printer.push_str("' does not exist");
            }
            Self::ConfigFile {
                path,
                line,
                message,
            } => {
                printer.push_str("config file '");
                printer.write_styled(path, &[Sequence::Dim]);
                printer.push_str("': line ");
                printer.write_styled(&line.to_string(), &[Sequence::Yellow]);
                printer.push_str(": ");
                message.print_to(printer);
            }
            Self::Message(message)
            | Self::Runtime(message)
            | Self::CertificateValidation(message) => {
                print_message_styled(printer, message);
            }
            _ => printer.push_str(&self.to_string()),
        }
    }
}

fn print_message_styled(printer: &mut Printer, message: &str) {
    if print_unknown_flag(printer, message)
        || print_arg_required(printer, message)
        || print_flag_no_args(printer, message)
        || print_exclusive_flags(printer, message)
        || print_required_flag(printer, message)
        || print_from_curl_exclusive(printer, message)
        || print_scheme_exclusive(printer, message)
        || print_file_is_directory(printer, message)
    {
        return;
    }
    printer.push_str(message);
}

fn print_unknown_flag(printer: &mut Printer, message: &str) -> bool {
    let Some(flag) = message
        .strip_prefix("unknown flag '")
        .and_then(|rest| rest.strip_suffix('\''))
    else {
        return false;
    };
    printer.push_str("unknown flag '");
    printer.push_str(flag);
    printer.push('\'');
    true
}

fn print_arg_required(printer: &mut Printer, message: &str) -> bool {
    let Some(flag) = message
        .strip_prefix("argument required for flag '")
        .and_then(|rest| rest.strip_suffix('\''))
    else {
        return false;
    };
    printer.push_str("argument required for flag '");
    printer.write_styled(flag, &[Sequence::Bold]);
    printer.push('\'');
    true
}

fn print_flag_no_args(printer: &mut Printer, message: &str) -> bool {
    let Some(flag) = message
        .strip_prefix("flag '")
        .and_then(|rest| rest.strip_suffix("' does not take any arguments"))
    else {
        return false;
    };
    printer.push_str("flag '");
    printer.write_styled(flag, &[Sequence::Bold]);
    printer.push_str("' does not take any arguments");
    true
}

fn print_exclusive_flags(printer: &mut Printer, message: &str) -> bool {
    let Some(rest) = message.strip_prefix("flags '") else {
        return false;
    };
    let Some((first, rest)) = rest.split_once("' and '") else {
        return false;
    };
    let Some(second) = rest.strip_suffix("' cannot be used together") else {
        return false;
    };
    printer.push_str("flags '");
    printer.write_styled(first, &[Sequence::Bold]);
    printer.push_str("' and '");
    printer.write_styled(second, &[Sequence::Bold]);
    printer.push_str("' cannot be used together");
    true
}

fn print_required_flag(printer: &mut Printer, message: &str) -> bool {
    let Some(rest) = message.strip_prefix("flag '") else {
        return false;
    };
    let Some((flag, required)) = rest.split_once("' requires '") else {
        return false;
    };
    let Some(required) = required.strip_suffix('\'') else {
        return false;
    };
    printer.push_str("flag '");
    printer.write_styled(flag, &[Sequence::Bold]);
    printer.push_str("' requires '");
    printer.write_styled(required, &[Sequence::Bold]);
    printer.push('\'');
    true
}

fn print_from_curl_exclusive(printer: &mut Printer, message: &str) -> bool {
    let Some(rest) = message.strip_prefix("'--from-curl' and ") else {
        return false;
    };
    printer.push('\'');
    printer.write_styled("--from-curl", &[Sequence::Bold]);
    if let Some(argument) = rest.strip_suffix(" argument cannot be used together") {
        let Some(argument) = argument.strip_prefix("a ") else {
            return false;
        };
        printer.push_str("' and a ");
        printer.write_styled(argument, &[Sequence::Bold]);
        printer.push_str(" argument cannot be used together");
        return true;
    }
    let Some(flag) = rest
        .strip_prefix('\'')
        .and_then(|rest| rest.strip_suffix("' cannot be used together"))
    else {
        return false;
    };
    printer.push_str("' and '");
    printer.write_styled(flag, &[Sequence::Bold]);
    printer.push_str("' cannot be used together");
    true
}

fn print_scheme_exclusive(printer: &mut Printer, message: &str) -> bool {
    let Some(rest) = message.strip_prefix('\'') else {
        return false;
    };
    let Some((scheme, rest)) = rest.split_once("' scheme and '") else {
        return false;
    };
    let Some(flag) = rest.strip_suffix("' flag cannot be used together") else {
        return false;
    };
    printer.push('\'');
    printer.write_styled(scheme, &[Sequence::Bold]);
    printer.push_str("' scheme and '");
    printer.write_styled(flag, &[Sequence::Bold]);
    printer.push_str("' flag cannot be used together");
    true
}

fn print_file_is_directory(printer: &mut Printer, message: &str) -> bool {
    let Some(path) = message
        .strip_prefix("file '")
        .and_then(|rest| rest.strip_suffix("' is a directory"))
    else {
        return false;
    };
    printer.push_str("file '");
    printer.write_styled(path, &[Sequence::Dim]);
    printer.push_str("' is a directory");
    true
}

fn parse_config_file_error(value: &str) -> Option<FetchError> {
    let rest = value.strip_prefix("config file '")?;
    let (path, rest) = rest.split_once("': line ")?;
    let (line, message) = rest.split_once(": ")?;
    Some(FetchError::ConfigFile {
        path: path.to_string(),
        line: line.parse().ok()?,
        message: Box::new(FetchError::from_message(message.to_string())),
    })
}

fn parse_invalid_value_error(value: &str) -> Option<FetchError> {
    let rest = value.strip_prefix("invalid value '")?;
    let (invalid, rest) = rest.split_once("' for option '")?;
    let (option, usage) = match rest.split_once("': ") {
        Some((option, usage)) => (option, Some(usage.to_string())),
        None => (rest.strip_suffix('\'')?, None),
    };
    Some(
        FetchError::InvalidValue {
            option: option.to_string(),
            value: invalid.to_string(),
            usage,
            usage_suffix: InvalidValueUsageSuffix(String::new()),
        }
        .with_usage_suffix(),
    )
}

fn parse_file_does_not_exist_error(value: &str) -> Option<&str> {
    value
        .strip_prefix("file '")
        .and_then(|rest| rest.strip_suffix("' does not exist"))
}

pub fn write_cli_error(err: impl std::fmt::Display) {
    write_cli_error_with_color(err, None);
}

pub fn write_cli_error_with_color(err: impl std::fmt::Display, color: Option<&str>) {
    let err = FetchError::from_message(err.to_string());
    let mut printer = Printer::stderr(color);
    write_fetch_error_msg_no_flush(&mut printer, &err);
    printer.push_str("\nFor more information, try '");
    printer.write_styled("--help", &[Sequence::Bold]);
    printer.push_str("'.\n");
    flush_stderr(printer);
}

pub fn write_runtime_error(err: FetchError) {
    write_runtime_error_with_color(err, None);
}

pub fn write_runtime_error_with_color(err: FetchError, color: Option<&str>) {
    match &err {
        FetchError::Runtime(_) => {
            write_error_with_color(err, color);
        }
        FetchError::CertificateValidation(_) => {
            let mut printer = Printer::stderr(color);
            write_fetch_error_msg_no_flush(&mut printer, &err);
            printer.push_str("\nIf you absolutely trust the server, try '");
            printer.write_styled("--insecure", &[Sequence::Bold]);
            printer.push_str("'.\n");
            flush_stderr(printer);
        }
        _ => write_cli_error_with_color(err, color),
    }
}

pub fn write_error_with_color(err: impl std::fmt::Display, color: Option<&str>) {
    let err = FetchError::from_message(err.to_string());
    let mut printer = Printer::stderr(color);
    write_fetch_error_msg_no_flush(&mut printer, &err);
    flush_stderr(printer);
}

pub fn write_warning_with_color(msg: impl std::fmt::Display, color: Option<&str>) {
    let mut printer = Printer::stderr(color);
    core::write_warning_msg_no_flush(&mut printer, msg);
    flush_stderr(printer);
}

pub fn write_warning_with_separator_with_color(msg: impl std::fmt::Display, color: Option<&str>) {
    let mut printer = Printer::stderr(color);
    core::write_warning_msg_no_flush(&mut printer, msg);
    core::write_warning_separator_no_flush(&mut printer);
    flush_stderr(printer);
}

pub fn write_warnings_with_separator_with_color<I, M>(warnings: I, color: Option<&str>)
where
    I: IntoIterator<Item = M>,
    M: std::fmt::Display,
{
    let mut printer = Printer::stderr(color);
    let mut wrote_warning = false;
    for warning in warnings {
        core::write_warning_msg_no_flush(&mut printer, warning);
        wrote_warning = true;
    }
    if wrote_warning {
        core::write_warning_separator_no_flush(&mut printer);
        flush_stderr(printer);
    }
}

fn flush_stderr(mut printer: Printer) {
    let mut stderr = std::io::stderr();
    let _ = printer.flush_to(&mut stderr);
}

fn write_fetch_error_msg_no_flush(printer: &mut Printer, err: &FetchError) {
    printer.write_error_label();
    printer.push_str(": ");
    err.print_to(printer);
    printer.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(err: impl std::fmt::Display) -> String {
        let err = FetchError::from_message(err.to_string());
        let mut printer = Printer::new(true);
        write_fetch_error_msg_no_flush(&mut printer, &err);
        printer.into_string().unwrap()
    }

    #[test]
    fn invalid_value_errors_style_value_and_option() {
        assert_eq!(
            render(
                "invalid value 'nocolon' for option '--basic': format must be <USERNAME:PASSWORD>"
            ),
            "\x1b[31m\x1b[1merror\x1b[0m: invalid value '\x1b[33mnocolon\x1b[0m' for option '\x1b[1m--basic\x1b[0m': format must be <USERNAME:PASSWORD>\n"
        );
    }

    #[test]
    fn missing_file_errors_style_path() {
        assert_eq!(
            render("file '/tmp/missing.proto' does not exist"),
            "\x1b[31m\x1b[1merror\x1b[0m: file '\x1b[2m/tmp/missing.proto\x1b[0m' does not exist\n"
        );
    }

    #[test]
    fn config_errors_style_context_and_nested_message() {
        assert_eq!(
            render(
                "config file '/tmp/fetchrc': line 3: invalid value ':bad' for option 'proxy': parse \":bad\": missing protocol scheme"
            ),
            "\x1b[31m\x1b[1merror\x1b[0m: config file '\x1b[2m/tmp/fetchrc\x1b[0m': line \x1b[33m3\x1b[0m: invalid value '\x1b[33m:bad\x1b[0m' for option '\x1b[1mproxy\x1b[0m': parse \":bad\": missing protocol scheme\n"
        );
    }

    #[test]
    fn cli_shape_errors_style_flags() {
        assert_eq!(
            render("unknown flag '--bad'"),
            "\x1b[31m\x1b[1merror\x1b[0m: unknown flag '--bad'\n"
        );
        assert_eq!(
            render("flags '--basic' and '--bearer' cannot be used together"),
            "\x1b[31m\x1b[1merror\x1b[0m: flags '\x1b[1m--basic\x1b[0m' and '\x1b[1m--bearer\x1b[0m' cannot be used together\n"
        );
        assert_eq!(
            render("flag '--key' requires '--cert'"),
            "\x1b[31m\x1b[1merror\x1b[0m: flag '\x1b[1m--key\x1b[0m' requires '\x1b[1m--cert\x1b[0m'\n"
        );
    }
}
