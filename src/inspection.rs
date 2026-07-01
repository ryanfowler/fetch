use crate::cli::Cli;
use crate::flag_registry::FlagCategory;

/// Append ignored request-related flag names (with `--` prefix) to `ignored`.
pub(crate) fn append_shared_ignored_request_flags(cli: &Cli, ignored: &mut Vec<&'static str>) {
    crate::flag_registry::append_ignored_of_category(cli, FlagCategory::Request, ignored);
}

/// Append ignored auth flag names (with `--` prefix) to `ignored`.
pub(crate) fn append_shared_ignored_auth_flags(cli: &Cli, ignored: &mut Vec<&'static str>) {
    crate::flag_registry::append_ignored_of_category(cli, FlagCategory::Auth, ignored);
}

/// Append ignored response flag names (with `--` prefix) to `ignored`.
pub(crate) fn append_shared_ignored_response_flags(cli: &Cli, ignored: &mut Vec<&'static str>) {
    crate::flag_registry::append_ignored_of_category(cli, FlagCategory::Response, ignored);
}

/// Append ignored TLS flag names (with `--` prefix) to `ignored`.
/// Used by DNS inspection (but not TLS inspection, where TLS flags are meaningful).
pub(crate) fn append_shared_ignored_tls_flags(cli: &Cli, ignored: &mut Vec<&'static str>) {
    crate::flag_registry::append_ignored_of_category(cli, FlagCategory::Tls, ignored);
}

/// Append ignored HTTP-version flag names (with `--` prefix) to `ignored`.
pub(crate) fn append_shared_ignored_http_version_flags(cli: &Cli, ignored: &mut Vec<&'static str>) {
    crate::flag_registry::append_ignored_of_category(cli, FlagCategory::HttpVersion, ignored);
}
