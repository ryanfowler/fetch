use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};

use crate::cli::Cli;
use crate::error::FetchError;

type ParseConfigValue = fn(&Path, usize, &mut ConfigValues, &str, &str) -> Result<(), String>;
type OverlayConfigValue = fn(&mut ConfigValues, &ConfigValues);
type ApplyConfigValue = fn(&mut Cli, &ConfigValues, &CliConfigSources);
type CliConfigSource = fn(&Cli) -> bool;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfigValueTrim {
    Both,
    Left,
}

impl ConfigValueTrim {
    fn apply(self, value: &str) -> &str {
        match self {
            Self::Both => value.trim(),
            Self::Left => value.trim_start(),
        }
    }
}

struct ConfigOption {
    field: ConfigField,
    keys: &'static [&'static str],
    #[cfg(test)]
    documented_keys: &'static [&'static str],
    #[cfg(test)]
    cli_flags: &'static [&'static str],
    trim: ConfigValueTrim,
    cli_source: CliConfigSource,
    parse: ParseConfigValue,
    overlay: OverlayConfigValue,
    apply: ApplyConfigValue,
}

macro_rules! config_option_descriptor {
    (
        @base
        variant: $variant:ident,
        field: $field:ident,
        keys: [$($key:literal),+ $(,)?],
        documented_keys: [$($documented_key:literal),* $(,)?],
        cli_flags: [$($cli_flag:literal),* $(,)?],
        trim: $trim:expr,
        cli_source: $cli_source:expr,
        parse: $parse:expr,
        overlay: $overlay:expr,
        apply: $apply:expr $(,)?
    ) => {
        ConfigOption {
            field: ConfigField::$variant,
            keys: &[$($key),+],
            #[cfg(test)]
            documented_keys: &[$($documented_key),*],
            #[cfg(test)]
            cli_flags: &[$($cli_flag),*],
            trim: $trim,
            cli_source: $cli_source,
            parse: $parse,
            overlay: $overlay,
            apply: $apply,
        }
    };
    (
        variant: $variant:ident,
        field: $field:ident,
        keys: [$($key:literal),+ $(,)?],
        documented_keys: [$($documented_key:literal),* $(,)?],
        cli_flags: [$($cli_flag:literal),* $(,)?],
        trim: $trim:expr,
        scalar {
            cli_field: $cli_field:ident,
            parse: $parse:expr $(,)?
        } $(,)?
    ) => {
        config_option_descriptor! {
            @base
            variant: $variant,
            field: $field,
            keys: [$($key),+],
            documented_keys: [$($documented_key),*],
            cli_flags: [$($cli_flag),*],
            trim: $trim,
            cli_source: |cli| cli.$cli_field.is_some(),
            parse: |path, line_num, config, key, value| {
                let parsed: Result<_, String> =
                    ($parse)(path, line_num, &mut *config, key, value);
                config.$field = Some(parsed?);
                Ok(())
            },
            overlay: |target, higher| choose(&mut target.$field, &higher.$field),
            apply: |cli, values, _sources| {
                if cli.$cli_field.is_none() {
                    cli.$cli_field = values.$field.clone();
                }
            },
        }
    };
    (
        variant: $variant:ident,
        field: $field:ident,
        keys: [$($key:literal),+ $(,)?],
        documented_keys: [$($documented_key:literal),* $(,)?],
        cli_flags: [$($cli_flag:literal),* $(,)?],
        trim: $trim:expr,
        scalar {
            cli_field: $cli_field:ident,
            cli_source: $cli_source:expr,
            apply: source,
            parse: $parse:expr $(,)?
        } $(,)?
    ) => {
        config_option_descriptor! {
            @base
            variant: $variant,
            field: $field,
            keys: [$($key),+],
            documented_keys: [$($documented_key),*],
            cli_flags: [$($cli_flag),*],
            trim: $trim,
            cli_source: $cli_source,
            parse: |path, line_num, config, key, value| {
                let parsed: Result<_, String> =
                    ($parse)(path, line_num, &mut *config, key, value);
                config.$field = Some(parsed?);
                Ok(())
            },
            overlay: |target, higher| choose(&mut target.$field, &higher.$field),
            apply: |cli, values, sources| {
                if !sources.contains(ConfigField::$variant) {
                    cli.$cli_field = values.$field.clone();
                }
            },
        }
    };
    (
        variant: $variant:ident,
        field: $field:ident,
        keys: [$($key:literal),+ $(,)?],
        documented_keys: [$($documented_key:literal),* $(,)?],
        cli_flags: [$($cli_flag:literal),* $(,)?],
        trim: $trim:expr,
        scalar {
            cli_field: $cli_field:ident,
            cli_source: $cli_source:expr,
            apply_if: $apply_if:expr,
            parse: $parse:expr $(,)?
        } $(,)?
    ) => {
        config_option_descriptor! {
            @base
            variant: $variant,
            field: $field,
            keys: [$($key),+],
            documented_keys: [$($documented_key),*],
            cli_flags: [$($cli_flag),*],
            trim: $trim,
            cli_source: $cli_source,
            parse: |path, line_num, config, key, value| {
                let parsed: Result<_, String> =
                    ($parse)(path, line_num, &mut *config, key, value);
                config.$field = Some(parsed?);
                Ok(())
            },
            overlay: |target, higher| choose(&mut target.$field, &higher.$field),
            apply: |cli, values, sources| {
                if ($apply_if)(cli, sources) {
                    cli.$cli_field = values.$field.clone();
                }
            },
        }
    };
    (
        variant: $variant:ident,
        field: $field:ident,
        keys: [$($key:literal),+ $(,)?],
        documented_keys: [$($documented_key:literal),* $(,)?],
        cli_flags: [$($cli_flag:literal),* $(,)?],
        trim: $trim:expr,
        boolean {
            cli_field: $cli_field:ident $(,)?
        } $(,)?
    ) => {
        config_option_descriptor! {
            @base
            variant: $variant,
            field: $field,
            keys: [$($key),+],
            documented_keys: [$($documented_key),*],
            cli_flags: [$($cli_flag),*],
            trim: $trim,
            cli_source: |cli| cli.$cli_field,
            parse: |path, line_num, config, key, value| {
                config.$field = Some(parse_bool_value(path, line_num, key, value)?);
                Ok(())
            },
            overlay: |target, higher| choose(&mut target.$field, &higher.$field),
            apply: |cli, values, sources| {
                if !sources.contains(ConfigField::$variant) {
                    cli.$cli_field = values.$field.unwrap_or(false);
                }
            },
        }
    };
    (
        variant: $variant:ident,
        field: $field:ident,
        keys: [$($key:literal),+ $(,)?],
        documented_keys: [$($documented_key:literal),* $(,)?],
        cli_flags: [$($cli_flag:literal),* $(,)?],
        trim: $trim:expr,
        vec_prepend {
            cli_field: $cli_field:ident,
            parse: $parse:expr $(,)?
        } $(,)?
    ) => {
        config_option_descriptor! {
            @base
            variant: $variant,
            field: $field,
            keys: [$($key),+],
            documented_keys: [$($documented_key),*],
            cli_flags: [$($cli_flag),*],
            trim: $trim,
            cli_source: |cli| !cli.$cli_field.is_empty(),
            parse: |path, line_num, config, key, value| {
                let parsed: Result<_, String> = ($parse)(path, line_num, key, value);
                config.$field.push(parsed?);
                Ok(())
            },
            overlay: |target, higher| target.$field.extend(higher.$field.iter().cloned()),
            apply: |cli, values, _sources| prepend_vec(&mut cli.$cli_field, values.$field.clone()),
        }
    };
    (
        variant: $variant:ident,
        field: $field:ident,
        keys: [$($key:literal),+ $(,)?],
        documented_keys: [$($documented_key:literal),* $(,)?],
        cli_flags: [$($cli_flag:literal),* $(,)?],
        trim: $trim:expr,
        alias_mapping {
            cli_field: $cli_field:ident,
            cli_source: $cli_source:expr,
            primary: $primary_key:literal,
            choices: $choices:expr,
            aliases: {
                $($alias_key:literal => $alias_mapper:expr),+ $(,)?
            } $(,)?
        } $(,)?
    ) => {
        config_option_descriptor! {
            @base
            variant: $variant,
            field: $field,
            keys: [$($key),+],
            documented_keys: [$($documented_key),*],
            cli_flags: [$($cli_flag),*],
            trim: $trim,
            cli_source: $cli_source,
            parse: |path, line_num, config, key, value| {
                match key {
                    $primary_key => {
                        validate_choice(path, line_num, $primary_key, value, $choices)?;
                        config.$field = Some(value.to_string());
                    }
                    $(
                        $alias_key => {
                            let enabled = parse_bool_value(path, line_num, $alias_key, value)?;
                            config.$field = Some(($alias_mapper)(enabled).to_string());
                        }
                    )+
                    _ => unreachable!("config key was matched before parsing"),
                }
                Ok(())
            },
            overlay: |target, higher| choose(&mut target.$field, &higher.$field),
            apply: |cli, values, sources| {
                if !sources.contains(ConfigField::$variant) {
                    cli.$cli_field = values.$field.clone();
                }
            },
        }
    };
    (
        variant: $variant:ident,
        field: $field:ident,
        keys: [$($key:literal),+ $(,)?],
        documented_keys: [$($documented_key:literal),* $(,)?],
        cli_flags: [$($cli_flag:literal),* $(,)?],
        trim: $trim:expr,
        cli_source: $cli_source:expr,
        parse: $parse:expr,
        overlay: $overlay:expr,
        apply: $apply:expr $(,)?
    ) => {
        config_option_descriptor! {
            @base
            variant: $variant,
            field: $field,
            keys: [$($key),+],
            documented_keys: [$($documented_key),*],
            cli_flags: [$($cli_flag),*],
            trim: $trim,
            cli_source: $cli_source,
            parse: $parse,
            overlay: $overlay,
            apply: $apply,
        }
    };
}

macro_rules! config_options {
    (
        $(
            $variant:ident {
                field: $field:ident,
                ty: $ty:ty,
                keys: [$($key:literal),+ $(,)?],
                documented_keys: [$($documented_key:literal),* $(,)?],
                cli_flags: [$($cli_flag:literal),* $(,)?],
                trim: $trim:expr,
                $($descriptor:tt)*
            }
        ),+ $(,)?
    ) => {
        #[derive(Clone, Debug, Default, PartialEq)]
        struct ConfigValues {
            $(
                $field: $ty,
            )+
        }

        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        enum ConfigField {
            $(
                $variant,
            )+
        }

        static CONFIG_OPTIONS: &[ConfigOption] = &[
            $(
                config_option_descriptor! {
                    variant: $variant,
                    field: $field,
                    keys: [$($key),+],
                    documented_keys: [$($documented_key),*],
                    cli_flags: [$($cli_flag),*],
                    trim: $trim,
                    $($descriptor)*
                },
            )+
        ];
    };
}

config_options! {
    AutoUpdate {
        field: auto_update,
        ty: Option<String>,
        keys: ["auto-update"],
        documented_keys: ["auto-update"],
        cli_flags: ["auto-update"],
        trim: ConfigValueTrim::Both,
        scalar {
            cli_field: auto_update,
            parse: |path, line_num, _config, _key, value| {
                validate_auto_update(path, line_num, value)
            },
        },
    },
    CaCert {
        field: ca_cert,
        ty: Vec<String>,
        keys: ["ca-cert"],
        documented_keys: ["ca-cert"],
        cli_flags: ["ca-cert"],
        trim: ConfigValueTrim::Both,
        vec_prepend {
            cli_field: ca_cert,
            parse: |path, line_num, _key, value| {
                validate_file_option(path, line_num, || {
                    crate::tls::validate_ca_certificate_file(value)
                })?;
                Ok(value.to_string())
            },
        },
    },
    Cert {
        field: cert,
        ty: Option<String>,
        keys: ["cert"],
        documented_keys: ["cert"],
        cli_flags: ["cert"],
        trim: ConfigValueTrim::Both,
        scalar {
            cli_field: cert,
            parse: |path, line_num, _config, _key, value| {
                validate_file_option(path, line_num, || {
                    crate::tls::validate_client_certificate_file(value)
                })?;
                Ok(value.to_string())
            },
        },
    },
    Color {
        field: color,
        ty: Option<String>,
        keys: ["color", "colour"],
        documented_keys: ["color", "colour"],
        cli_flags: ["color", "colour"],
        trim: ConfigValueTrim::Both,
        scalar {
            cli_field: color,
            parse: |path, line_num, _config, _key, value| {
                validate_choice(path, line_num, "color", value, &["auto", "off", "on"])?;
                Ok(value.to_string())
            },
        },
    },
    Compress {
        field: compress,
        ty: Option<String>,
        keys: ["compress", "no-encode"],
        documented_keys: ["compress"],
        cli_flags: ["compress", "no-encode"],
        trim: ConfigValueTrim::Both,
        alias_mapping {
            cli_field: compress,
            cli_source: |cli| cli.compress.is_some() || cli.no_encode,
            primary: "compress",
            choices: crate::cli::CompressionMode::VALUES,
            aliases: {
                "no-encode" => |no_encode| if no_encode { "off" } else { "auto" },
            },
        },
    },
    ConnectTimeout {
        field: connect_timeout,
        ty: Option<f64>,
        keys: ["connect-timeout"],
        documented_keys: ["connect-timeout"],
        cli_flags: ["connect-timeout"],
        trim: ConfigValueTrim::Both,
        scalar {
            cli_field: connect_timeout,
            parse: |path, line_num, _config, _key, value| {
                parse_duration_seconds(
                    path,
                    line_num,
                    "connect-timeout",
                    value,
                    "must be a non-negative number",
                )
            },
        },
    },
    Copy {
        field: copy,
        ty: Option<bool>,
        keys: ["copy"],
        documented_keys: ["copy"],
        cli_flags: ["copy"],
        trim: ConfigValueTrim::Both,
        boolean {
            cli_field: copy,
        },
    },
    DnsServer {
        field: dns_server,
        ty: Option<String>,
        keys: ["dns-server"],
        documented_keys: ["dns-server"],
        cli_flags: ["dns-server"],
        trim: ConfigValueTrim::Both,
        scalar {
            cli_field: dns_server,
            parse: |path, line_num, _config, _key, value| {
                validate_dns_server(path, line_num, value)?;
                Ok(value.to_string())
            },
        },
    },
    Ech {
        field: ech,
        ty: Option<String>,
        keys: ["ech"],
        documented_keys: ["ech"],
        cli_flags: ["ech"],
        trim: ConfigValueTrim::Both,
        scalar {
            cli_field: ech,
            parse: |path, line_num, _config, _key, value| {
                validate_choice(path, line_num, "ech", value, &["auto", "on", "off"])?;
                Ok(value.to_string())
            },
        },
    },
    Format {
        field: format,
        ty: Option<String>,
        keys: ["format"],
        documented_keys: ["format"],
        cli_flags: ["format"],
        trim: ConfigValueTrim::Both,
        scalar {
            cli_field: format,
            parse: |path, line_num, _config, _key, value| {
                validate_choice(path, line_num, "format", value, &["auto", "off", "on"])?;
                Ok(value.to_string())
            },
        },
    },
    Headers {
        field: headers,
        ty: Vec<String>,
        keys: ["header"],
        documented_keys: ["header"],
        cli_flags: ["header"],
        trim: ConfigValueTrim::Both,
        vec_prepend {
            cli_field: headers,
            parse: |path, line_num, _key, value| parse_header(path, line_num, value),
        },
    },
    Http {
        field: http,
        ty: Option<String>,
        keys: ["http"],
        documented_keys: ["http"],
        cli_flags: ["http"],
        trim: ConfigValueTrim::Both,
        scalar {
            cli_field: http,
            cli_source: |cli| crate::cli::has_http_version_flag(cli),
            apply_if: |cli, _sources| !crate::cli::has_http_version_flag(cli),
            parse: |path, line_num, _config, _key, value| {
                validate_choice(path, line_num, "http", value, &["1", "2", "3"])?;
                Ok(value.to_string())
            },
        },
    },
    IgnoreStatus {
        field: ignore_status,
        ty: Option<bool>,
        keys: ["ignore-status"],
        documented_keys: ["ignore-status"],
        cli_flags: ["ignore-status"],
        trim: ConfigValueTrim::Both,
        boolean {
            cli_field: ignore_status,
        },
    },
    Image {
        field: image,
        ty: Option<String>,
        keys: ["image"],
        documented_keys: ["image"],
        cli_flags: ["image"],
        trim: ConfigValueTrim::Both,
        scalar {
            cli_field: image,
            parse: |path, line_num, _config, _key, value| {
                validate_choice(path, line_num, "image", value, &["auto", "external", "off"])?;
                Ok(value.to_string())
            },
        },
    },
    Insecure {
        field: insecure,
        ty: Option<bool>,
        keys: ["insecure"],
        documented_keys: ["insecure"],
        cli_flags: ["insecure"],
        trim: ConfigValueTrim::Both,
        boolean {
            cli_field: insecure,
        },
    },
    Key {
        field: key,
        ty: Option<String>,
        keys: ["key"],
        documented_keys: ["key"],
        cli_flags: ["key"],
        trim: ConfigValueTrim::Both,
        scalar {
            cli_field: key,
            parse: |path, line_num, _config, _key, value| {
                validate_file_option(path, line_num, || {
                    crate::tls::validate_client_key_file(value)
                })?;
                Ok(value.to_string())
            },
        },
    },
    MaxTls {
        field: max_tls,
        ty: Option<String>,
        keys: ["max-tls"],
        documented_keys: ["max-tls"],
        cli_flags: ["max-tls"],
        trim: ConfigValueTrim::Both,
        scalar {
            cli_field: max_tls,
            parse: |path, line_num, config: &mut ConfigValues, _key, value| {
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
                Ok(value.to_string())
            },
        },
    },
    MinTls {
        field: min_tls,
        ty: Option<String>,
        keys: ["min-tls", "tls"],
        documented_keys: ["min-tls", "tls"],
        cli_flags: ["min-tls", "tls"],
        trim: ConfigValueTrim::Both,
        scalar {
            cli_field: min_tls,
            cli_source: |cli| cli.min_tls.is_some() || cli.tls.is_some(),
            apply: source,
            parse: |path, line_num, config: &mut ConfigValues, key, value| {
                validate_tls_value(path, line_num, key, value)?;
                if let Some(max_tls) = config.max_tls.as_deref()
                    && tls_order(value) > tls_order(max_tls)
                {
                    return Err(value_error(
                        path,
                        line_num,
                        key,
                        value,
                        "must be less than or equal to max-tls",
                    ));
                }
                Ok(value.to_string())
            },
        },
    },
    Pager {
        field: pager,
        ty: Option<String>,
        keys: ["pager", "no-pager"],
        documented_keys: ["pager"],
        cli_flags: ["pager"],
        trim: ConfigValueTrim::Both,
        alias_mapping {
            cli_field: pager,
            cli_source: |cli| cli.pager.is_some(),
            primary: "pager",
            choices: crate::cli::PagerMode::VALUES,
            aliases: {
                "no-pager" => |no_pager| if no_pager { "off" } else { "auto" },
            },
        },
    },
    Proxy {
        field: proxy,
        ty: Option<String>,
        keys: ["proxy"],
        documented_keys: ["proxy"],
        cli_flags: ["proxy"],
        trim: ConfigValueTrim::Both,
        scalar {
            cli_field: proxy,
            parse: |path, line_num, _config, _key, value| {
                validate_proxy(path, line_num, value)?;
                Ok(value.to_string())
            },
        },
    },
    Query {
        field: query,
        ty: Vec<String>,
        keys: ["query"],
        documented_keys: ["query"],
        cli_flags: ["query"],
        trim: ConfigValueTrim::Left,
        vec_prepend {
            cli_field: query,
            parse: |_path, _line_num, _key, value| Ok::<_, String>(parse_query(value)),
        },
    },
    Redirects {
        field: redirects,
        ty: Option<usize>,
        keys: ["redirects"],
        documented_keys: ["redirects"],
        cli_flags: ["redirects"],
        trim: ConfigValueTrim::Both,
        scalar {
            cli_field: redirects,
            parse: |path, line_num, _config, _key, value| {
                parse_nonnegative_usize(path, line_num, "redirects", value)
            },
        },
    },
    Retry {
        field: retry,
        ty: Option<usize>,
        keys: ["retry"],
        documented_keys: ["retry"],
        cli_flags: ["retry"],
        trim: ConfigValueTrim::Both,
        scalar {
            cli_field: retry,
            parse: |path, line_num, _config, _key, value| {
                parse_nonnegative_usize(path, line_num, "retry", value)
            },
        },
    },
    RetryDelay {
        field: retry_delay,
        ty: Option<f64>,
        keys: ["retry-delay"],
        documented_keys: ["retry-delay"],
        cli_flags: ["retry-delay"],
        trim: ConfigValueTrim::Both,
        scalar {
            cli_field: retry_delay,
            parse: |path, line_num, _config, _key, value| {
                parse_duration_seconds(
                    path,
                    line_num,
                    "retry-delay",
                    value,
                    "must be a non-negative number",
                )
            },
        },
    },
    Session {
        field: session,
        ty: Option<String>,
        keys: ["session"],
        documented_keys: ["session"],
        cli_flags: ["session"],
        trim: ConfigValueTrim::Both,
        scalar {
            cli_field: session,
            parse: |path, line_num, _config, _key, value| {
                if !crate::session::is_valid_name(value) {
                    return Err(value_error(
                        path,
                        line_num,
                        "session",
                        value,
                        "must contain only alphanumeric characters, hyphens, and underscores",
                    ));
                }
                Ok(value.to_string())
            },
        },
    },
    Silent {
        field: silent,
        ty: Option<bool>,
        keys: ["silent"],
        documented_keys: ["silent"],
        cli_flags: ["silent"],
        trim: ConfigValueTrim::Both,
        boolean {
            cli_field: silent,
        },
    },
    SortHeaders {
        field: sort_headers,
        ty: Option<bool>,
        keys: ["sort-headers"],
        documented_keys: ["sort-headers"],
        cli_flags: ["sort-headers"],
        trim: ConfigValueTrim::Both,
        boolean {
            cli_field: sort_headers,
        },
    },
    Timeout {
        field: timeout,
        ty: Option<f64>,
        keys: ["timeout"],
        documented_keys: ["timeout"],
        cli_flags: ["timeout"],
        trim: ConfigValueTrim::Both,
        scalar {
            cli_field: timeout,
            parse: |path, line_num, _config, _key, value| {
                parse_duration_seconds(
                    path,
                    line_num,
                    "timeout",
                    value,
                    "must be a non-negative number",
                )
            },
        },
    },
    Timing {
        field: timing,
        ty: Option<bool>,
        keys: ["timing"],
        documented_keys: ["timing"],
        cli_flags: ["timing"],
        trim: ConfigValueTrim::Both,
        boolean {
            cli_field: timing,
        },
    },
    Verbosity {
        field: verbosity,
        ty: Option<u8>,
        keys: ["verbosity"],
        documented_keys: ["verbosity"],
        cli_flags: ["verbose"],
        trim: ConfigValueTrim::Both,
        cli_source: |cli| cli.verbose > 0,
        parse: |path, line_num, config, _key, value| {
            let value = parse_nonnegative_u64(
                path,
                line_num,
                "verbosity",
                value,
                "must be a valid integer",
            )?;
            config.verbosity = Some(u8::try_from(value).unwrap_or(u8::MAX));
            Ok(())
        },
        overlay: |target, higher| choose(&mut target.verbosity, &higher.verbosity),
        apply: |cli, values, sources| {
            if !sources.contains(ConfigField::Verbosity) {
                cli.verbose = values.verbosity.unwrap_or(0);
            }
        },
    },
}

#[derive(Debug, Default, PartialEq)]
struct ConfigFile {
    global: ConfigValues,
    hosts: HashMap<String, ConfigValues>,
    path: PathBuf,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CliConfigSources {
    bits: u128,
}

impl CliConfigSources {
    fn capture(cli: &Cli) -> Self {
        let mut sources = Self::default();
        for option in CONFIG_OPTIONS {
            if (option.cli_source)(cli) {
                sources.insert(option.field);
            }
        }
        sources
    }

    fn contains(self, field: ConfigField) -> bool {
        self.bits & Self::bit(field) != 0
    }

    fn insert(&mut self, field: ConfigField) {
        self.bits |= Self::bit(field);
    }

    fn bit(field: ConfigField) -> u128 {
        1u128
            .checked_shl(field as u32)
            .expect("too many config fields for source tracking")
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
    if let Some(value) = cli.ech.as_deref() {
        validate_cli_choice("ech", value, &["auto", "on", "off"])?;
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
        let path = absolute_path(crate::fileutil::expand_home(path))?;
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

    for option in CONFIG_OPTIONS {
        (option.apply)(cli, &values, &sources);
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
    let mut host_lines = HashMap::new();
    let mut current_host: Option<String> = None;

    for (line_num, raw_line) in numbered_lines(contents) {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            let host = line[1..line.len() - 1].trim().to_ascii_lowercase();
            validate_host_section(path, line_num, &host)?;
            if let Some(first_line) = host_lines.get(&host) {
                return Err(file_error(
                    path,
                    line_num,
                    &format!(
                        "duplicate host section '[{host}]' (first defined on line {first_line})"
                    ),
                ));
            }
            host_lines.insert(host.clone(), line_num);
            current_host = Some(host.clone());
            file.hosts.insert(host, ConfigValues::default());
            continue;
        }

        let Some((key, value)) = raw_line.trim_start().split_once('=') else {
            return Err(file_error(
                path,
                line_num,
                &format!("invalid key/value pair '{line}'"),
            ));
        };
        let key = key.trim();
        let option = config_option_for_key(key)
            .ok_or_else(|| file_error(path, line_num, &format!("invalid option: '{key}'")))?;
        let value = option.trim.apply(value);
        let target = match current_host.as_deref() {
            Some(host) => file
                .hosts
                .get_mut(host)
                .expect("host section inserted before values"),
            None => &mut file.global,
        };
        (option.parse)(path, line_num, target, key, value)?;
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

fn config_option_for_key(key: &str) -> Option<&'static ConfigOption> {
    CONFIG_OPTIONS
        .iter()
        .find(|option| option.keys.contains(&key))
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
    if !seconds.is_finite() || !(0.0..=crate::duration::MAX_DURATION_SECONDS).contains(&seconds) {
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
    format!("{}={}", key.trim(), val)
}

fn validate_dns_server(path: &Path, line_num: usize, value: &str) -> Result<(), String> {
    crate::dns::custom::parse_dns_server(value)
        .map_err(|err| value_error(path, line_num, "dns-server", value, &err.to_string()))?;
    Ok(())
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
        for option in CONFIG_OPTIONS {
            (option.overlay)(self, higher);
        }
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

    let host = raw.split(['/', '?', '#']).next().unwrap_or(raw);
    let host = host.split('@').next_back().unwrap_or(host);
    if let Some(rest) = host.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        if !rest.is_empty() && !rest.starts_with(':') {
            return None;
        }
        return if host.is_empty() {
            None
        } else {
            Some(host.to_string())
        };
    }

    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn tls_order(value: &str) -> Option<u8> {
    match value {
        "1.2" => Some(12),
        "1.3" => Some(13),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};
    use std::collections::BTreeSet;
    use std::io::Write;

    #[test]
    fn config_option_descriptors_have_unique_keys_and_fields() {
        assert!(
            CONFIG_OPTIONS.len() <= u128::BITS as usize,
            "CliConfigSources bitset cannot track every config field"
        );

        let mut fields = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for option in CONFIG_OPTIONS {
            assert!(
                fields.insert(option.field),
                "duplicate config field descriptor: {:?}",
                option.field
            );
            for key in option.keys {
                assert!(keys.insert(*key), "duplicate config key: {key}");
                assert!(
                    config_option_for_key(key).is_some(),
                    "config key is not discoverable: {key}"
                );
            }
            for key in option.documented_keys {
                assert!(
                    option.keys.contains(key),
                    "documented key is not accepted by parser: {key}"
                );
            }
        }
    }

    #[test]
    fn config_option_descriptors_match_configuration_docs() {
        let expected: BTreeSet<String> = CONFIG_OPTIONS
            .iter()
            .flat_map(|option| option.documented_keys.iter().copied())
            .map(str::to_string)
            .collect();
        let actual = documented_config_option_keys();

        assert_eq!(actual, expected);
    }

    #[test]
    fn config_option_descriptors_reference_real_cli_flags() {
        let mut cli_flags = BTreeSet::new();
        for arg in Cli::command().get_arguments() {
            if let Some(long) = arg.get_long() {
                cli_flags.insert(long.to_string());
            }
            if let Some(aliases) = arg.get_all_aliases() {
                cli_flags.extend(aliases.into_iter().map(str::to_string));
            }
        }

        for option in CONFIG_OPTIONS {
            for flag in option.cli_flags {
                assert!(
                    cli_flags.contains(*flag),
                    "config descriptor references missing CLI flag --{flag}"
                );
            }
        }
    }

    fn documented_config_option_keys() -> BTreeSet<String> {
        let mut keys = BTreeSet::new();
        for line in include_str!("../../docs/configuration.md").lines() {
            let Some(mut rest) = line.strip_prefix("#### ") else {
                continue;
            };
            while let Some(start) = rest.find('`') {
                let after_start = &rest[start + 1..];
                let end = after_start
                    .find('`')
                    .expect("configuration option heading must close backtick");
                keys.insert(after_start[..end].to_string());
                rest = &after_start[end + 1..];
            }
        }
        keys
    }

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
    fn parse_query_preserves_value_spaces_after_equals() {
        assert_eq!(parse_query(" q = hello "), "q= hello ");
    }

    #[test]
    fn parse_file_preserves_query_value_trailing_space_after_equals() {
        let path = PathBuf::from("test/config");
        let file = parse_file(&path, "query = q= hello \n").unwrap();

        assert_eq!(file.global.query, vec!["q= hello "]);
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
    fn parse_file_rejects_legacy_tls_versions() {
        let path = PathBuf::from("test/config");
        let err = parse_file(&path, "min-tls = 1.0\n").unwrap_err();

        assert!(err.contains("line 1"));
        assert!(err.contains("invalid value '1.0' for option 'min-tls'"));
        assert!(err.contains("must be one of [1.2, 1.3]"));

        let err = parse_file(&path, "max-tls = 1.1\n").unwrap_err();

        assert!(err.contains("line 1"));
        assert!(err.contains("invalid value '1.1' for option 'max-tls'"));
        assert!(err.contains("must be one of [1.2, 1.3]"));
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
    fn parse_file_rejects_duplicate_host_sections() {
        let path = PathBuf::from("test/config");
        let err = parse_file(
            &path,
            "[Api.Example.com]
             header = X-Old: yes

             [api.example.com]
             header = X-New: yes
            ",
        )
        .unwrap_err();

        assert!(err.contains("line 4"), "{err}");
        assert!(
            err.contains("duplicate host section '[api.example.com]'"),
            "{err}"
        );
        assert!(err.contains("first defined on line 1"), "{err}");
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

        let cli =
            Cli::try_parse_from(["fetch", "--min-tls", "1.0", "https://example.com"]).unwrap();
        let err = validate(&cli).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid value '1.0' for option '--min-tls': must be one of [1.2, 1.3]"
        );

        let cli =
            Cli::try_parse_from(["fetch", "--max-tls", "1.1", "https://example.com"]).unwrap();
        let err = validate(&cli).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid value '1.1' for option '--max-tls': must be one of [1.2, 1.3]"
        );
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
              http = 1
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
            "--http2",
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
        assert_eq!(
            crate::cli::selected_http_version(&cli).unwrap(),
            Some(crate::cli::HttpVersion::Http2)
        );
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
    fn apply_file_matches_bare_bracketed_ipv6_url_to_host_section() {
        let path = PathBuf::from("test/config");
        let file = parse_file(
            &path,
            "
              [::1]
              color = on
            ",
        )
        .unwrap();
        let mut cli = Cli::try_parse_from(["fetch", "[::1]:3000/path"]).unwrap();

        let sources = CliConfigSources::capture(&cli);
        apply_file(&mut cli, &file, sources);

        assert_eq!(cli.color.as_deref(), Some("on"));
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

    fn write_temp_config_pem(contents: &[u8]) -> (tempfile::NamedTempFile, String) {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(contents).unwrap();
        let path = file.path().to_string_lossy().into_owned();
        (file, path)
    }
}
