use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{MAIN_SEPARATOR, Path};

#[derive(Clone, Debug, Eq, PartialEq)]
struct Completion {
    key: String,
    value: String,
}

#[derive(Clone, Copy)]
struct FlagValue {
    key: &'static str,
    value: &'static str,
}

#[derive(Clone, Copy)]
struct Flag {
    short: Option<char>,
    long: &'static str,
    args: &'static str,
    description: &'static str,
    aliases: &'static [&'static str],
    values: &'static [FlagValue],
}

const EMPTY_VALUES: &[FlagValue] = &[];
const COLOR_VALUES: &[FlagValue] = &[
    FlagValue {
        key: "auto",
        value: "Automatically determine color",
    },
    FlagValue {
        key: "off",
        value: "Disable color output",
    },
    FlagValue {
        key: "on",
        value: "Enable color output",
    },
];
const COMPLETE_VALUES: &[FlagValue] = &[
    FlagValue {
        key: "bash",
        value: "",
    },
    FlagValue {
        key: "fish",
        value: "",
    },
    FlagValue {
        key: "zsh",
        value: "",
    },
];
const COMPRESS_VALUES: &[FlagValue] = &[
    FlagValue {
        key: "auto",
        value: "Request gzip or zstd",
    },
    FlagValue {
        key: "gzip",
        value: "Request gzip compression",
    },
    FlagValue {
        key: "zstd",
        value: "Request zstd compression",
    },
    FlagValue {
        key: "off",
        value: "Disable compression negotiation",
    },
];
const FORMAT_VALUES: &[FlagValue] = &[
    FlagValue {
        key: "auto",
        value: "Automatically determine whether to format",
    },
    FlagValue {
        key: "off",
        value: "Disable output formatting",
    },
    FlagValue {
        key: "on",
        value: "Enable output formatting",
    },
];
const PAGER_VALUES: &[FlagValue] = &[
    FlagValue {
        key: "auto",
        value: "Use pager when stdout is a terminal",
    },
    FlagValue {
        key: "on",
        value: "Force pager use",
    },
    FlagValue {
        key: "off",
        value: "Disable pager",
    },
];
const HTTP_VALUES: &[FlagValue] = &[
    FlagValue {
        key: "1",
        value: "HTTP/1.1",
    },
    FlagValue {
        key: "2",
        value: "HTTP/2.0",
    },
    FlagValue {
        key: "3",
        value: "HTTP/3.0",
    },
];
const IMAGE_VALUES: &[FlagValue] = &[
    FlagValue {
        key: "auto",
        value: "Automatically decide image display",
    },
    FlagValue {
        key: "external",
        value: "Allow external image decoders",
    },
    FlagValue {
        key: "off",
        value: "Disable image display",
    },
];
const TLS_VALUES: &[FlagValue] = &[
    FlagValue {
        key: "1.2",
        value: "TLS v1.2",
    },
    FlagValue {
        key: "1.3",
        value: "TLS v1.3",
    },
];
const WS_INTERACTIVE_VALUES: &[FlagValue] = &[
    FlagValue {
        key: "auto",
        value: "Use interactive prompt when attached to a terminal",
    },
    FlagValue {
        key: "on",
        value: "Require interactive prompt",
    },
    FlagValue {
        key: "off",
        value: "Disable interactive prompt",
    },
];

const FLAGS: &[Flag] = &[
    flag(
        None,
        "aws-sigv4",
        "REGION/SERVICE",
        "Sign the request using AWS signature V4",
    ),
    flag(
        None,
        "basic",
        "USER:PASS",
        "Enable HTTP basic authentication",
    ),
    flag(None, "bearer", "TOKEN", "Enable HTTP bearer authentication"),
    flag(None, "buildinfo", "", "Print the build information"),
    flag(None, "ca-cert", "PATH", "CA certificate file path"),
    flag(None, "cert", "PATH", "Client certificate for mTLS"),
    flag(None, "clobber", "", "Overwrite existing output file"),
    Flag {
        short: None,
        long: "color",
        args: "OPTION",
        description: "Enable/disable color",
        aliases: &["colour"],
        values: COLOR_VALUES,
    },
    Flag {
        short: None,
        long: "complete",
        args: "SHELL",
        description: "Output shell completion",
        aliases: &[],
        values: COMPLETE_VALUES,
    },
    Flag {
        short: None,
        long: "compress",
        args: "MODE",
        description: "Control compression negotiation",
        aliases: &[],
        values: COMPRESS_VALUES,
    },
    flag(Some('c'), "config", "PATH", "Path to config file"),
    flag(
        None,
        "connect-timeout",
        "SECONDS",
        "Timeout for connection establishment",
    ),
    flag(None, "copy", "", "Copy the response body to clipboard"),
    flag(Some('d'), "data", "[@]VALUE", "Send a request body"),
    flag(
        None,
        "digest",
        "USER:PASS",
        "Enable HTTP digest authentication",
    ),
    flag(None, "discard", "", "Discard the response body"),
    flag(
        None,
        "dns-server",
        "IP[:PORT]|URL",
        "DNS server IP or DoH URL",
    ),
    flag(None, "dry-run", "", "Print out the request info and exit"),
    flag(
        Some('e'),
        "edit",
        "",
        "Use an editor to modify the request body",
    ),
    flag(
        Some('f'),
        "form",
        "KEY=VALUE",
        "Send a urlencoded form body",
    ),
    Flag {
        short: None,
        long: "format",
        args: "OPTION",
        description: "Enable/disable formatting",
        aliases: &[],
        values: FORMAT_VALUES,
    },
    flag(
        None,
        "from-curl",
        "COMMAND",
        "Execute a curl command using fetch",
    ),
    flag(None, "grpc", "", "Enable gRPC mode"),
    flag(
        None,
        "grpc-describe",
        "NAME",
        "Describe a gRPC service, method, or message",
    ),
    flag(None, "grpc-list", "", "List available gRPC services"),
    flag(
        Some('H'),
        "header",
        "NAME:VALUE",
        "Set headers for the request",
    ),
    flag(Some('h'), "help", "", "Print help"),
    Flag {
        short: None,
        long: "http",
        args: "VERSION",
        description: "HTTP version to use",
        aliases: &[],
        values: HTTP_VALUES,
    },
    flag(
        None,
        "ignore-status",
        "",
        "Exit code unaffected by HTTP status",
    ),
    Flag {
        short: None,
        long: "image",
        args: "OPTION",
        description: "Image rendering",
        aliases: &[],
        values: IMAGE_VALUES,
    },
    flag(None, "insecure", "", "Accept invalid TLS certs (!)"),
    flag(None, "inspect-dns", "", "Inspect DNS resolution"),
    flag(None, "inspect-tls", "", "Inspect the TLS certificate chain"),
    flag(Some('j'), "json", "[@]VALUE", "Send a JSON request body"),
    flag(None, "key", "PATH", "Client private key for mTLS"),
    Flag {
        short: None,
        long: "max-tls",
        args: "VERSION",
        description: "Maximum TLS version",
        aliases: &[],
        values: TLS_VALUES,
    },
    Flag {
        short: Some('m'),
        long: "method",
        args: "METHOD",
        description: "HTTP method to use",
        aliases: &["X"],
        values: EMPTY_VALUES,
    },
    Flag {
        short: None,
        long: "min-tls",
        args: "VERSION",
        description: "Minimum TLS version",
        aliases: &[],
        values: TLS_VALUES,
    },
    flag(
        Some('F'),
        "multipart",
        "NAME=[@]VALUE",
        "Send a multipart form body",
    ),
    Flag {
        short: None,
        long: "pager",
        args: "MODE",
        description: "Control pager use",
        aliases: &[],
        values: PAGER_VALUES,
    },
    flag(
        Some('o'),
        "output",
        "PATH",
        "Write the response body to a file",
    ),
    flag(
        None,
        "proto-desc",
        "PATH",
        "Pre-compiled descriptor set file",
    ),
    flag(
        None,
        "proto-file",
        "PATH",
        "Compile .proto file(s) via protoc",
    ),
    flag(
        None,
        "proto-import",
        "PATH",
        "Import path for proto compilation",
    ),
    flag(None, "proxy", "PROXY", "Configure a proxy"),
    flag(
        Some('q'),
        "query",
        "KEY=VALUE",
        "Append query parameters to the url",
    ),
    flag(Some('r'), "range", "RANGE", "Request a specific byte range"),
    flag(None, "redirects", "NUM", "Maximum number of redirects"),
    flag(
        Some('J'),
        "remote-header-name",
        "",
        "Use content-disposition header filename",
    ),
    Flag {
        short: Some('O'),
        long: "remote-name",
        args: "",
        description: "Use URL path component as output filename",
        aliases: &["output-current-dir"],
        values: EMPTY_VALUES,
    },
    flag(None, "retry", "NUM", "Maximum number of retries"),
    flag(
        None,
        "retry-delay",
        "SECONDS",
        "Initial delay between retries",
    ),
    flag(
        Some('S'),
        "session",
        "NAME",
        "Use a named session for cookies",
    ),
    flag(Some('s'), "silent", "", "Print only errors to stderr"),
    flag(None, "sort-headers", "", "Sort displayed headers by name"),
    flag(
        Some('t'),
        "timeout",
        "SECONDS",
        "Timeout applied to the request",
    ),
    flag(Some('T'), "timing", "", "Display a timing waterfall chart"),
    flag(None, "unix", "PATH", "Make the request over a unix socket"),
    flag(None, "update", "", "Update the fetch binary in place"),
    flag(Some('v'), "verbose", "", "Verbosity of the output"),
    flag(Some('V'), "version", "", "Print version"),
    Flag {
        short: None,
        long: "ws-interactive",
        args: "MODE",
        description: "WebSocket prompt mode",
        aliases: &[],
        values: WS_INTERACTIVE_VALUES,
    },
    flag(Some('x'), "xml", "[@]VALUE", "Send an XML request body"),
];

const fn flag(
    short: Option<char>,
    long: &'static str,
    args: &'static str,
    description: &'static str,
) -> Flag {
    Flag {
        short,
        long,
        args,
        description,
        aliases: &[],
        values: EMPTY_VALUES,
    }
}

#[derive(Clone, Copy)]
enum Shell {
    Bash,
    Fish,
    Zsh,
}

impl Shell {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "bash" => Some(Self::Bash),
            "fish" => Some(Self::Fish),
            "zsh" => Some(Self::Zsh),
            _ => None,
        }
    }

    fn register(self) -> &'static str {
        match self {
            Self::Bash => {
                r#"_fetch_complete() {
  local cur prev_tokens
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev_tokens=("${COMP_WORDS[@]:0:COMP_CWORD}")
  local IFS=$'\n'
  COMPREPLY=($(fetch --complete=bash -- "${prev_tokens[@]}" "$cur"))
  IFS=$' \t\n'
}
complete -o nosort -o nospace -F _fetch_complete fetch"#
            }
            Self::Fish => {
                r#"complete --keep-order --exclusive --command fetch --arguments "(fetch --complete=fish -- (commandline --current-process --tokens-expanded --cut-at-cursor) (commandline --cut-at-cursor --current-token))""#
            }
            Self::Zsh => {
                r#"# Completion function for the 'fetch' command
_fetch_complete() {
  # Array of tokens before the current word
  local -a prev_tokens
  local current_token
  prev_tokens=("${words[@]:0:$CURRENT-1}")
  current_token=${words[$CURRENT]}

  # Call fetch and split its output into an array of lines
  local -a completions=("${(@f)$(fetch --complete=zsh -- "${prev_tokens[@]}" "${current_token}")}")

  if [[ -n $completions ]]; then
    compadd -f -a completions
  fi
}

# Register the completion function for the 'fetch' command
compdef _fetch_complete fetch"#
            }
        }
    }

    fn complete(self, values: &[Completion]) -> String {
        match self {
            Self::Bash => complete_bash(values),
            Self::Fish => complete_fish(values),
            Self::Zsh => complete_zsh(values),
        }
    }
}

pub fn output(shell_name: &str, args: &[String]) -> Result<String, String> {
    let Some(shell) = Shell::from_name(shell_name) else {
        return Err(format!(
            "completions not supported for shell '{shell_name}'"
        ));
    };

    if args.is_empty() {
        return Ok(format!("{}\n", shell.register()));
    }

    Ok(shell.complete(&complete(args)))
}

fn complete(args: &[String]) -> Vec<Completion> {
    if args.len() <= 1 {
        return Vec::new();
    }
    let mut args = &args[1..];

    while let Some((arg, rest)) = args.split_first() {
        args = rest;

        if !arg.starts_with('-') {
            continue;
        }

        if args.is_empty() {
            if arg == "-" || arg == "--" {
                return all_flags();
            }

            if let Some(after) = arg.strip_prefix("--") {
                return complete_long_flag(after);
            }

            return complete_short_flag(&arg[1..]);
        }

        if let Some(after) = arg.strip_prefix("--") {
            let (name, has_value) = match after.split_once('=') {
                Some((name, _)) => (name, true),
                None => (after, false),
            };
            let Some(flag) = find_long(name) else {
                continue;
            };
            if flag.args.is_empty() || has_value {
                continue;
            }
            if args.len() == 1 {
                return complete_value(flag, "", &args[0]);
            }
            args = &args[1..];
            continue;
        }

        let values = &arg[1..];
        for (index, byte) in values.bytes().enumerate() {
            let name = byte as char;
            let Some(flag) = find_short(name) else {
                break;
            };
            if flag.args.is_empty() {
                continue;
            }
            if index != values.len() - 1 {
                break;
            }
            if args.len() == 1 {
                return complete_value(flag, "", &args[0]);
            }
            args = &args[1..];
            break;
        }
    }

    Vec::new()
}

fn complete_long_flag(value: &str) -> Vec<Completion> {
    if let Some((key, val)) = value.split_once('=') {
        let Some(flag) = find_long(key) else {
            return Vec::new();
        };
        let prefix = format!("--{key}=");
        return complete_value(flag, &prefix, val);
    }

    FLAGS
        .iter()
        .filter(|flag| flag.long.starts_with(value))
        .map(|flag| Completion {
            key: format!("--{}", flag.long),
            value: flag.description.to_string(),
        })
        .collect()
}

fn complete_short_flag(value: &str) -> Vec<Completion> {
    let mut used = HashSet::new();

    for (index, byte) in value.bytes().enumerate() {
        let name = byte as char;
        let Some(flag) = find_short(name) else {
            return Vec::new();
        };
        if !flag.args.is_empty() {
            let mut prefix = format!("-{}", &value[..index + 1]);
            let mut val = &value[index + 1..];
            if let Some(after) = val.strip_prefix('=') {
                prefix.push('=');
                val = after;
            }
            return complete_value(flag, &prefix, val);
        }
        used.insert(name);
    }

    FLAGS
        .iter()
        .filter_map(|flag| flag.short.map(|short| (short, flag)))
        .filter(|(short, _)| !used.contains(short))
        .map(|(short, flag)| Completion {
            key: format!("-{value}{short}"),
            value: flag.description.to_string(),
        })
        .collect()
}

fn complete_value(flag: &Flag, prefix: &str, value: &str) -> Vec<Completion> {
    if flag.args.is_empty() {
        return Vec::new();
    }

    if !flag.values.is_empty() {
        return flag
            .values
            .iter()
            .filter(|flag_value| flag_value.key.starts_with(value))
            .map(|flag_value| Completion {
                key: format!("{prefix}{}", flag_value.key),
                value: flag_value.value.to_string(),
            })
            .collect();
    }

    match flag.long {
        "ca-cert" | "cert" | "config" | "key" | "output" | "proto-desc" | "proto-file"
        | "proto-import" | "unix" => complete_path(prefix, value),
        "data" | "json" | "xml" => value
            .strip_prefix('@')
            .map(|path| complete_path(&format!("{prefix}@"), path))
            .unwrap_or_default(),
        "multipart" => {
            if let Some((key, val)) = value.split_once('=')
                && let Some(path) = val.strip_prefix('@')
            {
                return complete_path(&format!("{prefix}{key}=@"), path);
            }
            Vec::new()
        }
        _ => Vec::new(),
    }
}

fn complete_path(prefix: &str, orig: &str) -> Vec<Completion> {
    let mut path = expand_env(orig);

    if orig == "~" {
        return vec![Completion {
            key: format!("{prefix}~/"),
            value: "File".to_string(),
        }];
    }

    let tilde_prefix = format!("~{MAIN_SEPARATOR}");
    if path.starts_with(&tilde_prefix)
        && let Some(home) = env::var_os("HOME")
    {
        let mut home = home.to_string_lossy().into_owned();
        home.push_str(&path[1..]);
        path = home;
    }

    let dir = dir_name(&path);
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut entries = entries.flatten().collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name());

    let base = if !path.is_empty() && !path.ends_with(MAIN_SEPARATOR) {
        Path::new(&path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("")
            .to_string()
    } else {
        String::new()
    };
    let orig_dir = dir_name(orig);

    let mut out = Vec::new();
    for entry in entries {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if base.is_empty() && name.starts_with('.') {
            continue;
        }
        if !name.starts_with(&base) {
            continue;
        }

        let mut file = if orig_dir == "." {
            name.to_string()
        } else {
            Path::new(orig_dir)
                .join(name)
                .to_string_lossy()
                .into_owned()
        };
        if entry
            .file_type()
            .map(|file_type| file_type.is_dir())
            .unwrap_or(false)
        {
            file.push(MAIN_SEPARATOR);
        }
        out.push(Completion {
            key: format!("{prefix}{file}"),
            value: "File".to_string(),
        });
    }
    out
}

fn dir_name(path: &str) -> &str {
    let parent = Path::new(path).parent().and_then(|path| path.to_str());
    match parent {
        Some("") | None => ".",
        Some(parent) => parent,
    }
}

fn expand_env(input: &str) -> String {
    let mut out = String::new();
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '$' {
            out.push(ch);
            continue;
        }

        if chars.peek() == Some(&'{') {
            chars.next();
            let mut name = String::new();
            for next in chars.by_ref() {
                if next == '}' {
                    break;
                }
                name.push(next);
            }
            out.push_str(&env::var(name).unwrap_or_default());
            continue;
        }

        let mut name = String::new();
        while let Some(next) = chars.peek().copied() {
            if next == '_' || next.is_ascii_alphanumeric() {
                name.push(next);
                chars.next();
            } else {
                break;
            }
        }
        if name.is_empty() {
            out.push('$');
        } else {
            out.push_str(&env::var(name).unwrap_or_default());
        }
    }

    out
}

fn all_flags() -> Vec<Completion> {
    FLAGS
        .iter()
        .map(|flag| Completion {
            key: format!("--{}", flag.long),
            value: flag.description.to_string(),
        })
        .collect()
}

fn find_long(name: &str) -> Option<&'static Flag> {
    FLAGS
        .iter()
        .find(|flag| flag.long == name || flag.aliases.contains(&name))
}

fn find_short(name: char) -> Option<&'static Flag> {
    FLAGS.iter().find(|flag| {
        flag.short == Some(name)
            || flag
                .aliases
                .iter()
                .any(|alias| alias.len() == 1 && alias.as_bytes()[0] as char == name)
    })
}

fn complete_bash(values: &[Completion]) -> String {
    let mut out = String::new();
    for value in values {
        out.push_str(&value.key);
        if !value.key.ends_with('/') && !value.key.ends_with('=') {
            out.push(' ');
        }
        out.push('\n');
    }
    out
}

fn complete_fish(values: &[Completion]) -> String {
    let mut out = String::new();
    for value in values {
        out.push_str(&value.key);
        if !value.value.is_empty() {
            out.push('\t');
            out.push_str(&value.value);
        }
        out.push('\n');
    }
    out
}

fn complete_zsh(values: &[Completion]) -> String {
    let mut out = String::new();
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        out.push_str(&value.key);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flag_values(name: &str) -> &'static [FlagValue] {
        find_long(name).unwrap().values
    }

    #[test]
    fn test_complete_bash() {
        let tests = [
            (
                "should return nothing when no args",
                Vec::<String>::new(),
                String::new(),
            ),
            (
                "should return nothing when only arg is command",
                vec!["fetch".to_string()],
                String::new(),
            ),
            (
                "should complete color flag",
                vec!["fetch".to_string(), "--col".to_string()],
                "--color \n".to_string(),
            ),
            (
                "should complete color value",
                vec!["fetch".to_string(), "--color".to_string(), String::new()],
                flag_values("color")
                    .iter()
                    .map(|value| format!("{} \n", value.key))
                    .collect::<String>(),
            ),
            (
                "should complete color value with prefix",
                vec!["fetch".to_string(), "--color".to_string(), "o".to_string()],
                flag_values("color")
                    .iter()
                    .filter(|value| value.key.starts_with('o'))
                    .map(|value| format!("{} \n", value.key))
                    .collect::<String>(),
            ),
        ];

        for (name, args, expected) in tests {
            assert_eq!(Shell::Bash.complete(&complete(&args)), expected, "{name}");
        }
    }

    #[test]
    fn test_complete_fish() {
        let tests = [
            (
                "should return nothing when no args",
                Vec::<String>::new(),
                String::new(),
            ),
            (
                "should return nothing when only arg is command",
                vec!["fetch".to_string()],
                String::new(),
            ),
            (
                "should complete color flag",
                vec!["fetch".to_string(), "--col".to_string()],
                "fetch".to_string(),
            ),
        ];

        for (name, args, sentinel) in tests {
            let expected = if sentinel == "fetch" {
                format!("--color\t{}\n", find_long("color").unwrap().description)
            } else {
                sentinel
            };
            assert_eq!(Shell::Fish.complete(&complete(&args)), expected, "{name}");
        }

        let color_values = flag_values("color");
        let expected = color_values
            .iter()
            .map(|value| format!("{}\t{}\n", value.key, value.value))
            .collect::<String>();
        assert_eq!(
            Shell::Fish.complete(&complete(&[
                "fetch".to_string(),
                "--color".to_string(),
                String::new(),
            ])),
            expected,
            "should complete color value"
        );

        let expected = color_values
            .iter()
            .filter(|value| value.key.starts_with('o'))
            .map(|value| format!("{}\t{}\n", value.key, value.value))
            .collect::<String>();
        assert_eq!(
            Shell::Fish.complete(&complete(&[
                "fetch".to_string(),
                "--color".to_string(),
                "o".to_string(),
            ])),
            expected,
            "should complete color value with prefix"
        );
    }

    #[test]
    fn output_registers_supported_shells_and_rejects_unknown_shells() {
        assert!(output("bash", &[]).unwrap().contains("_fetch_complete()"));
        assert!(
            output("fish", &[])
                .unwrap()
                .contains("complete --keep-order")
        );
        assert!(
            output("zsh", &[])
                .unwrap()
                .contains("compdef _fetch_complete fetch")
        );
        assert_eq!(
            output("powershell", &[]).unwrap_err(),
            "completions not supported for shell 'powershell'"
        );
    }

    #[test]
    fn completes_value_after_equals_and_short_aliases_like_go() {
        assert_eq!(
            Shell::Bash.complete(&complete(&["fetch".into(), "--color=o".into()])),
            "--color=off \n--color=on \n"
        );
        assert_eq!(
            Shell::Bash.complete(&complete(&["fetch".into(), "--pager=o".into()])),
            "--pager=on \n--pager=off \n"
        );
        assert_eq!(
            Shell::Bash.complete(&complete(&["fetch".into(), "-X".into()])),
            ""
        );
        assert_eq!(
            Shell::Bash.complete(&complete(&["fetch".into(), "-X=".into()])),
            ""
        );
    }
}
