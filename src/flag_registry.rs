//! Unified declarative registry of all CLI flags.
//!
//! Every flag is defined once with its name, category, and a predicate that
//! returns `true` when the flag is set on the [`Cli`].  The shared inspection
//! ignored-flag functions and the `--from-curl` / websocket conflict
//! validators all filter this single registry instead of duplicating checks.
//!
//! Flag names include the `"--"` prefix so inspection warnings can join them
//! directly.  Conflict validators strip the two-character prefix for their
//! error messages (e.g. `"--method"` → `method`).

use crate::cli::Cli;

/// Category for grouping flags in inspection ignored-flag warnings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FlagCategory {
    Request,
    Auth,
    Response,
    Tls,
    HttpVersion,
}

/// One entry in the unified flag registry.
pub(crate) struct FlagDef {
    /// Flag name including the `"--"` prefix (e.g. `"--method"`).
    pub name: &'static str,
    /// Category for inspection ignored-flag grouping, or `None` for flags
    /// that don't belong to any standard group.
    pub category: Option<FlagCategory>,
    /// Predicate: returns `true` when this flag is explicitly set on `Cli`.
    pub is_set: fn(&Cli) -> bool,
    /// Optional WebSocket-specific predicate, used instead of [`is_set`] for
    /// websocket conflict checks.  When `None`, falls back to `is_set`.
    pub is_ws_conflict: Option<fn(&Cli) -> bool>,
    /// Whether this flag conflicts with `--from-curl`.
    pub conflicts_from_curl: bool,
    /// Whether this flag unconditionally conflicts with WebSocket.
    pub conflicts_websocket_always: bool,
    /// Whether this flag conflicts with `ws://` (plain WebSocket, no TLS).
    pub conflicts_websocket_plain: bool,
}

impl FlagDef {
    pub const fn new(
        name: &'static str,
        category: Option<FlagCategory>,
        is_set: fn(&Cli) -> bool,
    ) -> Self {
        Self {
            name,
            category,
            is_set,
            is_ws_conflict: None,
            conflicts_from_curl: false,
            conflicts_websocket_always: false,
            conflicts_websocket_plain: false,
        }
    }

    pub const fn with_from_curl(mut self) -> Self {
        self.conflicts_from_curl = true;
        self
    }

    pub const fn with_ws_always(mut self) -> Self {
        self.conflicts_websocket_always = true;
        self
    }

    pub const fn with_ws_conflict(mut self, predicate: fn(&Cli) -> bool) -> Self {
        self.is_ws_conflict = Some(predicate);
        self
    }

    pub const fn with_ws_plain(mut self) -> Self {
        self.conflicts_websocket_plain = true;
        self
    }

    /// Return the effective websocket-conflict predicate.
    fn ws_is_conflict(&self, cli: &Cli) -> bool {
        match self.is_ws_conflict {
            Some(p) => p(cli),
            None => (self.is_set)(cli),
        }
    }

    /// Return the flag name without the `"--"` prefix, for conflict error messages.
    pub fn conflict_name(&self) -> &str {
        &self.name[2..]
    }
}

// ── the single source of truth ──────────────────────────────────────────

pub(crate) static FLAGS: &[FlagDef] = &[
    // ── Request ─────────────────────────────────────────────────────────
    FlagDef::new("--data", Some(FlagCategory::Request), |c| c.data.is_some()).with_from_curl(),
    FlagDef::new("--json", Some(FlagCategory::Request), |c| c.json.is_some()).with_from_curl(),
    FlagDef::new("--xml", Some(FlagCategory::Request), |c| c.xml.is_some())
        .with_from_curl()
        .with_ws_always(),
    FlagDef::new("--form", Some(FlagCategory::Request), |c| {
        !c.form.is_empty()
    })
    .with_from_curl()
    .with_ws_always(),
    FlagDef::new("--multipart", Some(FlagCategory::Request), |c| {
        !c.multipart.is_empty()
    })
    .with_from_curl()
    .with_ws_always(),
    FlagDef::new("--grpc", Some(FlagCategory::Request), |c| c.grpc)
        .with_from_curl()
        .with_ws_always(),
    FlagDef::new("--grpc-describe", Some(FlagCategory::Request), |c| {
        c.grpc_describe.is_some()
    })
    .with_from_curl()
    .with_ws_always(),
    FlagDef::new("--grpc-list", Some(FlagCategory::Request), |c| c.grpc_list)
        .with_from_curl()
        .with_ws_always(),
    FlagDef::new("--proto-desc", Some(FlagCategory::Request), |c| {
        c.proto_desc.is_some()
    }),
    FlagDef::new("--proto-file", Some(FlagCategory::Request), |c| {
        !c.proto_files.is_empty()
    }),
    FlagDef::new("--proto-import", Some(FlagCategory::Request), |c| {
        !c.proto_imports.is_empty()
    }),
    FlagDef::new("--output", Some(FlagCategory::Request), |c| {
        c.output.is_some()
    })
    .with_from_curl()
    .with_ws_always(),
    FlagDef::new("--remote-name", Some(FlagCategory::Request), |c| {
        c.remote_name
    })
    .with_from_curl()
    .with_ws_always(),
    FlagDef::new("--remote-header-name", Some(FlagCategory::Request), |c| {
        c.remote_header_name
    })
    .with_from_curl()
    .with_ws_always(),
    FlagDef::new("--copy", Some(FlagCategory::Request), |c| c.copy).with_ws_always(),
    FlagDef::new("--clobber", Some(FlagCategory::Request), |c| c.clobber).with_ws_always(),
    FlagDef::new("--method", Some(FlagCategory::Request), |c| {
        c.method.is_some()
    })
    .with_from_curl(),
    FlagDef::new("--header", Some(FlagCategory::Request), |c| {
        !c.headers.is_empty()
    })
    .with_from_curl(),
    FlagDef::new("--query", Some(FlagCategory::Request), |c| {
        !c.query.is_empty()
    })
    .with_from_curl(),
    FlagDef::new("--edit", Some(FlagCategory::Request), |c| c.edit).with_ws_always(),
    FlagDef::new("--session", Some(FlagCategory::Request), |c| {
        c.session.is_some()
    }),
    FlagDef::new("--retry", Some(FlagCategory::Request), |c| {
        c.retry.is_some()
    })
    .with_from_curl()
    .with_ws_always()
    .with_ws_conflict(|c| c.retry() > 0),
    FlagDef::new("--retry-delay", Some(FlagCategory::Request), |c| {
        c.retry_delay.is_some()
    })
    .with_from_curl()
    .with_ws_always(),
    FlagDef::new("--redirects", Some(FlagCategory::Request), |c| {
        c.redirects.is_some()
    })
    .with_from_curl(),
    FlagDef::new("--range", Some(FlagCategory::Request), |c| {
        !c.ranges.is_empty()
    })
    .with_from_curl(),
    FlagDef::new("--timing", Some(FlagCategory::Request), |c| c.timing),
    FlagDef::new("--proxy", Some(FlagCategory::Request), |c| {
        c.proxy.is_some()
    })
    .with_from_curl(),
    FlagDef::new("--discard", Some(FlagCategory::Request), |c| c.discard).with_ws_always(),
    FlagDef::new("--unix", Some(FlagCategory::Request), |c| c.unix.is_some()).with_from_curl(),
    // ── Auth ────────────────────────────────────────────────────────────
    FlagDef::new("--basic", Some(FlagCategory::Auth), |c| c.basic.is_some()).with_from_curl(),
    FlagDef::new("--bearer", Some(FlagCategory::Auth), |c| c.bearer.is_some()).with_from_curl(),
    FlagDef::new("--digest", Some(FlagCategory::Auth), |c| c.digest.is_some())
        .with_from_curl()
        .with_ws_always(),
    FlagDef::new("--aws-sigv4", Some(FlagCategory::Auth), |c| {
        c.aws_sigv4.is_some()
    })
    .with_from_curl(),
    // ── Response ────────────────────────────────────────────────────────
    FlagDef::new("--article", Some(FlagCategory::Response), |c| c.article).with_ws_always(),
    FlagDef::new("--compress", Some(FlagCategory::Response), |c| {
        c.compress.is_some()
    }),
    FlagDef::new("--no-encode", Some(FlagCategory::Response), |c| c.no_encode),
    FlagDef::new("--format", Some(FlagCategory::Response), |c| {
        c.format.is_some()
    }),
    FlagDef::new("--image", Some(FlagCategory::Response), |c| {
        c.image.is_some()
    }),
    FlagDef::new("--pager", Some(FlagCategory::Response), |c| {
        c.pager.is_some()
    }),
    FlagDef::new("--ignore-status", Some(FlagCategory::Response), |c| {
        c.ignore_status
    }),
    FlagDef::new("--sort-headers", Some(FlagCategory::Response), |c| {
        c.sort_headers
    }),
    FlagDef::new("--ws-interactive", Some(FlagCategory::Response), |c| {
        c.ws_interactive.is_some()
    }),
    FlagDef::new("--ws-message-mode", Some(FlagCategory::Response), |c| {
        c.ws_message_mode.is_some()
    }),
    FlagDef::new("--dry-run", Some(FlagCategory::Response), |c| c.dry_run),
    // ── Resolver (not in any ignored group; used by inspection) ───────
    FlagDef::new("--dns-server", None, |c| c.dns_server.is_some()).with_from_curl(),
    // ── TLS ────────────────────────────────────────────────────────────
    FlagDef::new("--insecure", Some(FlagCategory::Tls), |c| c.insecure)
        .with_from_curl()
        .with_ws_plain(),
    FlagDef::new("--max-tls", Some(FlagCategory::Tls), |c| {
        c.max_tls.is_some()
    })
    .with_from_curl()
    .with_ws_plain(),
    FlagDef::new("--min-tls", Some(FlagCategory::Tls), |c| {
        c.min_tls.is_some()
    })
    .with_from_curl()
    .with_ws_plain(),
    FlagDef::new("--tls", Some(FlagCategory::Tls), |c| c.tls.is_some())
        .with_from_curl()
        .with_ws_plain(),
    FlagDef::new("--cert", Some(FlagCategory::Tls), |c| c.cert.is_some())
        .with_from_curl()
        .with_ws_plain(),
    FlagDef::new("--key", Some(FlagCategory::Tls), |c| c.key.is_some())
        .with_from_curl()
        .with_ws_plain(),
    FlagDef::new("--ca-cert", Some(FlagCategory::Tls), |c| {
        !c.ca_cert.is_empty()
    })
    .with_from_curl()
    .with_ws_plain(),
    FlagDef::new("--ech", Some(FlagCategory::Tls), |c| c.ech.is_some())
        .with_from_curl()
        .with_ws_plain(),
    // ── HTTP version ───────────────────────────────────────────────────
    FlagDef::new("--http", Some(FlagCategory::HttpVersion), |c| {
        c.http.is_some()
    })
    .with_from_curl(),
    FlagDef::new("--http1", Some(FlagCategory::HttpVersion), |c| c.http1).with_from_curl(),
    FlagDef::new("--http2", Some(FlagCategory::HttpVersion), |c| c.http2).with_from_curl(),
    FlagDef::new("--http3", Some(FlagCategory::HttpVersion), |c| c.http3).with_from_curl(),
    // ── Timeout ────────────────────────────────────────────────────────
    FlagDef::new("--timeout", None, |c| c.timeout.is_some()).with_from_curl(),
    FlagDef::new("--connect-timeout", None, |c| c.connect_timeout.is_some()).with_from_curl(),
];

// ── convenience iterators ──────────────────────────────────────────────

/// Return registry flag names explicitly set on the CLI.
pub(crate) fn set_flag_names(cli: &Cli) -> impl Iterator<Item = &'static str> + '_ {
    FLAGS
        .iter()
        .filter(move |definition| (definition.is_set)(cli))
        .map(|definition| definition.name)
}

/// Push names of all flags in `category` that are set on `cli` into `ignored`.
pub(crate) fn append_ignored_of_category(
    cli: &Cli,
    category: FlagCategory,
    ignored: &mut Vec<&'static str>,
) {
    for def in FLAGS {
        if def.category == Some(category) && (def.is_set)(cli) {
            ignored.push(def.name);
        }
    }
}

/// Return the conflict name (without `--`) of the first flag that is set
/// and conflicts with `--from-curl`, or `None`.
pub(crate) fn first_from_curl_conflicting_flag(cli: &Cli) -> Option<&'static str> {
    FLAGS
        .iter()
        .find(|def| def.conflicts_from_curl && (def.is_set)(cli))
        .map(|def| def.conflict_name())
}

/// Return the conflict name (without `--`) of the first flag that
/// unconditionally conflicts with WebSocket, or `None`.
pub(crate) fn first_websocket_always_conflicting_flag(cli: &Cli) -> Option<&'static str> {
    FLAGS
        .iter()
        .find(|def| def.conflicts_websocket_always && def.ws_is_conflict(cli))
        .map(|def| def.conflict_name())
}

/// Return the conflict name (without `--`) of the first TLS flag that
/// conflicts with plain `ws://` WebSocket, or `None`.
pub(crate) fn first_websocket_plain_conflicting_flag(cli: &Cli) -> Option<&'static str> {
    FLAGS
        .iter()
        .find(|def| def.conflicts_websocket_plain && def.ws_is_conflict(cli))
        .map(|def| def.conflict_name())
}
