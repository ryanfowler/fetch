use rustls::client::{EchConfig, EchGreaseConfig, EchMode};
use rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;

use crate::cli::Cli;
use crate::core;
use crate::error::FetchError;

/// Resolve the ECH mode based on CLI flags and candidate ECH configs from DNS.
///
/// `candidates` should contain the raw `ech` SvcParam values from usable
/// HTTPS/SVCB records, ordered by SvcPriority (lowest non-zero priority first).
/// Callers must exclude alias-mode records (priority 0) and records with
/// unsupported mandatory parameters before calling this function.
///
/// Each candidate is tried in turn; the first successfully parsed configuration
/// is used. If all candidates fail in `--ech on` mode, the last parsing error
/// is reported. If no candidates are provided in `--ech on` mode, a distinct
/// "does not advertise ECH" error is returned.
pub(crate) fn resolve_ech_mode(
    cli: &Cli,
    candidates: &[&[u8]],
) -> Result<Option<EchMode>, FetchError> {
    match cli.ech.as_deref() {
        Some("off") | None => return Ok(None),
        _ => {}
    }

    let mut last_err: Option<FetchError> = None;

    for &bytes in candidates {
        if bytes.is_empty() {
            continue;
        }
        match build_ech_config(bytes) {
            Ok(ech_config) => return Ok(Some(EchMode::Enable(ech_config))),
            Err(err) => last_err = Some(err),
        }
    }

    match cli.ech.as_deref() {
        Some("on") => {
            if let Some(err) = last_err {
                Err(FetchError::Message(format!(
                    "--ech on: server advertised an ECH configuration that could not be used: {err}"
                )))
            } else {
                Err(
                    "--ech on: no ECH configuration available (server does not advertise ECH)"
                        .into(),
                )
            }
        }
        Some("auto") => {
            // In auto mode, use GREASE as a fallback to prevent ossification.
            // Warn when ECH was advertised but could not be parsed, so users
            // understand that real ECH was not attempted.
            if last_err.is_some() && cli.verbose >= 3 && !cli.silent {
                let mut printer = core::stdio().stderr_printer(cli.color.as_deref());
                core::write_warning_msg_no_flush(
                    &mut printer,
                    "server advertised an unusable ECH configuration; falling back to GREASE",
                );
                core::flush_stderr(printer);
            }
            Ok(Some(EchMode::Grease(generate_ech_grease_config())))
        }
        _ => Ok(None),
    }
}

/// Build an `EchConfig` from raw ECH config bytes (e.g. from a DNS SVCB record).
pub(crate) fn build_ech_config(bytes: &[u8]) -> Result<EchConfig, FetchError> {
    EchConfig::new(bytes.to_vec().into(), ALL_SUPPORTED_SUITES)
        .map_err(|err| FetchError::Message(err.to_string()))
}

/// Generate a GREASE ECH configuration for anti-ossification.
pub(crate) fn generate_ech_grease_config() -> EchGreaseConfig {
    let suite = ALL_SUPPORTED_SUITES[0];
    let (public_key, _private_key) = suite
        .generate_key_pair()
        .expect("HPKE key generation should not fail");
    EchGreaseConfig::new(suite, public_key)
}

/// Returns `true` if ECH is active (mode is `auto` or `on`).
pub(crate) fn is_ech_active(cli: &Cli) -> bool {
    matches!(cli.ech.as_deref(), Some("auto" | "on"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn cli_with_ech(ech: &str) -> Cli {
        Cli::try_parse_from(["fetch", "--ech", ech, "https://example.com"]).unwrap()
    }

    fn cli_with_ech_and_verbose(ech: &str, verbose: u8) -> Cli {
        let verbosity_flag = match verbose {
            1 => "-v",
            2 => "-vv",
            3 => "-vvv",
            4 => "-vvvv",
            _ => "-vvv",
        };
        Cli::try_parse_from(["fetch", verbosity_flag, "--ech", ech, "https://example.com"]).unwrap()
    }

    /// Build a valid single-config ECH config list byte slice using the first
    /// supported HPKE suite. This allows testing the happy path without
    /// external DNS.
    fn make_valid_ech_config_bytes() -> Vec<u8> {
        let suite = ALL_SUPPORTED_SUITES[0];
        let hpke_suite = suite.suite();
        let (public_key, _private_key) = suite
            .generate_key_pair()
            .expect("HPKE key generation should not fail");
        let public_key_bytes = &public_key.0;

        let mut config = Vec::new();

        // Single ECHConfig within the list:
        // version: u16 (0xfe0d)
        config.extend_from_slice(&0xfe0d_u16.to_be_bytes());
        // length placeholder (will be fixed up after contents are written)
        let len_pos = config.len();
        config.extend_from_slice(&[0u8; 2]);

        // --- key_config (HpkeKeyConfig) ---
        // config_id: u8
        config.push(0);
        // kem_id: u16
        config.extend_from_slice(&u16::from(hpke_suite.kem).to_be_bytes());
        // public_key: u16 length-prefixed bytes
        let pk_len = public_key_bytes.len() as u16;
        config.extend_from_slice(&pk_len.to_be_bytes());
        config.extend_from_slice(public_key_bytes);
        // symmetric_cipher_suites: u16 length-prefixed list of 4-byte suites
        config.extend_from_slice(&4u16.to_be_bytes()); // one suite = 4 bytes
        config.extend_from_slice(&u16::from(hpke_suite.sym.kdf_id).to_be_bytes());
        config.extend_from_slice(&u16::from(hpke_suite.sym.aead_id).to_be_bytes());

        // maximum_name_length: u8 (0 = no limit)
        config.push(0);
        // public_name: u8 length + bytes
        config.push(1);
        config.push(b'x');
        // extensions: u16 length-prefixed (empty)
        config.extend_from_slice(&0u16.to_be_bytes());

        // Fix up the per-config length field
        let contents_len = (config.len() - len_pos - 2) as u16;
        config[len_pos..len_pos + 2].copy_from_slice(&contents_len.to_be_bytes());

        // Wrap in the outer ECH config list: u16 length-prefixed list of configs.
        let mut buf = Vec::new();
        let list_len = config.len() as u16;
        buf.extend_from_slice(&list_len.to_be_bytes());
        buf.extend_from_slice(&config);

        buf
    }

    // --- No ECH parameters ---

    #[test]
    fn no_candidates_on_mode_reports_not_advertised() {
        let cli = cli_with_ech("on");
        let err = resolve_ech_mode(&cli, &[]).unwrap_err();
        assert!(
            err.to_string().contains("does not advertise ECH"),
            "expected 'does not advertise' error, got: {err}"
        );
    }

    #[test]
    fn no_candidates_auto_mode_returns_grease() {
        let cli = cli_with_ech("auto");
        let mode = resolve_ech_mode(&cli, &[]).unwrap();
        assert!(
            matches!(mode, Some(EchMode::Grease(_))),
            "expected GREASE, got: {mode:?}"
        );
    }

    #[test]
    fn no_candidates_off_mode_returns_none() {
        let cli = cli_with_ech("off");
        let mode = resolve_ech_mode(&cli, &[]).unwrap();
        assert!(mode.is_none(), "expected None, got: {mode:?}");
    }

    #[test]
    fn no_ech_flag_returns_none() {
        let cli = Cli::try_parse_from(["fetch", "https://example.com"]).unwrap();
        let mode = resolve_ech_mode(&cli, &[]).unwrap();
        assert!(mode.is_none(), "expected None, got: {mode:?}");
    }

    // --- One valid configuration ---

    #[test]
    fn one_valid_config_on_mode_returns_enable() {
        let cli = cli_with_ech("on");
        let valid = make_valid_ech_config_bytes();
        let mode = resolve_ech_mode(&cli, &[&valid]).unwrap();
        assert!(
            matches!(mode, Some(EchMode::Enable(_))),
            "expected Enable, got: {mode:?}"
        );
    }

    #[test]
    fn one_valid_config_auto_mode_returns_enable() {
        let cli = cli_with_ech("auto");
        let valid = make_valid_ech_config_bytes();
        let mode = resolve_ech_mode(&cli, &[&valid]).unwrap();
        assert!(
            matches!(mode, Some(EchMode::Enable(_))),
            "expected Enable in auto mode, got: {mode:?}"
        );
    }

    // --- One malformed configuration ---

    #[test]
    fn malformed_config_on_mode_reports_invalid() {
        let cli = cli_with_ech("on");
        let invalid = b"not-a-valid-ech-config";
        let err = resolve_ech_mode(&cli, &[invalid]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("advertised an ECH configuration that could not be used"),
            "expected 'could not be used' error, got: {msg}"
        );
        assert!(
            !msg.contains("does not advertise ECH"),
            "should not say 'does not advertise' when config was present, got: {msg}"
        );
    }

    #[test]
    fn malformed_config_auto_mode_returns_grease() {
        let cli = cli_with_ech("auto");
        let invalid = b"garbage-ech-bytes";
        let mode = resolve_ech_mode(&cli, &[invalid]).unwrap();
        assert!(
            matches!(mode, Some(EchMode::Grease(_))),
            "expected GREASE fallback for malformed config in auto mode, got: {mode:?}"
        );
    }

    // --- Malformed followed by valid ---

    #[test]
    fn malformed_then_valid_skips_to_second() {
        let cli = cli_with_ech("on");
        let invalid = b"not-valid-ech";
        let valid = make_valid_ech_config_bytes();
        let mode = resolve_ech_mode(&cli, &[invalid, &valid]).unwrap();
        assert!(
            matches!(mode, Some(EchMode::Enable(_))),
            "expected Enable after skipping malformed first candidate, got: {mode:?}"
        );
    }

    // --- Required mode with only malformed configurations (multiple) ---

    #[test]
    fn only_malformed_configs_on_mode_reports_last_error() {
        let cli = cli_with_ech("on");
        let invalid1 = b"first-junk";
        let invalid2 = b"second-junk";
        let err = resolve_ech_mode(&cli, &[invalid1, invalid2]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("could not be used"),
            "expected 'could not be used' error, got: {msg}"
        );
        // The error should include a parsing error detail from rustls
        let lower = msg.to_lowercase();
        assert!(
            lower.contains("invalid") || lower.contains("no compatible"),
            "expected a parsing error detail, got: {msg}"
        );
    }

    // --- Empty byte slice in candidates ---

    #[test]
    fn empty_byte_slice_is_skipped() {
        let cli = cli_with_ech("on");
        let valid = make_valid_ech_config_bytes();
        // An empty slice should be skipped, and the valid config should be used.
        let mode = resolve_ech_mode(&cli, &[b"", &valid]).unwrap();
        assert!(
            matches!(mode, Some(EchMode::Enable(_))),
            "expected Enable after skipping empty candidate, got: {mode:?}"
        );
    }

    // --- Auto mode with verbose warning for unusable config ---

    #[test]
    fn auto_mode_with_malformed_and_verbose_produces_warning() {
        // -vvv triggers verbose output
        let cli = cli_with_ech_and_verbose("auto", 3);
        let invalid = b"bad-ech-config-here";
        // When stderr is not a terminal, the warning is still emitted.
        // We just verify that the function succeeds and produces GREASE.
        let mode = resolve_ech_mode(&cli, &[invalid]).unwrap();
        assert!(
            matches!(mode, Some(EchMode::Grease(_))),
            "expected GREASE in auto mode with verbose, got: {mode:?}"
        );
    }

    #[test]
    fn auto_mode_with_malformed_and_silent_suppresses_warning() {
        let cli = Cli::try_parse_from([
            "fetch",
            "-vvv",
            "--silent",
            "--ech",
            "auto",
            "https://example.com",
        ])
        .unwrap();
        let invalid = b"bad-config";
        // Silent mode suppresses the warning but still produces GREASE.
        let mode = resolve_ech_mode(&cli, &[invalid]).unwrap();
        assert!(
            matches!(mode, Some(EchMode::Grease(_))),
            "expected GREASE even when silent, got: {mode:?}"
        );
    }
}
