use std::io::Cursor;
use std::sync::Arc;

use reqwest::tls::Version;
use reqwest::{Certificate, Identity};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme, SupportedProtocolVersion};

use crate::error::FetchError;

pub mod inspect;

pub fn install_default_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

pub fn default_min_tls_version() -> Version {
    Version::TLS_1_2
}

pub fn reqwest_tls_version(option: &str, value: &str) -> Result<Version, FetchError> {
    match value {
        "1.0" => Ok(Version::TLS_1_0),
        "1.1" => Ok(Version::TLS_1_1),
        "1.2" => Ok(Version::TLS_1_2),
        "1.3" => Ok(Version::TLS_1_3),
        _ => Err(format!(
            "invalid value '{value}' for option '--{option}': must be one of [1.2, 1.3]"
        )
        .into()),
    }
}

pub fn ensure_rustls_supported_range(
    min_tls: Option<(&str, &str)>,
    max_tls: Option<&str>,
) -> Result<(), FetchError> {
    let min_requested = min_tls
        .map(|(option, value)| tls_order(option, value))
        .transpose()?;
    let max_requested = max_tls
        .map(|value| tls_order("max-tls", value))
        .transpose()?;
    let max = max_requested.unwrap_or(13);
    if max < 12 {
        return Err(unsupported_legacy_tls_versions(
            min_requested,
            max_requested,
        ));
    }
    Ok(())
}

pub fn rustls_protocol_versions(
    min_tls: Option<(&str, &str)>,
    max_tls: Option<&str>,
) -> Result<Vec<&'static SupportedProtocolVersion>, FetchError> {
    let min_requested = min_tls
        .map(|(option, value)| tls_order(option, value))
        .transpose()?;
    let max_requested = max_tls
        .map(|value| tls_order("max-tls", value))
        .transpose()?;
    let min = min_requested.unwrap_or(12);
    let max = max_requested.unwrap_or(13);

    let mut versions = Vec::new();
    if min <= 13 && max >= 13 {
        versions.push(&rustls::version::TLS13);
    }
    if min <= 12 && max >= 12 {
        versions.push(&rustls::version::TLS12);
    }
    if versions.is_empty() {
        return Err(unsupported_legacy_tls_versions(
            min_requested,
            max_requested,
        ));
    }
    Ok(versions)
}

pub fn rustls_client_config(
    ca_cert_paths: &[String],
    cert_path: Option<&str>,
    key_path: Option<&str>,
    insecure: bool,
    min_tls: Option<(&str, &str)>,
    max_tls: Option<&str>,
) -> Result<rustls::ClientConfig, FetchError> {
    install_default_crypto_provider();

    let versions = rustls_protocol_versions(min_tls, max_tls)?;
    let builder = rustls::ClientConfig::builder_with_protocol_versions(&versions);
    let builder = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
    } else {
        builder.with_root_certificates(rustls_root_store(ca_cert_paths)?)
    };

    if let Some((certs, key)) = rustls_client_auth(cert_path, key_path)? {
        builder
            .with_client_auth_cert(certs, key)
            .map_err(|err| FetchError::Message(err.to_string()))
    } else {
        Ok(builder.with_no_client_auth())
    }
}

pub(crate) fn tls_order(option: &str, value: &str) -> Result<u8, FetchError> {
    match value {
        "1.0" => Ok(10),
        "1.1" => Ok(11),
        "1.2" => Ok(12),
        "1.3" => Ok(13),
        _ => Err(format!(
            "invalid value '{value}' for option '--{option}': must be one of [1.2, 1.3]"
        )
        .into()),
    }
}

pub(crate) fn tls_order_label(order: u8) -> &'static str {
    match order {
        10 => "1.0",
        11 => "1.1",
        12 => "1.2",
        13 => "1.3",
        _ => "unknown",
    }
}

pub(crate) fn unsupported_legacy_tls_versions(
    min_requested: Option<u8>,
    max_requested: Option<u8>,
) -> FetchError {
    let mut requested: Vec<&'static str> = [min_requested, max_requested]
        .into_iter()
        .flatten()
        .filter(|version| *version < 12)
        .map(tls_order_label)
        .collect();
    requested.sort_unstable();
    requested.dedup();

    match requested.as_slice() {
        [version] => format!("TLS version {version} is not supported").into(),
        [first, second] => format!("TLS versions {first} and {second} are not supported").into(),
        _ => "requested TLS version is not supported".into(),
    }
}

pub fn ca_certificates(paths: &[String]) -> Result<Vec<Certificate>, FetchError> {
    let mut certs = Vec::new();
    for path in paths {
        let data = read_pem_file(path)?;
        if !has_certificate_block(&data) {
            return Err(format!("invalid CA certificate '{path}': no certificates found").into());
        }
        let parsed = Certificate::from_pem_bundle(&data)
            .map_err(|err| format!("invalid CA certificate '{path}': {err}"))?;
        if parsed.is_empty() {
            return Err(format!("invalid CA certificate '{path}': no certificates found").into());
        }
        certs.extend(parsed);
    }
    Ok(certs)
}

pub fn validate_ca_certificate_file(path: &str) -> Result<(), FetchError> {
    let data = read_pem_file(path)?;
    if !has_certificate_block(&data) {
        return Err(format!("invalid CA certificate '{path}': no certificates found").into());
    }
    let parsed = Certificate::from_pem_bundle(&data)
        .map_err(|err| format!("invalid CA certificate '{path}': {err}"))?;
    if parsed.is_empty() {
        return Err(format!("invalid CA certificate '{path}': no certificates found").into());
    }
    Ok(())
}

pub fn validate_client_certificate_file(path: &str) -> Result<(), FetchError> {
    let data = read_pem_file(path)?;
    validate_client_cert(path, &data)
}

pub fn validate_client_key_file(path: &str) -> Result<(), FetchError> {
    let data = read_pem_file(path)?;
    validate_client_key(path, &data)
}

pub fn client_identity(
    cert_path: Option<&str>,
    key_path: Option<&str>,
) -> Result<Option<Identity>, FetchError> {
    let Some(cert_path) = cert_path else {
        return Ok(None);
    };

    let cert_data = read_pem_file(cert_path)?;
    validate_client_cert(cert_path, &cert_data)?;

    let identity_data = if let Some(key_path) = key_path {
        let key_data = read_pem_file(key_path)?;
        validate_client_key(key_path, &key_data)?;
        let mut combined = cert_data;
        combined.extend_from_slice(&key_data);
        combined
    } else {
        cert_data
    };

    match Identity::from_pem(&identity_data) {
        Ok(identity) => Ok(Some(identity)),
        Err(err) if key_path.is_some() => Err(format!(
            "certificate '{}' and key '{}' may not match: {err}",
            cert_path,
            key_path.expect("key_path checked")
        )
        .into()),
        Err(err) => Err(format!(
            "client certificate '{cert_path}' may require a private key (use --key): {err}"
        )
        .into()),
    }
}

fn rustls_root_store(ca_cert_paths: &[String]) -> Result<RootCertStore, FetchError> {
    let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let native_certs = rustls_native_certs::load_native_certs().certs;
    let _ = roots.add_parsable_certificates(native_certs);

    for path in ca_cert_paths {
        let data = read_pem_file(path)?;
        let certs = pem_certificates(&data).map_err(|err| {
            FetchError::Message(format!("invalid CA certificate '{path}': {err}"))
        })?;
        if certs.is_empty() {
            return Err(format!("invalid CA certificate '{path}': no certificates found").into());
        }
        for cert in certs {
            roots.add(CertificateDer::from(cert)).map_err(|err| {
                FetchError::Message(format!("invalid CA certificate '{path}': {err}"))
            })?;
        }
    }
    Ok(roots)
}

fn rustls_client_auth(
    cert_path: Option<&str>,
    key_path: Option<&str>,
) -> Result<Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>, FetchError> {
    let Some(cert_path) = cert_path else {
        return Ok(None);
    };

    let cert_data = read_pem_file(cert_path)?;
    validate_client_cert(cert_path, &cert_data)?;
    let certs = pem_certificates(&cert_data).map_err(|err| {
        FetchError::Message(format!("invalid client certificate '{cert_path}': {err}"))
    })?;
    if certs.is_empty() {
        return Err(format!("invalid client certificate '{cert_path}': no PEM data found").into());
    }

    let key_data = if let Some(path) = key_path {
        let data = read_pem_file(path)?;
        validate_client_key(path, &data)?;
        data
    } else {
        cert_data
    };
    let Some(key) = first_private_key(&key_data)? else {
        return if let Some(key_path) = key_path {
            Err(format!("certificate '{cert_path}' and key '{key_path}' may not match: private key or certificate not found").into())
        } else {
            Err(format!("client certificate '{cert_path}' may require a private key (use --key): private key or certificate not found").into())
        };
    };

    Ok(Some((
        certs.into_iter().map(CertificateDer::from).collect(),
        key,
    )))
}

fn pem_certificates(data: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut cursor = Cursor::new(data);
    let mut certs = Vec::new();
    while let Some((kind, item)) =
        rustls::pki_types::pem::from_buf(&mut cursor).map_err(|_| "invalid PEM data".to_string())?
    {
        if kind == rustls::pki_types::pem::SectionKind::Certificate {
            certs.push(item);
        }
    }
    Ok(certs)
}

fn first_private_key(data: &[u8]) -> Result<Option<PrivateKeyDer<'static>>, FetchError> {
    let mut cursor = Cursor::new(data);
    while let Some((kind, item)) = rustls::pki_types::pem::from_buf(&mut cursor)
        .map_err(|_| FetchError::Message("invalid PEM data".to_string()))?
    {
        use rustls::pki_types::pem::SectionKind;
        let key = match kind {
            SectionKind::PrivateKey => Some(PrivateKeyDer::Pkcs8(item.into())),
            SectionKind::RsaPrivateKey => Some(PrivateKeyDer::Pkcs1(item.into())),
            SectionKind::EcPrivateKey => Some(PrivateKeyDer::Sec1(item.into())),
            _ => None,
        };
        if key.is_some() {
            return Ok(key);
        }
    }
    Ok(None)
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

fn read_pem_file(path: &str) -> Result<Vec<u8>, FetchError> {
    match std::fs::read(path) {
        Ok(data) => Ok(data),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            Err(format!("file '{path}' does not exist").into())
        }
        Err(err) => Err(err.into()),
    }
}

fn validate_client_cert(path: &str, data: &[u8]) -> Result<(), FetchError> {
    match first_pem_label(data).as_deref() {
        None => Err(format!("invalid client certificate '{path}': no PEM data found").into()),
        Some("CERTIFICATE") => Ok(()),
        Some(label) => Err(format!(
            "invalid client certificate '{path}': expected CERTIFICATE, got {label}"
        )
        .into()),
    }
}

fn validate_client_key(path: &str, data: &[u8]) -> Result<(), FetchError> {
    match first_pem_label(data).as_deref() {
        None => Err(format!("invalid client key '{path}': no PEM data found").into()),
        Some(label) if label.contains("ENCRYPTED") => Err(format!(
            "invalid client key '{path}': encrypted private keys are not supported"
        )
        .into()),
        Some(label) if label.contains("PRIVATE KEY") => Ok(()),
        Some(label) => {
            Err(format!("invalid client key '{path}': expected PRIVATE KEY, got {label}").into())
        }
    }
}

fn has_certificate_block(data: &[u8]) -> bool {
    pem_labels(data).any(|label| label == "CERTIFICATE")
}

fn first_pem_label(data: &[u8]) -> Option<String> {
    pem_labels(data).next()
}

fn pem_labels(data: &[u8]) -> impl Iterator<Item = String> + '_ {
    std::str::from_utf8(data)
        .ok()
        .into_iter()
        .flat_map(str::lines)
        .filter_map(|line| {
            let line = line.trim();
            let label = line.strip_prefix("-----BEGIN ")?;
            let label = label.strip_suffix("-----")?;
            Some(label.to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp(contents: &[u8]) -> (tempfile::NamedTempFile, String) {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(contents).unwrap();
        let path = file.path().to_string_lossy().into_owned();
        (file, path)
    }

    #[test]
    fn client_identity_key_without_cert_is_ignored_after_cli_validation() {
        let identity = client_identity(None, Some("client.key")).unwrap();

        assert!(identity.is_none());
    }

    #[test]
    fn client_identity_missing_cert_reports_go_style_file_error() {
        let err = client_identity(Some("/nonexistent/client.crt"), None).unwrap_err();

        assert_eq!(
            err.to_string(),
            "file '/nonexistent/client.crt' does not exist"
        );
    }

    #[test]
    fn client_identity_cert_without_key_mentions_private_key() {
        let (_cert_file, cert_path) =
            write_temp(b"-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n");

        let err = client_identity(Some(&cert_path), None).unwrap_err();

        assert!(err.to_string().contains("may require a private key"));
    }

    #[test]
    fn client_identity_rejects_non_certificate_first_block() {
        let (_cert_file, cert_path) = write_temp(
            b"-----BEGIN RSA PRIVATE KEY-----\nZmFrZQ==\n-----END RSA PRIVATE KEY-----\n",
        );

        let err = client_identity(Some(&cert_path), None).unwrap_err();

        assert!(
            err.to_string()
                .contains("expected CERTIFICATE, got RSA PRIVATE KEY")
        );
    }

    #[test]
    fn client_identity_rejects_key_without_private_key_block() {
        let (_cert_file, cert_path) =
            write_temp(b"-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n");
        let (_key_file, key_path) =
            write_temp(b"-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n");

        let err = client_identity(Some(&cert_path), Some(&key_path)).unwrap_err();

        assert!(err.to_string().contains("invalid client key"));
        assert!(
            err.to_string()
                .contains("expected PRIVATE KEY, got CERTIFICATE")
        );
    }

    #[test]
    fn ca_certificates_requires_certificate_block() {
        let (_file, path) = write_temp(
            b"-----BEGIN RSA PRIVATE KEY-----\nZmFrZQ==\n-----END RSA PRIVATE KEY-----\n",
        );

        let err = ca_certificates(&[path]).unwrap_err();

        assert!(err.to_string().contains("invalid CA certificate"));
        assert!(err.to_string().contains("no certificates found"));
    }

    #[test]
    fn first_pem_label_ignores_text_before_pem_like_go_pem_decode() {
        let label = first_pem_label(b"ignored\n-----BEGIN CERTIFICATE-----\n");

        assert_eq!(label.as_deref(), Some("CERTIFICATE"));
    }

    #[test]
    fn tls_version_bounds_match_go_defaults_and_supported_values() {
        assert_eq!(default_min_tls_version(), Version::TLS_1_2);
        assert_eq!(reqwest_tls_version("tls", "1.0").unwrap(), Version::TLS_1_0);
        assert_eq!(
            reqwest_tls_version("min-tls", "1.2").unwrap(),
            Version::TLS_1_2
        );
        assert_eq!(
            reqwest_tls_version("max-tls", "1.3").unwrap(),
            Version::TLS_1_3
        );

        let err = reqwest_tls_version("min-tls", "1.4").unwrap_err();
        assert!(err.to_string().contains("invalid value '1.4'"));
        assert!(err.to_string().contains("must be one of"));
    }

    #[test]
    fn rustls_supported_range_documents_legacy_tls_limit() {
        ensure_rustls_supported_range(Some(("min-tls", "1.0")), None).unwrap();
        ensure_rustls_supported_range(Some(("min-tls", "1.1")), Some("1.2")).unwrap();

        let err = ensure_rustls_supported_range(Some(("min-tls", "1.0")), Some("1.1")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS versions 1.0 and 1.1 are not supported"
        );

        let err = ensure_rustls_supported_range(None, Some("1.1")).unwrap_err();
        assert_eq!(err.to_string(), "TLS version 1.1 is not supported");
    }
}
