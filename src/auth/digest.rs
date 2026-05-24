use md5::Md5;
use sha2::{Digest as _, Sha256, Sha512_256};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub realm: String,
    pub nonce: String,
    pub opaque: String,
    pub qop: String,
    pub algorithm: String,
    pub stale: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DigestError {
    #[error("not a digest challenge")]
    NotDigest,
    #[error("missing required digest challenge parameter")]
    MissingRequiredParameter,
    #[error("unsupported digest algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("unsupported digest qop: {0}")]
    UnsupportedQop(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    Md5,
    Md5Sess,
    Sha256,
    Sha256Sess,
    Sha512256,
    Sha512256Sess,
}

pub fn parse_challenge(header: &str) -> Result<Challenge, DigestError> {
    if !header.to_ascii_uppercase().starts_with("DIGEST ") {
        return Err(DigestError::NotDigest);
    }

    let params =
        parse_params(&header[header.find(' ').map(|idx| idx + 1).unwrap_or(header.len())..]);
    let challenge = Challenge {
        realm: params.get("realm").cloned().unwrap_or_default(),
        nonce: params.get("nonce").cloned().unwrap_or_default(),
        opaque: params.get("opaque").cloned().unwrap_or_default(),
        qop: params.get("qop").cloned().unwrap_or_default(),
        algorithm: params.get("algorithm").cloned().unwrap_or_default(),
        stale: params.get("stale").cloned().unwrap_or_default(),
    };

    if challenge.realm.is_empty() || challenge.nonce.is_empty() {
        return Err(DigestError::MissingRequiredParameter);
    }
    Ok(challenge)
}

pub fn response(
    method: &str,
    uri: &str,
    challenge: &Challenge,
    username: &str,
    password: &str,
) -> Result<String, DigestError> {
    let uri = if uri.is_empty() { "/" } else { uri };
    let algorithm = Algorithm::parse(&challenge.algorithm)?;
    let qop = challenge.qop.to_ascii_lowercase();
    let qop_has_auth = qop.split(',').map(str::trim).any(|token| token == "auth");
    if !qop.is_empty() && !qop_has_auth {
        return Err(DigestError::UnsupportedQop(challenge.qop.clone()));
    }

    let cnonce = if algorithm.is_sess() || qop_has_auth {
        random_nonce()
    } else {
        String::new()
    };

    let mut ha1 = hash_digest(
        algorithm,
        &format!("{}:{}:{}", username, challenge.realm, password),
    );
    if algorithm.is_sess() {
        ha1 = hash_digest(algorithm, &format!("{ha1}:{}:{cnonce}", challenge.nonce));
    }

    let ha2 = hash_digest(algorithm, &format!("{method}:{uri}"));
    if qop_has_auth {
        let nc = "00000001";
        let digest_response = hash_digest(
            algorithm,
            &format!("{ha1}:{}:{nc}:{cnonce}:auth:{ha2}", challenge.nonce),
        );
        return Ok(format!(
            "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", algorithm={}, response=\"{}\", qop=auth, nc={}, cnonce=\"{}\"{}",
            escape_quotes(username),
            escape_quotes(&challenge.realm),
            escape_quotes(&challenge.nonce),
            escape_quotes(uri),
            algorithm.header_value(),
            digest_response,
            nc,
            cnonce,
            opaque_param(&challenge.opaque)
        ));
    }

    let digest_response = hash_digest(algorithm, &format!("{ha1}:{}:{ha2}", challenge.nonce));
    Ok(format!(
        "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", algorithm={}, response=\"{}\"{}",
        escape_quotes(username),
        escape_quotes(&challenge.realm),
        escape_quotes(&challenge.nonce),
        escape_quotes(uri),
        algorithm.header_value(),
        digest_response,
        opaque_param(&challenge.opaque)
    ))
}

pub fn find_digest_challenge<'a>(values: impl IntoIterator<Item = &'a str>) -> Option<String> {
    values.into_iter().find_map(extract_digest_challenge)
}

fn parse_params(mut value: &str) -> std::collections::HashMap<String, String> {
    let mut params = std::collections::HashMap::new();
    while !value.trim_start().is_empty() {
        value = value.trim_start();
        let Some((key, rest)) = value.split_once('=') else {
            break;
        };
        let key = key.trim().to_ascii_lowercase();
        let rest = rest.trim_start();

        let (param_value, next) = if rest.starts_with('"') {
            parse_quoted_string(rest)
        } else {
            match rest.split_once(',') {
                Some((param, next)) => (param.trim().to_string(), next),
                None => (rest.trim().to_string(), ""),
            }
        };
        params.insert(key, param_value);

        value = next;
        if let Some(stripped) = value.strip_prefix(',') {
            value = stripped;
        }
    }
    params
}

fn parse_quoted_string(value: &str) -> (String, &str) {
    if !value.starts_with('"') {
        return (String::new(), value);
    }

    let bytes = value.as_bytes();
    let mut out = String::new();
    let mut i = 1;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                i += 1;
                break;
            }
            b'\\' if i + 1 < bytes.len() => {
                out.push(bytes[i + 1] as char);
                i += 2;
            }
            byte => {
                out.push(byte as char);
                i += 1;
            }
        }
    }
    (out, &value[i..])
}

fn extract_digest_challenge(value: &str) -> Option<String> {
    let upper = value.to_ascii_uppercase();
    if upper.starts_with("DIGEST ") {
        return Some(extract_digest_from(value, 0));
    }

    let mut in_quotes = false;
    let mut escaped = false;
    for (idx, byte) in value.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if byte == b'\\' {
            escaped = true;
            continue;
        }
        if byte == b'"' {
            in_quotes = !in_quotes;
            continue;
        }
        if in_quotes {
            continue;
        }
        if upper[idx..].starts_with("DIGEST ") {
            if idx > 0 {
                let previous = value.as_bytes()[idx - 1];
                if previous != b' ' && previous != b',' {
                    continue;
                }
            }
            return Some(extract_digest_from(value, idx));
        }
    }
    None
}

fn extract_digest_from(value: &str, start: usize) -> String {
    let mut end = value.len();
    let mut in_quotes = false;
    let mut escaped = false;
    for idx in start + "Digest".len()..value.len() {
        let byte = value.as_bytes()[idx];
        if escaped {
            escaped = false;
            continue;
        }
        if byte == b'\\' {
            escaped = true;
            continue;
        }
        if byte == b'"' {
            in_quotes = !in_quotes;
            continue;
        }
        if !in_quotes && (byte == b',' || byte == b' ') {
            let rest = value[idx + 1..].trim_start();
            if is_known_scheme(rest) {
                end = idx;
                break;
            }
        }
    }
    value[start..end].trim().to_string()
}

fn is_known_scheme(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    [
        "BASIC ",
        "BEARER ",
        "DIGEST ",
        "NEGOTIATE ",
        "NTLM ",
        "HOBA ",
        "MUTUAL ",
        "SCRAM-SHA-1 ",
        "SCRAM-SHA-256 ",
        "AWS4-HMAC-SHA256 ",
    ]
    .iter()
    .any(|scheme| upper.starts_with(scheme))
}

impl Algorithm {
    fn parse(value: &str) -> Result<Self, DigestError> {
        match value.to_ascii_lowercase().as_str() {
            "" | "md5" => Ok(Self::Md5),
            "md5-sess" => Ok(Self::Md5Sess),
            "sha-256" => Ok(Self::Sha256),
            "sha-256-sess" => Ok(Self::Sha256Sess),
            "sha-512-256" => Ok(Self::Sha512256),
            "sha-512-256-sess" => Ok(Self::Sha512256Sess),
            other => Err(DigestError::UnsupportedAlgorithm(other.to_string())),
        }
    }

    fn is_sess(self) -> bool {
        matches!(self, Self::Md5Sess | Self::Sha256Sess | Self::Sha512256Sess)
    }

    fn header_value(self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Md5Sess => "MD5-SESS",
            Self::Sha256 => "SHA-256",
            Self::Sha256Sess => "SHA-256-SESS",
            Self::Sha512256 => "SHA-512-256",
            Self::Sha512256Sess => "SHA-512-256-SESS",
        }
    }
}

fn hash_digest(algorithm: Algorithm, value: &str) -> String {
    match algorithm {
        Algorithm::Md5 | Algorithm::Md5Sess => {
            let mut hasher = Md5::new();
            hasher.update(value.as_bytes());
            hex_encode(&hasher.finalize())
        }
        Algorithm::Sha256 | Algorithm::Sha256Sess => {
            let mut hasher = Sha256::new();
            hasher.update(value.as_bytes());
            hex_encode(&hasher.finalize())
        }
        Algorithm::Sha512256 | Algorithm::Sha512256Sess => {
            let mut hasher = Sha512_256::new();
            hasher.update(value.as_bytes());
            hex_encode(&hasher.finalize())
        }
    }
}

fn random_nonce() -> String {
    let bytes: [u8; 8] = rand::random();
    hex_encode(&bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn opaque_param(opaque: &str) -> String {
    if opaque.is_empty() {
        String::new()
    } else {
        format!(", opaque=\"{}\"", escape_quotes(opaque))
    }
}

fn escape_quotes(value: &str) -> String {
    value.replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_challenge() {
        let cases = [
            (
                "simple",
                r#"Digest realm="test", nonce="abc123""#,
                Ok(Challenge {
                    realm: "test".to_string(),
                    nonce: "abc123".to_string(),
                    opaque: String::new(),
                    qop: String::new(),
                    algorithm: String::new(),
                    stale: String::new(),
                }),
            ),
            (
                "full",
                r#"Digest realm="test", nonce="abc123", qop="auth", algorithm="MD5", opaque="opaque123", stale="true""#,
                Ok(Challenge {
                    realm: "test".to_string(),
                    nonce: "abc123".to_string(),
                    opaque: "opaque123".to_string(),
                    qop: "auth".to_string(),
                    algorithm: "MD5".to_string(),
                    stale: "true".to_string(),
                }),
            ),
            (
                "unquoted algorithm",
                r#"Digest realm="test", nonce="abc123", algorithm=MD5"#,
                Ok(Challenge {
                    realm: "test".to_string(),
                    nonce: "abc123".to_string(),
                    opaque: String::new(),
                    qop: String::new(),
                    algorithm: "MD5".to_string(),
                    stale: String::new(),
                }),
            ),
            (
                "escaped quotes",
                r#"Digest realm="test \"realm\"", nonce="abc123""#,
                Ok(Challenge {
                    realm: r#"test "realm""#.to_string(),
                    nonce: "abc123".to_string(),
                    opaque: String::new(),
                    qop: String::new(),
                    algorithm: String::new(),
                    stale: String::new(),
                }),
            ),
        ];

        for (name, input, want) in cases {
            assert_eq!(parse_challenge(input), want, "{name}");
        }

        assert_eq!(
            parse_challenge(r#"Digest nonce="abc123""#),
            Err(DigestError::MissingRequiredParameter)
        );
        assert_eq!(
            parse_challenge(r#"Digest realm="test""#),
            Err(DigestError::MissingRequiredParameter)
        );
        assert_eq!(
            parse_challenge(r#"Basic realm="test""#),
            Err(DigestError::NotDigest)
        );
    }

    #[test]
    fn test_response() {
        let challenge = Challenge {
            realm: "test".to_string(),
            nonce: "nonce123".to_string(),
            opaque: String::new(),
            qop: String::new(),
            algorithm: "MD5".to_string(),
            stale: String::new(),
        };

        let auth = response("GET", "/path?query=1", &challenge, "user", "pass").unwrap();
        assert!(auth.starts_with("Digest "));
        assert!(auth.contains(r#"username="user""#));
        assert!(auth.contains(r#"realm="test""#));
        assert!(auth.contains(r#"uri="/path?query=1""#));
        assert!(auth.contains(r#"response=""#));
        assert!(!auth.contains("nc="));
    }

    #[test]
    fn test_response_with_qop() {
        let challenge = Challenge {
            realm: "test".to_string(),
            nonce: "nonce123".to_string(),
            opaque: "opaque123".to_string(),
            qop: "auth".to_string(),
            algorithm: "MD5".to_string(),
            stale: String::new(),
        };

        let auth = response("POST", "/api", &challenge, "user", "pass").unwrap();
        assert!(auth.starts_with("Digest "));
        assert!(auth.contains("qop=auth"));
        assert!(auth.contains("nc=00000001"));
        assert!(auth.contains(r#"cnonce=""#));
        assert!(auth.contains(r#"opaque="opaque123""#));
    }

    #[test]
    fn test_response_md5_sess() {
        let challenge = Challenge {
            realm: "test".to_string(),
            nonce: "nonce123".to_string(),
            opaque: String::new(),
            qop: "auth".to_string(),
            algorithm: "MD5-sess".to_string(),
            stale: String::new(),
        };

        let auth = response("GET", "/", &challenge, "user", "pass").unwrap();
        assert!(auth.contains("algorithm=MD5-SESS"));
        assert!(auth.contains("qop=auth"));
    }

    #[test]
    fn test_hash_digest() {
        assert_eq!(
            hash_digest(Algorithm::Md5, "user:test:pass"),
            "0f1cafcb677261987de453fb58ea335f"
        );
        assert_eq!(hash_digest(Algorithm::Sha256, "user:test:pass").len(), 64);
    }

    #[test]
    fn test_response_sha256() {
        let challenge = Challenge {
            realm: "test".to_string(),
            nonce: "nonce123".to_string(),
            opaque: String::new(),
            qop: "auth".to_string(),
            algorithm: "SHA-256".to_string(),
            stale: String::new(),
        };

        let auth = response("GET", "/", &challenge, "user", "pass").unwrap();
        assert!(auth.contains("algorithm=SHA-256"));
        assert!(auth.contains("qop=auth"));
    }

    #[test]
    fn test_response_auth_int_only() {
        let challenge = Challenge {
            realm: "test".to_string(),
            nonce: "nonce123".to_string(),
            opaque: String::new(),
            qop: "auth-int".to_string(),
            algorithm: "MD5".to_string(),
            stale: String::new(),
        };

        assert_eq!(
            response("GET", "/", &challenge, "user", "pass"),
            Err(DigestError::UnsupportedQop("auth-int".to_string()))
        );
    }

    #[test]
    fn test_response_unsupported_algorithm() {
        let challenge = Challenge {
            realm: "test".to_string(),
            nonce: "nonce123".to_string(),
            opaque: String::new(),
            qop: String::new(),
            algorithm: "UNKNOWN".to_string(),
            stale: String::new(),
        };

        assert_eq!(
            response("GET", "/", &challenge, "user", "pass"),
            Err(DigestError::UnsupportedAlgorithm("unknown".to_string()))
        );
    }

    #[test]
    fn test_find_digest_challenge() {
        let cases: &[(&[&str], &str)] = &[
            (
                &[r#"Digest realm="test", nonce="abc123""#],
                r#"Digest realm="test", nonce="abc123""#,
            ),
            (&[r#"Basic realm="test""#], ""),
            (
                &[r#"Basic realm="x", Digest realm="y", nonce="abc123""#],
                r#"Digest realm="y", nonce="abc123""#,
            ),
            (
                &[r#"Basic realm="x",Digest realm="y",nonce="abc123""#],
                r#"Digest realm="y",nonce="abc123""#,
            ),
            (
                &[r#"Digest realm="y", nonce="abc123", Basic realm="x""#],
                r#"Digest realm="y", nonce="abc123""#,
            ),
            (
                &[r#"Basic realm="x", Digest realm="y", nonce="abc123", Bearer token="z""#],
                r#"Digest realm="y", nonce="abc123""#,
            ),
            (
                &[r#"Basic realm="x""#, r#"Digest realm="y", nonce="abc123""#],
                r#"Digest realm="y", nonce="abc123""#,
            ),
            (
                &[r#"Basic realm="My Digest", Digest realm="y", nonce="abc123""#],
                r#"Digest realm="y", nonce="abc123""#,
            ),
            (
                &[r#"Basic realm="My \"Digest\"", Digest realm="y", nonce="abc123""#],
                r#"Digest realm="y", nonce="abc123""#,
            ),
            (
                &[r#"Basic realm="x" Digest realm="y" nonce="abc123""#],
                r#"Digest realm="y" nonce="abc123""#,
            ),
            (&[r#"Basic realm="x", Bearer token="z""#], ""),
        ];

        for (values, want) in cases {
            let got = find_digest_challenge(values.iter().copied()).unwrap_or_default();
            assert_eq!(&got, want);
        }
    }
}
