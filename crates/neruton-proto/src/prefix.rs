use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::TUNNEL_WS_PATH;

/// Reserved subdomain labels that cannot be registered by tunnel clients.
pub const RESERVED_PREFIXES: &[&str] = &["neruton", "www", "api", "admin", "_neruton"];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PrefixError {
    #[error("prefix cannot be empty")]
    Empty,
    #[error("prefix must be 1..=63 characters, got {0}")]
    TooLong(usize),
    #[error("prefix '{0}' must match DNS label ^[a-z0-9]([a-z0-9-]{{0,61}}[a-z0-9])?$")]
    InvalidFormat(String),
    #[error("prefix '{0}' is reserved")]
    Reserved(String),
}

/// Generate a fresh lowercase UUID v4 string suitable as a DNS subdomain label.
pub fn generate_uuid_prefix() -> String {
    Uuid::new_v4().to_string()
}

/// Normalize (trim & lowercase) and validate a subdomain prefix.
pub fn validate_prefix(raw: &str) -> Result<String, PrefixError> {
    validate_prefix_with_extra_reserved(raw, None)
}

/// Normalize and validate a subdomain prefix, also rejecting an optional extra reserved label
/// (for instance, the panel host subdomain if customized).
pub fn validate_prefix_with_extra_reserved(
    raw: &str,
    extra_reserved: Option<&str>,
) -> Result<String, PrefixError> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(PrefixError::Empty);
    }

    // Check reserved names before character validation so e.g. "_neruton" reports Reserved.
    if RESERVED_PREFIXES.contains(&normalized.as_str()) {
        return Err(PrefixError::Reserved(normalized));
    }
    if let Some(extra) = extra_reserved {
        if normalized == extra.trim().to_ascii_lowercase() {
            return Err(PrefixError::Reserved(normalized));
        }
    }

    if normalized.len() > 63 {
        return Err(PrefixError::TooLong(normalized.len()));
    }

    let bytes = normalized.as_bytes();
    let valid_edge = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let valid_mid = |b: u8| valid_edge(b) || b == b'-';

    if !valid_edge(bytes[0]) || !valid_edge(bytes[bytes.len() - 1]) {
        return Err(PrefixError::InvalidFormat(normalized));
    }
    if !bytes.iter().copied().all(valid_mid) {
        return Err(PrefixError::InvalidFormat(normalized));
    }

    Ok(normalized)
}

/// Convert a user-supplied `--server` value (`https://...`, `http://...`, `wss://...`, `ws://...`,
/// or bare `host[:port]`) into the tunnel WebSocket endpoint URL (`wss://<host>/_neruton/tunnel`).
pub fn build_tunnel_ws_url(server: &str) -> Result<Url, url::ParseError> {
    let trimmed = server.trim();
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };

    let mut url = Url::parse(&with_scheme)?;
    match url.scheme() {
        "https" => {
            let _ = url.set_scheme("wss");
        }
        "http" => {
            let _ = url.set_scheme("ws");
        }
        "wss" | "ws" => {}
        _ => return Err(url::ParseError::RelativeUrlWithoutBase),
    }

    let path = url.path().trim_end_matches('/');
    if path.is_empty() || path == "/" {
        url.set_path(TUNNEL_WS_PATH);
    } else if !path.ends_with(TUNNEL_WS_PATH) {
        url.set_path(&format!("{path}{TUNNEL_WS_PATH}"));
    }

    Ok(url)
}

/// Normalize a local target specification like `3000`, `localhost:3000`, or `http://127.0.0.1:8080`.
pub fn normalize_target_url(raw: &str) -> Result<Url, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("target URL cannot be empty".to_string());
    }

    let candidate = if let Ok(port) = trimmed.parse::<u16>() {
        format!("http://127.0.0.1:{port}")
    } else if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else if trimmed.contains("://") {
        return Err(format!(
            "unsupported target scheme in '{trimmed}' (expected http:// or https://)"
        ));
    } else {
        format!("http://{trimmed}")
    };

    let url = Url::parse(&candidate).map_err(|e| format!("invalid target URL '{raw}': {e}"))?;
    if url.host_str().is_none() {
        return Err(format!("target URL '{raw}' is missing a host"));
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_prefix_is_valid() {
        let id = generate_uuid_prefix();
        assert_eq!(id.len(), 36);
        assert_eq!(validate_prefix(&id).unwrap(), id);
    }

    #[test]
    fn valid_prefixes_pass() {
        assert_eq!(validate_prefix("a").unwrap(), "a");
        assert_eq!(validate_prefix("0").unwrap(), "0");
        assert_eq!(validate_prefix("Test-Test").unwrap(), "test-test");
        assert_eq!(validate_prefix("  my-app-123  ").unwrap(), "my-app-123");
        let max_len = "a".repeat(63);
        assert_eq!(validate_prefix(&max_len).unwrap(), max_len);
    }

    #[test]
    fn invalid_and_reserved_prefixes_fail() {
        assert_eq!(validate_prefix(""), Err(PrefixError::Empty));
        assert_eq!(validate_prefix("   "), Err(PrefixError::Empty));
        assert!(matches!(
            validate_prefix(&"a".repeat(64)),
            Err(PrefixError::TooLong(64))
        ));
        assert!(matches!(
            validate_prefix("-abc"),
            Err(PrefixError::InvalidFormat(_))
        ));
        assert!(matches!(
            validate_prefix("abc-"),
            Err(PrefixError::InvalidFormat(_))
        ));
        assert!(matches!(
            validate_prefix("foo.bar"),
            Err(PrefixError::InvalidFormat(_))
        ));
        assert!(matches!(
            validate_prefix("foo_bar"),
            Err(PrefixError::InvalidFormat(_))
        ));
        for reserved in RESERVED_PREFIXES {
            assert_eq!(
                validate_prefix(reserved),
                Err(PrefixError::Reserved((*reserved).to_string()))
            );
        }
        assert_eq!(
            validate_prefix_with_extra_reserved("panel", Some("panel")),
            Err(PrefixError::Reserved("panel".to_string()))
        );
    }

    #[test]
    fn server_ws_url_conversion() {
        assert_eq!(
            build_tunnel_ws_url("https://neruton.moer.eu.org")
                .unwrap()
                .as_str(),
            "wss://neruton.moer.eu.org/_neruton/tunnel"
        );
        assert_eq!(
            build_tunnel_ws_url("http://127.0.0.1:8080")
                .unwrap()
                .as_str(),
            "ws://127.0.0.1:8080/_neruton/tunnel"
        );
        assert_eq!(
            build_tunnel_ws_url("neruton.moer.eu.org:443")
                .unwrap()
                .as_str(),
            "wss://neruton.moer.eu.org/_neruton/tunnel"
        );
        assert_eq!(
            build_tunnel_ws_url("wss://neruton.moer.eu.org/_neruton/tunnel")
                .unwrap()
                .as_str(),
            "wss://neruton.moer.eu.org/_neruton/tunnel"
        );
    }

    #[test]
    fn target_url_normalization() {
        assert_eq!(
            normalize_target_url("3000").unwrap().as_str(),
            "http://127.0.0.1:3000/"
        );
        assert_eq!(
            normalize_target_url("localhost:8080").unwrap().as_str(),
            "http://localhost:8080/"
        );
        assert_eq!(
            normalize_target_url("https://localhost:8443/app")
                .unwrap()
                .as_str(),
            "https://localhost:8443/app"
        );
        assert!(normalize_target_url("ftp://example.com").is_err());
    }
}
