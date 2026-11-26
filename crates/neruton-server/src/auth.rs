use anyhow::{anyhow, Result};
use argon2::password_hash::rand_core::OsRng as ArgonOsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use hmac::{Hmac, Mac};
use http::{header, HeaderMap};
use neruton_proto::UserRole;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub const SESSION_COOKIE_NAME: &str = "neruton_session";
pub const SESSION_MAX_AGE_SECS: i64 = 604_800; // 7 days

const TOKEN_ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const TOKEN_RANDOM_LEN: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPayload {
    pub uid: String,
    pub username: String,
    pub role: UserRole,
    pub exp: i64,
    pub token_version: u64,
}

/// Constant-time byte comparison.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Lowercase hex SHA-256 digest.
pub fn sha256_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    hex_encode(&digest)
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Generate a cryptographically random 32-byte hex session signing secret (64 hex chars).
pub fn generate_session_secret() -> String {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    hex_encode(&buf)
}

/// Generate a new tunnel token secret `ntk_<32 alphanumeric chars>`, its display prefix
/// (`ntk_xxxxxxxx...`), and its SHA-256 hex digest.
pub fn generate_tunnel_token() -> (String, String, String) {
    let mut secret = String::with_capacity(4 + TOKEN_RANDOM_LEN);
    secret.push_str("ntk_");

    // Rejection sampling over [0, 248) = 4 * 62 for zero modulo bias.
    let limit = (256 / TOKEN_ALPHABET.len()) * TOKEN_ALPHABET.len();
    let mut buf = [0u8; 64];
    while secret.len() < 4 + TOKEN_RANDOM_LEN {
        OsRng.fill_bytes(&mut buf);
        for &b in &buf {
            if (b as usize) < limit {
                secret.push(TOKEN_ALPHABET[(b as usize) % TOKEN_ALPHABET.len()] as char);
                if secret.len() == 4 + TOKEN_RANDOM_LEN {
                    break;
                }
            }
        }
    }

    let prefix = format!("{}...", &secret[..12]);
    let hash = sha256_hex(&secret);
    (secret, prefix, hash)
}

/// Synchronous Argon2id password hashing (run via `spawn_blocking` in async handlers).
pub fn hash_password_sync(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut ArgonOsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("failed to hash password: {e}"))?;
    Ok(hash.to_string())
}

/// Async Argon2id password hashing offloaded to Tokio's blocking pool.
pub async fn hash_password(password: String) -> Result<String> {
    tokio::task::spawn_blocking(move || hash_password_sync(&password))
        .await
        .map_err(|e| anyhow!("password hashing task failed: {e}"))?
}

/// Synchronous Argon2id password verification.
pub fn verify_password_sync(password: &str, encoded_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(encoded_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Async Argon2id password verification offloaded to Tokio's blocking pool.
pub async fn verify_password(password: String, encoded_hash: String) -> bool {
    tokio::task::spawn_blocking(move || verify_password_sync(&password, &encoded_hash))
        .await
        .unwrap_or(false)
}

/// Sign a session payload into `<base64url(json)>.<base64url(hmac_sha256)>`.
pub fn sign_session(secret: &str, payload: &SessionPayload) -> Result<String> {
    let json = serde_json::to_vec(payload)?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(json);
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| anyhow!("invalid HMAC key: {e}"))?;
    mac.update(payload_b64.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    Ok(format!("{payload_b64}.{sig_b64}"))
}

/// Verify signature and expiration of a session cookie value.
pub fn verify_session(secret: &str, cookie_val: &str) -> Option<SessionPayload> {
    let (payload_b64, sig_b64) = cookie_val.split_once('.')?;
    if sig_b64.contains('.') {
        return None;
    }

    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).ok()?;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(payload_b64.as_bytes());
    mac.verify_slice(&sig_bytes).ok()?;

    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let payload: SessionPayload = serde_json::from_slice(&payload_bytes).ok()?;
    if payload.exp <= Utc::now().timestamp() {
        return None;
    }
    Some(payload)
}

/// Extract a named cookie value from incoming `Cookie` header(s).
pub fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    for hv in headers.get_all(header::COOKIE) {
        let Ok(raw) = hv.to_str() else {
            continue;
        };
        for pair in raw.split(';') {
            let Some((k, v)) = pair.trim().split_once('=') else {
                continue;
            };
            if k.trim() == name {
                let val = v.trim();
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

/// Determine whether `Set-Cookie` should include the `Secure` attribute.
pub fn should_set_secure_cookie(public_scheme: &str, headers: &HeaderMap) -> bool {
    if public_scheme.eq_ignore_ascii_case("https") {
        return true;
    }
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|proto| proto.trim().eq_ignore_ascii_case("https"))
        .unwrap_or(false)
}

/// Format a `Set-Cookie` header value establishing the session cookie.
pub fn build_session_cookie(token_value: &str, secure: bool) -> String {
    if secure {
        format!(
            "{SESSION_COOKIE_NAME}={token_value}; HttpOnly; Path=/; SameSite=Lax; Max-Age={SESSION_MAX_AGE_SECS}; Secure"
        )
    } else {
        format!(
            "{SESSION_COOKIE_NAME}={token_value}; HttpOnly; Path=/; SameSite=Lax; Max-Age={SESSION_MAX_AGE_SECS}"
        )
    }
}

/// Format a `Set-Cookie` header value clearing the session cookie.
pub fn build_clear_session_cookie(secure: bool) -> String {
    if secure {
        format!("{SESSION_COOKIE_NAME}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0; Secure")
    } else {
        format!("{SESSION_COOKIE_NAME}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0")
    }
}

/// Extract optional Bearer token from `Authorization: Bearer <token>` or `?token=...`.
pub fn extract_tunnel_token(headers: &HeaderMap, query_token: Option<&str>) -> Option<String> {
    if let Some(auth_val) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(token) = auth_val
            .strip_prefix("Bearer ")
            .or_else(|| auth_val.strip_prefix("bearer "))
        {
            let trimmed = token.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    query_token
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn argon2_hash_and_verify_roundtrip() {
        let hash = hash_password_sync("super-secret-password").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password_sync("super-secret-password", &hash));
        assert!(!verify_password_sync("wrong-password", &hash));
    }

    #[test]
    fn tunnel_token_generation_format_and_hash() {
        let (secret, prefix, hash) = generate_tunnel_token();
        assert!(secret.starts_with("ntk_"));
        assert_eq!(secret.len(), 36);
        assert_eq!(prefix, format!("{}...", &secret[..12]));
        assert_eq!(hash, sha256_hex(&secret));
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn session_cookie_sign_verify_and_tamper_detection() {
        let secret = generate_session_secret();
        let payload = SessionPayload {
            uid: "user-1".to_string(),
            username: "admin".to_string(),
            role: UserRole::Admin,
            exp: Utc::now().timestamp() + 3600,
            token_version: 2,
        };
        let cookie_val = sign_session(&secret, &payload).unwrap();
        let verified = verify_session(&secret, &cookie_val).unwrap();
        assert_eq!(verified.uid, "user-1");
        assert_eq!(verified.token_version, 2);

        // Wrong secret fails
        assert!(verify_session("wrong-secret", &cookie_val).is_none());

        // Tampered payload fails
        let tampered = format!("x{cookie_val}");
        assert!(verify_session(&secret, &tampered).is_none());

        // Expired token fails
        let expired = SessionPayload {
            exp: Utc::now().timestamp() - 10,
            ..payload
        };
        let expired_val = sign_session(&secret, &expired).unwrap();
        assert!(verify_session(&secret, &expired_val).is_none());
    }

    #[test]
    fn cookie_extraction_and_secure_detection() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("foo=bar; neruton_session=abc.def; other=1"),
        );
        assert_eq!(
            extract_cookie(&headers, SESSION_COOKIE_NAME).as_deref(),
            Some("abc.def")
        );

        assert!(should_set_secure_cookie("https", &HeaderMap::new()));
        assert!(!should_set_secure_cookie("http", &HeaderMap::new()));

        let mut xf_headers = HeaderMap::new();
        xf_headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert!(should_set_secure_cookie("http", &xf_headers));
    }
}
