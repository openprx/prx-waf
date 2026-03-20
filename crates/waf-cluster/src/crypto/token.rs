//! Join token generation and validation.
//!
//! Tokens are used by workers to authenticate to main during the join handshake.
//! An admin generates a token on main; the token is then provided to the worker
//! operator who includes it in the join request.
//!
//! Token format (hex-encoded): `{expiry_ms_be_hex}.{hmac_sha256_hex}`
//! where HMAC-SHA256 is computed over `{expiry_ms_be_hex}` using a key derived
//! from the cluster CA private key.

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tracing::warn;

type HmacSha256 = Hmac<Sha256>;

/// Generate a join token valid for `ttl_ms` milliseconds from now.
///
/// `ca_key_pem` is used to derive the signing key so that only the holder
/// of the CA private key can generate valid tokens.
pub fn generate_token(ca_key_pem: &str, ttl_ms: u64) -> Result<String> {
    let now_ms = now_unix_ms();
    let expiry_ms = now_ms.checked_add(ttl_ms).context("token TTL overflow")?;
    let expiry_hex = format!("{:016x}", expiry_ms);

    let signing_key = derive_signing_key(ca_key_pem);
    let mut mac = HmacSha256::new_from_slice(&signing_key)
        .map_err(|e| anyhow::anyhow!("HMAC key error: {e}"))?;
    mac.update(expiry_hex.as_bytes());
    let signature = mac.finalize().into_bytes();
    let signature_hex = hex::encode(signature);

    Ok(format!("{expiry_hex}.{signature_hex}"))
}

/// Validate a join token against the CA private key.
///
/// Returns `Ok(())` if the token is valid and not expired, or an error otherwise.
pub fn validate_token(ca_key_pem: &str, token: &str) -> Result<()> {
    let (expiry_hex, signature_hex) = token
        .split_once('.')
        .context("invalid token format: missing '.' separator")?;

    let expiry_ms =
        u64::from_str_radix(expiry_hex, 16).context("invalid token format: bad expiry hex")?;

    let signing_key = derive_signing_key(ca_key_pem);
    let mut mac = HmacSha256::new_from_slice(&signing_key)
        .map_err(|e| anyhow::anyhow!("HMAC key error: {e}"))?;
    mac.update(expiry_hex.as_bytes());

    let provided_sig =
        hex::decode(signature_hex).context("invalid token format: bad signature hex")?;

    mac.verify_slice(&provided_sig)
        .map_err(|_| anyhow::anyhow!("token signature verification failed"))?;

    let now_ms = now_unix_ms();
    if now_ms > expiry_ms {
        warn!(expiry_ms, now_ms, "Join token has expired");
        return Err(anyhow::anyhow!("join token has expired"));
    }

    Ok(())
}

/// Derive a 32-byte HMAC signing key from the CA private key PEM.
fn derive_signing_key(ca_key_pem: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"prx-waf-cluster-token-signing-v1:");
    hasher.update(ca_key_pem.as_bytes());
    hasher.finalize().into()
}

fn now_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAKE_CA_KEY: &str =
        "-----BEGIN PRIVATE KEY-----\nfake-key-for-test\n-----END PRIVATE KEY-----\n";

    #[test]
    fn generate_and_validate_token() {
        let token = generate_token(FAKE_CA_KEY, 3_600_000).unwrap(); // 1h TTL
        assert!(validate_token(FAKE_CA_KEY, &token).is_ok());
    }

    #[test]
    fn wrong_signing_key_rejected() {
        let token = generate_token(FAKE_CA_KEY, 3_600_000).unwrap();
        let other_key = "-----BEGIN PRIVATE KEY-----\ndifferent-key\n-----END PRIVATE KEY-----\n";
        assert!(validate_token(other_key, &token).is_err());
    }

    #[test]
    fn expired_token_rejected() {
        // TTL = 0ms → already expired
        let token = generate_token(FAKE_CA_KEY, 0).unwrap();
        // Sleep 1ms to ensure now > expiry
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert!(validate_token(FAKE_CA_KEY, &token).is_err());
    }

    #[test]
    fn malformed_token_rejected() {
        assert!(validate_token(FAKE_CA_KEY, "no-dot-separator").is_err());
        assert!(validate_token(FAKE_CA_KEY, "xxxx.yyyy").is_err());
    }
}
