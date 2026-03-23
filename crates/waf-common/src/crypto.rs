/// AES-256-GCM encryption utilities for sensitive config fields.
///
/// The master key is derived from the `MASTER_KEY` environment variable via SHA-256.
/// If the env var is not set, a zero key is used (no-op in production--operators must
/// set `MASTER_KEY` to get real encryption).
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use sha2::{Digest, Sha256};

/// Derive a 32-byte AES key from an arbitrary master password string via SHA-256.
pub fn derive_key(master_password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"prx-waf-v1:");
    hasher.update(master_password.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(result.as_slice());
    key
}

/// Load master key from `MASTER_KEY` env var.
///
/// Returns an error if the variable is not set or is empty.
/// Operators **must** set `MASTER_KEY` to a strong random value in production.
pub fn master_key() -> anyhow::Result<[u8; 32]> {
    match std::env::var("MASTER_KEY") {
        Ok(s) if !s.is_empty() => Ok(derive_key(&s)),
        _ => Err(anyhow::anyhow!(
            "MASTER_KEY environment variable is not set. \
             Set a strong random value (>= 32 chars) for encryption at rest."
        )),
    }
}

/// Encrypt `plaintext` with AES-256-GCM using `key`.
///
/// Returns base64(nonce || ciphertext).
pub fn encrypt_field(key: &[u8; 32], plaintext: &str) -> anyhow::Result<String> {
    use base64::Engine as _;

    let k = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(k);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("encryption error: {e}"))?;
    let mut combined = nonce.to_vec();
    combined.extend_from_slice(&ciphertext);
    Ok(base64::engine::general_purpose::STANDARD.encode(combined))
}

/// Decrypt a base64(nonce || ciphertext) value produced by [`encrypt_field`].
pub fn decrypt_field(key: &[u8; 32], encoded: &str) -> anyhow::Result<String> {
    use base64::Engine;

    let combined = base64::engine::general_purpose::STANDARD.decode(encoded)?;
    if combined.len() < 12 {
        return Err(anyhow::anyhow!("ciphertext too short"));
    }
    let (nonce_bytes, ct) = combined.split_at(12);
    let k = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(k);
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ct)
        .map_err(|e| anyhow::anyhow!("decryption error: {e}"))?;
    Ok(String::from_utf8(plaintext)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = derive_key("test-password");
        let plain = "smtp-secret-password-123";
        let enc = encrypt_field(&key, plain).unwrap();
        let dec = decrypt_field(&key, &enc).unwrap();
        assert_eq!(plain, dec);
    }
}
