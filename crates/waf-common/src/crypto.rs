/// AES-256-GCM encryption utilities for sensitive config fields.
///
/// The master key is derived from the `MASTER_KEY` environment variable. New
/// ciphertexts use a slow, salted KDF (Argon2id over the key material with a
/// per-ciphertext random salt) so a weak passphrase cannot be brute-forced
/// offline (M-12). Legacy ciphertexts written with the previous single-round,
/// unsalted SHA-256 KDF are still decryptable for backward-compatible migration.
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use anyhow::Context as _;
use argon2::Argon2;
use rand::RngCore as _;
use sha2::{Digest, Sha256};

/// Magic + version prefix marking the Argon2id + random-salt field format.
///
/// Four-byte magic `PWF1` followed by a one-byte format version (`0x01`).
const FIELD_MAGIC_V1: [u8; 5] = *b"PWF1\x01";
/// Random salt length for Argon2id derivation.
const SALT_LEN: usize = 16;
/// AES-GCM nonce length.
const NONCE_LEN: usize = 12;
/// New-format header length: magic/version (5) + salt (16) + nonce (12).
const FIELD_HEADER_LEN: usize = FIELD_MAGIC_V1.len() + SALT_LEN + NONCE_LEN;

/// Minimum passphrase length accepted for encryption at rest (M-12).
pub const MIN_PASSPHRASE_LEN: usize = 16;

/// Derive a 32-byte value from an arbitrary master password string via SHA-256.
///
/// Retained for the legacy decryption path and as the input keying material fed
/// into the new Argon2id KDF. Not a strong stand-alone KDF on its own.
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
/// Returns an error if the variable is unset or shorter than
/// [`MIN_PASSPHRASE_LEN`]. Operators **must** set `MASTER_KEY` to a strong
/// random value in production.
pub fn master_key() -> anyhow::Result<[u8; 32]> {
    match std::env::var("MASTER_KEY") {
        Ok(s) if s.len() >= MIN_PASSPHRASE_LEN => Ok(derive_key(&s)),
        Ok(_) => Err(anyhow::anyhow!(
            "MASTER_KEY is too short: set at least {MIN_PASSPHRASE_LEN} characters for encryption at rest."
        )),
        _ => Err(anyhow::anyhow!(
            "MASTER_KEY environment variable is not set. \
             Set a strong random value (>= {MIN_PASSPHRASE_LEN} chars) for encryption at rest."
        )),
    }
}

/// Derive a 32-byte AES key from input keying material and a salt via Argon2id.
fn argon2_derive(ikm: &[u8], salt: &[u8]) -> anyhow::Result<[u8; 32]> {
    let mut out = [0u8; 32];
    Argon2::default()
        .hash_password_into(ikm, salt, &mut out)
        .map_err(|e| anyhow::anyhow!("argon2 key derivation failed: {e}"))?;
    Ok(out)
}

/// Encrypt `plaintext` with AES-256-GCM, deriving the encryption key with
/// Argon2id over `key` and a fresh random salt (M-12).
///
/// Returns base64(`FIELD_MAGIC_V1` || salt || nonce || ciphertext).
pub fn encrypt_field(key: &[u8; 32], plaintext: &str) -> anyhow::Result<String> {
    use base64::Engine as _;

    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let aes_key = argon2_derive(key, &salt)?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("encryption error: {e}"))?;

    let mut out = Vec::with_capacity(FIELD_HEADER_LEN + ciphertext.len());
    out.extend_from_slice(&FIELD_MAGIC_V1);
    out.extend_from_slice(&salt);
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ciphertext);
    Ok(base64::engine::general_purpose::STANDARD.encode(out))
}

/// Decrypt a value produced by [`encrypt_field`].
///
/// Handles both the current Argon2id format and the legacy
/// `base64(nonce || ciphertext)` SHA-256 format for backward-compatible
/// migration (M-12).
pub fn decrypt_field(key: &[u8; 32], encoded: &str) -> anyhow::Result<String> {
    use base64::Engine as _;

    let combined = base64::engine::general_purpose::STANDARD.decode(encoded)?;

    if combined.starts_with(&FIELD_MAGIC_V1) && combined.len() >= FIELD_HEADER_LEN {
        // Current format: Argon2id-derived key with embedded random salt.
        let salt = combined
            .get(FIELD_MAGIC_V1.len()..FIELD_MAGIC_V1.len() + SALT_LEN)
            .context("ciphertext truncated: missing salt")?;
        let nonce_bytes = combined
            .get(FIELD_MAGIC_V1.len() + SALT_LEN..FIELD_HEADER_LEN)
            .context("ciphertext truncated: missing nonce")?;
        let ct = combined
            .get(FIELD_HEADER_LEN..)
            .context("ciphertext truncated: missing body")?;
        let aes_key = argon2_derive(key, salt)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ct)
            .map_err(|e| anyhow::anyhow!("decryption error: {e}"))?;
        return Ok(String::from_utf8(plaintext)?);
    }

    // Legacy format: nonce || ciphertext, key used directly as the AES-256 key.
    if combined.len() < NONCE_LEN {
        return Err(anyhow::anyhow!("ciphertext too short"));
    }
    let (nonce_bytes, ct) = combined.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ct)
        .map_err(|e| anyhow::anyhow!("decryption error: {e}"))?;
    Ok(String::from_utf8(plaintext)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    /// Reproduce the pre-M-12 on-disk format (base64(nonce || ct), SHA-256 key).
    fn legacy_encrypt(key: &[u8; 32], plaintext: &str) -> String {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct = cipher.encrypt(&nonce, plaintext.as_bytes()).expect("legacy encrypt");
        let mut combined = nonce.to_vec();
        combined.extend_from_slice(&ct);
        base64::engine::general_purpose::STANDARD.encode(combined)
    }

    #[test]
    fn new_format_roundtrip() {
        let key = derive_key("strong-master-password");
        let plain = "smtp-secret-password-123";
        let enc = encrypt_field(&key, plain).unwrap();
        let raw = base64::engine::general_purpose::STANDARD.decode(&enc).unwrap();
        assert!(
            raw.starts_with(&FIELD_MAGIC_V1),
            "new ciphertext must carry the magic prefix"
        );
        let dec = decrypt_field(&key, &enc).unwrap();
        assert_eq!(plain, dec);
    }

    #[test]
    fn decrypts_legacy_sha256_format() {
        let key = derive_key("legacy-master-password");
        let enc = legacy_encrypt(&key, "legacy-secret");
        // New code must still decrypt the old, unsalted format for migration.
        assert_eq!(decrypt_field(&key, &enc).unwrap(), "legacy-secret");
    }

    #[test]
    fn wrong_key_fails() {
        let key = derive_key("correct-master-password");
        let enc = encrypt_field(&key, "secret").unwrap();
        let wrong = derive_key("wrong-master-password");
        assert!(decrypt_field(&wrong, &enc).is_err());
    }

    #[test]
    fn distinct_salts_produce_distinct_ciphertexts() {
        let key = derive_key("strong-master-password");
        let a = encrypt_field(&key, "same").unwrap();
        let b = encrypt_field(&key, "same").unwrap();
        assert_ne!(a, b, "random salt+nonce must randomise ciphertexts");
    }
}
