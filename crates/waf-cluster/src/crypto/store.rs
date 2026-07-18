//! Encrypted on-disk store for the cluster CA private key.
//!
//! The CA key is encrypted at rest with AES-256-GCM. New blobs derive the AES
//! key from the passphrase with a slow, salted KDF (Argon2id + per-blob random
//! salt) so a weak passphrase cannot be brute-forced offline (M-12). Legacy
//! blobs written with the previous single-round, unsalted SHA-256 KDF are still
//! decryptable for backward-compatible migration.
//!
//! Current file / blob format (binary):
//!   5 bytes   — magic + version (`PWB1\x01`)
//!   16 bytes  — Argon2id salt
//!   12 bytes  — AES-GCM nonce
//!   remaining — AES-GCM ciphertext
//!
//! Legacy format (still accepted on read):
//!   12 bytes  — AES-GCM nonce
//!   remaining — AES-GCM ciphertext (SHA-256-derived key)

use std::fs;
use std::path::Path;

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use anyhow::{Context, Result};
use argon2::Argon2;
use rand::RngCore as _;
use sha2::{Digest, Sha256};
use tracing::info;

/// Magic + version prefix marking the Argon2id + random-salt blob format.
const BLOB_MAGIC_V1: [u8; 5] = *b"PWB1\x01";
/// Random salt length for Argon2id derivation.
const SALT_LEN: usize = 16;
/// AES-GCM nonce length.
const NONCE_LEN: usize = 12;
/// New-format header length: magic/version (5) + salt (16) + nonce (12).
const BLOB_HEADER_LEN: usize = BLOB_MAGIC_V1.len() + SALT_LEN + NONCE_LEN;
/// Minimum passphrase length accepted for encryption at rest (M-12).
pub const MIN_PASSPHRASE_LEN: usize = 16;

/// Encrypted on-disk store for the cluster CA private key.
pub struct KeyStore {
    path: String,
}

impl KeyStore {
    /// Create a new key store pointing at `path`.
    pub fn new(path: &str) -> Self {
        Self { path: path.to_string() }
    }

    /// File path for the encrypted CA key.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Load and decrypt the CA private key PEM from disk.
    ///
    /// Returns the raw PEM string of the CA private key.
    pub fn load_ca_key(&self, passphrase: &str) -> Result<String> {
        let data = fs::read(&self.path).with_context(|| format!("failed to read key store: {}", self.path))?;
        let plaintext = decrypt_blob(&data, passphrase)?;
        String::from_utf8(plaintext).context("CA key PEM is not valid UTF-8")
    }

    /// Encrypt the CA private key PEM and persist it to disk.
    pub fn save_ca_key(&self, key_pem: &str, passphrase: &str) -> Result<()> {
        let data = encrypt_blob(key_pem.as_bytes(), passphrase)?;

        // Ensure parent directory exists
        if let Some(parent) = Path::new(&self.path).parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).with_context(|| format!("failed to create dir: {}", parent.display()))?;
        }

        fs::write(&self.path, &data).with_context(|| format!("failed to write key store: {}", self.path))?;

        info!(path = %self.path, "CA key encrypted and saved to disk");
        Ok(())
    }

    /// Returns `true` if the key store file exists.
    pub fn exists(&self) -> bool {
        Path::new(&self.path).exists()
    }
}

// ─── In-memory encrypt/decrypt helpers ───────────────────────────────────────

/// Derive a 32-byte AES key from a passphrase and salt via Argon2id.
fn argon2_derive(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| anyhow::anyhow!("argon2 key derivation failed: {e}"))?;
    Ok(out)
}

/// Encrypt `plaintext` bytes with AES-256-GCM using an Argon2id-derived key and
/// a fresh random salt (M-12).
///
/// Output format: `BLOB_MAGIC_V1` || salt(16) || nonce(12) || ciphertext.
///
/// Rejects passphrases shorter than [`MIN_PASSPHRASE_LEN`].
pub fn encrypt_blob(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    if passphrase.len() < MIN_PASSPHRASE_LEN {
        anyhow::bail!("CA passphrase too short: require at least {MIN_PASSPHRASE_LEN} characters");
    }
    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let aes_key = argon2_derive(passphrase, &salt)?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("blob encryption failed: {e}"))?;

    let mut out = Vec::with_capacity(BLOB_HEADER_LEN + ciphertext.len());
    out.extend_from_slice(&BLOB_MAGIC_V1);
    out.extend_from_slice(&salt);
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a blob produced by [`encrypt_blob`].
///
/// Handles both the current Argon2id format and the legacy
/// `nonce || ciphertext` SHA-256 format for backward-compatible migration.
/// Returns an error on wrong passphrase or corrupted data.
pub fn decrypt_blob(data: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    if data.starts_with(&BLOB_MAGIC_V1) && data.len() >= BLOB_HEADER_LEN {
        // Current format: Argon2id-derived key with embedded random salt.
        let salt = data
            .get(BLOB_MAGIC_V1.len()..BLOB_MAGIC_V1.len() + SALT_LEN)
            .context("encrypted blob truncated: missing salt")?;
        let nonce_bytes = data
            .get(BLOB_MAGIC_V1.len() + SALT_LEN..BLOB_HEADER_LEN)
            .context("encrypted blob truncated: missing nonce")?;
        let ct = data
            .get(BLOB_HEADER_LEN..)
            .context("encrypted blob truncated: missing body")?;
        let aes_key = argon2_derive(passphrase, salt)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
        let nonce = Nonce::from_slice(nonce_bytes);
        return cipher
            .decrypt(nonce, ct)
            .map_err(|_| anyhow::anyhow!("blob decryption failed — wrong passphrase?"));
    }

    // Legacy format: nonce || ciphertext, SHA-256-derived key.
    if data.len() < NONCE_LEN {
        return Err(anyhow::anyhow!("encrypted blob too short (corrupt?)"));
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let cipher = legacy_cipher(passphrase);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("blob decryption failed — wrong passphrase?"))
}

/// Derive a legacy AES-256 cipher from a passphrase using single-round SHA-256.
///
/// Retained solely to decrypt blobs written before the M-12 Argon2id migration.
fn legacy_cipher(passphrase: &str) -> Aes256Gcm {
    let mut hasher = Sha256::new();
    hasher.update(b"prx-waf-cluster-ca-key-v1:");
    hasher.update(passphrase.as_bytes());
    let derived: [u8; 32] = hasher.finalize().into();
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    const PASSPHRASE: &str = "test-passphrase-16chars";

    /// Reproduce the pre-M-12 on-disk format (nonce || ct, SHA-256 key).
    fn legacy_encrypt_blob(plaintext: &[u8], passphrase: &str) -> Vec<u8> {
        let cipher = legacy_cipher(passphrase);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct = cipher.encrypt(&nonce, plaintext).expect("legacy encrypt");
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        out
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = env::temp_dir();
        let path = dir.join("test_cluster_ca_key_m12.bin");
        let store = KeyStore::new(path.to_str().unwrap());

        let fake_key_pem = "-----BEGIN PRIVATE KEY-----\nfake-key-for-testing\n-----END PRIVATE KEY-----\n";

        store.save_ca_key(fake_key_pem, PASSPHRASE).unwrap();
        assert!(store.exists());

        // On-disk blob must be in the new (magic-prefixed) format.
        let raw = std::fs::read(&path).unwrap();
        assert!(raw.starts_with(&BLOB_MAGIC_V1));

        let loaded = store.load_ca_key(PASSPHRASE).unwrap();
        assert_eq!(loaded, fake_key_pem);

        // Wrong passphrase must fail
        assert!(store.load_ca_key("wrong-passphrase-16c").is_err());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn new_blob_roundtrip() {
        let enc = encrypt_blob(b"top-secret-ca-key", PASSPHRASE).unwrap();
        assert!(enc.starts_with(&BLOB_MAGIC_V1));
        let dec = decrypt_blob(&enc, PASSPHRASE).unwrap();
        assert_eq!(dec, b"top-secret-ca-key");
    }

    #[test]
    fn decrypts_legacy_sha256_blob() {
        let legacy = legacy_encrypt_blob(b"old-ca-key-material", PASSPHRASE);
        // New code must still decrypt the old, unsalted format for migration.
        let dec = decrypt_blob(&legacy, PASSPHRASE).unwrap();
        assert_eq!(dec, b"old-ca-key-material");
    }

    #[test]
    fn short_passphrase_is_rejected() {
        assert!(
            encrypt_blob(b"data", "short").is_err(),
            "sub-16-char passphrase must be rejected"
        );
    }

    #[test]
    fn distinct_salts_produce_distinct_blobs() {
        let a = encrypt_blob(b"same", PASSPHRASE).unwrap();
        let b = encrypt_blob(b"same", PASSPHRASE).unwrap();
        assert_ne!(a, b, "random salt+nonce must randomise blobs");
    }
}
