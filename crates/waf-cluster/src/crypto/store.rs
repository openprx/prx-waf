//! Encrypted on-disk store for the cluster CA private key.
//!
//! The CA key is encrypted at rest with AES-256-GCM using a passphrase-derived
//! key. The same patterns are used as in waf_common::crypto, but applied to raw
//! bytes (the CA key PEM) instead of config field strings.
//!
//! File format (binary):
//!   12 bytes  — AES-GCM nonce
//!   remaining — AES-GCM ciphertext (encrypted CA key PEM UTF-8 bytes)

use std::fs;
use std::path::Path;

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use tracing::info;

/// Encrypted on-disk store for the cluster CA private key.
pub struct KeyStore {
    path: String,
}

impl KeyStore {
    /// Create a new key store pointing at `path`.
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
        }
    }

    /// File path for the encrypted CA key.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Load and decrypt the CA private key PEM from disk.
    ///
    /// Returns the raw PEM string of the CA private key.
    pub fn load_ca_key(&self, passphrase: &str) -> Result<String> {
        let data = fs::read(&self.path)
            .with_context(|| format!("failed to read key store: {}", self.path))?;
        if data.len() < 12 {
            return Err(anyhow::anyhow!("key store file is too short (corrupt?)"));
        }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let cipher = make_cipher(passphrase);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("failed to decrypt CA key — wrong passphrase?"))?;
        String::from_utf8(plaintext).context("CA key PEM is not valid UTF-8")
    }

    /// Encrypt the CA private key PEM and persist it to disk.
    pub fn save_ca_key(&self, key_pem: &str, passphrase: &str) -> Result<()> {
        let cipher = make_cipher(passphrase);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, key_pem.as_bytes())
            .map_err(|e| anyhow::anyhow!("CA key encryption failed: {e}"))?;

        // Prepend nonce so it can be read back on load
        let mut data = Vec::with_capacity(nonce.len() + ciphertext.len());
        data.extend_from_slice(&nonce);
        data.extend_from_slice(&ciphertext);

        // Ensure parent directory exists
        if let Some(parent) = Path::new(&self.path).parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create dir: {}", parent.display()))?;
        }

        fs::write(&self.path, &data)
            .with_context(|| format!("failed to write key store: {}", self.path))?;

        info!(path = %self.path, "CA key encrypted and saved to disk");
        Ok(())
    }

    /// Returns `true` if the key store file exists.
    pub fn exists(&self) -> bool {
        Path::new(&self.path).exists()
    }
}

// ─── In-memory encrypt/decrypt helpers ───────────────────────────────────────

/// Encrypt `plaintext` bytes with AES-256-GCM using `passphrase`.
///
/// Output format: 12-byte nonce || ciphertext.
pub fn encrypt_blob(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let cipher = make_cipher(passphrase);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("blob encryption failed: {e}"))?;
    let mut out = Vec::with_capacity(nonce.len() + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a blob produced by [`encrypt_blob`].
///
/// Returns an error on wrong passphrase or corrupted data.
pub fn decrypt_blob(data: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    if data.len() < 12 {
        return Err(anyhow::anyhow!("encrypted blob too short (corrupt?)"));
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let cipher = make_cipher(passphrase);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("blob decryption failed — wrong passphrase?"))
}

/// Derive a 32-byte AES-256 key from a passphrase using SHA-256.
fn make_cipher(passphrase: &str) -> Aes256Gcm {
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

    #[test]
    fn save_and_load_roundtrip() {
        let dir = env::temp_dir();
        let path = dir.join("test_cluster_ca_key.bin");
        let store = KeyStore::new(path.to_str().unwrap());

        let fake_key_pem =
            "-----BEGIN PRIVATE KEY-----\nfake-key-for-testing\n-----END PRIVATE KEY-----\n";
        let passphrase = "test-passphrase-123";

        store.save_ca_key(fake_key_pem, passphrase).unwrap();
        assert!(store.exists());

        let loaded = store.load_ca_key(passphrase).unwrap();
        assert_eq!(loaded, fake_key_pem);

        // Wrong passphrase must fail
        assert!(store.load_ca_key("wrong-passphrase").is_err());

        // Cleanup
        let _ = std::fs::remove_file(&path);
    }
}
