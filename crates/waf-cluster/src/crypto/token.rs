//! Join token generation and validation.
//!
//! Tokens are used by workers to authenticate to main during the join handshake.
//! An admin generates a token on main; the token is then provided to the worker
//! operator who includes it in the join request.
//!
//! # Token format (v2)
//!
//! ```text
//! v2.{expiry_ms_be_hex}.{nonce_hex}.{subject_hex}.{hmac_sha256_hex}
//! ```
//!
//! * `expiry_ms_be_hex` — absolute expiry, 16 hex digits.
//! * `nonce_hex` — 128 bits of randomness. Makes every token unique (two tokens
//!   minted in the same millisecond with the same TTL are no longer identical)
//!   and gives the Main a key to record the token as spent.
//! * `subject_hex` — hex of the `node_id` the token is bound to, or of `*` for a
//!   token any node may redeem once.
//! * HMAC-SHA256 over `v2|{expiry}|{nonce}|{subject}` with a key derived from
//!   the cluster CA private key, so only the CA-key holder can mint tokens.
//!
//! # Replay (AUD-L4)
//!
//! The v1 format signed nothing but the expiry: it carried no nonce, was not
//! bound to a node, and was never recorded as used, so anyone who read it out of
//! a config file could enrol arbitrary nodes for the whole TTL. v2 tokens are
//! rejected on replay by [`UsedJoinTokens`], which the Main consults on every
//! join, and can additionally be pinned to a single `node_id` at mint time.
//! v1 tokens are refused outright — mint a fresh one after upgrading.

use std::collections::HashMap;

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tracing::warn;

type HmacSha256 = Hmac<Sha256>;

/// Token format version prefix.
const TOKEN_VERSION: &str = "v2";

/// Subject value used by tokens that are not pinned to a specific node.
const WILDCARD_SUBJECT: &str = "*";

/// Validated contents of a join token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinTokenClaims {
    /// Absolute expiry (Unix ms).
    pub expiry_ms: u64,
    /// Unique token id — the replay-detection key.
    pub nonce: String,
    /// Node this token is pinned to; `None` for a wildcard token.
    pub subject: Option<String>,
}

/// Generate a join token valid for `ttl_ms` milliseconds that any node may
/// redeem **once**.
///
/// Prefer [`generate_token_for_node`] where the joining node is known: a
/// node-bound token cannot be redeemed by anyone else even before its first use.
///
/// `ca_key_pem` is used to derive the signing key so that only the holder
/// of the CA private key can generate valid tokens.
pub fn generate_token(ca_key_pem: &str, ttl_ms: u64) -> Result<String> {
    mint(ca_key_pem, ttl_ms, WILDCARD_SUBJECT)
}

/// Generate a join token valid for `ttl_ms` milliseconds and pinned to `node_id`.
///
/// The Main rejects the token if the authenticated joiner is not `node_id`.
pub fn generate_token_for_node(ca_key_pem: &str, ttl_ms: u64, node_id: &str) -> Result<String> {
    anyhow::ensure!(!node_id.is_empty(), "cannot mint a join token for an empty node_id");
    anyhow::ensure!(
        node_id != WILDCARD_SUBJECT,
        "'{WILDCARD_SUBJECT}' is reserved for wildcard join tokens"
    );
    mint(ca_key_pem, ttl_ms, node_id)
}

fn mint(ca_key_pem: &str, ttl_ms: u64, subject: &str) -> Result<String> {
    let now_ms = now_unix_ms();
    let expiry_ms = now_ms.checked_add(ttl_ms).context("token TTL overflow")?;
    let expiry_hex = format!("{expiry_ms:016x}");
    let nonce_hex = hex::encode(rand::random::<[u8; 16]>());
    let subject_hex = hex::encode(subject.as_bytes());

    let signature_hex = sign(ca_key_pem, &expiry_hex, &nonce_hex, &subject_hex)?;

    Ok(format!(
        "{TOKEN_VERSION}.{expiry_hex}.{nonce_hex}.{subject_hex}.{signature_hex}"
    ))
}

/// Verify a join token against the CA private key and the joiner's identity.
///
/// `presenter_node_id` is the node id proven by the joiner's mTLS certificate
/// (see [`crate::transport::identity`]) — never a self-declared one.
///
/// Verification covers: format and version, HMAC (constant time), expiry, and
/// the subject binding. Replay is **not** checked here; the caller must also
/// burn the returned claims through [`UsedJoinTokens::claim`].
///
/// # Errors
///
/// Returns an error when the token is malformed, of an unsupported version,
/// unsigned by this CA, expired, or pinned to a different node.
pub fn verify_token(ca_key_pem: &str, token: &str, presenter_node_id: &str) -> Result<JoinTokenClaims> {
    let mut parts = token.split('.');
    let (Some(version), Some(expiry_hex), Some(nonce_hex), Some(subject_hex), Some(signature_hex), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        anyhow::bail!("invalid token format: expected {TOKEN_VERSION}.expiry.nonce.subject.signature");
    };
    anyhow::ensure!(
        version == TOKEN_VERSION,
        "unsupported join token version (mint a new {TOKEN_VERSION} token)"
    );

    let expiry_ms = u64::from_str_radix(expiry_hex, 16).context("invalid token format: bad expiry hex")?;
    anyhow::ensure!(!nonce_hex.is_empty(), "invalid token format: empty nonce");
    let subject_bytes = hex::decode(subject_hex).context("invalid token format: bad subject hex")?;
    let subject = String::from_utf8(subject_bytes).context("invalid token format: non-UTF-8 subject")?;

    let provided_sig = hex::decode(signature_hex).context("invalid token format: bad signature hex")?;
    let signing_key = derive_signing_key(ca_key_pem);
    let mut mac = HmacSha256::new_from_slice(&signing_key).map_err(|e| anyhow::anyhow!("HMAC key error: {e}"))?;
    mac.update(signed_payload(expiry_hex, nonce_hex, subject_hex).as_bytes());
    mac.verify_slice(&provided_sig)
        .map_err(|_| anyhow::anyhow!("token signature verification failed"))?;

    let now_ms = now_unix_ms();
    if now_ms > expiry_ms {
        warn!(expiry_ms, now_ms, "Join token has expired");
        return Err(anyhow::anyhow!("join token has expired"));
    }

    let subject = if subject == WILDCARD_SUBJECT {
        None
    } else {
        Some(subject)
    };
    if let Some(bound_to) = subject.as_deref()
        && bound_to != presenter_node_id
    {
        return Err(anyhow::anyhow!(
            "join token is bound to another node (presented by '{presenter_node_id}')"
        ));
    }

    Ok(JoinTokenClaims {
        expiry_ms,
        nonce: nonce_hex.to_string(),
        subject,
    })
}

/// Record of join tokens already spent on this node.
///
/// Bounded: entries are pruned once expired, and the map never grows past its
/// capacity (the entry closest to expiry is evicted first). Only a holder of the
/// CA key can mint tokens, so an attacker cannot flood it.
pub struct UsedJoinTokens {
    seen: HashMap<String, SpentToken>,
    capacity: usize,
}

/// One spent token: who redeemed it and when it stops being replayable.
struct SpentToken {
    node_id: String,
    expiry_ms: u64,
}

impl UsedJoinTokens {
    /// Create a registry holding at most `capacity` unexpired token nonces.
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: HashMap::new(),
            capacity: capacity.max(1),
        }
    }

    /// Number of retained (unexpired) nonces.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Returns `true` when no token has been recorded.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Claim `claims` on behalf of `node_id`.
    ///
    /// First use records the nonce. A repeat presentation by the **same** node
    /// is accepted (worker restart / reconnect); a presentation by any other
    /// node is a replay and is refused.
    ///
    /// # Errors
    ///
    /// Returns an error when the nonce was already spent by a different node.
    pub fn claim(&mut self, claims: &JoinTokenClaims, node_id: &str, now_ms: u64) -> Result<()> {
        self.prune(now_ms);
        if let Some(spent) = self.seen.get(&claims.nonce) {
            if spent.node_id == node_id {
                return Ok(());
            }
            return Err(anyhow::anyhow!(
                "join token replay: nonce already redeemed by another node"
            ));
        }
        if self.seen.len() >= self.capacity {
            self.evict_soonest_expiring();
        }
        self.seen.insert(
            claims.nonce.clone(),
            SpentToken {
                node_id: node_id.to_string(),
                expiry_ms: claims.expiry_ms,
            },
        );
        Ok(())
    }

    /// Drop entries whose token has expired — a replay of an expired token is
    /// already refused by [`verify_token`].
    fn prune(&mut self, now_ms: u64) {
        self.seen.retain(|_, spent| spent.expiry_ms >= now_ms);
    }

    fn evict_soonest_expiring(&mut self) {
        let victim = self
            .seen
            .iter()
            .min_by_key(|(_, spent)| spent.expiry_ms)
            .map(|(nonce, _)| nonce.clone());
        if let Some(nonce) = victim {
            self.seen.remove(&nonce);
            warn!("Join-token replay cache is full; evicted the entry closest to expiry");
        }
    }
}

/// Bytes covered by the token HMAC.
fn signed_payload(expiry_hex: &str, nonce_hex: &str, subject_hex: &str) -> String {
    format!("{TOKEN_VERSION}|{expiry_hex}|{nonce_hex}|{subject_hex}")
}

fn sign(ca_key_pem: &str, expiry_hex: &str, nonce_hex: &str, subject_hex: &str) -> Result<String> {
    let signing_key = derive_signing_key(ca_key_pem);
    let mut mac = HmacSha256::new_from_slice(&signing_key).map_err(|e| anyhow::anyhow!("HMAC key error: {e}"))?;
    mac.update(signed_payload(expiry_hex, nonce_hex, subject_hex).as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
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
    #[allow(clippy::cast_possible_truncation)]
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    ms
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAKE_CA_KEY: &str = "-----BEGIN PRIVATE KEY-----\nfake-key-for-test\n-----END PRIVATE KEY-----\n";

    fn claims_of(token: &str, presenter: &str) -> JoinTokenClaims {
        verify_token(FAKE_CA_KEY, token, presenter).expect("token must verify")
    }

    #[test]
    fn generate_and_validate_token() {
        let token = generate_token(FAKE_CA_KEY, 3_600_000).unwrap(); // 1h TTL
        let claims = claims_of(&token, "worker-1");
        assert!(claims.subject.is_none(), "wildcard token has no subject binding");
        assert_eq!(claims.nonce.len(), 32, "128-bit nonce, hex encoded");
    }

    #[test]
    fn wrong_signing_key_rejected() {
        let token = generate_token(FAKE_CA_KEY, 3_600_000).unwrap();
        let other_key = "-----BEGIN PRIVATE KEY-----\ndifferent-key\n-----END PRIVATE KEY-----\n";
        assert!(verify_token(other_key, &token, "worker-1").is_err());
    }

    #[test]
    fn expired_token_rejected() {
        // TTL = 0ms → already expired
        let token = generate_token(FAKE_CA_KEY, 0).unwrap();
        // Sleep 1ms to ensure now > expiry
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert!(verify_token(FAKE_CA_KEY, &token, "worker-1").is_err());
    }

    #[test]
    fn malformed_token_rejected() {
        assert!(verify_token(FAKE_CA_KEY, "no-dot-separator", "w").is_err());
        assert!(verify_token(FAKE_CA_KEY, "xxxx.yyyy", "w").is_err());
        assert!(verify_token(FAKE_CA_KEY, "v2.a.b.c.d.e", "w").is_err());
    }

    /// AUD-L4: the unauthenticated v1 format (`expiry.signature`) is refused.
    #[test]
    fn legacy_v1_token_rejected() {
        let expiry_hex = format!("{:016x}", now_unix_ms() + 3_600_000);
        let signing_key = derive_signing_key(FAKE_CA_KEY);
        let mut mac = HmacSha256::new_from_slice(&signing_key).unwrap();
        mac.update(expiry_hex.as_bytes());
        let v1 = format!("{expiry_hex}.{}", hex::encode(mac.finalize().into_bytes()));
        assert!(
            verify_token(FAKE_CA_KEY, &v1, "worker-1").is_err(),
            "v1 tokens carry no nonce or binding and must not be accepted"
        );
    }

    /// AUD-L4: two tokens minted back-to-back with the same TTL must differ.
    #[test]
    fn tokens_are_unique_even_within_the_same_millisecond() {
        let a = generate_token(FAKE_CA_KEY, 3_600_000).unwrap();
        let b = generate_token(FAKE_CA_KEY, 3_600_000).unwrap();
        assert_ne!(a, b, "nonce must make every minted token unique");
        assert_ne!(claims_of(&a, "w").nonce, claims_of(&b, "w").nonce);
    }

    /// AUD-L4: a node-bound token is unusable by any other node.
    #[test]
    fn node_bound_token_rejected_for_other_node() {
        let token = generate_token_for_node(FAKE_CA_KEY, 3_600_000, "worker-1").unwrap();
        assert_eq!(claims_of(&token, "worker-1").subject.as_deref(), Some("worker-1"));
        let err = verify_token(FAKE_CA_KEY, &token, "worker-2")
            .expect_err("a token bound to worker-1 must not verify for worker-2");
        assert!(err.to_string().contains("bound to another node"));
    }

    #[test]
    fn node_bound_token_rejects_reserved_subject() {
        assert!(generate_token_for_node(FAKE_CA_KEY, 1000, "*").is_err());
        assert!(generate_token_for_node(FAKE_CA_KEY, 1000, "").is_err());
    }

    /// AUD-L4: a wildcard token stolen from a config file cannot enrol a second
    /// node, but the node that first used it may re-present it (restart).
    #[test]
    fn replay_by_another_node_is_rejected_same_node_may_reuse() {
        let mut used = UsedJoinTokens::new(16);
        let token = generate_token(FAKE_CA_KEY, 3_600_000).unwrap();
        let claims = claims_of(&token, "worker-1");
        let now = now_unix_ms();

        used.claim(&claims, "worker-1", now).expect("first use is accepted");
        used.claim(&claims, "worker-1", now)
            .expect("the same node may re-present its token after a restart");
        let err = used
            .claim(&claims, "rogue-2", now)
            .expect_err("a second node must not redeem the same token");
        assert!(err.to_string().contains("replay"));
        assert_eq!(used.len(), 1);
    }

    #[test]
    fn expired_entries_are_pruned_and_capacity_is_bounded() {
        let mut used = UsedJoinTokens::new(2);
        let now = 1_000_000_u64;
        for (i, expiry) in [now + 10, now + 20, now + 30].into_iter().enumerate() {
            let claims = JoinTokenClaims {
                expiry_ms: expiry,
                nonce: format!("nonce-{i}"),
                subject: None,
            };
            used.claim(&claims, "worker-1", now).expect("claim");
        }
        assert_eq!(used.len(), 2, "registry must stay within its capacity");

        // Once every retained token has expired the registry empties out.
        let claims = JoinTokenClaims {
            expiry_ms: now + 10_000,
            nonce: "fresh".to_string(),
            subject: None,
        };
        used.claim(&claims, "worker-1", now + 1_000).expect("claim");
        assert_eq!(used.len(), 1, "expired nonces are pruned");
        assert!(!used.is_empty());
    }
}
