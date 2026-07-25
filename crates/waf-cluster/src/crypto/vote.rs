//! Signed vote grants — the quorum certificate behind every election (H-12).
//!
//! # Why
//!
//! Vote grants used to be unicast, unsigned echoes: only the candidate ever saw
//! them, and the `ElectionResult` it broadcast was a self-declared list of voter
//! names that no receiver could recount. H-11 closed the worst of that by
//! anchoring acceptance to the receiver's own vote, but a candidate that had
//! genuinely collected a *minority* of votes could still fabricate the rest of
//! the ballot and be recognised as Main by exactly those nodes that had voted
//! for it — their local anchor really did hold, and they had no way to check the
//! remaining names.
//!
//! A [`SignedGrant`] makes a vote grant verifiable by **any** holder of the
//! cluster CA certificate: the voter signs `(term, candidate_id)` with the same
//! Ed25519 key that backs its mTLS identity and ships the signature together
//! with its CA-issued leaf certificate. A receiver validates the certificate
//! chain, recovers the voter's `node_id` from the certificate SAN (never from a
//! self-declared field), and checks the signature. Counting the distinct voters
//! that survive all three steps *is* recounting the ballot, so a fabricated
//! quorum is now infeasible rather than merely inconvenient.
//!
//! # Signed payload
//!
//! ```text
//! prx-waf/cluster/vote-grant/v1\n{term:016x}\n{candidate_id}
//! ```
//!
//! The leading domain string keeps this signature space disjoint from every
//! other use of the node key — in particular from TLS 1.3 `CertificateVerify`,
//! whose payload always starts with 64 `0x20` bytes. `term` is fixed-width so
//! the trailing variable-length `candidate_id` cannot be shifted between fields,
//! which is what binds a grant to exactly one term **and** one candidate: a
//! grant cannot be replayed into a later term, nor moved to another candidate.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::Engine as _;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;
use rustls_pki_types::pem::PemObject as _;
use x509_parser::oid_registry::OID_SIG_ED25519;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::protocol::SignedGrant;
use crate::transport::identity::node_id_from_cert_der;

/// Domain separator prefixed to every signed grant payload.
const GRANT_DOMAIN: &str = "prx-waf/cluster/vote-grant/v1";

/// Largest voter certificate accepted in a grant, in DER bytes.
///
/// Cluster leaf certificates are Ed25519 and well under 1 KiB; the bound exists
/// so a hostile ballot cannot make us decode megabytes per entry.
const MAX_CERT_DER_LEN: usize = 8 * 1024;

/// Ed25519 signature length in bytes.
const ED25519_SIG_LEN: usize = 64;

/// Largest intermediate chain accepted in a grant.
///
/// This crate mints a single-level PKI (root signs leaves), so the normal value
/// is zero; the allowance exists for externally provisioned deployments. Each
/// extra certificate is path-validation work an authenticated peer can ask for,
/// so it stays small.
const MAX_CHAIN_DEPTH: usize = 4;

/// Bytes a voter signs to grant its vote for `term` to `candidate_id`.
fn grant_payload(term: u64, candidate_id: &str) -> Vec<u8> {
    format!("{GRANT_DOMAIN}\n{term:016x}\n{candidate_id}").into_bytes()
}

/// This node's election signing identity plus the trust anchor used to verify
/// everybody else's grants.
///
/// Built once at startup from the same certificate material the QUIC transport
/// presents, so a grant's signer is provably the same principal that
/// authenticates the mTLS connections (H-9).
pub struct ClusterIdentity {
    /// `node_id` recovered from this node's own certificate SAN.
    node_id: String,
    /// Ed25519 key backing the node certificate — never log or export.
    signing_key: Ed25519KeyPair,
    /// This node's leaf certificate, DER, base64 — shipped with every grant.
    cert_b64: String,
    /// Intermediates between that leaf and the cluster root, DER, base64.
    /// Empty for the single-level PKI this crate generates.
    chain_b64: Vec<String>,
    /// Cluster CA trust anchor, wrapped in rustls' web-PKI path validator.
    verifier: Arc<dyn ClientCertVerifier>,
}

/// Deliberately hand-written: a derived `Debug` would print the signing key.
impl std::fmt::Debug for ClusterIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClusterIdentity")
            .field("node_id", &self.node_id)
            .finish_non_exhaustive()
    }
}

impl ClusterIdentity {
    /// Build the election identity from this node's certificate material.
    ///
    /// # Errors
    ///
    /// Returns an error when the certificate or key PEM cannot be parsed, the
    /// private key is not a PKCS#8 Ed25519 key, the key does not match the
    /// certificate's public key, the certificate carries no `node_id` SAN, or
    /// the CA certificate cannot be used as a trust anchor.
    pub fn new(node_cert_pem: &str, node_key_pem: &str, ca_cert_der: &CertificateDer<'static>) -> Result<Self> {
        let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(node_cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .context("failed to parse node certificate PEM for the election identity")?;
        let leaf = chain
            .first()
            .context("node certificate PEM contains no certificate")?
            .clone();

        let key_der = PrivateKeyDer::from_pem_slice(node_key_pem.as_bytes())
            .context("no private key found in the node key PEM")?;
        let signing_key = load_ed25519_key(key_der.secret_der())?;

        // A key that does not match the certificate would produce grants nobody
        // can verify; catching it at startup beats a silent election stall.
        let cert_public_key = ed25519_public_key(leaf.as_ref())?;
        anyhow::ensure!(
            signing_key.public_key().as_ref() == cert_public_key.as_slice(),
            "node private key does not match the public key in the node certificate"
        );

        let node_id = node_id_from_cert_der(leaf.as_ref())?;

        let mut roots = RootCertStore::empty();
        roots
            .add(ca_cert_der.clone())
            .context("failed to add the cluster CA to the vote-grant trust anchor")?;
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .context("failed to build the vote-grant certificate verifier")?;

        let chain_b64 = chain
            .iter()
            .skip(1)
            .take(MAX_CHAIN_DEPTH)
            .map(|c| base64::engine::general_purpose::STANDARD.encode(c.as_ref()))
            .collect();

        Ok(Self {
            node_id,
            signing_key,
            cert_b64: base64::engine::general_purpose::STANDARD.encode(leaf.as_ref()),
            chain_b64,
            verifier,
        })
    }

    /// The `node_id` proven by this node's own certificate.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Sign a vote grant for `candidate_id` in `term`.
    pub fn sign_grant(&self, term: u64, candidate_id: &str) -> SignedGrant {
        let signature = self.signing_key.sign(&grant_payload(term, candidate_id));
        SignedGrant {
            cert_b64: self.cert_b64.clone(),
            chain_b64: self.chain_b64.clone(),
            signature_b64: base64::engine::general_purpose::STANDARD.encode(signature.as_ref()),
        }
    }

    /// Verify `grant` as a vote for `candidate_id` in `term`.
    ///
    /// Returns the voter's `node_id`, taken from the certificate SAN — never
    /// from anything the sender could choose.
    ///
    /// # Errors
    ///
    /// Returns an error when the encoded certificate or signature is malformed
    /// or oversized, the certificate does not chain to the cluster CA (or is
    /// outside its validity window), it carries no `node_id` SAN, its key is not
    /// Ed25519, or the signature does not cover exactly this `(term,
    /// candidate_id)` pair.
    pub fn verify_grant(&self, grant: &SignedGrant, term: u64, candidate_id: &str) -> Result<String> {
        let cert_der = decode_bounded(&grant.cert_b64, MAX_CERT_DER_LEN, "voter certificate")?;
        let signature = decode_bounded(&grant.signature_b64, ED25519_SIG_LEN, "vote grant signature")?;
        anyhow::ensure!(
            signature.len() == ED25519_SIG_LEN,
            "vote grant signature is {} bytes, expected {ED25519_SIG_LEN}",
            signature.len()
        );
        anyhow::ensure!(
            grant.chain_b64.len() <= MAX_CHAIN_DEPTH,
            "vote grant carries {} intermediates, over the {MAX_CHAIN_DEPTH} limit",
            grant.chain_b64.len()
        );
        let intermediates = grant
            .chain_b64
            .iter()
            .map(|c| decode_bounded(c, MAX_CERT_DER_LEN, "voter intermediate certificate").map(CertificateDer::from))
            .collect::<Result<Vec<_>>>()?;

        let cert = CertificateDer::from(cert_der);
        self.verifier
            .verify_client_cert(&cert, &intermediates, now_unix_time())
            .map_err(|e| anyhow::anyhow!("voter certificate is not valid under the cluster CA: {e}"))?;

        let voter_id = node_id_from_cert_der(cert.as_ref())?;
        let public_key = ed25519_public_key(cert.as_ref())?;
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(&grant_payload(term, candidate_id), &signature)
            .map_err(|_| {
                anyhow::anyhow!("vote grant signature does not cover term {term} for candidate '{candidate_id}'")
            })?;

        Ok(voter_id)
    }
}

/// Load a PKCS#8 Ed25519 private key, accepting both the v2 encoding rcgen
/// emits and the v1 encoding other tooling (e.g. `openssl genpkey`) produces.
fn load_ed25519_key(pkcs8_der: &[u8]) -> Result<Ed25519KeyPair> {
    Ed25519KeyPair::from_pkcs8(pkcs8_der).or_else(|_| {
        Ed25519KeyPair::from_pkcs8_maybe_unchecked(pkcs8_der)
            .map_err(|e| anyhow::anyhow!("node private key is not a PKCS#8 Ed25519 key: {e}"))
    })
}

/// Extract the raw Ed25519 public key from a DER-encoded certificate.
fn ed25519_public_key(cert_der: &[u8]) -> Result<Vec<u8>> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| anyhow::anyhow!("failed to parse certificate for public key extraction: {e}"))?;
    let spki = cert.public_key();
    anyhow::ensure!(
        spki.algorithm.algorithm == OID_SIG_ED25519,
        "cluster node certificates must carry an Ed25519 public key"
    );
    Ok(spki.subject_public_key.data.to_vec())
}

/// Base64-decode `encoded`, refusing anything that could exceed `max_len` bytes
/// before the decode buffer is allocated.
fn decode_bounded(encoded: &str, max_len: usize, what: &str) -> Result<Vec<u8>> {
    // 4 base64 characters carry 3 bytes; the +4 covers padding.
    let ceiling = max_len.saturating_mul(4).saturating_div(3).saturating_add(4);
    anyhow::ensure!(
        encoded.len() <= ceiling,
        "encoded {what} is {} characters, over the {max_len}-byte limit",
        encoded.len()
    );
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .with_context(|| format!("{what} is not valid base64"))?;
    anyhow::ensure!(
        decoded.len() <= max_len,
        "decoded {what} is {} bytes, over the {max_len}-byte limit",
        decoded.len()
    );
    Ok(decoded)
}

/// Current wall-clock time in the shape rustls' path validator expects.
fn now_unix_time() -> UnixTime {
    UnixTime::since_unix_epoch(SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::ca::CertificateAuthority;
    use crate::crypto::node_cert::NodeCertificate;

    fn provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    fn identity(node_id: &str, ca: &CertificateAuthority) -> ClusterIdentity {
        let cert = NodeCertificate::generate(node_id, ca, 365).expect("node cert");
        let ca_der = ca.cert_der().expect("CA DER");
        ClusterIdentity::new(&cert.cert_pem, &cert.key_pem, &ca_der).expect("identity")
    }

    #[test]
    fn grant_signed_by_a_cluster_member_verifies() {
        provider();
        let ca = CertificateAuthority::generate(365).expect("CA");
        let voter = identity("voter-1", &ca);
        let checker = identity("checker", &ca);

        assert_eq!(voter.node_id(), "voter-1");
        let grant = voter.sign_grant(7, "winner");
        let recovered = checker.verify_grant(&grant, 7, "winner").expect("verify");
        assert_eq!(recovered, "voter-1", "the voter id comes from the certificate SAN");
    }

    #[test]
    fn grant_does_not_verify_for_another_term_or_candidate() {
        provider();
        let ca = CertificateAuthority::generate(365).expect("CA");
        let voter = identity("voter-1", &ca);
        let checker = identity("checker", &ca);
        let grant = voter.sign_grant(7, "winner");

        assert!(
            checker.verify_grant(&grant, 8, "winner").is_err(),
            "a grant must not replay into a later term"
        );
        assert!(
            checker.verify_grant(&grant, 6, "winner").is_err(),
            "a grant must not replay into an earlier term"
        );
        assert!(
            checker.verify_grant(&grant, 7, "someone-else").is_err(),
            "a grant must not be transferable to another candidate"
        );
    }

    #[test]
    fn certificate_from_a_foreign_ca_is_refused() {
        provider();
        let ca = CertificateAuthority::generate(365).expect("CA");
        let rogue_ca = CertificateAuthority::generate(365).expect("rogue CA");
        let outsider = identity("outsider", &rogue_ca);
        let checker = identity("checker", &ca);

        let grant = outsider.sign_grant(3, "winner");
        let err = checker
            .verify_grant(&grant, 3, "winner")
            .expect_err("a certificate outside the cluster CA must not verify");
        assert!(err.to_string().contains("not valid under the cluster CA"), "{err}");
    }

    #[test]
    fn tampered_signature_is_refused() {
        provider();
        let ca = CertificateAuthority::generate(365).expect("CA");
        let voter = identity("voter-1", &ca);
        let checker = identity("checker", &ca);

        let mut grant = voter.sign_grant(3, "winner");
        let mut raw = base64::engine::general_purpose::STANDARD
            .decode(&grant.signature_b64)
            .expect("decode");
        if let Some(first) = raw.first_mut() {
            *first ^= 0x01;
        }
        grant.signature_b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
        assert!(checker.verify_grant(&grant, 3, "winner").is_err());
    }

    #[test]
    fn malformed_and_oversized_material_is_refused() {
        provider();
        let ca = CertificateAuthority::generate(365).expect("CA");
        let checker = identity("checker", &ca);

        let junk = SignedGrant {
            cert_b64: "!!!not base64!!!".to_string(),
            chain_b64: Vec::new(),
            signature_b64: "AAAA".to_string(),
        };
        assert!(checker.verify_grant(&junk, 1, "winner").is_err());

        let huge = SignedGrant {
            cert_b64: "A".repeat(MAX_CERT_DER_LEN * 2),
            chain_b64: Vec::new(),
            signature_b64: "A".repeat(88),
        };
        let err = checker
            .verify_grant(&huge, 1, "winner")
            .expect_err("oversized certificates must be refused before decoding");
        assert!(err.to_string().contains("limit"), "{err}");
    }

    #[test]
    fn key_certificate_mismatch_is_caught_at_construction() {
        provider();
        let ca = CertificateAuthority::generate(365).expect("CA");
        let a = NodeCertificate::generate("node-a", &ca, 365).expect("cert a");
        let b = NodeCertificate::generate("node-b", &ca, 365).expect("cert b");
        let ca_der = ca.cert_der().expect("CA DER");

        let err = ClusterIdentity::new(&a.cert_pem, &b.key_pem, &ca_der)
            .expect_err("a key that does not match the certificate must be rejected");
        assert!(err.to_string().contains("does not match"), "{err}");
    }
}
