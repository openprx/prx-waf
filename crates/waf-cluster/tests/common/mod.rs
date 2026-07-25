//! Shared cluster-PKI helpers for the integration tests.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use waf_cluster::crypto::{ca::CertificateAuthority, node_cert::NodeCertificate, vote::ClusterIdentity};
use waf_cluster::protocol::{ElectionResult, SignedGrant};

/// A throwaway cluster PKI: one CA that mints node identities on demand.
///
/// Two `TestPki` instances are two mutually distrusting clusters, which is how
/// the tests build "certificate issued by a CA we do not trust" ballots.
pub struct TestPki {
    ca: CertificateAuthority,
}

impl TestPki {
    /// Generate a fresh cluster CA and install the ring crypto provider.
    pub fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        Self {
            ca: CertificateAuthority::generate(365).expect("test CA"),
        }
    }

    /// The CA everything under this PKI chains to.
    pub const fn ca(&self) -> &CertificateAuthority {
        &self.ca
    }

    /// Mint a node certificate under this CA.
    pub fn node_cert(&self, node_id: &str) -> NodeCertificate {
        NodeCertificate::generate(node_id, &self.ca, 365).expect("node cert")
    }

    /// Mint a signing identity for `node_id` under this CA.
    pub fn identity(&self, node_id: &str) -> Arc<ClusterIdentity> {
        let cert = self.node_cert(node_id);
        let ca_der = self.ca.cert_der().expect("CA DER");
        Arc::new(ClusterIdentity::new(&cert.cert_pem, &cert.key_pem, &ca_der).expect("cluster identity"))
    }

    /// A single grant: `voter` votes for `candidate` in `term`.
    pub fn grant(&self, voter: &str, term: u64, candidate: &str) -> SignedGrant {
        self.identity(voter).sign_grant(term, candidate)
    }

    /// A whole ballot: every listed voter grants `candidate` its vote in `term`.
    pub fn grants(&self, voters: &[&str], term: u64, candidate: &str) -> Vec<SignedGrant> {
        voters.iter().map(|v| self.grant(v, term, candidate)).collect()
    }

    /// An `ElectionResult` whose quorum certificate really is signed by `voters`.
    pub fn election_result(&self, term: u64, elected: &str, voters: &[&str]) -> ElectionResult {
        ElectionResult {
            term,
            elected_id: elected.to_string(),
            grants: self.grants(voters, term, elected),
        }
    }
}

/// A grant that is structurally well-formed but cryptographically worthless:
/// a genuine certificate for `voter` paired with a signature from a different
/// key of the same name.
pub fn signature_forgery(pki: &TestPki, voter: &str, term: u64, candidate: &str) -> SignedGrant {
    SignedGrant {
        cert_b64: pki.grant(voter, term, candidate).cert_b64,
        chain_b64: Vec::new(),
        signature_b64: pki.grant(voter, term, candidate).signature_b64,
    }
}
