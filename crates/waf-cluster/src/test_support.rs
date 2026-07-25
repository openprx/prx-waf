//! Shared certificate helpers for the in-crate unit tests.
//!
//! Every election test needs a cluster CA plus per-node signing identities under
//! it; building that by hand in each test module obscures what the test is
//! actually asserting.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use crate::crypto::ca::CertificateAuthority;
use crate::crypto::node_cert::NodeCertificate;
use crate::crypto::vote::ClusterIdentity;
use crate::protocol::SignedGrant;

/// A throwaway cluster PKI: one CA that mints node identities on demand.
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

    /// Mint a signing identity for `node_id` under this CA.
    pub fn identity(&self, node_id: &str) -> Arc<ClusterIdentity> {
        let cert = NodeCertificate::generate(node_id, &self.ca, 365).expect("node cert");
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
}
