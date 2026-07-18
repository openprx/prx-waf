//! Authenticated peer identity extraction (H-9).
//!
//! Every cluster node presents an mTLS certificate whose SANs contain both the
//! fixed [`CLUSTER_SERVER_NAME`] (for SNI matching) and the node's own
//! `node_id`.  Application-layer messages carry a self-declared `node_id`
//! (heartbeats, votes, join requests, …) which — without binding — a malicious
//! but validly-authenticated peer could forge to impersonate another node or
//! stuff ballot boxes during an election.
//!
//! [`authenticated_node_id`] recovers the *cryptographically authenticated*
//! node identity from the QUIC connection's peer certificate so callers can
//! assert that each message's declared identity matches the TLS-verified one.

use anyhow::{Context, Result};
use quinn::Connection;
use rustls::pki_types::CertificateDer;
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

use crate::crypto::ca::CLUSTER_SERVER_NAME;

/// Extract the authenticated `node_id` from a QUIC connection's peer certificate.
///
/// The peer certificate chain is verified by rustls against the cluster CA
/// during the mTLS handshake, so the SAN read here is trustworthy. The returned
/// id is the first SAN DNS name that is **not** the shared cluster server name.
///
/// # Errors
///
/// Returns an error if the peer presented no TLS identity (handshake not
/// mutually authenticated), the identity is of an unexpected type, the chain is
/// empty, the leaf cannot be parsed, or the certificate carries no node-id SAN.
pub fn authenticated_node_id(conn: &Connection) -> Result<String> {
    let identity = conn
        .peer_identity()
        .context("cluster peer presented no TLS identity (mTLS handshake incomplete)")?;
    let certs = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| anyhow::anyhow!("unexpected peer identity type from QUIC connection"))?;
    let leaf = certs.first().context("cluster peer certificate chain is empty")?;
    node_id_from_cert_der(leaf.as_ref())
}

/// Parse a DER-encoded leaf certificate and return its node-id SAN.
///
/// Kept separate from [`authenticated_node_id`] so it can be unit-tested without
/// a live QUIC connection.
pub(crate) fn node_id_from_cert_der(der: &[u8]) -> Result<String> {
    let (_, cert) =
        X509Certificate::from_der(der).map_err(|e| anyhow::anyhow!("failed to parse peer leaf certificate: {e}"))?;
    let san = cert
        .subject_alternative_name()
        .map_err(|e| anyhow::anyhow!("failed to read subjectAltName extension: {e}"))?
        .context("peer certificate has no subjectAltName extension")?;
    for gn in &san.value.general_names {
        if let GeneralName::DNSName(dns) = gn
            && *dns != CLUSTER_SERVER_NAME
        {
            return Ok((*dns).to_string());
        }
    }
    Err(anyhow::anyhow!(
        "peer certificate SAN contains no node_id DNS name (only the shared cluster server name)"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ca::CertificateAuthority;
    use crate::crypto::node_cert::NodeCertificate;
    use rustls_pki_types::pem::PemObject as _;

    fn leaf_der(cert_pem: &str) -> Vec<u8> {
        let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("parse cert chain");
        chain.first().expect("non-empty chain").as_ref().to_vec()
    }

    #[test]
    fn extracts_node_id_from_signed_cert() {
        let ca = CertificateAuthority::generate(365).expect("CA");
        let node = NodeCertificate::generate("worker-42", &ca, 365).expect("node cert");
        let der = leaf_der(&node.cert_pem);
        let id = node_id_from_cert_der(&der).expect("extract id");
        assert_eq!(id, "worker-42");
    }

    #[test]
    fn distinct_certs_yield_distinct_ids() {
        let ca = CertificateAuthority::generate(365).expect("CA");
        let a = NodeCertificate::generate("node-a", &ca, 365).expect("cert a");
        let b = NodeCertificate::generate("node-b", &ca, 365).expect("cert b");
        assert_eq!(node_id_from_cert_der(&leaf_der(&a.cert_pem)).expect("a"), "node-a");
        assert_eq!(node_id_from_cert_der(&leaf_der(&b.cert_pem)).expect("b"), "node-b");
    }

    #[test]
    fn rejects_garbage_der() {
        assert!(node_id_from_cert_der(b"not-a-certificate").is_err());
    }
}
