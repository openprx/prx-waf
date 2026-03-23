//! Per-node TLS certificate management.
//!
//! Each cluster node gets an Ed25519 certificate signed by the cluster CA.
//! All node certs include `CLUSTER_SERVER_NAME` as a SAN so the SNI check
//! passes when connecting with `ServerName` "cluster.prx-waf".

use anyhow::{Context, Result};
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use time::OffsetDateTime;
use tracing::info;

use super::ca::{CLUSTER_SERVER_NAME, CertificateAuthority};

/// Generated node certificate material ready for use in Quinn mTLS.
pub struct NodeCertificate {
    /// Signed node cert PEM (presented to peers during TLS handshake)
    pub cert_pem: String,
    /// Node private key PEM — never log this
    pub key_pem: String,
}

impl NodeCertificate {
    /// Generate a new Ed25519 node certificate signed by the cluster CA.
    ///
    /// SANs include both `CLUSTER_SERVER_NAME` (for SNI matching on the server
    /// side) and `node_id` (for node-level identification).
    ///
    /// # Errors
    ///
    /// Returns an error if CA reconstruction, keypair generation, or certificate
    /// signing fails.
    pub fn generate(node_id: &str, ca: &CertificateAuthority, validity_days: u32) -> Result<Self> {
        let (ca_cert, ca_key) = ca.as_rcgen_issuer().context("failed to reconstruct CA")?;

        let node_key = KeyPair::generate_for(&PKCS_ED25519).context("failed to generate node Ed25519 keypair")?;

        // Both the fixed cluster server name (for SNI matching) and the node_id
        // are included as DNS SANs.
        let mut node_params = CertificateParams::new(vec![CLUSTER_SERVER_NAME.to_owned(), node_id.to_owned()])
            .context("invalid SAN for node certificate")?;

        node_params.not_before = OffsetDateTime::now_utc();
        node_params.not_after = OffsetDateTime::now_utc() + time::Duration::days(i64::from(validity_days));

        let node_cert = node_params
            .signed_by(&node_key, &ca_cert, &ca_key)
            .context("failed to sign node certificate with CA")?;

        info!(node_id, validity_days, "Generated node certificate");

        Ok(Self {
            cert_pem: node_cert.pem(),
            key_pem: node_key.serialize_pem(),
        })
    }

    /// Load node cert from PEM strings (e.g., read from disk on restart).
    pub const fn from_pem(cert_pem: String, key_pem: String) -> Self {
        Self { cert_pem, key_pem }
    }

    /// Parse the node cert PEM into DER bytes for use in rustls cert chains.
    pub fn cert_chain_der(&self) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
        rustls_pemfile::certs(&mut self.cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .context("failed to parse node certificate chain PEM")
    }

    /// Parse the node private key PEM into a `PrivateKeyDer` for rustls.
    pub fn private_key_der(&self) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
        rustls_pemfile::private_key(&mut self.key_pem.as_bytes())
            .context("failed to read node private key PEM")?
            .context("no private key found in node key PEM")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ca::CertificateAuthority;

    #[test]
    fn generate_and_parse_node_cert() {
        let ca = CertificateAuthority::generate(3650).unwrap();
        let node_cert = NodeCertificate::generate("test-node-001", &ca, 365).unwrap();

        assert!(!node_cert.cert_pem.is_empty());
        assert!(!node_cert.key_pem.is_empty());

        let chain = node_cert.cert_chain_der().unwrap();
        assert!(!chain.is_empty());
        node_cert.private_key_der().unwrap();
    }

    #[test]
    fn from_pem_roundtrip() {
        let ca = CertificateAuthority::generate(3650).unwrap();
        let node_cert = NodeCertificate::generate("node-roundtrip", &ca, 365).unwrap();

        let loaded = NodeCertificate::from_pem(node_cert.cert_pem.clone(), node_cert.key_pem.clone());
        assert_eq!(loaded.cert_pem, node_cert.cert_pem);
        assert_eq!(loaded.key_pem, node_cert.key_pem);
    }
}
