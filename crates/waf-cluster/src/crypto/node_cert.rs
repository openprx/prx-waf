//! Per-node TLS certificate management.
//!
//! Each cluster node gets an Ed25519 certificate signed by the cluster CA.
//! All node certs include `CLUSTER_SERVER_NAME` as a SAN so the SNI check
//! passes when connecting with `ServerName` "cluster.prx-waf".

use anyhow::{Context, Result};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose, PKCS_ED25519};
use rustls_pki_types::pem::PemObject as _;
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
        let issuer = ca.as_rcgen_issuer().context("failed to reconstruct CA")?;

        let node_key = KeyPair::generate_for(&PKCS_ED25519).context("failed to generate node Ed25519 keypair")?;

        // Both the fixed cluster server name (for SNI matching) and the node_id
        // are included as DNS SANs.
        let mut node_params = CertificateParams::new(vec![CLUSTER_SERVER_NAME.to_owned(), node_id.to_owned()])
            .context("invalid SAN for node certificate")?;

        node_params.not_before = OffsetDateTime::now_utc();
        node_params.not_after = OffsetDateTime::now_utc() + time::Duration::days(i64::from(validity_days));

        // AUD-L4: state the certificate's purpose instead of leaving KU/EKU
        // unset (rcgen defaults to empty vectors, which emit no extension at all
        // and therefore constrain nothing). Ed25519 only ever signs, so
        // `digitalSignature` is the sole key usage; TLS 1.3 needs nothing more.
        //
        // Both TLS EKUs are present on purpose: cluster nodes form a full mesh
        // in which every node is simultaneously a QUIC server (accepting peers)
        // and a QUIC client (dialling seeds), so one identity legitimately plays
        // both roles. Splitting them would need two key pairs per node and a
        // provisioning change; the win here is that the certificate is now
        // scoped to TLS peer authentication and can no longer be used for
        // unrelated purposes such as code or OCSP signing.
        node_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        node_params.extended_key_usages =
            vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];

        let node_cert = node_params
            .signed_by(&node_key, &issuer)
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
        rustls::pki_types::CertificateDer::pem_slice_iter(self.cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .context("failed to parse node certificate chain PEM")
    }

    /// Parse the node private key PEM into a `PrivateKeyDer` for rustls.
    pub fn private_key_der(&self) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
        rustls::pki_types::PrivateKeyDer::from_pem_slice(self.key_pem.as_bytes())
            .context("no private key found in node key PEM")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ca::CertificateAuthority;
    use rustls::pki_types::CertificateDer;
    use x509_parser::prelude::{FromDer, X509Certificate};

    /// Parse the leaf certificate out of a PEM chain for extension inspection.
    fn with_leaf<T>(cert_pem: &str, f: impl FnOnce(&X509Certificate<'_>) -> T) -> T {
        let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("parse chain");
        let der = chain.first().expect("non-empty chain").as_ref().to_vec();
        let (_, cert) = X509Certificate::from_der(&der).expect("parse leaf");
        f(&cert)
    }

    /// **Attack scenario ④ (control)** — node certificates must declare what
    /// they may be used for. Before the fix rcgen emitted no KU/EKU extension at
    /// all, so the certificate placed no constraint on its own use.
    #[test]
    fn node_cert_declares_key_usage_and_eku() {
        let ca = CertificateAuthority::generate(3650).unwrap();
        let node_cert = NodeCertificate::generate("ku-node", &ca, 365).unwrap();

        with_leaf(&node_cert.cert_pem, |cert| {
            let ku = cert
                .key_usage()
                .expect("read keyUsage")
                .expect("node cert must carry a keyUsage extension")
                .value;
            assert!(ku.digital_signature(), "Ed25519 TLS auth needs digitalSignature");
            assert!(!ku.key_cert_sign(), "a leaf must not be able to sign certificates");
            assert!(!ku.crl_sign());

            let eku = cert
                .extended_key_usage()
                .expect("read EKU")
                .expect("node cert must carry an extendedKeyUsage extension")
                .value;
            // Full-mesh cluster: every node is both a QUIC server and a client.
            assert!(eku.server_auth, "needed to accept peer connections");
            assert!(eku.client_auth, "needed to dial seeds");
            assert!(!eku.any, "must not be an unconstrained anyExtendedKeyUsage");
            assert!(!eku.code_signing);
            assert!(!eku.ocsp_signing);
        });
    }

    /// The CA must assert `keyCertSign`, otherwise nothing in its certificate
    /// says it is allowed to issue the node certificates it signs.
    #[test]
    fn ca_cert_declares_cert_signing_usage() {
        let ca = CertificateAuthority::generate(3650).unwrap();
        with_leaf(ca.cert_pem(), |cert| {
            let ku = cert
                .key_usage()
                .expect("read keyUsage")
                .expect("CA cert must carry a keyUsage extension")
                .value;
            assert!(ku.key_cert_sign(), "a CA must assert keyCertSign");
            assert!(ku.crl_sign());
            assert!(cert.is_ca(), "basicConstraints CA must still be set");
            assert!(
                cert.extended_key_usage().expect("read EKU").is_none(),
                "an EKU on the root would constrain every certificate beneath it"
            );
        });
    }

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
