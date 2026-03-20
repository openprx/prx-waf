//! Cluster root Certificate Authority generation and management.
//!
//! The first main node generates the CA on startup using Ed25519. The CA cert
//! is self-signed with 10-year validity and signs all node certificates.

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, PKCS_ED25519,
};
use time::OffsetDateTime;
use tracing::info;

/// Fixed internal cluster server name used as TLS SNI and SAN in all node certs.
pub const CLUSTER_SERVER_NAME: &str = "cluster.prx-waf";

/// Cluster root Certificate Authority.
///
/// Generated once by the first main node. The CA signs all node certificates
/// and is distributed to workers during the join handshake.
pub struct CertificateAuthority {
    cert_pem: String,
    key_pem: String,
}

impl CertificateAuthority {
    /// Generate a new self-signed Ed25519 CA keypair valid for `validity_days`.
    pub fn generate(validity_days: u32) -> Result<Self> {
        let key_pair = KeyPair::generate_for(&PKCS_ED25519)
            .context("failed to generate CA Ed25519 keypair")?;

        // CertificateParams::new() handles DNS SAN creation from strings
        let mut params = CertificateParams::new(vec![CLUSTER_SERVER_NAME.to_owned()])
            .context("invalid cluster server name for CA SAN")?;

        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + time::Duration::days(validity_days as i64);

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "prx-waf Cluster CA");
        dn.push(DnType::OrganizationName, "prx-waf");
        params.distinguished_name = dn;

        let cert = params
            .self_signed(&key_pair)
            .context("failed to self-sign CA certificate")?;

        info!(validity_days, "Generated new cluster CA certificate");

        Ok(Self {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
        })
    }

    /// Load an existing CA from PEM strings.
    pub fn from_pem(cert_pem: String, key_pem: String) -> Self {
        Self { cert_pem, key_pem }
    }

    /// Load only the CA certificate PEM without the private key.
    ///
    /// Useful for nodes that only need to verify peer certificates (e.g. worker
    /// nodes loading a pre-generated CA cert). Calling [`Self::as_rcgen_issuer`]
    /// on a cert-only instance will return an error.
    pub fn from_cert_pem(cert_pem: String) -> Self {
        Self {
            cert_pem,
            key_pem: String::new(),
        }
    }

    /// CA certificate as PEM string.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// CA private key as PEM string — never log this.
    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }

    /// Return the CA certificate DER bytes for use in rustls root stores.
    pub fn cert_der(&self) -> Result<rustls::pki_types::CertificateDer<'static>> {
        rustls_pemfile::certs(&mut self.cert_pem.as_bytes())
            .next()
            .context("CA PEM contains no certificate")?
            .context("failed to parse CA certificate DER")
    }

    /// Reconstruct rcgen issuer objects from stored PEM for signing node certificates.
    ///
    /// Creates a fresh CA cert with the same keypair and subject DN so that
    /// signed node certificates pass chain verification against the stored CA cert.
    /// (The Subject Key Identifier is derived from the public key, so it matches
    /// regardless of whether serial number / timestamps differ.)
    ///
    /// Returns an error if this CA was constructed without a private key
    /// (e.g. via [`Self::from_cert_pem`]).
    pub fn as_rcgen_issuer(&self) -> Result<(rcgen::Certificate, rcgen::KeyPair)> {
        anyhow::ensure!(
            !self.key_pem.is_empty(),
            "CA private key is not available — this CA was loaded without a key (cert-only mode)"
        );
        let ca_key =
            KeyPair::from_pem(&self.key_pem).context("failed to load CA private key PEM")?;

        let mut ca_params = CertificateParams::new(vec![CLUSTER_SERVER_NAME.to_owned()])
            .context("invalid cluster server name for CA reconstruction")?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "prx-waf Cluster CA");
        dn.push(DnType::OrganizationName, "prx-waf");
        ca_params.distinguished_name = dn;

        let ca_cert = ca_params
            .self_signed(&ca_key)
            .context("failed to reconstruct CA cert for signing")?;

        Ok((ca_cert, ca_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ca_roundtrip() {
        let ca = CertificateAuthority::generate(3650).unwrap();
        assert!(!ca.cert_pem().is_empty());
        assert!(!ca.key_pem().is_empty());
        assert!(ca.cert_pem().starts_with("-----BEGIN CERTIFICATE-----"));
        // Ed25519 private key PEM
        assert!(ca.key_pem().contains("PRIVATE KEY"));
        // Must be able to get DER
        ca.cert_der().unwrap();
    }

    #[test]
    fn from_pem_preserves_values() {
        let ca = CertificateAuthority::generate(365).unwrap();
        let cert_pem = ca.cert_pem().to_string();
        let key_pem = ca.key_pem().to_string();
        let ca2 = CertificateAuthority::from_pem(cert_pem.clone(), key_pem.clone());
        assert_eq!(ca2.cert_pem(), cert_pem);
        assert_eq!(ca2.key_pem(), key_pem);
    }

    #[test]
    fn rcgen_issuer_reconstruction() {
        let ca = CertificateAuthority::generate(3650).unwrap();
        let (cert, _key) = ca.as_rcgen_issuer().unwrap();
        // The reconstructed cert should be self-signed (CA)
        let _ = cert.pem();
    }
}
