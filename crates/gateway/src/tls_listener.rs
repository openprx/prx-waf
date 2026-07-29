//! Certificate material for the proxy's TLS listener.
//!
//! [`crate::ssl`] issues certificates and files them in the `certificates`
//! table. Until this module existed nothing read them back for serving: the
//! only other reader is the ACME loop's own "have I already got one of these?"
//! bookkeeping, so issuance and renewal formed a closed circuit that never
//! terminated a connection. This is the wire from that store to the listener.
//!
//! Two things about Pingora 0.8.1's rustls backend shape everything below.
//!
//! **It takes paths, not PEM.** `TlsSettings::intermediate` stores a
//! `cert_path`/`key_path` pair and `build()` loads them with
//! `load_certs_and_key_files` (`pingora-core-0.8.1/src/listeners/tls/rustls/mod.rs:31-33,54`).
//! A certificate that lives in Postgres therefore has to be written out before
//! the listener can be built, which [`materialize`] does into a directory the
//! caller has already vetted as private.
//!
//! **It panics on bad input.** That same `build()` is `panic!("Failed to load
//! provided certificates …")` on a load failure (:56-61) and `.unwrap()` on the
//! `with_single_cert` result (:73), and it runs inside `run_forever`, well past
//! the point where an error could be reported cleanly. So [`validate`] performs
//! exactly the same parse and pairing check first, and nothing reaches
//! `TlsSettings` until it has passed.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use waf_storage::Database;

/// File names the database-sourced certificate is written to.
const CERT_FILE_NAME: &str = "listener.crt";
const KEY_FILE_NAME: &str = "listener.key";

/// Where the certificate the listener will serve came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertOrigin {
    /// `[proxy] tls_cert_pem` / `tls_key_pem`, served from the configured paths
    /// as they are.
    ConfiguredFiles,
    /// The `certificates` table — what ACME issued and renews.
    AcmeStore {
        domain: String,
        not_after: Option<chrono::DateTime<chrono::Utc>>,
    },
}

impl CertOrigin {
    /// One clause naming the source, for the startup line.
    pub fn describe(&self) -> String {
        match self {
            Self::ConfiguredFiles => "[proxy] tls_cert_pem / tls_key_pem".to_string(),
            Self::AcmeStore { domain, not_after } => not_after.map_or_else(
                || format!("the certificates table, domain {domain}, no recorded expiry"),
                |expiry| {
                    format!(
                        "the certificates table, domain {domain}, valid until {}",
                        expiry.format("%Y-%m-%d %H:%M:%SZ")
                    )
                },
            ),
        }
    }
}

/// A certificate and key on disk, ready to hand to Pingora.
#[derive(Debug, Clone)]
pub struct TlsMaterial {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub origin: CertOrigin,
    /// Domains of the other usable certificates in the store, which this
    /// listener cannot serve because the backend has one certificate per
    /// endpoint. Empty when there are none.
    pub unserved_domains: Vec<String>,
}

/// The outcome of looking for something to serve on `[proxy] listen_addr_tls`.
#[derive(Debug, Clone)]
pub enum TlsPlan {
    Ready(Box<TlsMaterial>),
    /// No listener will be created. `reason` is a finished operator-facing
    /// sentence explaining which sources were consulted and what each said.
    Unavailable {
        reason: String,
    },
}

/// Parse a certificate chain and key, and check they belong together.
///
/// Deliberately the same three steps Pingora's `build()` takes, in the same
/// order and with the same protocol versions, so that a pair accepted here
/// cannot make it panic later. Errors carry the failing step because "invalid
/// certificate" alone does not distinguish a truncated PEM from a key that
/// belongs to a different certificate.
pub fn validate(cert_pem: &str, key_pem: &str) -> anyhow::Result<()> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls_pki_types::pem::PemObject as _;

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .context("the certificate PEM does not parse")?;
    if certs.is_empty() {
        bail!("the certificate PEM holds no CERTIFICATE block");
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).context("the private key PEM does not parse")?;

    rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("the certificate and the private key are not a pair")?;
    Ok(())
}

/// Write `cert_pem` and `key_pem` into `dir` and return their paths.
///
/// Both files are created 0600 and renamed into place, so a reader never sees a
/// half-written key and never sees one at the umask's mode. The caller owns the
/// directory's permissions; this only refuses to widen them.
fn materialize(dir: &Path, cert_pem: &str, key_pem: &str) -> anyhow::Result<(PathBuf, PathBuf)> {
    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;

    let cert_path = dir.join(CERT_FILE_NAME);
    let key_path = dir.join(KEY_FILE_NAME);
    write_private(&cert_path, cert_pem)?;
    write_private(&key_path, key_pem)?;
    Ok((cert_path, key_path))
}

fn write_private(path: &Path, contents: &str) -> anyhow::Result<()> {
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("cannot create {}", tmp.display()))?;
        file.write_all(contents.as_bytes())
            .with_context(|| format!("cannot write {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("cannot flush {}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("cannot move {} into place", path.display()))
}

/// A store row that has everything needed to serve.
struct UsableCert {
    domain: String,
    cert_pem: String,
    key_pem: String,
    not_after: Option<chrono::DateTime<chrono::Utc>>,
}

/// The domains in `usable` that the certificate at `served` does not cover.
///
/// Names, not rows, and that distinction is the whole function. Renewal inserts
/// a new certificate and leaves the superseded one active, so a domain renewed
/// once has two rows and a domain renewed ten times has eleven. Counting rows
/// would announce at WARN that this listener refuses to serve a hostname it is
/// serving right now, and would do it more loudly the longer the WAF had been
/// running.
fn unserved_domains(usable: &[UsableCert], served: usize) -> Vec<String> {
    let Some(served_domain) = usable.get(served).map(|c| c.domain.as_str()) else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for cert in usable {
        if cert.domain == served_domain || out.iter().any(|seen| seen == &cert.domain) {
            continue;
        }
        out.push(cert.domain.clone());
    }
    out
}

/// Decide what the TLS listener should serve.
///
/// Configured files win over the store, because an operator who names a path
/// has said which certificate this port presents and should not have that
/// silently overridden by whatever ACME provisioned last. Within the store the
/// candidates are tried in ascending domain order, which is stable across
/// restarts — "newest" would move the served certificate every time a host was
/// added — and the first that validates is used.
///
/// Ties inside one domain go to the most recent row, and that matters more than
/// it looks: renewal INSERTS rather than updates (`SslManager::request_certificate`
/// calls `create_certificate` every time) and leaves the superseded row active,
/// so a domain that has ever been renewed has several. The sort is stable and
/// the rows arrive newest-first from `list_certificates`, which is what makes
/// the freshest certificate for a domain the one that gets served.
///
/// `material_dir` is a thunk rather than a path because resolving one has a
/// cost — it creates and vets a private directory — that configured files do
/// not need to pay, and must not be able to fail a launch that never uses it.
pub async fn resolve<D>(
    configured_cert: Option<&str>,
    configured_key: Option<&str>,
    db: &Database,
    material_dir: D,
) -> TlsPlan
where
    D: FnOnce() -> anyhow::Result<PathBuf>,
{
    match (configured_cert, configured_key) {
        (Some(cert), Some(key)) => return from_configured_files(cert, key),
        (Some(_), None) => {
            return TlsPlan::Unavailable {
                reason:
                    "[proxy] tls_cert_pem is set but [proxy] tls_key_pem is not. Set both, or neither to fall back \
                         to the certificates table."
                        .to_string(),
            };
        }
        (None, Some(_)) => {
            return TlsPlan::Unavailable {
                reason:
                    "[proxy] tls_key_pem is set but [proxy] tls_cert_pem is not. Set both, or neither to fall back \
                         to the certificates table."
                        .to_string(),
            };
        }
        (None, None) => {}
    }

    let rows = match db.list_certificates(None).await {
        Ok(rows) => rows,
        Err(e) => {
            return TlsPlan::Unavailable {
                reason: format!(
                    "the certificates table could not be read ({e}), so no certificate could be resolved. Fix the \
                     database connection, or set [proxy] tls_cert_pem / tls_key_pem to serve from files instead."
                ),
            };
        }
    };

    let total = rows.len();
    let mut usable: Vec<UsableCert> = rows
        .into_iter()
        .filter(|c| c.status == "active")
        .filter_map(|c| {
            let (cert_pem, key_pem) = (c.cert_pem?, c.key_pem?);
            // ACME stores the leaf and its issuers together in cert_pem;
            // chain_pem is only populated by a manual upload that separated
            // them, and appending it there is what makes such a row serve a
            // complete chain.
            let cert_pem = match c.chain_pem {
                Some(chain) if !chain.trim().is_empty() => format!("{}\n{}", cert_pem.trim_end(), chain.trim_start()),
                _ => cert_pem,
            };
            Some(UsableCert {
                domain: c.domain,
                cert_pem,
                key_pem,
                not_after: c.not_after,
            })
        })
        .collect();
    usable.sort_by(|a, b| a.domain.cmp(&b.domain));

    if usable.is_empty() {
        return TlsPlan::Unavailable {
            reason: format!(
                "no usable certificate exists: the certificates table holds {total} row(s), none of them active with \
                 both a certificate and a private key. Provision one with ACME ([acme] enabled = true and a host with \
                 ssl = true), upload one through the management API, or set [proxy] tls_cert_pem / tls_key_pem."
            ),
        };
    }

    let material_dir = match material_dir() {
        Ok(dir) => dir,
        Err(e) => {
            return TlsPlan::Unavailable {
                reason: format!(
                    "{e:#} Pingora's rustls backend loads certificates from paths rather than from memory, so a \
                     certificate held in the database cannot be served without one."
                ),
            };
        }
    };

    let mut rejected = Vec::new();
    for (index, candidate) in usable.iter().enumerate() {
        if let Err(e) = validate(&candidate.cert_pem, &candidate.key_pem) {
            rejected.push(format!("{}: {e:#}", candidate.domain));
            continue;
        }
        let (cert_path, key_path) = match materialize(&material_dir, &candidate.cert_pem, &candidate.key_pem) {
            Ok(paths) => paths,
            Err(e) => {
                return TlsPlan::Unavailable {
                    reason: format!(
                        "the certificate for {} is valid but could not be written to {}: {e:#}. That directory has to \
                         be writable by this process because Pingora's rustls backend loads certificates from paths, \
                         not from memory.",
                        candidate.domain,
                        material_dir.display()
                    ),
                };
            }
        };
        let unserved_domains = unserved_domains(&usable, index);
        return TlsPlan::Ready(Box::new(TlsMaterial {
            cert_path,
            key_path,
            origin: CertOrigin::AcmeStore {
                domain: candidate.domain.clone(),
                not_after: candidate.not_after,
            },
            unserved_domains,
        }));
    }

    TlsPlan::Unavailable {
        reason: format!(
            "every active certificate in the store failed to load ({}). Re-issue or re-upload them, or set [proxy] \
             tls_cert_pem / tls_key_pem to serve from files instead.",
            rejected.join("; ")
        ),
    }
}

/// Serve the operator's own files, checked but not copied.
fn from_configured_files(cert: &str, key: &str) -> TlsPlan {
    let cert_pem = match std::fs::read_to_string(cert) {
        Ok(pem) => pem,
        Err(e) => {
            return TlsPlan::Unavailable {
                reason: format!("[proxy] tls_cert_pem = {cert:?} could not be read: {e}"),
            };
        }
    };
    let key_pem = match std::fs::read_to_string(key) {
        Ok(pem) => pem,
        Err(e) => {
            return TlsPlan::Unavailable {
                reason: format!("[proxy] tls_key_pem = {key:?} could not be read: {e}"),
            };
        }
    };
    if let Err(e) = validate(&cert_pem, &key_pem) {
        return TlsPlan::Unavailable {
            reason: format!("[proxy] tls_cert_pem = {cert:?} with tls_key_pem = {key:?} is not usable: {e:#}"),
        };
    }
    TlsPlan::Ready(Box::new(TlsMaterial {
        cert_path: PathBuf::from(cert),
        key_path: PathBuf::from(key),
        origin: CertOrigin::ConfiguredFiles,
        unserved_domains: Vec::new(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn provider() {
        // Returns Err once a provider is installed; every test needs one and
        // only the first call can win.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    fn self_signed(domain: &str) -> (String, String) {
        let key_pair = rcgen::KeyPair::generate().expect("BUG: key generation must succeed in tests");
        let params =
            rcgen::CertificateParams::new(vec![domain.to_string()]).expect("BUG: SAN list must be valid in tests");
        let cert = params
            .self_signed(&key_pair)
            .expect("BUG: self-signing must succeed in tests");
        (cert.pem(), key_pair.serialize_pem())
    }

    #[test]
    fn accepts_a_matching_pair() {
        provider();
        let (cert, key) = self_signed("waf.test");
        assert!(validate(&cert, &key).is_ok());
    }

    #[test]
    fn rejects_a_key_from_a_different_certificate() {
        provider();
        let (cert, _) = self_signed("waf.test");
        let (_, other_key) = self_signed("other.test");
        let err = validate(&cert, &other_key).expect_err("a mismatched pair must not validate");
        assert!(format!("{err:#}").contains("not a pair"), "{err:#}");
    }

    #[test]
    fn rejects_pem_without_a_certificate() {
        provider();
        let (_, key) = self_signed("waf.test");
        let err = validate("not a certificate", &key).expect_err("garbage must not validate");
        assert!(format!("{err:#}").contains("no CERTIFICATE block"), "{err:#}");
    }

    #[test]
    fn materialized_key_is_private_and_reloadable() {
        provider();
        let (cert, key) = self_signed("waf.test");
        let dir = std::env::temp_dir().join(format!("prx-waf-tls-test-{}", std::process::id()));
        let (cert_path, key_path) = materialize(&dir, &cert, &key).expect("BUG: temp dir must be writable in tests");

        let mode = std::fs::metadata(&key_path)
            .expect("BUG: the key must exist after materialize")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the private key must not be readable by group or other");

        let reread_cert = std::fs::read_to_string(&cert_path).expect("BUG: the cert must be readable back");
        let reread_key = std::fs::read_to_string(&key_path).expect("BUG: the key must be readable back");
        assert!(validate(&reread_cert, &reread_key).is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn one_configured_path_without_the_other_is_refused() {
        let plan = from_configured_files("/nonexistent/cert.pem", "/nonexistent/key.pem");
        match plan {
            TlsPlan::Unavailable { reason } => assert!(reason.contains("tls_cert_pem"), "{reason}"),
            TlsPlan::Ready(_) => panic!("a missing file must not produce a listener"),
        }
    }

    fn row(domain: &str) -> UsableCert {
        UsableCert {
            domain: domain.to_string(),
            cert_pem: String::new(),
            key_pem: String::new(),
            not_after: None,
        }
    }

    #[test]
    fn renewed_rows_of_the_served_domain_are_not_reported_as_unserved() {
        // What the store looks like after `waf.test` has been renewed twice.
        let usable = [row("waf.test"), row("waf.test"), row("waf.test")];
        assert!(unserved_domains(&usable, 0).is_empty());
    }

    #[test]
    fn each_other_domain_is_named_once_however_many_rows_it_has() {
        let usable = [
            row("a.test"),
            row("b.test"),
            row("b.test"),
            row("c.test"),
            row("a.test"),
        ];
        assert_eq!(
            unserved_domains(&usable, 0),
            vec!["b.test".to_string(), "c.test".to_string()]
        );
    }

    #[test]
    fn nothing_is_unserved_when_nothing_is_served() {
        assert!(unserved_domains(&[], 0).is_empty());
        assert!(unserved_domains(&[row("a.test")], 7).is_empty());
    }

    #[test]
    fn origin_describes_the_store_row() {
        let origin = CertOrigin::AcmeStore {
            domain: "waf.test".to_string(),
            not_after: None,
        };
        assert!(origin.describe().contains("waf.test"));
        assert!(CertOrigin::ConfiguredFiles.describe().contains("tls_cert_pem"));
    }
}
