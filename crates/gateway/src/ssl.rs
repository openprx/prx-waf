//! SSL/TLS Certificate Automation
//!
//! Manages TLS certificates for WAF-protected sites:
//!   - Storage in `PostgreSQL` (PEM format)
//!   - Let's Encrypt via ACME HTTP-01 challenge (instant-acme crate)
//!   - CSR generation via rcgen
//!   - Auto-renewal 30 days before expiry
//!   - Manual certificate upload API
//!
//! # ACME HTTP-01 Challenge
//!
//! The `SslManager` maintains an in-memory map of pending challenges.
//! The gateway proxy serves challenge tokens at:
//! `GET /.well-known/acme-challenge/{token}`

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;

use tracing::{error, info, warn};
use uuid::Uuid;

use waf_storage::{Database, models::CreateCertificate};

// ── Challenge store ───────────────────────────────────────────────────────────

/// In-memory store for pending ACME HTTP-01 challenges.
///
/// Maps `token → key_authorization` for serving at
/// `/.well-known/acme-challenge/{token}`.
#[derive(Default)]
pub struct ChallengeStore {
    inner: RwLock<HashMap<String, String>>,
}

impl ChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a challenge token -> `key_authorization` pair.
    pub fn set(&self, token: String, key_auth: String) {
        self.inner.write().insert(token, key_auth);
    }

    /// Look up the key authorization for a token.
    pub fn get(&self, token: &str) -> Option<String> {
        self.inner.read().get(token).cloned()
    }

    /// Remove a challenge after it has been processed.
    pub fn remove(&self, token: &str) {
        self.inner.write().remove(token);
    }

    /// The HTTP-01 response body for `path`, or `None` if this is not a
    /// challenge URL or the token is not one we are waiting on.
    ///
    /// The whole of RFC 8555 §8.3 on our side: the CA fetches
    /// `/.well-known/acme-challenge/{token}` over plain HTTP and the body must
    /// be the key authorization, exactly. Owned by the store rather than
    /// written inline in the proxy so that the prefix and the lookup are one
    /// thing, testable without a Pingora session — the end-to-end test answers
    /// Pebble with this function, so a mismatch between what a real CA asks for
    /// and what the proxy answers cannot hide behind a re-implementation.
    pub fn response_for_path(&self, path: &str) -> Option<String> {
        self.get(path.strip_prefix("/.well-known/acme-challenge/")?)
    }
}

// ── CertInfo ──────────────────────────────────────────────────────────────────

/// Parsed certificate information extracted from PEM.
#[derive(Debug, Clone)]
pub struct CertInfo {
    pub cert_pem: String,
    pub key_pem: String,
    pub chain_pem: Option<String>,
    pub not_before: chrono::DateTime<chrono::Utc>,
    pub not_after: chrono::DateTime<chrono::Utc>,
    pub subject: String,
    pub issuer: String,
}

// ── SslManager ────────────────────────────────────────────────────────────────

/// Manages TLS certificates for all WAF-protected hosts.
pub struct SslManager {
    db: Arc<Database>,
    /// Pending ACME HTTP-01 challenges
    pub challenges: Arc<ChallengeStore>,
    /// ACME contact email
    acme_email: String,
    /// Use Let's Encrypt staging (true) or production (false)
    acme_staging: bool,
    /// Directory URL of an ACME server that is not Let's Encrypt. `None` means
    /// the `acme_staging` flag selects between the two Let's Encrypt endpoints.
    acme_directory_url: Option<String>,
    /// PEM file holding the root certificate to trust for the ACME server's own
    /// HTTPS endpoint. `None` means the platform trust store, which is what any
    /// publicly trusted CA needs.
    acme_root_pem: Option<PathBuf>,
}

impl SslManager {
    pub fn new(db: Arc<Database>, acme_email: impl Into<String>, acme_staging: bool) -> Self {
        Self {
            db,
            challenges: Arc::new(ChallengeStore::new()),
            acme_email: acme_email.into(),
            acme_staging,
            acme_directory_url: None,
            acme_root_pem: None,
        }
    }

    /// Point issuance at an ACME server other than Let's Encrypt.
    ///
    /// Two independent knobs, because a private CA needs both and a public one
    /// needs neither:
    ///
    ///   - `directory_url` overrides the endpoint, which is what makes `ZeroSSL`,
    ///     Buypass, an in-house step-ca or a Pebble test server reachable at
    ///     all. When it is `None` the `staging` flag keeps choosing between the
    ///     two Let's Encrypt directories, unchanged.
    ///   - `root_pem` adds the root that signed the ACME server's *own* TLS
    ///     certificate. A private CA is by definition absent from the platform
    ///     trust store, so without this the client cannot even fetch the
    ///     directory. It never affects which certificates this manager issues,
    ///     only which server it is willing to talk to.
    ///
    /// This is also the seam the Pebble end-to-end test drives
    /// (`crates/gateway/tests/acme_pebble_e2e.rs`): issuance is not something
    /// that can be rehearsed against the real Let's Encrypt without spending
    /// rate limits and owning a public domain.
    #[must_use]
    pub fn with_directory(mut self, directory_url: Option<String>, root_pem: Option<PathBuf>) -> Self {
        self.acme_directory_url = directory_url;
        self.acme_root_pem = root_pem;
        self
    }

    /// Upload a certificate manually (from file or API).
    ///
    /// Stores the PEM data directly without going through ACME.
    pub async fn upload_certificate(
        &self,
        host_code: &str,
        domain: &str,
        cert_pem: &str,
        key_pem: &str,
        chain_pem: Option<&str>,
    ) -> anyhow::Result<Uuid> {
        let req = CreateCertificate {
            host_code: host_code.to_string(),
            domain: domain.to_string(),
            cert_pem: Some(cert_pem.to_string()),
            key_pem: Some(key_pem.to_string()),
            chain_pem: chain_pem.map(str::to_string),
            auto_renew: Some(false),
        };
        let cert = self.db.create_certificate(req).await?;
        self.db.update_certificate_status(cert.id, "active", None).await?;
        info!("Uploaded certificate for domain {} (id={})", domain, cert.id);
        Ok(cert.id)
    }

    /// The Let's Encrypt directory URL the `staging` flag selects.
    ///
    /// Split out of `request_certificate` so the staging/production choice can
    /// be asserted without a database or a network round trip. Getting it
    /// backwards is not a cosmetic mistake: it spends Let's Encrypt production
    /// rate limits on what was meant to be a rehearsal.
    const fn lets_encrypt_directory_url(staging: bool) -> &'static str {
        if staging {
            instant_acme::LetsEncrypt::Staging.url()
        } else {
            instant_acme::LetsEncrypt::Production.url()
        }
    }

    /// The ACME directory URL to issue against: an explicit override if one was
    /// configured, otherwise Let's Encrypt per the staging flag.
    ///
    /// Pure, and takes its inputs rather than reading `self`, so the precedence
    /// rule is testable without a database handle. An override that silently
    /// lost to the staging flag would send a deployment that believes it is
    /// talking to its own CA to Let's Encrypt instead.
    const fn resolve_directory_url(override_url: Option<&str>, staging: bool) -> &str {
        match override_url {
            Some(url) => url,
            None => Self::lets_encrypt_directory_url(staging),
        }
    }

    /// Request a new certificate via ACME HTTP-01 for `domain`.
    ///
    /// Stores challenge tokens so the gateway can serve them, then waits for
    /// ACME validation and stores the issued certificate in `PostgreSQL`.
    pub async fn request_certificate(self: Arc<Self>, host_code: &str, domain: &str) -> anyhow::Result<Uuid> {
        use instant_acme::{
            Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
        };
        use rcgen::{CertificateParams, KeyPair};

        info!("Requesting ACME certificate for domain: {}", domain);

        // Create or restore ACME account
        let server_url = Self::resolve_directory_url(self.acme_directory_url.as_deref(), self.acme_staging);

        let contact = format!("mailto:{}", self.acme_email);
        let builder = match &self.acme_root_pem {
            Some(path) => Account::builder_with_root(path)?,
            None => Account::builder()?,
        };
        let (account, _credentials) = builder
            .create(
                &NewAccount {
                    contact: &[&contact],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                server_url.to_owned(),
                None,
            )
            .await?;

        // Place new order
        let identifiers = [Identifier::Dns(domain.to_string())];
        let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;

        // Create a DB entry for tracking
        let req = CreateCertificate {
            host_code: host_code.to_string(),
            domain: domain.to_string(),
            cert_pem: None,
            key_pem: None,
            chain_pem: None,
            auto_renew: Some(true),
        };
        let cert_row = self.db.create_certificate(req).await?;
        let cert_id = cert_row.id;

        // Process HTTP-01 challenges. `authorizations()` borrows the order
        // mutably and yields one handle at a time, so the tokens are copied out
        // here and used for cleanup once the order has been finalized.
        let mut tokens: Vec<String> = Vec::new();
        {
            let mut authorizations = order.authorizations();
            while let Some(authz) = authorizations.next().await {
                let mut authz = authz?;
                match authz.status {
                    // Nothing to prove: this identifier is already authorized
                    // for the account, so it has no challenge to answer.
                    AuthorizationStatus::Valid => continue,
                    AuthorizationStatus::Pending => {}
                    other => anyhow::bail!("ACME authorization for {domain} is in state {other:?}, expected pending"),
                }

                let mut challenge = authz
                    .challenge(ChallengeType::Http01)
                    .ok_or_else(|| anyhow::anyhow!("No HTTP-01 challenge available"))?;

                let key_auth = challenge.key_authorization();
                let token = challenge.token.clone();
                self.challenges.set(token.clone(), key_auth.as_str().to_string());
                tokens.push(token);

                challenge.set_ready().await?;
            }
        }

        // Wait for the order to become ready. `poll_ready` backs off
        // exponentially and honours the CA's Retry-After, returning either
        // `Ready`/`Invalid` or `Error::Timeout` once the policy expires.
        let retry = RetryPolicy::default()
            .initial_delay(Duration::from_secs(2))
            .timeout(Duration::from_mins(1));

        let status = match order.poll_ready(&retry).await {
            Ok(status) => status,
            Err(e) => {
                let _ = self
                    .db
                    .update_certificate_status(cert_id, "error", Some("ACME validation failed"))
                    .await;
                return Err(anyhow::Error::new(e).context(format!("ACME validation failed for domain {domain}")));
            }
        };

        if status != OrderStatus::Ready {
            let _ = self
                .db
                .update_certificate_status(cert_id, "error", Some("ACME validation failed"))
                .await;
            anyhow::bail!("ACME order for domain {domain} ended in state {status:?}, expected ready");
        }

        // Generate key pair and CSR
        let key_pair = KeyPair::generate()?;
        let csr_params = CertificateParams::new(vec![domain.to_string()])?;
        let csr = csr_params.serialize_request(&key_pair)?;

        // Finalize and download certificate. Without a deadline a stalled ACME
        // server could hang this task indefinitely, so the same retry policy
        // caps the download too.
        order.finalize_csr(csr.der()).await?;

        let cert_chain = match order.poll_certificate(&retry).await {
            Ok(chain) => chain,
            Err(e) => {
                let _ = self
                    .db
                    .update_certificate_status(cert_id, "error", Some("ACME certificate download failed"))
                    .await;
                return Err(
                    anyhow::Error::new(e).context(format!("ACME certificate download failed for domain {domain}"))
                );
            }
        };

        let cert_pem = cert_chain;
        let key_pem = key_pair.serialize_pem();
        let now = chrono::Utc::now();
        let not_after = now + chrono::Duration::days(90); // typical LE validity

        self.db
            .update_certificate_pem(&waf_storage::models::UpdateCertificatePem {
                id: cert_id,
                cert_pem: &cert_pem,
                key_pem: &key_pem,
                chain_pem: None,
                not_before: now,
                not_after,
                issuer: "Let's Encrypt",
                subject: domain,
            })
            .await?;

        // Clean up challenges
        for token in &tokens {
            self.challenges.remove(token);
        }

        info!(
            "Certificate issued for domain {} (id={}), valid until {}",
            domain, cert_id, not_after
        );
        Ok(cert_id)
    }

    /// Check certificates due for renewal and renew them.
    ///
    /// Should be called periodically (e.g., daily) by a background task.
    pub async fn renew_due_certificates(self: Arc<Self>) -> anyhow::Result<()> {
        let due = self.db.list_certificates_due_renewal(30).await?;
        if due.is_empty() {
            return Ok(());
        }

        info!("Found {} certificate(s) due for renewal", due.len());
        for cert in due {
            let mgr = Arc::clone(&self);
            let domain = cert.domain.clone();
            let host_code = cert.host_code.clone();
            tokio::spawn(async move {
                match mgr.request_certificate(&host_code, &domain).await {
                    // The renewal has reached the database, and that is as far
                    // as it goes on its own. The TLS listener parsed its
                    // certificate when Pingora built the endpoint and Pingora
                    // offers no way to replace it on a running one, so the old
                    // certificate stays on the wire until the process is
                    // replaced. Said here, at the moment it becomes true,
                    // rather than left for an expiry alert to reveal.
                    Ok(_) => info!(
                        "Renewed certificate for {} and stored it. The TLS listener still serves the previous \
                         certificate: it is read once at startup. Run `prx-waf run --upgrade` to pick the new one up \
                         without dropping connections.",
                        domain
                    ),
                    Err(e) => error!("Failed to renew certificate for {}: {}", domain, e),
                }
            });
        }

        Ok(())
    }

    /// Spawn the auto-renewal background task.
    ///
    /// Checks for certificates due for renewal every `interval`.
    pub fn spawn_renewal_task(self: Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                if let Err(e) = Arc::clone(&self).renew_due_certificates().await {
                    warn!("Certificate renewal check failed: {}", e);
                }
            }
        })
    }

    /// Generate a self-signed certificate for a domain (useful for testing).
    pub fn generate_self_signed(domain: &str) -> anyhow::Result<(String, String)> {
        use rcgen::{CertificateParams, KeyPair};

        let key_pair = KeyPair::generate()?;
        let params = CertificateParams::new(vec![domain.to_string()])?;
        let cert = params.self_signed(&key_pair)?;

        Ok((cert.pem(), key_pair.serialize_pem()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_store() {
        let store = ChallengeStore::new();
        store.set("token123".into(), "keyauth456".into());
        assert_eq!(store.get("token123"), Some("keyauth456".to_string()));
        store.remove("token123");
        assert_eq!(store.get("token123"), None);
    }

    #[test]
    fn test_response_for_path_answers_only_challenge_urls() {
        let store = ChallengeStore::new();
        store.set("tok".into(), "tok.thumbprint".into());

        assert_eq!(
            store.response_for_path("/.well-known/acme-challenge/tok"),
            Some("tok.thumbprint".to_string())
        );

        // A token we are not waiting on, and paths that merely resemble the
        // challenge URL, fall through to normal routing rather than answering.
        assert_eq!(store.response_for_path("/.well-known/acme-challenge/other"), None);
        assert_eq!(store.response_for_path("/.well-known/acme-challenge/"), None);
        assert_eq!(store.response_for_path("/.well-known/acme-challenge"), None);
        assert_eq!(store.response_for_path("/acme-challenge/tok"), None);
        assert_eq!(store.response_for_path("/tok"), None);
    }

    #[test]
    fn test_acme_directory_url_honours_staging_flag() {
        let staging = SslManager::lets_encrypt_directory_url(true);
        let production = SslManager::lets_encrypt_directory_url(false);

        assert!(staging.contains("staging"), "staging directory URL was {staging}");
        assert!(
            !production.contains("staging"),
            "production directory URL was {production}"
        );
        assert_ne!(staging, production);
    }

    #[test]
    fn test_directory_override_beats_the_staging_flag() {
        let custom = "https://ca.internal.example/acme/directory";

        // An override wins whichever way the staging flag is set: the flag only
        // chooses between the two Let's Encrypt endpoints, and once an operator
        // has named a different CA neither of them is the right answer.
        assert_eq!(SslManager::resolve_directory_url(Some(custom), false), custom);
        assert_eq!(SslManager::resolve_directory_url(Some(custom), true), custom);

        // Without one, nothing about the previous behaviour changes.
        assert_eq!(
            SslManager::resolve_directory_url(None, true),
            SslManager::lets_encrypt_directory_url(true)
        );
        assert_eq!(
            SslManager::resolve_directory_url(None, false),
            SslManager::lets_encrypt_directory_url(false)
        );
    }

    #[test]
    fn test_self_signed_generation() {
        let (cert_pem, key_pem) = SslManager::generate_self_signed("example.com").unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("BEGIN"));
    }
}
