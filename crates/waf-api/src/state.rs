use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use gateway::{HostRouter, ResponseCache, TunnelRegistry};
use waf_engine::{CommunityReporter, CrowdSecClient, DecisionCache, PluginManager, WafEngine};
use waf_storage::Database;

use crate::notifications::NotifRateLimiter;

/// Shared application state for the API server.
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    pub engine: Arc<WafEngine>,
    pub router: Arc<HostRouter>,
    /// Total request counter (incremented by the proxy layer)
    pub request_counter: Arc<AtomicU64>,
    /// Blocked request counter
    pub blocked_counter: Arc<AtomicU64>,
    /// Active WebSocket connection count (capped at 50)
    pub ws_connections: Arc<AtomicU32>,
    /// JWT signing/verifying secret (from env `JWT_SECRET`)
    pub jwt_secret: String,
    /// In-process rate limiter for notifications
    pub notif_rate_limiter: NotifRateLimiter,
    // ── Phase 5 ──────────────────────────────────────────────────────────────
    /// Response cache (moka-backed LRU)
    pub cache: Arc<ResponseCache>,
    /// WASM plugin manager
    pub plugin_manager: Arc<PluginManager>,
    /// Reverse tunnel registry
    pub tunnel_registry: Arc<TunnelRegistry>,
    // ── Phase 6: CrowdSec ────────────────────────────────────────────────────
    /// In-memory decision cache (None if `CrowdSec` not enabled)
    pub crowdsec_cache: Option<Arc<DecisionCache>>,
    /// LAPI client for delete/test operations (None if `CrowdSec` not enabled)
    pub crowdsec_client: Option<Arc<CrowdSecClient>>,
    /// LAPI base URL (for display in status endpoint)
    pub crowdsec_lapi_url: Option<String>,
    // ── Community threat intelligence ──────────────────────────────────────
    /// Community signal reporter (None if community sharing not enabled)
    pub community_reporter: Option<Arc<CommunityReporter>>,
    // ── Phase 7: Cluster ─────────────────────────────────────────────────────
    /// Shared cluster node state (None when running in standalone mode)
    pub cluster_state: Option<Arc<waf_cluster::NodeState>>,
    /// Allowed CORS origins for admin API (empty = allow all — insecure default)
    pub cors_origins: Vec<String>,
    /// Security config for IP allowlist and rate limiting
    pub security_config: waf_common::config::SecurityConfig,
    /// In-process API rate limiter (None if rate limiting disabled)
    pub rate_limiter: Option<Arc<crate::security::ApiRateLimiter>>,
    /// Dedicated rate limiter for login endpoint — stricter than general API
    /// to mitigate brute-force credential attacks (None if disabled)
    pub login_rate_limiter: Option<Arc<crate::security::ApiRateLimiter>>,
}

/// Minimum acceptable length for `JWT_SECRET` (characters).
const JWT_SECRET_MIN_LEN: usize = 32;

/// Minimum number of distinct characters required (low-entropy guard).
const JWT_SECRET_MIN_DISTINCT: usize = 8;

/// Known placeholder / example secrets that must never be used in production.
/// Includes the historical `docker-compose` defaults so an operator who relies
/// on the shipped compose file cannot silently run with a public secret.
const JWT_SECRET_BLOCKLIST: &[&str] = &[
    "change-me-in-production-with-a-long-random-secret",
    "cluster-demo-jwt-secret-change-in-production",
    "change-me-in-production",
    "changeme",
    "change_me",
    "secret",
    "your-secret-key",
    "please-change-me",
];

/// Validate a candidate `JWT_SECRET` for production use.
///
/// Rejects secrets that are too short, appear on the known-placeholder
/// blocklist, or have too few distinct characters (low entropy). Extracted as
/// a pure function so the policy can be unit-tested in isolation.
pub fn validate_jwt_secret(secret: &str) -> anyhow::Result<()> {
    if secret.is_empty() {
        anyhow::bail!(
            "JWT_SECRET is not set. Set a strong random secret (>= {JWT_SECRET_MIN_LEN} chars) before starting the server."
        );
    }
    if secret.chars().count() < JWT_SECRET_MIN_LEN {
        anyhow::bail!("JWT_SECRET is too short: it must be at least {JWT_SECRET_MIN_LEN} characters.");
    }

    let lowered = secret.to_ascii_lowercase();
    if JWT_SECRET_BLOCKLIST
        .iter()
        .any(|bad| lowered == bad.to_ascii_lowercase())
    {
        anyhow::bail!("JWT_SECRET matches a known placeholder value. Generate a unique random secret.");
    }

    let distinct = secret.chars().collect::<std::collections::HashSet<_>>().len();
    if distinct < JWT_SECRET_MIN_DISTINCT {
        anyhow::bail!(
            "JWT_SECRET has too few distinct characters ({distinct}); at least {JWT_SECRET_MIN_DISTINCT} are required. Use a random secret."
        );
    }

    Ok(())
}

impl AppState {
    /// Create new application state.
    ///
    /// Returns an error if the `JWT_SECRET` environment variable is not set,
    /// too short, a known placeholder, or too low-entropy. In production this
    /// ensures the operator explicitly configures a strong secret.
    pub fn new(db: Arc<Database>, engine: Arc<WafEngine>, router: Arc<HostRouter>) -> anyhow::Result<Self> {
        let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_default();
        validate_jwt_secret(&jwt_secret)?;

        Ok(Self {
            db,
            engine,
            router,
            request_counter: Arc::new(AtomicU64::new(0)),
            blocked_counter: Arc::new(AtomicU64::new(0)),
            ws_connections: Arc::new(AtomicU32::new(0)),
            jwt_secret,
            notif_rate_limiter: crate::notifications::new_rate_limiter(),
            cache: ResponseCache::new(256, 60, 3600),
            plugin_manager: Arc::new(PluginManager::new()),
            tunnel_registry: TunnelRegistry::new(),
            crowdsec_cache: None,
            crowdsec_client: None,
            crowdsec_lapi_url: None,
            community_reporter: None,
            cluster_state: None,
            cors_origins: Vec::new(),
            security_config: waf_common::config::SecurityConfig::default(),
            rate_limiter: None,
            login_rate_limiter: None,
        })
    }

    pub fn increment_requests(&self) {
        self.request_counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_blocked(&self) {
        self.blocked_counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn total_requests(&self) -> u64 {
        self.request_counter.load(Ordering::Relaxed)
    }

    pub fn total_blocked(&self) -> u64 {
        self.blocked_counter.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::validate_jwt_secret;

    #[test]
    fn rejects_empty_secret() {
        assert!(validate_jwt_secret("").is_err());
    }

    #[test]
    fn rejects_short_secret() {
        assert!(validate_jwt_secret("short-secret").is_err());
        // 31 distinct-ish chars but under 32 length
        assert!(validate_jwt_secret("abcdefghijklmnopqrstuvwxyz01234").is_err());
    }

    #[test]
    fn rejects_compose_default_secrets() {
        assert!(validate_jwt_secret("change-me-in-production-with-a-long-random-secret").is_err());
        assert!(validate_jwt_secret("cluster-demo-jwt-secret-change-in-production").is_err());
    }

    #[test]
    fn rejects_low_entropy_secret() {
        // 40 chars but only 1 distinct character.
        assert!(validate_jwt_secret(&"a".repeat(40)).is_err());
        // 32 chars, 2 distinct characters.
        assert!(validate_jwt_secret("abababababababababababababababab").is_err());
    }

    #[test]
    fn accepts_strong_secret() {
        assert!(validate_jwt_secret("Xk9$mP2vLq7wZr4nTb8yEc3jHu6sAd0F").is_ok());
    }
}
