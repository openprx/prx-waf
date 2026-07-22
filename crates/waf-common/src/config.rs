use serde::{Deserialize, Serialize};

/// Top-level application configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppConfig {
    pub proxy: ProxyConfig,
    pub api: ApiConfig,
    pub storage: StorageConfig,
    #[serde(default)]
    pub hosts: Vec<HostEntry>,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub http3: Http3Config,
    #[serde(default)]
    pub security: SecurityConfig,
    /// Phase 6: `CrowdSec` integration
    #[serde(default)]
    pub crowdsec: CrowdSecConfig,
    /// Phase 7: Rule management
    #[serde(default)]
    pub rules: RulesConfig,
    /// `GeoIP` lookup configuration
    #[serde(default)]
    pub geoip: GeoIpConfig,
    /// Community threat intelligence sharing
    #[serde(default)]
    pub community: CommunityConfig,
    /// Cluster configuration — None means standalone mode (default)
    #[serde(default)]
    pub cluster: Option<ClusterConfig>,
    /// ACME / Let's Encrypt automatic TLS certificate management
    #[serde(default)]
    pub acme: AcmeConfig,
    /// Threat-intelligence IP feeds (raw IP/CIDR blocklists).
    ///
    /// **Empty by default** — no feed is fetched or enabled unless explicitly
    /// configured. This is deliberate: several sources carry licensing terms
    /// (e.g. Spamhaus DROP requires attribution and forbids some commercial
    /// use), so activation is opt-in per operator. See `configs/default.toml`
    /// for commented, license-annotated examples.
    #[serde(default)]
    pub ip_feeds: Vec<IpFeedEntry>,
    /// Lane 2 semantic content-security engine configuration.
    ///
    /// **Off by default** (`enabled = false`, `enforcement_mode = "log_only"`):
    /// a zero-config install never activates the semantic lane. See
    /// [`crate::content_security_config::ContentSecurityConfig`].
    #[serde(default)]
    pub content_security: crate::content_security_config::ContentSecurityConfig,
}

impl AppConfig {
    /// Cross-field semantic validation applied after deserialisation.
    ///
    /// Currently this only validates the Lane 2 semantic content-security
    /// config (plan §6.2 strict loader rule). Returns a human-readable error
    /// on the first violation.
    pub fn validate(&self) -> Result<(), String> {
        self.content_security.validate()
    }
}

/// Typed configuration-load error (plan §14.1 / P1a must-fix P1-4).
///
/// Lets callers distinguish "no config file" (safe to fall back to defaults)
/// from "config exists but is broken" (must be a hard startup failure).
#[derive(Debug)]
pub enum ConfigError {
    /// The configuration file does not exist. Callers may fall back to
    /// [`AppConfig::default`].
    NotFound(String),
    /// The file exists but could not be read (I/O error other than not-found)
    /// or failed to parse as TOML. Fatal.
    Parse(String),
    /// The file parsed but failed semantic validation ([`AppConfig::validate`]).
    /// Fatal.
    Validate(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(p) => write!(f, "configuration file not found: {p}"),
            Self::Parse(e) => write!(f, "configuration parse error: {e}"),
            Self::Validate(e) => write!(f, "configuration validation error: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// A single threat-intelligence IP-feed source (raw IP/CIDR blocklist).
///
/// Mirrors `waf_engine::rules::ip_feed::IpFeedSource`; kept in waf-common so the
/// TOML loader need not depend on the engine crate. Converted to the engine
/// type at startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpFeedEntry {
    /// Unique, human-readable feed name. Doubles as the source tag used for
    /// per-source replacement, cleanup and block-reason traceability.
    pub name: String,
    /// HTTP(S) URL of the raw blocklist.
    pub url: String,
    /// Body format: `plain` (one IP/CIDR per line, `#`/`;` comments tolerated)
    /// or `spamhaus_json` (Spamhaus DROP JSONL with a `cidr` field).
    #[serde(default = "default_ip_feed_format")]
    pub format: String,
    /// Refresh interval in seconds (clamped to a sane minimum at runtime).
    #[serde(default = "default_ip_feed_interval")]
    pub update_interval_secs: u64,
    /// Whether this feed is active. Defaults to `true`: adding the entry is
    /// itself the opt-in, while the flag lets an operator keep a feed in the
    /// config but temporarily disable it.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_ip_feed_format() -> String {
    "plain".to_string()
}
const fn default_ip_feed_interval() -> u64 {
    3600
}

/// ACME (Let's Encrypt) automatic certificate configuration.
///
/// When `enabled`, the gateway constructs an `SslManager`, spawns the periodic
/// renewal task, and requests certificates for SSL-enabled hosts that do not
/// already have an active certificate. HTTP-01 challenges are served by the
/// proxy at `/.well-known/acme-challenge/{token}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    /// Enable ACME automatic issuance and renewal. Default: `false`.
    #[serde(default)]
    pub enabled: bool,
    /// Contact email registered with the ACME account. Required for issuance.
    #[serde(default)]
    pub email: String,
    /// Use the Let's Encrypt staging environment (untrusted certs, relaxed
    /// rate limits) instead of production. Default: `false` (production).
    #[serde(default)]
    pub staging: bool,
    /// How often the background task checks for certificates due for renewal,
    /// in seconds. Default: 86400 (24h).
    #[serde(default = "default_acme_renewal_interval")]
    pub renewal_check_interval_secs: u64,
}

const fn default_acme_renewal_interval() -> u64 {
    86_400
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            email: String::new(),
            staging: false,
            renewal_check_interval_secs: default_acme_renewal_interval(),
        }
    }
}

/// Rule source entry from configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSourceEntry {
    pub name: String,
    /// Local directory path (for local sources)
    pub path: Option<String>,
    /// Remote URL (for remote sources)
    pub url: Option<String>,
    /// Rule format: yaml | modsec | json
    #[serde(default = "default_rule_format")]
    pub format: String,
    /// Update interval in seconds (for remote sources)
    #[serde(default = "default_update_interval")]
    pub update_interval: u64,
}

fn default_rule_format() -> String {
    "yaml".to_string()
}
const fn default_update_interval() -> u64 {
    86400
}

/// Phase 7: Rule management configuration
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesConfig {
    /// Directory to watch for rule files
    #[serde(default = "default_rules_dir")]
    pub dir: String,
    /// Enable file-system hot-reload
    #[serde(default = "default_hot_reload")]
    pub hot_reload: bool,
    /// Debounce ms after last file change before reload
    #[serde(default = "default_debounce_ms")]
    pub reload_debounce_ms: u64,
    /// Load built-in OWASP CRS rules
    #[serde(default = "default_true")]
    pub enable_builtin_owasp: bool,
    /// Load built-in bot detection rules
    #[serde(default = "default_true")]
    pub enable_builtin_bot: bool,
    /// Load built-in scanner detection rules
    #[serde(default = "default_true")]
    pub enable_builtin_scanner: bool,
    /// Configured rule sources
    #[serde(default)]
    pub sources: Vec<RuleSourceEntry>,
}

fn default_rules_dir() -> String {
    "rules/".to_string()
}
const fn default_hot_reload() -> bool {
    true
}
const fn default_debounce_ms() -> u64 {
    500
}
const fn default_true() -> bool {
    true
}

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            dir: default_rules_dir(),
            hot_reload: default_hot_reload(),
            reload_debounce_ms: default_debounce_ms(),
            enable_builtin_owasp: true,
            enable_builtin_bot: true,
            enable_builtin_scanner: true,
            sources: Vec::new(),
        }
    }
}

/// `CrowdSec` integration configuration.
///
/// Mirrors waf-engine `CrowdSecConfig` but lives in waf-common so it can be
/// loaded from the TOML without pulling in the full engine crate as a dep of
/// prx-waf's config loader.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrowdSecConfig {
    pub enabled: bool,
    #[serde(default)]
    pub mode: String,
    pub lapi_url: String,
    pub api_key: String,
    #[serde(default = "default_cs_update_secs")]
    pub update_frequency_secs: u64,
    #[serde(default)]
    pub cache_ttl_secs: u64,
    #[serde(default = "default_cs_fallback")]
    pub fallback_action: String,
    #[serde(default)]
    pub scenarios_containing: Vec<String>,
    #[serde(default)]
    pub scenarios_not_containing: Vec<String>,
    pub appsec_endpoint: Option<String>,
    pub appsec_key: Option<String>,
    #[serde(default = "default_appsec_timeout")]
    pub appsec_timeout_ms: u64,
    /// Action when the `AppSec` engine is unavailable. Independent from the
    /// top-level `fallback_action` (which governs the LAPI bouncer). Defaults
    /// to "allow" (fail open) for backward compatibility.
    #[serde(default = "default_appsec_failure_action")]
    pub appsec_failure_action: String,
    pub pusher_login: Option<String>,
    pub pusher_password: Option<String>,
}

impl Default for CrowdSecConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: "bouncer".to_string(),
            lapi_url: "http://127.0.0.1:8080".to_string(),
            api_key: String::new(),
            update_frequency_secs: default_cs_update_secs(),
            cache_ttl_secs: 0,
            fallback_action: default_cs_fallback(),
            scenarios_containing: Vec::new(),
            scenarios_not_containing: Vec::new(),
            appsec_endpoint: None,
            appsec_key: None,
            appsec_timeout_ms: default_appsec_timeout(),
            appsec_failure_action: default_appsec_failure_action(),
            pusher_login: None,
            pusher_password: None,
        }
    }
}

const fn default_cs_update_secs() -> u64 {
    10
}
fn default_cs_fallback() -> String {
    "allow".to_string()
}
fn default_appsec_failure_action() -> String {
    "allow".to_string()
}
const fn default_appsec_timeout() -> u64 {
    500
}

/// Proxy listener configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub listen_addr: String,
    pub listen_addr_tls: String,
    pub worker_threads: Option<usize>,
    /// Trust X-Forwarded-For / X-Real-IP headers from upstream proxies.
    /// When `false` (default), the client IP is always taken from the TCP
    /// connection peer address. Only enable this when running behind a
    /// trusted reverse proxy.
    #[serde(default)]
    pub trust_proxy_headers: bool,
    /// List of trusted proxy CIDRs. When `trust_proxy_headers` is true,
    /// only XFF headers from connections originating in these ranges are
    /// honoured. Empty list means trust XFF from any source (legacy
    /// behaviour, NOT recommended for production).
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:80".to_string(),
            listen_addr_tls: "0.0.0.0:443".to_string(),
            worker_threads: None,
            trust_proxy_headers: false,
            trusted_proxies: Vec::new(),
        }
    }
}

/// Management API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub listen_addr: String,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:9527".to_string(),
        }
    }
}

/// Database storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub database_url: String,
    pub max_connections: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            database_url: "postgresql://prx_waf:prx_waf@127.0.0.1:5432/prx_waf".to_string(),
            max_connections: 20,
        }
    }
}

/// Static host entry from configuration file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostEntry {
    pub host: String,
    pub port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    pub ssl: Option<bool>,
    pub guard_status: Option<bool>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    /// Optional multi-backend pool. Empty (default) → single
    /// `remote_host`/`remote_port` backend (backward compatible).
    #[serde(default)]
    pub backends: Vec<crate::types::BackendConfig>,
    /// Load-balancing strategy for the backend pool. Only relevant when
    /// `backends` is non-empty. Defaults to round-robin.
    #[serde(default)]
    pub load_balance_strategy: crate::types::LoadBalanceStrategy,
}

/// Response caching configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Enable response caching
    pub enabled: bool,
    /// Maximum cache size in megabytes
    pub max_size_mb: u64,
    /// Default TTL in seconds (used when Cache-Control is absent)
    pub default_ttl_secs: u64,
    /// Maximum TTL in seconds (caps upstream Cache-Control max-age)
    pub max_ttl_secs: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_size_mb: 256,
            default_ttl_secs: 60,
            max_ttl_secs: 3600,
        }
    }
}

/// HTTP/3 (QUIC) listener configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http3Config {
    /// Enable HTTP/3 listener
    pub enabled: bool,
    /// UDP listen address for QUIC
    pub listen_addr: String,
    /// Path to TLS certificate PEM (required when enabled)
    pub cert_pem: Option<String>,
    /// Path to TLS key PEM (required when enabled)
    pub key_pem: Option<String>,
    /// Verify upstream TLS certificates.
    /// When `true` (default), invalid/self-signed upstream certs are rejected.
    /// Set to `false` only for development/testing with self-signed upstreams.
    #[serde(default = "default_true")]
    pub upstream_tls_verify: bool,
}

impl Default for Http3Config {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: "0.0.0.0:443".to_string(),
            cert_pem: None,
            key_pem: None,
            upstream_tls_verify: true,
        }
    }
}

/// Security hardening configuration for the management API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// IP allowlist for admin API (empty = allow all)
    #[serde(default)]
    pub admin_ip_allowlist: Vec<String>,
    /// Maximum request body size in bytes (default 10 MB)
    pub max_request_body_bytes: u64,
    /// Admin-API rate limit (requests per second per IP, 0 = disabled).
    ///
    /// Default: 100 req/s per IP (token bucket, burst = 5x = 500). This only
    /// governs the management API, never proxied traffic, so a generous cap
    /// leaves normal admin-UI usage untouched while blunting brute-force /
    /// scripted abuse of the admin surface. Set to 0 to disable.
    pub api_rate_limit_rps: u32,
    /// Allowed CORS origins for admin API (empty = all)
    #[serde(default)]
    pub cors_origins: Vec<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            admin_ip_allowlist: Vec::new(),
            max_request_body_bytes: 10 * 1024 * 1024, // 10 MB
            // Generous per-IP admin-API cap (see field docs). Protects the
            // management surface without disrupting legitimate admin usage.
            api_rate_limit_rps: 100,
            cors_origins: Vec::new(),
        }
    }
}

/// Automatic ip2region xdb update configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpAutoUpdateConfig {
    /// Enable periodic automatic xdb updates.  Default: `false`.
    #[serde(default)]
    pub enabled: bool,
    /// Update check interval.  Supports suffixes: `d` (days), `h` (hours),
    /// `m` (minutes), `s` (seconds).  Default: `"7d"`.
    #[serde(default = "default_geoip_update_interval")]
    pub interval: String,
    /// Base URL for downloading xdb files.
    /// Default: GitHub raw content URL for ip2region master.
    #[serde(default = "default_geoip_source_url")]
    pub source_url: String,
}

fn default_geoip_update_interval() -> String {
    "7d".to_string()
}
fn default_geoip_source_url() -> String {
    "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data".to_string()
}

impl Default for GeoIpAutoUpdateConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval: default_geoip_update_interval(),
            source_url: default_geoip_source_url(),
        }
    }
}

/// `GeoIP` lookup configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpConfig {
    /// Enable `GeoIP` lookups on every request.
    ///
    /// Default: `true`. `GeoIP` is a pure-detection feature that degrades
    /// gracefully — if the xdb database files are missing, `GeoIpService::init`
    /// fails, the failure is logged with `warn!`, and the pipeline continues
    /// with `ctx.geo = None` (the geo check then no-ops: it neither blocks nor
    /// panics). It also has no effect until country/region rules are configured,
    /// so enabling it by default is safe for a zero-config single-node install.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Path to the ip2region IPv4 xdb file (default: `data/ip2region_v4.xdb`).
    #[serde(default = "default_ipv4_xdb")]
    pub ipv4_xdb_path: String,
    /// Path to the ip2region IPv6 xdb file (default: `data/ip2region_v6.xdb`).
    #[serde(default = "default_ipv6_xdb")]
    pub ipv6_xdb_path: String,
    /// Cache policy: `full_memory` (fastest, ~20MB), `vector_index` (~2MB), `no_cache` (1-2MB).
    #[serde(default = "default_geoip_cache_policy")]
    pub cache_policy: String,
    /// Automatic xdb update settings.
    #[serde(default)]
    pub auto_update: GeoIpAutoUpdateConfig,
}

fn default_ipv4_xdb() -> String {
    "data/ip2region_v4.xdb".to_string()
}
fn default_ipv6_xdb() -> String {
    "data/ip2region_v6.xdb".to_string()
}
fn default_geoip_cache_policy() -> String {
    "full_memory".to_string()
}

impl Default for GeoIpConfig {
    fn default() -> Self {
        Self {
            // Enabled by default; degrades gracefully when the xdb files are
            // absent (see the `enabled` field docs) so it never blocks startup.
            enabled: true,
            ipv4_xdb_path: default_ipv4_xdb(),
            ipv6_xdb_path: default_ipv6_xdb(),
            cache_policy: default_geoip_cache_policy(),
            auto_update: GeoIpAutoUpdateConfig::default(),
        }
    }
}

/// Community threat intelligence sharing configuration.
///
/// Mirrors `waf_engine::community::config::CommunityConfig` so the TOML
/// config can be loaded without pulling in the full engine crate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunityConfig {
    /// Enable community threat intelligence sharing.
    #[serde(default)]
    pub enabled: bool,
    /// Community server base URL.
    #[serde(default = "default_community_server_url")]
    pub server_url: String,
    /// API key obtained during machine enrollment.
    #[serde(default)]
    pub api_key: Option<String>,
    /// Machine identifier obtained during enrollment.
    #[serde(default)]
    pub machine_id: Option<String>,
    /// Ed25519 public key (hex-encoded 32 bytes) for blocklist signature verification.
    /// When set, the WAF verifies signed snapshots from `/blocklist/full`.
    /// When absent, falls back to the unverified `/blocklist/decoded` endpoint.
    #[serde(default)]
    pub public_key: Option<String>,
    /// Maximum number of signals to batch before flushing.
    #[serde(default = "default_community_batch_size")]
    pub batch_size: usize,
    /// Flush interval in seconds.
    #[serde(default = "default_community_flush_interval")]
    pub flush_interval_secs: u64,
    /// Blocklist sync interval in seconds.
    #[serde(default = "default_community_sync_interval")]
    pub sync_interval_secs: u64,
}

fn default_community_server_url() -> String {
    "https://community.openprx.dev".to_string()
}
const fn default_community_batch_size() -> usize {
    50
}
const fn default_community_flush_interval() -> u64 {
    30
}
const fn default_community_sync_interval() -> u64 {
    300
}

impl Default for CommunityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_url: default_community_server_url(),
            api_key: None,
            machine_id: None,
            public_key: None,
            batch_size: default_community_batch_size(),
            flush_interval_secs: default_community_flush_interval(),
            sync_interval_secs: default_community_sync_interval(),
        }
    }
}

/// Load and validate configuration from a TOML file.
///
/// Distinguishes three outcomes so the caller can react correctly (plan §14.1):
///
/// * [`ConfigError::NotFound`] — the file is absent; the caller may fall back to
///   [`AppConfig::default`].
/// * [`ConfigError::Parse`] — the file exists but cannot be read or parsed; this
///   is a hard failure (do **not** silently fall back to defaults).
/// * [`ConfigError::Validate`] — the file parsed but failed semantic validation
///   (e.g. an illegal semantic-lane weight sum); also a hard failure.
pub fn load_config(path: &str) -> Result<AppConfig, ConfigError> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ConfigError::NotFound(path.to_string()));
        }
        Err(e) => return Err(ConfigError::Parse(format!("{path}: {e}"))),
    };
    let config: AppConfig = toml::from_str(&content).map_err(|e| ConfigError::Parse(e.to_string()))?;
    config.validate().map_err(ConfigError::Validate)?;
    Ok(config)
}

// --- Environment-variable override layer ---
//
// Security-critical and deployment-specific settings can be overridden from the
// environment so operators configure everything in one place (`.env` /
// systemd `EnvironmentFile` / container env) without editing TOML per node.
//
// Naming convention:
//   * `DATABASE_URL`            — ecosystem-standard, honoured as-is.
//   * `PRXWAF_*`                — everything that overrides a TOML field.
//
// An unset **or empty** variable leaves the TOML/default value untouched, so a
// docker-compose `${VAR}` that expands to an empty string never clobbers a
// configured value. Comma-separated lists are trimmed with empty entries
// dropped.

/// Parse a boolean environment value, accepting common truthy/falsy spellings.
///
/// Returns an explicit error (never panics) on an unrecognised value so a
/// typo becomes a hard startup failure rather than a silent wrong default.
fn parse_env_bool(key: &str, raw: &str) -> anyhow::Result<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => anyhow::bail!(
            "environment variable {key} has invalid boolean value '{other}' \
             (expected one of: true/false, 1/0, yes/no, on/off)"
        ),
    }
}

/// Split a comma-separated environment value into trimmed, non-empty entries.
fn parse_env_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect()
}

/// Apply environment-variable overrides on top of a loaded [`AppConfig`].
///
/// Existing environment variables override the corresponding TOML/default
/// value; unset (or empty) variables leave the loaded value untouched. Cluster
/// overrides only apply when the TOML already declares a `[cluster]` section,
/// since that section is what enables clustering in the first place.
///
/// Returns an error (never panics) when a boolean-valued override cannot be
/// parsed, so a misconfigured environment fails startup loudly.
///
/// # Recognised variables
///
/// | Variable | Overrides | Format |
/// |----------|-----------|--------|
/// | `DATABASE_URL` | `storage.database_url` | string |
/// | `PRXWAF_TRUST_PROXY_HEADERS` | `proxy.trust_proxy_headers` | bool |
/// | `PRXWAF_TRUSTED_PROXIES` | `proxy.trusted_proxies` | comma-separated CIDRs |
/// | `PRXWAF_CLUSTER_JOIN_TOKEN` | `cluster.join_token` | string |
/// | `PRXWAF_CLUSTER_MEMBERS` | `cluster.members` | comma-separated node ids |
/// | `PRXWAF_CLUSTER_SEEDS` | `cluster.seeds` | comma-separated host:port |
/// | `PRXWAF_CLUSTER_REPLICATE_CA_KEY` | `cluster.replicate_ca_key` | bool |
/// | `PRXWAF_CLUSTER_AUTO_GENERATE` | `cluster.crypto.auto_generate` | bool |
/// | `PRXWAF_CLUSTER_CA_PASSPHRASE` | `cluster.crypto.ca_passphrase` | string |
pub fn apply_env_overrides(config: &mut AppConfig) -> anyhow::Result<()> {
    apply_env_overrides_from(config, |key| std::env::var(key).ok())
}

/// Core override logic, parameterised over the environment source so it can be
/// exercised deterministically in tests without mutating the process
/// environment. `get_raw` returns the raw value for a key (or `None` when
/// unset); a value that is empty or whitespace-only is treated as unset here so
/// a docker-compose `${VAR}` expanding to an empty string never clobbers a
/// configured value.
fn apply_env_overrides_from<F>(config: &mut AppConfig, get_raw: F) -> anyhow::Result<()>
where
    F: Fn(&str) -> Option<String>,
{
    let get = |key: &str| get_raw(key).filter(|v| !v.trim().is_empty());

    // Database connection string (ecosystem-standard name).
    if let Some(v) = get("DATABASE_URL") {
        config.storage.database_url = v;
    }

    // Reverse-proxy trust settings. A wrong pairing here is a hard startup
    // error downstream (see M-1 check in prx-waf/main.rs), so allowing env
    // overrides keeps that safety net configurable in one place.
    if let Some(v) = get("PRXWAF_TRUST_PROXY_HEADERS") {
        config.proxy.trust_proxy_headers = parse_env_bool("PRXWAF_TRUST_PROXY_HEADERS", &v)?;
    }
    if let Some(v) = get("PRXWAF_TRUSTED_PROXIES") {
        config.proxy.trusted_proxies = parse_env_list(&v);
    }

    // Cluster overrides only when a [cluster] section is present.
    if let Some(cluster) = config.cluster.as_mut() {
        if let Some(v) = get("PRXWAF_CLUSTER_JOIN_TOKEN") {
            cluster.join_token = v;
        }
        if let Some(v) = get("PRXWAF_CLUSTER_MEMBERS") {
            cluster.members = parse_env_list(&v);
        }
        if let Some(v) = get("PRXWAF_CLUSTER_SEEDS") {
            cluster.seeds = parse_env_list(&v);
        }
        if let Some(v) = get("PRXWAF_CLUSTER_REPLICATE_CA_KEY") {
            cluster.replicate_ca_key = parse_env_bool("PRXWAF_CLUSTER_REPLICATE_CA_KEY", &v)?;
        }
        if let Some(v) = get("PRXWAF_CLUSTER_AUTO_GENERATE") {
            cluster.crypto.auto_generate = parse_env_bool("PRXWAF_CLUSTER_AUTO_GENERATE", &v)?;
        }
        if let Some(v) = get("PRXWAF_CLUSTER_CA_PASSPHRASE") {
            cluster.crypto.ca_passphrase = v;
        }
    }

    Ok(())
}

// --- Cluster Configuration ---

/// Node role in the cluster
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    Main,
    Worker,
    Candidate,
}

/// Cluster TLS/certificate configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterCryptoConfig {
    /// Path to CA certificate PEM file
    #[serde(default = "default_ca_cert_path")]
    pub ca_cert: String,
    /// Path to CA private key PEM file.
    /// Required on the main node only; leave empty on worker nodes.
    /// Used when `auto_generate = false` to load a pre-generated CA key.
    #[serde(default)]
    pub ca_key: String,
    /// Path to node certificate PEM file
    #[serde(default = "default_node_cert_path")]
    pub node_cert: String,
    /// Path to node private key PEM file
    #[serde(default = "default_node_key_path")]
    pub node_key: String,
    /// Auto-generate CA and node certs on first startup
    #[serde(default = "default_true")]
    pub auto_generate: bool,
    /// CA certificate validity in days (default 10 years)
    #[serde(default = "default_ca_validity_days")]
    pub ca_validity_days: u32,
    /// Node certificate validity in days (default 1 year)
    #[serde(default = "default_node_validity_days")]
    pub node_validity_days: u32,
    /// Renew node cert this many days before expiry
    #[serde(default = "default_renewal_before_days")]
    pub renewal_before_days: u32,
    /// Passphrase used to encrypt the CA private key for replication to workers.
    /// If empty, CA key replication is disabled.
    #[serde(default)]
    pub ca_passphrase: String,
}

fn default_ca_cert_path() -> String {
    "/app/certs/cluster-ca.pem".to_string()
}
fn default_node_cert_path() -> String {
    "/app/certs/node.pem".to_string()
}
fn default_node_key_path() -> String {
    "/app/certs/node.key".to_string()
}
const fn default_ca_validity_days() -> u32 {
    3650
}
const fn default_node_validity_days() -> u32 {
    365
}
const fn default_renewal_before_days() -> u32 {
    7
}

impl Default for ClusterCryptoConfig {
    fn default() -> Self {
        Self {
            ca_cert: default_ca_cert_path(),
            ca_key: String::new(),
            node_cert: default_node_cert_path(),
            node_key: default_node_key_path(),
            auto_generate: true,
            ca_validity_days: default_ca_validity_days(),
            node_validity_days: default_node_validity_days(),
            renewal_before_days: default_renewal_before_days(),
            ca_passphrase: String::new(),
        }
    }
}

/// Cluster sync intervals and batch sizes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterSyncConfig {
    /// Periodic rule version check interval in seconds
    #[serde(default = "default_rules_interval")]
    pub rules_interval_secs: u64,
    /// Config sync interval in seconds
    #[serde(default = "default_config_interval")]
    pub config_interval_secs: u64,
    /// Flush event batch after this many events
    #[serde(default = "default_events_batch_size")]
    pub events_batch_size: usize,
    /// Flush event batch after this many seconds even if not full
    #[serde(default = "default_events_flush_interval")]
    pub events_flush_interval_secs: u64,
    /// Stats push interval in seconds
    #[serde(default = "default_stats_interval")]
    pub stats_interval_secs: u64,
    /// Maximum events in the worker queue before dropping oldest
    #[serde(default = "default_events_queue_size")]
    pub events_queue_size: usize,
}

const fn default_rules_interval() -> u64 {
    10
}
const fn default_config_interval() -> u64 {
    30
}
const fn default_events_batch_size() -> usize {
    100
}
const fn default_events_flush_interval() -> u64 {
    5
}
const fn default_stats_interval() -> u64 {
    10
}
const fn default_events_queue_size() -> usize {
    10_000
}

impl Default for ClusterSyncConfig {
    fn default() -> Self {
        Self {
            rules_interval_secs: default_rules_interval(),
            config_interval_secs: default_config_interval(),
            events_batch_size: default_events_batch_size(),
            events_flush_interval_secs: default_events_flush_interval(),
            stats_interval_secs: default_stats_interval(),
            events_queue_size: default_events_queue_size(),
        }
    }
}

/// Raft-lite election configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterElectionConfig {
    /// Minimum election timeout in milliseconds
    #[serde(default = "default_timeout_min_ms")]
    pub timeout_min_ms: u64,
    /// Maximum election timeout in milliseconds
    #[serde(default = "default_timeout_max_ms")]
    pub timeout_max_ms: u64,
    /// Main→workers heartbeat interval in milliseconds
    #[serde(default = "default_heartbeat_interval_ms")]
    pub heartbeat_interval_ms: u64,
    /// Phi threshold to suspect a node is failing
    #[serde(default = "default_phi_suspect")]
    pub phi_suspect: f64,
    /// Phi threshold to declare a node dead and trigger election
    #[serde(default = "default_phi_dead")]
    pub phi_dead: f64,
}

const fn default_timeout_min_ms() -> u64 {
    150
}
const fn default_timeout_max_ms() -> u64 {
    300
}
const fn default_heartbeat_interval_ms() -> u64 {
    50
}
const fn default_phi_suspect() -> f64 {
    8.0
}
const fn default_phi_dead() -> f64 {
    12.0
}

impl Default for ClusterElectionConfig {
    fn default() -> Self {
        Self {
            timeout_min_ms: default_timeout_min_ms(),
            timeout_max_ms: default_timeout_max_ms(),
            heartbeat_interval_ms: default_heartbeat_interval_ms(),
            phi_suspect: default_phi_suspect(),
            phi_dead: default_phi_dead(),
        }
    }
}

/// Node health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterHealthConfig {
    /// Health check interval in seconds
    #[serde(default = "default_health_check_interval")]
    pub check_interval_secs: u64,
    /// Number of missed heartbeats before declaring node unhealthy
    #[serde(default = "default_max_missed_heartbeats")]
    pub max_missed_heartbeats: u32,
}

const fn default_health_check_interval() -> u64 {
    5
}
const fn default_max_missed_heartbeats() -> u32 {
    3
}

impl Default for ClusterHealthConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: default_health_check_interval(),
            max_missed_heartbeats: default_max_missed_heartbeats(),
        }
    }
}

/// Full cluster configuration — presence of this section enables clustering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    /// Enable clustering. Must be true for any cluster behaviour.
    #[serde(default)]
    pub enabled: bool,
    /// Unique node identifier. Auto-generated from hostname+random suffix if empty.
    #[serde(default)]
    pub node_id: String,
    /// Role assignment: "auto" | "main" | "worker"
    #[serde(default = "default_cluster_role")]
    pub role: String,
    /// QUIC listen address for cluster communication
    #[serde(default = "default_cluster_addr")]
    pub listen_addr: String,
    /// Static seed nodes. At least one reachable seed required to join an existing cluster.
    #[serde(default)]
    pub seeds: Vec<String>,
    /// Join token presented to the main during the join handshake (H-10).
    ///
    /// Generated on the main via the cluster admin API and configured on each
    /// worker. The main validates it against the cluster CA key before accepting
    /// a `JoinRequest`; an empty or invalid token is rejected.
    #[serde(default)]
    pub join_token: String,
    /// Fixed cluster membership (node ids) used to compute election quorum (M-16).
    ///
    /// When non-empty, quorum is derived from this declared size rather than the
    /// dynamically-shrinking live peer view, preventing partitioned minorities
    /// from each electing their own Main (split-brain).
    #[serde(default)]
    pub members: Vec<String>,
    /// Whether the main replicates its (encrypted) CA private key to workers in
    /// the `JoinResponse` for failover (H-10). Defaults to `false`: CA key
    /// material never leaves the main unless explicitly enabled.
    #[serde(default)]
    pub replicate_ca_key: bool,
    /// TLS/certificate settings
    #[serde(default)]
    pub crypto: ClusterCryptoConfig,
    /// Sync intervals and batch sizes
    #[serde(default)]
    pub sync: ClusterSyncConfig,
    /// Election protocol settings
    #[serde(default)]
    pub election: ClusterElectionConfig,
    /// Health check settings
    #[serde(default)]
    pub health: ClusterHealthConfig,
}

fn default_cluster_role() -> String {
    "auto".to_string()
}
fn default_cluster_addr() -> String {
    "0.0.0.0:16851".to_string()
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            node_id: String::new(),
            role: default_cluster_role(),
            listen_addr: default_cluster_addr(),
            seeds: Vec::new(),
            join_token: String::new(),
            members: Vec::new(),
            replicate_ca_key: false,
            crypto: ClusterCryptoConfig::default(),
            sync: ClusterSyncConfig::default(),
            election: ClusterElectionConfig::default(),
            health: ClusterHealthConfig::default(),
        }
    }
}

#[cfg(test)]
mod load_config_tests {
    use super::*;

    /// A missing config file must map to `NotFound` (caller may default).
    #[test]
    fn missing_file_is_not_found() {
        let path = format!(
            "{}/prx-waf-does-not-exist-{}.toml",
            std::env::temp_dir().display(),
            std::process::id()
        );
        match load_config(&path) {
            Err(ConfigError::NotFound(_)) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    /// A file that parses but fails semantic validation must map to `Validate`
    /// (a hard failure — never silently defaulted). Plan §14.1.
    #[test]
    fn invalid_semantic_config_is_validate_error() {
        use crate::content_security_config::{ContentSecurityConfig, SemanticAttackConfig};
        use std::collections::BTreeMap;

        let dir = std::env::temp_dir();
        let path = format!("{}/prx-waf-invalid-{}.toml", dir.display(), std::process::id());

        // Build a fully-parseable config whose only fault is an enabled SQLi
        // family with weights summing to 0.8 (not 1.0) — so the failure is
        // Validate, not Parse.
        let mut weights = BTreeMap::new();
        weights.insert("struct_rule".to_string(), 0.5);
        weights.insert("ast".to_string(), 0.3);
        let mut attacks = BTreeMap::new();
        attacks.insert(
            "sql_injection".to_string(),
            SemanticAttackConfig {
                enabled: true,
                weights,
                log_threshold: 40,
                block_threshold: 80,
                hard_veto_allowlist: Vec::new(),
            },
        );
        let cfg = AppConfig {
            content_security: ContentSecurityConfig {
                enabled: true,
                attacks,
                ..ContentSecurityConfig::default()
            },
            ..AppConfig::default()
        };
        let toml = toml::to_string(&cfg).expect("serialize invalid config");
        std::fs::write(&path, toml).expect("write temp config");
        let result = load_config(&path);
        let _ = std::fs::remove_file(&path);
        match result {
            Err(ConfigError::Validate(msg)) => assert!(msg.contains("sum to 1.0"), "unexpected msg: {msg}"),
            other => panic!("expected Validate, got {other:?}"),
        }
    }

    /// A valid file (a serialized default config) loads cleanly with the
    /// semantic lane off.
    #[test]
    fn valid_config_loads() {
        let dir = std::env::temp_dir();
        let path = format!("{}/prx-waf-valid-{}.toml", dir.display(), std::process::id());
        let toml = toml::to_string(&AppConfig::default()).expect("serialize default");
        std::fs::write(&path, toml).expect("write temp config");
        let result = load_config(&path);
        let _ = std::fs::remove_file(&path);
        let cfg = result.expect("valid config must load");
        assert!(!cfg.content_security.enabled, "semantic lane off by default");
    }
}

#[cfg(test)]
mod env_override_tests {
    use std::collections::HashMap;

    use super::*;

    /// Build an env getter closure backed by a fixed map, so overrides are
    /// tested deterministically without touching the process environment.
    fn getter(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |key: &str| map.get(key).cloned()
    }

    #[test]
    fn parse_env_bool_accepts_common_spellings() {
        for v in ["1", "true", "TRUE", "Yes", "on"] {
            assert!(parse_env_bool("K", v).expect("should parse truthy"));
        }
        for v in ["0", "false", "FALSE", "No", "off"] {
            assert!(!parse_env_bool("K", v).expect("should parse falsy"));
        }
    }

    #[test]
    fn parse_env_bool_rejects_garbage() {
        let err = parse_env_bool("PRXWAF_TRUST_PROXY_HEADERS", "maybe").expect_err("must reject");
        assert!(err.to_string().contains("PRXWAF_TRUST_PROXY_HEADERS"));
    }

    #[test]
    fn parse_env_list_trims_and_drops_empty() {
        assert_eq!(
            parse_env_list(" 10.0.0.0/8 , ,192.168.0.0/16,"),
            vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()]
        );
        assert!(parse_env_list("   ").is_empty());
    }

    /// A cluster section carrying distinct TOML values, so overrides are
    /// observable as changes away from these.
    fn toml_cluster() -> ClusterConfig {
        ClusterConfig {
            enabled: true,
            join_token: "toml-token".to_string(),
            members: vec!["toml-a".to_string()],
            seeds: vec!["toml-seed:1".to_string()],
            replicate_ca_key: false,
            crypto: ClusterCryptoConfig {
                auto_generate: true,
                ca_passphrase: "toml-pass".to_string(),
                ..ClusterCryptoConfig::default()
            },
            ..ClusterConfig::default()
        }
    }

    #[test]
    fn env_set_overrides_toml() {
        let mut cfg = AppConfig {
            cluster: Some(toml_cluster()),
            ..AppConfig::default()
        };
        let get = getter(&[
            ("DATABASE_URL", "postgres://env/db"),
            ("PRXWAF_TRUST_PROXY_HEADERS", "true"),
            ("PRXWAF_TRUSTED_PROXIES", "10.0.0.0/8, 172.16.0.0/12"),
            ("PRXWAF_CLUSTER_JOIN_TOKEN", "env-token"),
            ("PRXWAF_CLUSTER_MEMBERS", "env-a,env-b"),
            ("PRXWAF_CLUSTER_SEEDS", "env-seed:16851"),
            ("PRXWAF_CLUSTER_REPLICATE_CA_KEY", "yes"),
            ("PRXWAF_CLUSTER_AUTO_GENERATE", "false"),
            ("PRXWAF_CLUSTER_CA_PASSPHRASE", "env-pass"),
        ]);

        apply_env_overrides_from(&mut cfg, get).expect("overrides should apply cleanly");

        assert_eq!(cfg.storage.database_url, "postgres://env/db");
        assert!(cfg.proxy.trust_proxy_headers);
        assert_eq!(cfg.proxy.trusted_proxies, vec!["10.0.0.0/8", "172.16.0.0/12"]);
        let c = cfg.cluster.as_ref().expect("cluster present");
        assert_eq!(c.join_token, "env-token");
        assert_eq!(c.members, vec!["env-a", "env-b"]);
        assert_eq!(c.seeds, vec!["env-seed:16851"]);
        assert!(c.replicate_ca_key);
        assert!(!c.crypto.auto_generate);
        assert_eq!(c.crypto.ca_passphrase, "env-pass");
    }

    #[test]
    fn env_unset_preserves_toml() {
        let default_db = StorageConfig::default().database_url;
        let mut cfg = AppConfig {
            cluster: Some(toml_cluster()),
            ..AppConfig::default()
        };

        // Empty getter: nothing is overridden.
        apply_env_overrides_from(&mut cfg, getter(&[])).expect("no-op overrides should apply cleanly");

        assert_eq!(cfg.storage.database_url, default_db);
        assert!(!cfg.proxy.trust_proxy_headers);
        assert!(cfg.proxy.trusted_proxies.is_empty());
        let c = cfg.cluster.as_ref().expect("cluster present");
        assert_eq!(c.join_token, "toml-token");
        assert_eq!(c.members, vec!["toml-a"]);
        assert_eq!(c.seeds, vec!["toml-seed:1"]);
        assert!(!c.replicate_ca_key);
        assert!(c.crypto.auto_generate);
        assert_eq!(c.crypto.ca_passphrase, "toml-pass");
    }

    #[test]
    fn empty_env_value_does_not_clobber_toml() {
        let mut cfg = AppConfig {
            cluster: Some(toml_cluster()),
            ..AppConfig::default()
        };
        // A set-but-empty value (as a docker-compose `${VAR}` expands when unset)
        // must be treated as "not set".
        apply_env_overrides_from(&mut cfg, getter(&[("PRXWAF_CLUSTER_JOIN_TOKEN", "")]))
            .expect("empty override should be a no-op");
        assert_eq!(
            cfg.cluster.as_ref().expect("cluster present").join_token,
            "toml-token",
            "an empty env value must not clobber the TOML value"
        );
    }

    #[test]
    fn cluster_overrides_ignored_without_cluster_section() {
        let mut cfg = AppConfig::default();
        assert!(cfg.cluster.is_none());
        apply_env_overrides_from(&mut cfg, getter(&[("PRXWAF_CLUSTER_JOIN_TOKEN", "env-token")]))
            .expect("should apply cleanly");
        assert!(
            cfg.cluster.is_none(),
            "cluster overrides must not materialise a [cluster] section on their own"
        );
    }

    #[test]
    fn invalid_bool_is_a_hard_error() {
        let mut cfg = AppConfig::default();
        let err = apply_env_overrides_from(&mut cfg, getter(&[("PRXWAF_TRUST_PROXY_HEADERS", "notabool")]))
            .expect_err("invalid bool must error");
        assert!(err.to_string().contains("PRXWAF_TRUST_PROXY_HEADERS"));
    }
}
