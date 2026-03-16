use serde::{Deserialize, Serialize};

/// Top-level application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Phase 6: CrowdSec integration
    #[serde(default)]
    pub crowdsec: CrowdSecConfig,
    /// Phase 7: Rule management
    #[serde(default)]
    pub rules: RulesConfig,
    /// GeoIP lookup configuration
    #[serde(default)]
    pub geoip: GeoIpConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            proxy: ProxyConfig::default(),
            api: ApiConfig::default(),
            storage: StorageConfig::default(),
            hosts: Vec::new(),
            cache: CacheConfig::default(),
            http3: Http3Config::default(),
            security: SecurityConfig::default(),
            crowdsec: CrowdSecConfig::default(),
            rules: RulesConfig::default(),
            geoip: GeoIpConfig::default(),
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

fn default_rule_format() -> String { "yaml".to_string() }
fn default_update_interval() -> u64 { 86400 }

/// Phase 7: Rule management configuration
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

fn default_rules_dir() -> String { "rules/".to_string() }
fn default_hot_reload() -> bool { true }
fn default_debounce_ms() -> u64 { 500 }
fn default_true() -> bool { true }

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

/// CrowdSec integration configuration (mirrors waf-engine CrowdSecConfig but
/// lives in waf-common so it can be loaded from the TOML without pulling in
/// the full engine crate as a dep of prx-waf's config loader).
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
            pusher_login: None,
            pusher_password: None,
        }
    }
}

fn default_cs_update_secs() -> u64 {
    10
}
fn default_cs_fallback() -> String {
    "allow".to_string()
}
fn default_appsec_timeout() -> u64 {
    500
}

/// Proxy listener configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub listen_addr: String,
    pub listen_addr_tls: String,
    pub worker_threads: Option<usize>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:80".to_string(),
            listen_addr_tls: "0.0.0.0:443".to_string(),
            worker_threads: None,
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
}

impl Default for Http3Config {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: "0.0.0.0:443".to_string(),
            cert_pem: None,
            key_pem: None,
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
    /// API rate limit (requests per second per IP, 0 = disabled)
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
            api_rate_limit_rps: 0,
            cors_origins: Vec::new(),
        }
    }
}

/// GeoIP lookup configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpConfig {
    /// Enable GeoIP lookups on every request.
    pub enabled: bool,
    /// Path to the ip2region IPv4 xdb file (default: "data/ip2region_v4.xdb").
    #[serde(default = "default_ipv4_xdb")]
    pub ipv4_xdb_path: String,
    /// Path to the ip2region IPv6 xdb file (default: "data/ip2region_v6.xdb").
    #[serde(default = "default_ipv6_xdb")]
    pub ipv6_xdb_path: String,
    /// Cache policy: "full_memory" (fastest, ~20MB), "vector_index" (~2MB), "no_cache" (1-2MB).
    #[serde(default = "default_geoip_cache_policy")]
    pub cache_policy: String,
}

fn default_ipv4_xdb() -> String { "data/ip2region_v4.xdb".to_string() }
fn default_ipv6_xdb() -> String { "data/ip2region_v6.xdb".to_string() }
fn default_geoip_cache_policy() -> String { "full_memory".to_string() }

impl Default for GeoIpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ipv4_xdb_path: default_ipv4_xdb(),
            ipv6_xdb_path: default_ipv6_xdb(),
            cache_policy: default_geoip_cache_policy(),
        }
    }
}

/// Load configuration from a TOML file
pub fn load_config(path: &str) -> anyhow::Result<AppConfig> {
    let content = std::fs::read_to_string(path)?;
    let config: AppConfig = toml::from_str(&content)?;
    Ok(config)
}
