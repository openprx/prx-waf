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
    /// Phase 6: CrowdSec integration
    #[serde(default)]
    pub crowdsec: CrowdSecConfig,
    /// Phase 7: Rule management
    #[serde(default)]
    pub rules: RulesConfig,
    /// GeoIP lookup configuration
    #[serde(default)]
    pub geoip: GeoIpConfig,
    /// Cluster configuration — None means standalone mode (default)
    #[serde(default)]
    pub cluster: Option<ClusterConfig>,
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

fn default_geoip_update_interval() -> String { "7d".to_string() }
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
    /// Automatic xdb update settings.
    #[serde(default)]
    pub auto_update: GeoIpAutoUpdateConfig,
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
            auto_update: GeoIpAutoUpdateConfig::default(),
        }
    }
}

/// Load configuration from a TOML file
pub fn load_config(path: &str) -> anyhow::Result<AppConfig> {
    let content = std::fs::read_to_string(path)?;
    let config: AppConfig = toml::from_str(&content)?;
    Ok(config)
}

// ─── Cluster Configuration ─────────────────────────────────────────────────

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

fn default_ca_cert_path() -> String { "/app/certs/cluster-ca.pem".to_string() }
fn default_node_cert_path() -> String { "/app/certs/node.pem".to_string() }
fn default_node_key_path() -> String { "/app/certs/node.key".to_string() }
fn default_ca_validity_days() -> u32 { 3650 }
fn default_node_validity_days() -> u32 { 365 }
fn default_renewal_before_days() -> u32 { 7 }

impl Default for ClusterCryptoConfig {
    fn default() -> Self {
        Self {
            ca_cert: default_ca_cert_path(),
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

fn default_rules_interval() -> u64 { 10 }
fn default_config_interval() -> u64 { 30 }
fn default_events_batch_size() -> usize { 100 }
fn default_events_flush_interval() -> u64 { 5 }
fn default_stats_interval() -> u64 { 10 }
fn default_events_queue_size() -> usize { 10_000 }

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

fn default_timeout_min_ms() -> u64 { 150 }
fn default_timeout_max_ms() -> u64 { 300 }
fn default_heartbeat_interval_ms() -> u64 { 50 }
fn default_phi_suspect() -> f64 { 8.0 }
fn default_phi_dead() -> f64 { 12.0 }

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

fn default_health_check_interval() -> u64 { 5 }
fn default_max_missed_heartbeats() -> u32 { 3 }

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

fn default_cluster_role() -> String { "auto".to_string() }
fn default_cluster_addr() -> String { "0.0.0.0:16851".to_string() }

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            node_id: String::new(),
            role: default_cluster_role(),
            listen_addr: default_cluster_addr(),
            seeds: Vec::new(),
            crypto: ClusterCryptoConfig::default(),
            sync: ClusterSyncConfig::default(),
            election: ClusterElectionConfig::default(),
            health: ClusterHealthConfig::default(),
        }
    }
}
