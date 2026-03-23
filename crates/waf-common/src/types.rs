use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

/// `GeoIP` information resolved from the client IP address.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GeoIpInfo {
    pub country: String,
    pub province: String,
    pub city: String,
    pub isp: String,
    pub iso_code: String,
}

/// Request context passed through the WAF pipeline
#[derive(Debug, Clone)]
pub struct RequestCtx {
    pub req_id: String,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub method: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub query: String,
    pub headers: HashMap<String, String>,
    pub body_preview: Bytes,
    pub content_length: u64,
    pub is_tls: bool,
    pub host_config: Arc<HostConfig>,
    /// `GeoIP` info populated by the WAF engine before checks run.
    ///
    /// `None` if `GeoIP` is disabled or the xdb file is missing.
    pub geo: Option<GeoIpInfo>,
}

/// WAF action decision
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WafAction {
    Allow,
    Block { status: u16, body: Option<String> },
    LogOnly,
    Redirect { url: String },
}

/// WAF decision with context
#[derive(Debug, Clone)]
pub struct WafDecision {
    pub action: WafAction,
    pub result: Option<DetectionResult>,
}

impl WafDecision {
    pub const fn allow() -> Self {
        Self {
            action: WafAction::Allow,
            result: None,
        }
    }

    pub const fn block(status: u16, body: Option<String>, result: DetectionResult) -> Self {
        Self {
            action: WafAction::Block { status, body },
            result: Some(result),
        }
    }

    pub const fn is_allowed(&self) -> bool {
        matches!(self.action, WafAction::Allow | WafAction::LogOnly)
    }
}

/// Detection phase
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Phase {
    IpWhitelist = 1,
    IpBlacklist = 2,
    UrlWhitelist = 3,
    UrlBlacklist = 4,
    SqlInjection = 5,
    Xss = 6,
    Rce = 7,
    Scanner = 8,
    DirTraversal = 9,
    Bot = 10,
    RateLimit = 11,
    /// Custom scripted rules engine
    CustomRule = 12,
    /// OWASP Core Rule Set checks
    Owasp = 13,
    /// Sensitive word / data-leak detection
    Sensitive = 14,
    /// Anti-hotlinking (Referer check)
    AntiHotlink = 15,
    /// `CrowdSec` bouncer / `AppSec` decision
    CrowdSec = 16,
    /// `GeoIP`-based access control
    GeoIp = 17,
    /// Community threat intelligence blocklist
    Community = 18,
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IpWhitelist => write!(f, "IP Whitelist"),
            Self::IpBlacklist => write!(f, "IP Blacklist"),
            Self::UrlWhitelist => write!(f, "URL Whitelist"),
            Self::UrlBlacklist => write!(f, "URL Blacklist"),
            Self::SqlInjection => write!(f, "SQL Injection"),
            Self::Xss => write!(f, "XSS"),
            Self::Rce => write!(f, "RCE"),
            Self::Scanner => write!(f, "Scanner"),
            Self::DirTraversal => write!(f, "Directory Traversal"),
            Self::Bot => write!(f, "Bot"),
            Self::RateLimit => write!(f, "Rate Limit"),
            Self::CustomRule => write!(f, "Custom Rule"),
            Self::Owasp => write!(f, "OWASP CRS"),
            Self::Sensitive => write!(f, "Sensitive Data"),
            Self::AntiHotlink => write!(f, "Anti-Hotlink"),
            Self::CrowdSec => write!(f, "CrowdSec"),
            Self::GeoIp => write!(f, "GeoIP"),
            Self::Community => write!(f, "Community"),
        }
    }
}

/// Detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub rule_id: Option<String>,
    pub rule_name: String,
    pub phase: Phase,
    pub detail: String,
}

/// Host configuration matching `SamWaf` Hosts model
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfig {
    pub code: String,
    pub host: String,
    pub port: u16,
    pub ssl: bool,
    pub guard_status: bool,
    pub remote_host: String,
    pub remote_port: u16,
    pub remote_ip: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub remarks: Option<String>,
    pub start_status: bool,
    pub exclude_url_log: Vec<String>,
    pub is_enable_load_balance: bool,
    pub load_balance_strategy: LoadBalanceStrategy,
    pub defense_config: DefenseConfig,
    pub log_only_mode: bool,
    /// Custom HTML block page template; placeholders: `{{req_id}}`, `{{rule_name}}`, `{{client_ip}}`
    pub block_page_template: Option<String>,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            code: String::new(),
            host: String::new(),
            port: 80,
            ssl: false,
            guard_status: true,
            remote_host: String::new(),
            remote_port: 8080,
            remote_ip: None,
            cert_file: None,
            key_file: None,
            remarks: None,
            start_status: true,
            exclude_url_log: Vec::new(),
            is_enable_load_balance: false,
            load_balance_strategy: LoadBalanceStrategy::RoundRobin,
            defense_config: DefenseConfig::default(),
            log_only_mode: false,
            block_page_template: None,
        }
    }
}

/// Load balancing strategy
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalanceStrategy {
    #[default]
    RoundRobin,
    IpHash,
    WeightedRoundRobin,
    LeastConnections,
}

/// Defense configuration per host
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct DefenseConfig {
    pub bot: bool,
    pub sqli: bool,
    pub xss: bool,
    pub scan: bool,
    pub rce: bool,
    pub sensitive: bool,
    pub dir_traversal: bool,
    pub owasp_set: bool,
    /// CC / rate-limit protection enabled
    #[serde(default = "bool_true")]
    pub cc: bool,
    /// Token bucket refill rate (requests per second)
    #[serde(default = "default_cc_rps")]
    pub cc_rps: f64,
    /// Token bucket burst capacity
    #[serde(default = "default_cc_burst")]
    pub cc_burst: u32,
    /// Violations before auto-ban
    #[serde(default = "default_cc_ban_threshold")]
    pub cc_ban_threshold: u32,
    /// Auto-ban duration in seconds
    #[serde(default = "default_cc_ban_duration_secs")]
    pub cc_ban_duration_secs: u64,
    /// OWASP CRS paranoia level (1-4, default 1 = most permissive)
    #[serde(default = "default_owasp_paranoia")]
    pub owasp_paranoia: u8,
}

const fn bool_true() -> bool {
    true
}
const fn default_cc_rps() -> f64 {
    100.0
}
const fn default_cc_burst() -> u32 {
    200
}
const fn default_cc_ban_threshold() -> u32 {
    10
}
const fn default_cc_ban_duration_secs() -> u64 {
    300
}
const fn default_owasp_paranoia() -> u8 {
    1
}

impl Default for DefenseConfig {
    fn default() -> Self {
        Self {
            bot: true,
            sqli: true,
            xss: true,
            scan: true,
            rce: true,
            sensitive: true,
            dir_traversal: true,
            owasp_set: false,
            cc: true,
            cc_rps: default_cc_rps(),
            cc_burst: default_cc_burst(),
            cc_ban_threshold: default_cc_ban_threshold(),
            cc_ban_duration_secs: default_cc_ban_duration_secs(),
            owasp_paranoia: default_owasp_paranoia(),
        }
    }
}
