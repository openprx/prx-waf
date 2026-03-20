use serde::{Deserialize, Serialize};

/// Community threat intelligence sharing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunityConfig {
    /// Enable community threat intelligence sharing.
    pub enabled: bool,
    /// Community server base URL (e.g. "https://community.openprx.dev").
    #[serde(default = "default_server_url")]
    pub server_url: String,
    /// API key obtained during machine enrollment.
    /// If absent on first run, the machine will auto-enroll.
    #[serde(default)]
    pub api_key: Option<String>,
    /// Machine identifier obtained during enrollment.
    #[serde(default)]
    pub machine_id: Option<String>,
    /// Maximum number of signals to batch before flushing.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    /// Flush interval in seconds (flush even if batch is not full).
    #[serde(default = "default_flush_interval")]
    pub flush_interval_secs: u64,
    /// Blocklist sync interval in seconds.
    #[serde(default = "default_sync_interval")]
    pub sync_interval_secs: u64,
}

impl Default for CommunityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_url: default_server_url(),
            api_key: None,
            machine_id: None,
            batch_size: default_batch_size(),
            flush_interval_secs: default_flush_interval(),
            sync_interval_secs: default_sync_interval(),
        }
    }
}

fn default_server_url() -> String {
    "https://community.openprx.dev".to_string()
}

fn default_batch_size() -> usize {
    50
}

fn default_flush_interval() -> u64 {
    30
}

fn default_sync_interval() -> u64 {
    300
}
