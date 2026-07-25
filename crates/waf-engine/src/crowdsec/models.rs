use serde::{Deserialize, Serialize};
use std::time::Instant;

/// A `CrowdSec` decision from the LAPI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    /// Decision database ID
    pub id: i64,
    /// Origin: "crowdsec", "cscli", "CAPI", etc.
    pub origin: String,
    /// Scope: "Ip", "Range", "Country", "AS", etc.
    pub scope: String,
    /// Value: IP address, CIDR, country code, AS number, etc.
    pub value: String,
    /// Type: "ban", "captcha", "throttle", etc.
    #[serde(rename = "type")]
    pub type_: String,
    /// Scenario that triggered this decision
    pub scenario: String,
    /// Duration string, e.g. "4h35m6.571762785s"
    pub duration: Option<String>,
    /// Creation timestamp (RFC3339)
    #[serde(default)]
    pub created_at: Option<String>,
}

/// Stream of decisions returned by GET /v1/decisions/stream
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DecisionStream {
    /// Decisions to add to cache
    #[serde(default)]
    pub new: Option<Vec<Decision>>,
    /// Decisions to remove from cache
    #[serde(default)]
    pub deleted: Option<Vec<Decision>>,
}

/// A cached decision with expiry tracking
#[derive(Debug, Clone)]
pub struct CachedDecision {
    pub decision: Decision,
    pub expires_at: Instant,
    /// `true` while this entry came from the durable local mirror
    /// (`crowdsec_decisions`) and has not yet been re-confirmed by a full LAPI
    /// pull.
    ///
    /// Restored entries close the fail-open window at startup, but they are a
    /// *guess* about upstream state: a ban lifted while this process was down
    /// would still be in the mirror. The flag lets
    /// [`crate::crowdsec::DecisionCache::drop_unconfirmed_restored`] evict
    /// exactly those entries the moment a full pull establishes the real set,
    /// so a revoked ban lives at most until the first successful pull.
    pub restored: bool,
}

impl CachedDecision {
    pub fn is_expired(&self) -> bool {
        self.expires_at <= Instant::now()
    }
}

/// Response from POST /v1/decisions/stream (`AppSec`)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSecResponse {
    pub action: String,
    pub http_status: Option<u16>,
    pub message: Option<String>,
}

/// Response from POST /v1/watchers/login
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineAuthResponse {
    pub token: String,
    #[serde(default)]
    pub expire: Option<String>,
}

/// Summary of cache statistics (serializable for API responses)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub total_cached: u64,
    pub hits: u64,
    pub misses: u64,
    pub hit_rate_pct: f64,
}
