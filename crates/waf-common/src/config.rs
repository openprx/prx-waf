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
    /// OWASP CRS anomaly-scoring model (severity weights + blocking threshold).
    ///
    /// Defaults reproduce upstream CRS v4.25.0 exactly, so a zero-config
    /// install behaves like a stock CRS deployment. See [`OwaspConfig`].
    #[serde(default)]
    pub owasp: OwaspConfig,
    /// Per-request rule-hit audit log.
    ///
    /// **Off by default** — enabling it creates a file and writes one line per
    /// matched rule, which no existing deployment asked for. See
    /// [`AuditLogConfig`].
    #[serde(default)]
    pub audit_log: AuditLogConfig,
    /// Delivery of operator notifications (attack / cert-expiry / backend-down)
    /// to the channels configured in the admin UI.
    ///
    /// **On by default**, but inert until at least one notification channel is
    /// configured — an install with no channels raises no events to anyone. See
    /// [`NotificationsConfig`].
    #[serde(default)]
    pub notifications: NotificationsConfig,
    /// Prometheus scrape endpoint.
    ///
    /// **On by default, bound to `127.0.0.1:9127`.** See
    /// [`crate::metrics::MetricsConfig`] for why that combination and not
    /// off-by-default.
    #[serde(default)]
    pub metrics: crate::metrics::MetricsConfig,
}

/// Runtime settings for operator-notification delivery.
///
/// These govern *when* an event becomes an alert. The *where* (email / webhook /
/// Telegram endpoint, and the per-channel `rate_limit_secs`) is configured per
/// channel in the admin UI and stored in `notification_configs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationsConfig {
    /// Master switch. When `false` no event producer or dispatcher is started
    /// and nothing is ever sent. Default: `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Coalescing window, in seconds.
    ///
    /// The first event of a given kind+scope alerts **immediately**; every
    /// further event with the same scope inside this window is folded into a
    /// single follow-up summary emitted at the end of the window. This is what
    /// stops a scanner generating one email per blocked request. Default: 300
    /// (5 minutes).
    #[serde(default = "default_notify_coalesce_window_secs")]
    pub coalesce_window_secs: u64,
    /// Bounded depth of the in-process event queue. Events published while the
    /// queue is full are dropped and counted (reported in the log). Default:
    /// 1024.
    #[serde(default = "default_notify_queue_capacity")]
    pub queue_capacity: usize,
    /// How often certificates are checked for imminent expiry, in seconds.
    /// Default: 3600 (hourly).
    #[serde(default = "default_notify_cert_check_secs")]
    pub cert_expiry_check_interval_secs: u64,
    /// Start warning this many days before a certificate's `not_after`.
    /// At most one alert per certificate per day is emitted, escalating as the
    /// remaining days count down. Default: 14.
    #[serde(default = "default_notify_cert_warn_days")]
    pub cert_expiry_warn_days: i64,
    /// How often upstream backend health is sampled for up/down transitions, in
    /// seconds. Matches the gateway's own 10s health-check period. Default: 10.
    #[serde(default = "default_notify_backend_poll_secs")]
    pub backend_health_poll_secs: u64,
}

const fn default_notify_coalesce_window_secs() -> u64 {
    300
}

const fn default_notify_queue_capacity() -> usize {
    1024
}

const fn default_notify_cert_check_secs() -> u64 {
    3600
}

const fn default_notify_cert_warn_days() -> i64 {
    14
}

const fn default_notify_backend_poll_secs() -> u64 {
    10
}

impl Default for NotificationsConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            coalesce_window_secs: default_notify_coalesce_window_secs(),
            queue_capacity: default_notify_queue_capacity(),
            cert_expiry_check_interval_secs: default_notify_cert_check_secs(),
            cert_expiry_warn_days: default_notify_cert_warn_days(),
            backend_health_poll_secs: default_notify_backend_poll_secs(),
        }
    }
}

impl NotificationsConfig {
    /// Reject settings that would make the notification runtime misbehave.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.coalesce_window_secs == 0 {
            return Err("notifications.coalesce_window_secs must be >= 1".to_owned());
        }
        if self.queue_capacity == 0 {
            return Err("notifications.queue_capacity must be >= 1".to_owned());
        }
        if self.cert_expiry_check_interval_secs == 0 {
            return Err("notifications.cert_expiry_check_interval_secs must be >= 1".to_owned());
        }
        if self.cert_expiry_warn_days < 0 {
            return Err("notifications.cert_expiry_warn_days must be >= 0".to_owned());
        }
        if self.backend_health_poll_secs == 0 {
            return Err("notifications.backend_health_poll_secs must be >= 1".to_owned());
        }
        Ok(())
    }
}

impl AppConfig {
    /// Cross-field semantic validation applied after deserialisation.
    ///
    /// Validates the Lane 2 semantic content-security config (plan §6.2 strict
    /// loader rule), the OWASP anomaly-scoring model, the audit log and the
    /// notification runtime. Returns a human-readable error on the first
    /// violation.
    pub fn validate(&self) -> Result<(), String> {
        self.content_security.validate()?;
        self.owasp.validate()?;
        self.notifications.validate()?;
        self.proxy.http2.validate()?;
        self.audit_log.validate()
    }
}

impl Http2Config {
    /// Reject values that would wedge the HTTP/2 listener rather than harden it.
    ///
    /// Zero concurrent streams or zero pending-accept resets would refuse every
    /// client; a header-list ceiling below what a bare request's pseudo-headers
    /// need would 431 all traffic. These are bounds against a footgun, not a
    /// policy — any value at or above them is the operator's to choose.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_concurrent_streams == 0 {
            return Err("[proxy.http2] max_concurrent_streams must be at least 1".to_string());
        }
        if self.max_pending_accept_reset_streams == 0 {
            return Err("[proxy.http2] max_pending_accept_reset_streams must be at least 1".to_string());
        }
        if self.max_header_list_size_bytes < 1024 {
            return Err(format!(
                "[proxy.http2] max_header_list_size_bytes must be at least 1024, got {}",
                self.max_header_list_size_bytes
            ));
        }
        Ok(())
    }
}

/// Per-request rule-hit audit log.
///
/// # What it is for
///
/// `security_events` records the *verdict*: one row, one rule id — the heaviest
/// contributor. That answers "why was this blocked" and nothing else. The
/// question an operator actually asks when tuning a rule set is "which rules did
/// this request touch, and how much did each of them add", including for the
/// requests that scored but stayed under the threshold and therefore produce no
/// row at all. This log answers that: one line per matched rule, plus one line
/// for the anomaly-score verdict, in `ModSecurity` error-log shape.
///
/// # PII
///
/// The log records request *metadata*, not request content: client IP, host,
/// method and URI path — the same fields `attack_logs` already persists — plus
/// the rule ids that matched. The query string is **excluded unless**
/// [`Self::include_query`] is set, and the matched data is never written at all.
/// Because the file is the operator's to keep, [`Self::max_size_mb`] and
/// [`Self::keep_rotations`] bound both its size and how long that metadata
/// survives on disk; the equivalent of the database retention pruner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogConfig {
    /// Write the audit log at all. `false` (the default) means no file is
    /// opened, no writer task is started and nothing is recorded.
    #[serde(default)]
    pub enabled: bool,
    /// Path of the live log file. Relative paths resolve against the working
    /// directory, like `rules.dir`.
    #[serde(default = "default_audit_log_path")]
    pub path: String,
    /// Rotate the live file once it exceeds this many megabytes. `0` disables
    /// rotation, which lets the file grow without bound — only sensible when
    /// something external (logrotate, a container log driver) truncates it.
    #[serde(default = "default_audit_log_max_size_mb")]
    pub max_size_mb: u64,
    /// How many rotated generations (`<path>.1`, `<path>.2`, …) to keep. The
    /// oldest is deleted on each rotation, which is what bounds the lifetime of
    /// the request metadata on disk.
    #[serde(default = "default_audit_log_keep_rotations")]
    pub keep_rotations: u8,
    /// Append the query string to the logged URI. Off by default: query strings
    /// carry user-supplied data and, on an attack, the payload itself.
    #[serde(default)]
    pub include_query: bool,
    /// Name of a request header whose value is echoed to the log as a
    /// synchronisation marker, and whose presence suppresses that request's own
    /// rule lines.
    ///
    /// Empty (the default) turns the marker protocol off. Setting it to
    /// `X-CRS-Test` reproduces what the upstream CRS test container does with
    /// `CRS_ENABLE_TEST_MARKER=1` (rule `999999`: log the header value, then
    /// `ctl:ruleRemoveById=1-999999` so the marker request contributes no other
    /// line), which is what `go-ftw`'s log mode reads to delimit one test.
    #[serde(default)]
    pub marker_header: String,
}

fn default_audit_log_path() -> String {
    "logs/audit.log".to_owned()
}
const fn default_audit_log_max_size_mb() -> u64 {
    64
}
const fn default_audit_log_keep_rotations() -> u8 {
    3
}

impl Default for AuditLogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_audit_log_path(),
            max_size_mb: default_audit_log_max_size_mb(),
            keep_rotations: default_audit_log_keep_rotations(),
            include_query: false,
            marker_header: String::new(),
        }
    }
}

impl AuditLogConfig {
    /// Reject a configuration that cannot produce a usable log.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.path.trim().is_empty() {
            return Err("audit_log.path must not be empty when audit_log.enabled is true".to_owned());
        }
        if self.marker_header.contains(char::is_whitespace) {
            return Err(format!(
                "audit_log.marker_header must be a single HTTP header name, got {:?}",
                self.marker_header
            ));
        }
        Ok(())
    }

    /// Rotation threshold in bytes, or `None` when rotation is disabled.
    #[must_use]
    pub const fn max_size_bytes(&self) -> Option<u64> {
        if self.max_size_mb == 0 {
            None
        } else {
            Some(self.max_size_mb.saturating_mul(1024 * 1024))
        }
    }

    /// The marker header name in lower case, or `None` when the marker protocol
    /// is off. Request headers are stored lower-cased by the gateway.
    #[must_use]
    pub fn marker_header_lower(&self) -> Option<String> {
        let trimmed = self.marker_header.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_ascii_lowercase())
        }
    }
}

/// OWASP CRS anomaly-scoring configuration.
///
/// # Why this exists
///
/// Upstream CRS does **not** block on the first rule that matches. Almost every
/// rule carries `pass` (via `SecDefaultAction "phase:2,log,auditlog,pass"` in
/// `crs-setup.conf.example:98-99`) plus a
/// `setvar:tx.inbound_anomaly_score_plN=+%{tx.<severity>_anomaly_score}`, and a
/// single dedicated rule — `949110` in `REQUEST-949-BLOCKING-EVALUATION.conf` —
/// denies the request when the accumulated score reaches
/// `tx.inbound_anomaly_score_threshold`.
///
/// The defaults below are the values that rule set actually ships, read from
/// `rules/REQUEST-901-INITIALIZATION.conf`: rules `901140`..`901143` set the
/// four severity scores (lines 146-180) and `901100` / `901110` set the inbound
/// and outbound thresholds (lines 76-93). `crs-setup.conf.example:275-278` and
/// `:336-337` show the same numbers as the commented operator-facing knobs.
///
/// # What a threshold of 5 means
///
/// A `CRITICAL` rule alone scores 5, which already reaches the default
/// threshold — so the change is **not** "nothing blocks any more". It is
/// specifically that a `WARNING` (3) or `NOTICE` (2) rule no longer blocks on
/// its own, which is CRS's own false-positive control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwaspConfig {
    /// Accumulate per-rule scores and block on the threshold (upstream CRS
    /// semantics). When `false` the check reverts to "first matching rule
    /// blocks", which is stricter than upstream and a documented source of
    /// false positives — kept only as an escape hatch.
    #[serde(default = "default_true")]
    pub anomaly_scoring: bool,
    /// Score contributed by a rule with `severity: critical`
    /// (`tx.critical_anomaly_score`, upstream default 5).
    #[serde(default = "default_critical_anomaly_score")]
    pub critical_anomaly_score: u32,
    /// Score contributed by a rule with `severity: error`
    /// (`tx.error_anomaly_score`, upstream default 4).
    #[serde(default = "default_error_anomaly_score")]
    pub error_anomaly_score: u32,
    /// Score contributed by a rule with `severity: warning`
    /// (`tx.warning_anomaly_score`, upstream default 3).
    #[serde(default = "default_warning_anomaly_score")]
    pub warning_anomaly_score: u32,
    /// Score contributed by a rule with `severity: notice`
    /// (`tx.notice_anomaly_score`, upstream default 2).
    #[serde(default = "default_notice_anomaly_score")]
    pub notice_anomaly_score: u32,
    /// Block when the accumulated inbound score reaches this value
    /// (`tx.inbound_anomaly_score_threshold`, upstream default 5).
    ///
    /// Must be at least 1: a threshold of 0 is reached by every request,
    /// including one that matched nothing, and would deny all traffic.
    #[serde(default = "default_inbound_anomaly_score_threshold")]
    pub inbound_anomaly_score_threshold: u32,
    /// Act on a response when the accumulated **outbound** score reaches this
    /// value (`tx.outbound_anomaly_score_threshold`, upstream default 4).
    ///
    /// # Why this is not the inbound threshold
    ///
    /// It is a different number upstream and the difference is deliberate:
    /// `REQUEST-901-INITIALIZATION.conf` sets `tx.inbound_anomaly_score_threshold`
    /// to 5 and `tx.outbound_anomaly_score_threshold` to 4, and
    /// `RESPONSE-959-BLOCKING-EVALUATION.conf` rule `959100` compares the
    /// outbound total against the latter. With the shipped severity weights a
    /// single `ERROR` response rule (4) therefore reaches the outbound threshold
    /// on its own while it would not reach the inbound one — response-phase CRS
    /// is trigger-happier than request-phase CRS by design, because a leaked
    /// stack trace is a fact about the response rather than an inference about
    /// intent.
    ///
    /// Must be at least 1, for the same reason as the inbound threshold.
    #[serde(default = "default_outbound_anomaly_score_threshold")]
    pub outbound_anomaly_score_threshold: u32,
}

const fn default_critical_anomaly_score() -> u32 {
    5
}
const fn default_error_anomaly_score() -> u32 {
    4
}
const fn default_warning_anomaly_score() -> u32 {
    3
}
const fn default_notice_anomaly_score() -> u32 {
    2
}
const fn default_inbound_anomaly_score_threshold() -> u32 {
    5
}
const fn default_outbound_anomaly_score_threshold() -> u32 {
    4
}

impl Default for OwaspConfig {
    fn default() -> Self {
        Self {
            anomaly_scoring: true,
            critical_anomaly_score: default_critical_anomaly_score(),
            error_anomaly_score: default_error_anomaly_score(),
            warning_anomaly_score: default_warning_anomaly_score(),
            notice_anomaly_score: default_notice_anomaly_score(),
            inbound_anomaly_score_threshold: default_inbound_anomaly_score_threshold(),
            outbound_anomaly_score_threshold: default_outbound_anomaly_score_threshold(),
        }
    }
}

impl OwaspConfig {
    /// Reject a scoring model that cannot express a decision.
    ///
    /// A zero threshold denies every request (the score starts at 0 and `>=`
    /// holds immediately), and a threshold no severity can ever reach makes the
    /// check unable to block at all. Both are configuration mistakes that would
    /// otherwise only surface as a production outage or a silent hole.
    pub fn validate(&self) -> Result<(), String> {
        if !self.anomaly_scoring {
            return Ok(());
        }
        if self.inbound_anomaly_score_threshold == 0 {
            return Err(
                "owasp.inbound_anomaly_score_threshold must be >= 1: a threshold of 0 is reached by \
                 every request, including one that matched no rule, and would deny all traffic"
                    .to_owned(),
            );
        }
        if self.outbound_anomaly_score_threshold == 0 {
            return Err(
                "owasp.outbound_anomaly_score_threshold must be >= 1: a threshold of 0 is reached by \
                 every response, including one that matched no rule, and would condemn all traffic"
                    .to_owned(),
            );
        }
        let highest = self.critical_anomaly_score;
        if highest == 0 {
            return Err(
                "owasp.critical_anomaly_score must be >= 1: with a zero weight no rule can ever \
                 contribute to the anomaly score and the CRS check can never block"
                    .to_owned(),
            );
        }
        Ok(())
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
    /// Mirror every cached LAPI decision into the `crowdsec_decisions` table and
    /// restore from it at startup.
    ///
    /// The bouncer's decision cache is in-memory and starts empty on every
    /// process start. With the mirror off, a process that comes up while LAPI is
    /// unreachable matches **no** IP at all — every previously banned client is
    /// allowed through — until a poll finally succeeds. With it on, the still
    /// valid decisions are loaded from the local database before the proxy
    /// starts serving, and the first successful full pull immediately reconciles
    /// them against upstream so a ban lifted while the process was down cannot
    /// be resurrected.
    ///
    /// Defaults to on. Turn it off only when banned client IPs must not be
    /// written to the database at all (they are personal data; the
    /// `storage.crowdsec_decision_retention_days` window bounds how long they
    /// are kept), or when the database is read-only.
    #[serde(default = "default_true")]
    pub persist_decisions: bool,
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
            persist_decisions: true,
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
    /// Where the proxy terminates TLS. Set to the empty string to run no TLS
    /// listener at all.
    ///
    /// A certificate is required before this can bind, and the default install
    /// has none, so the listener is created only when one can be resolved —
    /// from [`Self::tls_cert_pem`] if configured, otherwise from the newest
    /// usable row in the `certificates` table, which is what ACME issues into.
    /// When neither yields a certificate the address is not bound and the
    /// reason is logged at WARN; the plaintext listener is unaffected.
    ///
    /// **One certificate, no SNI.** Pingora 0.8.1's rustls backend builds each
    /// endpoint's acceptor with `with_single_cert`
    /// (`pingora-core-0.8.1/src/listeners/tls/rustls/mod.rs:70`) and its
    /// `TlsSettings` exposes no certificate callback — `with_callbacks` there
    /// returns "Certificate callbacks are not supported with feature
    /// \"rustls\"" (:114-118) — so one certificate serves every hostname that
    /// arrives on this port. Hosts not covered by it get a name-mismatch
    /// failure in the client. Cover several names with one SAN or wildcard
    /// certificate, or terminate their TLS elsewhere.
    pub listen_addr_tls: String,
    /// PEM certificate chain file for [`Self::listen_addr_tls`], leaf first.
    ///
    /// Set together with [`Self::tls_key_pem`] to serve a specific certificate
    /// instead of whatever the `certificates` table currently holds. That is
    /// the way to pin one host when several are provisioned, to run TLS with
    /// no ACME at all, and to make the TCP listener serve the same file
    /// `[http3] cert_pem` does — HTTP/3 reads only from configured paths and
    /// never from the database, so leaving this unset while HTTP/3 is enabled
    /// means the two protocols can present different certificates.
    ///
    /// Renewal is not this file's business: whatever writes it is responsible
    /// for keeping it current, and a change is picked up on restart.
    #[serde(default)]
    pub tls_cert_pem: Option<String>,
    /// PEM private key file for [`Self::tls_cert_pem`]. Both must be set for
    /// either to take effect.
    #[serde(default)]
    pub tls_key_pem: Option<String>,
    /// Worker threads for the Pingora proxy data plane — the runtime every
    /// request is accepted, inspected and relayed on.
    ///
    /// * **absent** (the shipped default) — follow the CPUs this process is
    ///   allowed to run on, i.e. [`std::thread::available_parallelism`].
    /// * **`0`** — the same thing, said explicitly.
    /// * **`N > 0`** — exactly `N` threads, whatever the machine has.
    ///
    /// "The CPUs this process is allowed to run on" is deliberately not "the
    /// host's core count": on Linux `available_parallelism` honours the cgroup
    /// CPU quota and the process's CPU affinity mask, so a container limited to
    /// `cpus: 2` gets 2 and a `taskset -c 0-3` run gets 4 — which is the number
    /// that can actually do work. Detection failing is not fatal: the proxy
    /// falls back to a single thread and says so at startup.
    ///
    /// Resolution lives in [`ProxyConfig::worker_thread_plan`]; the value
    /// reaches Pingora as `ServerConf::threads`.
    #[serde(default)]
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
    /// Enable HTTP request-smuggling structural detection in the gateway
    /// header phase. Detection is **shadow / log-only**: matched requests are
    /// logged (`tracing::warn`, target `waf.smuggling`) but never blocked or
    /// altered. Defaults to `true`.
    #[serde(default = "default_true")]
    pub smuggling_detection: bool,
    /// Per-stage timeouts applied to the connection the proxy opens to the
    /// upstream. **Every stage is unlimited by default** — see
    /// [`UpstreamTimeoutConfig`].
    #[serde(default)]
    pub upstream_timeouts: UpstreamTimeoutConfig,
    /// Filesystem path of the Unix socket the two processes of a zero-downtime
    /// upgrade use to hand the listening sockets over.
    ///
    /// **Absent** (the shipped default) means the path is derived from the
    /// process's effective uid rather than read from a file, so the outgoing
    /// and incoming process agree on it without either being configured. The
    /// derivation is in `prx-waf`'s `upgrade` module and is announced at
    /// startup.
    ///
    /// Set it only to move the socket somewhere specific — a persistent
    /// runtime directory a supervisor creates, say. Whatever it points at, the
    /// **parent directory** is the security boundary: the socket itself is
    /// chmod 0666 by Pingora (`transfer_fd/mod.rs:133`), and whoever can create
    /// a socket at this path while an upgrade is in flight receives the
    /// listening file descriptors of the port this WAF is protecting. prx-waf
    /// therefore refuses a parent directory that is a symlink, is owned by
    /// another user, or grants any access to group or other.
    #[serde(default)]
    pub upgrade_sock: Option<String>,
    /// Seconds a process keeps serving requests it has already accepted after
    /// it has been told to stop — by `SIGTERM`, or by handing its listeners to
    /// a replacement.
    ///
    /// It is a **fixed wait, not a drain detector**. Pingora sleeps the whole
    /// period whether or not anything is still in flight
    /// (`pingora-core-0.8.1/src/server/mod.rs:777`) and then gives the runtimes
    /// five more seconds before cutting them, so this is the exact cost of
    /// every stop and every upgrade, not a worst case. Pingora's own default —
    /// applied when this is left unset, which is what prx-waf used to do — is
    /// **300 seconds** (`server/mod.rs:56`): five minutes of two processes, two
    /// database pools, and no management API, after a handover that finished in
    /// two seconds.
    ///
    /// Size it to the longest request this proxy should be allowed to finish.
    /// `0` cuts straight to the five-second runtime shutdown, which severs
    /// anything still running.
    #[serde(default = "default_drain_timeout_secs")]
    pub drain_timeout_secs: u64,
    /// HTTP/2 frame-layer limits for the TLS listener. Every field defaults to
    /// the value the listener already ran with, so leaving this table out
    /// changes nothing — see [`Http2Config`].
    #[serde(default)]
    pub http2: Http2Config,
}

/// See [`ProxyConfig::drain_timeout_secs`].
const fn default_drain_timeout_secs() -> u64 {
    30
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:80".to_string(),
            listen_addr_tls: "0.0.0.0:443".to_string(),
            tls_cert_pem: None,
            tls_key_pem: None,
            worker_threads: None,
            trust_proxy_headers: false,
            trusted_proxies: Vec::new(),
            smuggling_detection: true,
            upstream_timeouts: UpstreamTimeoutConfig::default(),
            upgrade_sock: None,
            drain_timeout_secs: default_drain_timeout_secs(),
            http2: Http2Config::default(),
        }
    }
}

/// HTTP/2 frame-layer limits for the TLS listener (ALPN `h2`).
///
/// These are `h2`-crate knobs, not anything this proxy implements. `h2` 0.4.15
/// already answers the HTTP/2 denial-of-service surface — Rapid Reset
/// (CVE-2023-44487), the CONTINUATION flood (CVE-2024-27316), and the
/// control-frame floods — inside `conn.accept()`, before a request ever reaches
/// WAF detection. The defaults here reproduce exactly what the listener ran
/// with before this table existed, so an operator who sets nothing gets the
/// same, proven behaviour; the point of the table is to let one *tighten* those
/// ceilings for extra hardening, and to pin the reset ceiling that Pingora's
/// `default_h2_options()` otherwise leaves floating at whatever `h2` version is
/// compiled in. See `docs/http2-attack-surface.md` for the evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http2Config {
    /// `SETTINGS_MAX_CONCURRENT_STREAMS` advertised to clients: the most
    /// request streams one connection may have open at once. Default 100
    /// (`pingora-core-0.8.1`'s `default_h2_options`). Lower it to cap the
    /// per-connection fan-out an attacker can hold; too low throttles
    /// legitimate multiplexing clients.
    #[serde(default = "default_h2_max_concurrent_streams")]
    pub max_concurrent_streams: u32,
    /// `SETTINGS_MAX_HEADER_LIST_SIZE`: the decoded header-list byte ceiling,
    /// enforced by `h2` *during* header accumulation, not only at the end — so
    /// it also bounds a CONTINUATION flood. Default 65536 (64 KiB).
    #[serde(default = "default_h2_max_header_list_size")]
    pub max_header_list_size_bytes: u32,
    /// How many streams a client may reset *before this server has accepted
    /// them* before the whole connection is failed with
    /// `GOAWAY(ENHANCE_YOUR_CALM)`. This is `h2`'s Rapid-Reset
    /// (CVE-2023-44487) ceiling. Default 20 (`h2`'s
    /// `DEFAULT_REMOTE_RESET_STREAM_MAX`). Lower it to kill a reset flood
    /// sooner; a handful is enough for the polite cancellations real clients
    /// send.
    #[serde(default = "default_h2_max_pending_accept_reset_streams")]
    pub max_pending_accept_reset_streams: u32,
}

/// See [`Http2Config::max_concurrent_streams`]. Matches
/// `pingora-core-0.8.1/src/protocols/http/v2/server.rs`'s
/// `DEFAULT_MAX_CONCURRENT_STREAMS`.
const fn default_h2_max_concurrent_streams() -> u32 {
    100
}

/// See [`Http2Config::max_header_list_size_bytes`]. Matches
/// `pingora-core-0.8.1`'s `DEFAULT_MAX_HEADER_LIST_SIZE`.
const fn default_h2_max_header_list_size() -> u32 {
    64 * 1024
}

/// See [`Http2Config::max_pending_accept_reset_streams`]. Matches `h2`
/// 0.4.15's `DEFAULT_REMOTE_RESET_STREAM_MAX`.
const fn default_h2_max_pending_accept_reset_streams() -> u32 {
    20
}

impl Default for Http2Config {
    fn default() -> Self {
        Self {
            max_concurrent_streams: default_h2_max_concurrent_streams(),
            max_header_list_size_bytes: default_h2_max_header_list_size(),
            max_pending_accept_reset_streams: default_h2_max_pending_accept_reset_streams(),
        }
    }
}

/// Where the effective proxy worker-thread count came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerThreadSource {
    /// `[proxy] worker_threads` is not set, so the count follows the CPUs this
    /// process may run on.
    DefaultFollowsCpus,
    /// `[proxy] worker_threads = 0` — follow the CPUs, stated explicitly.
    ExplicitFollowsCpus,
    /// `[proxy] worker_threads = N`, `N > 0` — a fixed count, independent of
    /// the machine.
    Fixed,
}

/// The resolved worker-thread decision: how many threads the proxy data plane
/// will run on, and why.
///
/// Kept separate from the raw config value because the *why* is what the
/// startup broadcast has to say. An operator reading `worker_threads: 4` in a
/// log cannot tell whether the box has four cores, whether a container quota
/// cut it to four, or whether someone pinned it — and those have different
/// remedies when throughput is short.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerThreadPlan {
    /// Threads to hand Pingora. Always at least 1.
    pub threads: usize,
    /// How [`Self::threads`] was decided.
    pub source: WorkerThreadSource,
    /// CPUs this process may run on, when they could be detected.
    pub available_cpus: Option<usize>,
}

impl WorkerThreadPlan {
    /// Resolve a plan from the configured value and an already-detected CPU
    /// count. `available_cpus` is `None` when detection failed.
    ///
    /// Split out from [`Self::detect`] so the decision table is testable
    /// without depending on the number of cores the test host happens to have.
    #[must_use]
    pub fn resolve(configured: Option<usize>, available_cpus: Option<usize>) -> Self {
        let source = match configured {
            None => WorkerThreadSource::DefaultFollowsCpus,
            Some(0) => WorkerThreadSource::ExplicitFollowsCpus,
            Some(_) => WorkerThreadSource::Fixed,
        };
        let threads = match configured {
            Some(n) if n > 0 => n,
            // Follow the CPUs. A failed detection falls back to one thread
            // rather than to a guess: one thread is the behaviour every release
            // before this key had, so an unreadable affinity mask degrades to
            // the old, known-safe posture instead of oversubscribing a machine
            // nothing can currently measure.
            _ => available_cpus.unwrap_or(1),
        };
        Self {
            threads,
            source,
            available_cpus,
        }
    }

    /// Resolve a plan, detecting the CPUs this process may run on.
    #[must_use]
    pub fn detect(configured: Option<usize>) -> Self {
        let available = std::thread::available_parallelism()
            .ok()
            .map(std::num::NonZeroUsize::get);
        Self::resolve(configured, available)
    }

    /// True when the proxy ends up on one thread on a host that offered more —
    /// the shape of the throughput ceiling this key exists to lift.
    #[must_use]
    pub fn is_single_threaded_on_a_wider_host(&self) -> bool {
        self.threads == 1 && self.available_cpus.is_none_or(|cpus| cpus > 1)
    }
}

impl ProxyConfig {
    /// Resolve [`ProxyConfig::worker_threads`] into the count Pingora is given.
    #[must_use]
    pub fn worker_thread_plan(&self) -> WorkerThreadPlan {
        WorkerThreadPlan::detect(self.worker_threads)
    }
}

/// Timeouts for the proxy → upstream connection, one key per Pingora
/// `PeerOptions` stage.
///
/// **All five default to `0` = no timeout**, which is what the proxy has always
/// done: `HttpPeer::new()` leaves `PeerOptions::connection_timeout`,
/// `total_connection_timeout`, `read_timeout`, `write_timeout` and
/// `idle_timeout` at `None`, and `None` means *wait forever*
/// (`pingora-core-0.8.1/src/upstreams/peer.rs:471-478`). An install that sets
/// none of these keys is byte-for-byte the old behaviour: no timer is armed and
/// the peer options are never written.
///
/// Turning any of them on is a real trade. It bounds how long a slow or
/// black-holed upstream can pin the proxy's single worker thread, and it
/// severs any connection that exceeds the bound — including long-lived
/// streaming responses that are behaving exactly as designed. `read_ms` is the
/// dangerous one: it is an **inactivity** timer re-armed per read, so a
/// Server-Sent Events feed that is silent for longer than `read_ms` between
/// events is killed mid-stream. See `stream_exempt` and `docs/dos-budget.md`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpstreamTimeoutConfig {
    /// Milliseconds allowed for one TCP connect attempt to the upstream.
    /// `0` = unlimited (default). Maps to `PeerOptions::connection_timeout`.
    pub connect_ms: u64,
    /// Milliseconds allowed for the whole connection setup — TCP connect plus
    /// the TLS handshake, across all address-family attempts. `0` = unlimited
    /// (default). Maps to `PeerOptions::total_connection_timeout`. Should be no
    /// smaller than `connect_ms`; the two are independent deadlines and
    /// whichever fires first wins.
    pub total_connect_ms: u64,
    /// Milliseconds the proxy will wait for *any single read* from the
    /// upstream — the response header, then each body chunk. `0` = unlimited
    /// (default). Maps to `PeerOptions::read_timeout`.
    ///
    /// This is not a total response deadline: the timer restarts on every byte
    /// received, so a steady trickle never trips it and a stalled stream trips
    /// it after `read_ms` of silence. On expiry Pingora fails the request with
    /// `ReadTimedout`.
    pub read_ms: u64,
    /// Milliseconds the proxy will wait for any single write to the upstream
    /// (request header, then each request-body chunk). `0` = unlimited
    /// (default). Maps to `PeerOptions::write_timeout`.
    pub write_ms: u64,
    /// Milliseconds an idle keep-alive connection may sit in the upstream
    /// connection pool before it is closed. `0` = unlimited (default), i.e.
    /// pooled connections are held until the upstream itself hangs up. Maps to
    /// `PeerOptions::idle_timeout`. This is a pool-residency bound, not a
    /// request-path timeout: no in-flight request is ever affected by it.
    pub idle_ms: u64,
    /// Exempt streaming requests from `read_ms` / `write_ms`. Default `false`.
    ///
    /// A request counts as streaming when it carries an `Upgrade` header
    /// (WebSocket and friends) or asks for `Accept: text/event-stream` (SSE).
    /// Pingora itself draws no such distinction — `proxy_h1.rs:39-40` copies
    /// the peer's read/write timeouts onto the upstream session before the
    /// upgrade is even known, and they then govern every body read including
    /// the post-101 WebSocket frames — so this exemption is the proxy's own,
    /// applied when the peer is built.
    ///
    /// **Default off, deliberately.** Both signals are request headers, so
    /// they are attacker-chosen: with the exemption on, anyone who adds
    /// `Accept: text/event-stream` to a request opts *themselves* out of
    /// `read_ms` and gets the unbounded behaviour back. Turn it on only when
    /// you genuinely serve long-idle streams through this proxy and accept
    /// that hole; the alternative that keeps the bound honest is to set
    /// `read_ms` above your stream's heartbeat interval.
    ///
    /// `connect_ms`, `total_connect_ms` and `idle_ms` are never exempted —
    /// connection setup is not a streaming activity, and an upgraded
    /// connection is never returned to the idle pool.
    pub stream_exempt: bool,
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
    /// Retention window, in days, for the Lane 2 `semantic_observations`
    /// shadow-telemetry table.
    ///
    /// That table carries `client_ip` and `req_id` for every semantic
    /// detection and the lane is shadow-enabled by default, so without a TTL it
    /// grows without bound and holds personal data indefinitely. A background
    /// pruner deletes rows older than this window.
    ///
    /// `0` disables pruning entirely (rows are kept forever); startup logs a
    /// warning in that case so the choice is never silent.
    #[serde(default = "default_semantic_observation_retention_days")]
    pub semantic_observation_retention_days: i64,
    /// Retention window, in days, for `security_events` — the rule-detection
    /// feed behind the dashboard. Rows carry `client_ip`, method, path and geo.
    /// `0` keeps rows forever and warns at startup.
    #[serde(default = "default_security_event_retention_days")]
    pub security_event_retention_days: i64,
    /// Retention window, in days, for `attack_logs` — blocked / logged requests
    /// including `client_ip`, query string and captured request headers. `0`
    /// keeps rows forever and warns at startup.
    #[serde(default = "default_attack_log_retention_days")]
    pub attack_log_retention_days: i64,
    /// Retention window, in days, for `audit_log` — the record of every mutating
    /// admin API call. `0` keeps rows forever and warns at startup.
    #[serde(default = "default_audit_log_retention_days")]
    pub audit_log_retention_days: i64,
    /// Retention window, in days, for `crowdsec_events` — the local echo of
    /// `CrowdSec` decisions, carrying `client_ip`. `0` keeps rows forever and
    /// warns at startup.
    #[serde(default = "default_crowdsec_event_retention_days")]
    pub crowdsec_event_retention_days: i64,
    /// Retention window, in days, for `crowdsec_decisions` — cached `CrowdSec`
    /// LAPI decisions, whose `value` column holds the banned client IP when
    /// `scope='Ip'`. Unlike the other tables this is keyed on the decision's
    /// own `expires_at`, not row insertion time: rows are deleted once they
    /// have been expired for longer than this window. `0` keeps rows forever
    /// and warns at startup.
    #[serde(default = "default_crowdsec_decision_retention_days")]
    pub crowdsec_decision_retention_days: i64,
    /// Retention window, in days, for `refresh_tokens` — JWT refresh token
    /// hashes. Keyed on `expires_at`, but a revoked token is deleted on the
    /// next sweep regardless of this window since it can never be redeemed
    /// again. `0` keeps rows forever (including revoked ones) and warns at
    /// startup.
    #[serde(default = "default_refresh_token_retention_days")]
    pub refresh_token_retention_days: i64,
    /// Retention window, in days, for `notification_log` — delivery records
    /// whose `message`/`error_msg` free text may embed a `client_ip` from the
    /// triggering event. `0` keeps rows forever and warns at startup.
    #[serde(default = "default_notification_log_retention_days")]
    pub notification_log_retention_days: i64,
    /// Retention window, in days, for `request_stats` — aggregated per-host
    /// request/block counters with no personal data. Keyed on the
    /// aggregation bucket's own `period_start`, not row insertion time. `0`
    /// keeps rows forever and warns at startup.
    #[serde(default = "default_request_stats_retention_days")]
    pub request_stats_retention_days: i64,
    /// How often the retention pruner runs, in hours. Clamped to at least 1.
    #[serde(default = "default_retention_prune_interval_hours")]
    pub retention_prune_interval_hours: u64,
    /// Rows deleted per `DELETE` statement while draining a table. Bounding the
    /// statement keeps each transaction short instead of locking millions of
    /// rows at once. Clamped to `1..=100000`; `0` falls back to the default.
    #[serde(default = "default_retention_prune_batch_size")]
    pub retention_prune_batch_size: i64,
}

/// Default `semantic_observations` retention: 30 days.
///
/// The table is shadow telemetry for tuning detection / false-positive rates,
/// which is a short-horizon activity — a month of history already spans several
/// tuning cycles. It is deliberately at the low end of the 30–90 day range
/// common for security logs because these rows carry `client_ip` (personal
/// data) with no operational need for long-term retention.
const fn default_semantic_observation_retention_days() -> i64 {
    30
}

/// Default `security_events` retention: 90 days.
///
/// This is the attack-telemetry feed operators actually work from: tuning a
/// noisy rule, judging whether a campaign is new or recurring, and writing up an
/// incident all need more than a month of history — a quarter is the shortest
/// window that contains a full "is this seasonal?" comparison. 90 days is also
/// the conventional hot window for security logs (PCI DSS 10.5.1 asks for three
/// months immediately available). It stops there rather than going longer
/// because every row carries `client_ip`: past a quarter the personal-data cost
/// outgrows the analytical value, and long-term trends belong in an aggregated
/// export, not in raw per-request rows.
const fn default_security_event_retention_days() -> i64 {
    90
}

/// Default `attack_logs` retention: 90 days.
///
/// Kept in lockstep with `security_events`: the two tables are the same incident
/// viewed from the request side and the rule side, and an investigation that can
/// see one but not the other is worse than useless. `attack_logs` is the more
/// sensitive of the pair — it stores the query string and captured request
/// headers, which can contain tokens and session cookies — so it gets the same
/// ceiling and not a day more.
const fn default_attack_log_retention_days() -> i64 {
    90
}

/// Default `audit_log` retention: 365 days.
///
/// Deliberately far longer than the telemetry tables, for two reasons. First,
/// content: this table records *administrator* actions — who changed a rule,
/// disabled a host, rotated a certificate — keyed by `admin_username` and the
/// admin's source IP. That is a small, known, internal population, not the open
/// internet, so the privacy argument for aggressive deletion is much weaker
/// while the accountability argument for keeping it is much stronger. Second,
/// compliance: one year of retained audit history is the common floor (PCI DSS
/// 10.5.1, and what SOC 2 / ISO 27001 auditors sample against), and a
/// misconfiguration is routinely discovered months after it was made. Volume is
/// a non-issue — this table grows with admin activity, not with traffic.
const fn default_audit_log_retention_days() -> i64 {
    365
}

/// Default `crowdsec_events` retention: 30 days.
///
/// A local echo of decisions owned by the `CrowdSec` LAPI, which keeps its own
/// authoritative history. These rows exist to answer "did the bouncer act on
/// this IP?" while an integration is being verified or a block is being
/// disputed — a days-to-weeks question. They carry `client_ip` and duplicate
/// data held elsewhere, so the shortest useful window applies.
const fn default_crowdsec_event_retention_days() -> i64 {
    30
}

/// Default `crowdsec_decisions` retention: 3 days *past expiry*.
///
/// This window does not gate row age — it gates how long an already-expired
/// decision is kept around after `CrowdSec` itself stops enforcing it. An
/// active decision (`expires_at` still in the future, or unset for a
/// decision with no known expiry) is never touched by this policy regardless
/// of how old the row is. Three days is enough for an operator to answer
/// "was this IP blocked as of yesterday?" while reviewing a dispute, without
/// indefinitely retaining a live client IP for a ban that `CrowdSec`'s own
/// authoritative LAPI history has already superseded.
const fn default_crowdsec_decision_retention_days() -> i64 {
    3
}

/// Default `refresh_tokens` retention: 7 days past expiry.
///
/// Gates the "expired but never revoked" case; a revoked token is deleted on
/// the very next sweep regardless of this window (`waf_storage`'s
/// `RetentionTable::RefreshTokens` ORs in `revoked = TRUE` unconditionally).
/// A week of grace past natural expiry gives an operator room to investigate
/// "was an expired token replayed" without keeping authentication material
/// that no longer authenticates anything.
const fn default_refresh_token_retention_days() -> i64 {
    7
}

/// Default `notification_log` retention: 30 days.
///
/// A delivery record's operational value is "did this alert fire, and did it
/// succeed" while an integration is being set up or debugged — a
/// days-to-weeks question, matching `crowdsec_events`. The `message` /
/// `error_msg` free text can embed a `client_ip` from the event that
/// triggered it, so the same short window applies.
const fn default_notification_log_retention_days() -> i64 {
    30
}

/// Default `request_stats` retention: 180 days.
///
/// No personal data and low row volume (one row per host per aggregation
/// bucket), so the ceiling here is set by dashboard usefulness rather than
/// privacy: half a year comfortably covers quarter-over-quarter trend
/// comparisons in the admin UI without accumulating forever.
const fn default_request_stats_retention_days() -> i64 {
    180
}

/// Default retention sweep interval: every 6 hours.
const fn default_retention_prune_interval_hours() -> u64 {
    6
}

/// Default rows per `DELETE` statement: 5000.
const fn default_retention_prune_batch_size() -> i64 {
    5_000
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            database_url: "postgresql://prx_waf:prx_waf@127.0.0.1:5432/prx_waf".to_string(),
            max_connections: 20,
            semantic_observation_retention_days: default_semantic_observation_retention_days(),
            security_event_retention_days: default_security_event_retention_days(),
            attack_log_retention_days: default_attack_log_retention_days(),
            audit_log_retention_days: default_audit_log_retention_days(),
            crowdsec_event_retention_days: default_crowdsec_event_retention_days(),
            crowdsec_decision_retention_days: default_crowdsec_decision_retention_days(),
            refresh_token_retention_days: default_refresh_token_retention_days(),
            notification_log_retention_days: default_notification_log_retention_days(),
            request_stats_retention_days: default_request_stats_retention_days(),
            retention_prune_interval_hours: default_retention_prune_interval_hours(),
            retention_prune_batch_size: default_retention_prune_batch_size(),
        }
    }
}

/// Static host entry from configuration file.
///
/// This is a *subset* of [`crate::types::HostConfig`], not a mirror of it, and
/// the difference is deliberate. `HostConfig` is the runtime shape shared with
/// the database row, so it carries columns that only the admin API writes and,
/// in one case, a column nothing reads at all. Adding a key here that the data
/// plane never consults would produce exactly the failure `start_status` used to
/// have — a config file that parses cleanly and changes nothing — so the three
/// remaining `HostConfig` fields are absent on purpose:
///
/// * `remote_ip` — an `INET` column on the `hosts` table with no reader in
///   `gateway` or `waf-engine`. The upstream is dialled from
///   `remote_host`/`remote_port` (`gateway::proxy::upstream_peer`,
///   `gateway::http3::upstream_target`); an IP goes in `remote_host` if that is
///   what you want. Exposing it here would be a second inert knob.
/// * `remarks` — free-text description for the admin UI's host list, which
///   reads the database and never sees a config-file host. In a TOML file a `#`
///   comment does the same job and is visible in the same place.
/// * `exclude_url_log` — no reader anywhere: not in the request path, not in
///   the attack-log writer, not even in the API's own `Host` → `HostConfig`
///   projection. The feature does not exist yet, and a config key is not the
///   place to imply that it does.
///
/// `cert_file`/`key_file` are likewise carried but unconsumed today; they
/// predate this note and are left alone rather than removed under it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostEntry {
    pub host: String,
    pub port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    /// Whether the *site* is TLS. Drives ACME issuance and renewal for this
    /// host, and — unless `upstream_ssl` says otherwise — the scheme used to
    /// reach the upstream. See [`crate::types::HostConfig::ssl`]. Absent →
    /// `false`.
    pub ssl: Option<bool>,
    /// Whether the *upstream* is dialled over TLS, when that differs from
    /// `ssl`. Absent → follow `ssl`, which is the behaviour every existing
    /// config file has. Set it to `false` on a TLS site with a plaintext origin
    /// (`ssl = true`, `remote_host = "127.0.0.1"`), which otherwise 502s on
    /// both protocols. See [`crate::types::HostConfig::upstream_ssl`].
    #[serde(default)]
    pub upstream_ssl: Option<bool>,
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
    /// Per-host Lane1 detector toggles. Defaults to every detector on
    /// (`DefenseConfig::default`), matching the historical config-file
    /// behaviour when the key is absent.
    #[serde(default)]
    pub defense_config: crate::types::DefenseConfig,
    /// Detect but do not enforce: every block this host would produce is
    /// downgraded to a logged `LogOnly` decision and the request is proxied
    /// through. The equivalent of `ModSecurity`'s `SecRuleEngine DetectionOnly`.
    ///
    /// Defaults to `false` (enforce), which is what a config file without the
    /// key has always meant. Hosts created through the admin API carry the same
    /// flag on their database row; this is the config-file half of it, which was
    /// previously unreachable without the API.
    #[serde(default)]
    pub log_only_mode: bool,
    /// Administrative on/off switch for the site. `false` makes the gateway
    /// answer every request for this host with `503 Service Unavailable`
    /// (`gateway::proxy` and `gateway::http3`) instead of proxying it upstream.
    ///
    /// Defaults to `true` — a config file that never mentions the key serves the
    /// site, which is what it has always done.
    ///
    /// This field exists because its absence was worse than a missing feature.
    /// The database row and the admin API have carried `start_status` since the
    /// first migration, but `HostEntry` did not have the field, and serde
    /// silently drops unknown keys: an operator who wrote `start_status = false`
    /// into the config file to take a site down got a parse that succeeded and a
    /// site that kept serving. A knob that reads as "off" while the thing is on
    /// is more dangerous than no knob at all.
    #[serde(default = "default_true")]
    pub start_status: bool,
    /// Custom HTML body for this host's block page, replacing the built-in
    /// template. Three placeholders are substituted, each HTML-escaped:
    /// `{{req_id}}`, `{{rule_name}}`, `{{client_ip}}`. See
    /// `waf_engine::block_page::render_block_page`, which is the sole reader and
    /// which serves the default template when this is `None`.
    ///
    /// Absent from a config file until now, though `HostConfig` has carried it
    /// and the renderer has honoured it since block pages were added — the
    /// admin API does not surface it either, so the field was reachable only by
    /// writing the `hosts` row by hand.
    #[serde(default)]
    pub block_page_template: Option<String>,
}

/// Response caching configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Enable response caching
    pub enabled: bool,
    /// Maximum total cache size in MiB — a real byte budget.
    ///
    /// Enforced by weighing every entry (body + headers + key + per-entry
    /// bookkeeping) and evicting until the total is within budget; see
    /// `gateway::cache::ResponseCache::new`. Values below 1 MiB are floored at
    /// 1 MiB. No single response may occupy more than 1/16 of this.
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
    /// UDP listen address for QUIC.
    ///
    /// On a port other than 443, every `[[hosts]]` entry to be served over
    /// HTTP/3 must declare *that* port. HTTP/3 has no `Host` header and is
    /// routed on RFC 9114's `:authority`, which clients populate with the port
    /// whenever it is not the scheme default (`curl https://a.example:18443/`
    /// sends `:authority: a.example:18443`). `gateway::router::HostRouter`
    /// registers the bare-hostname key only for ports 80/443 and withholds the
    /// bare-host fallback for any other port, so a host declared `port = 443`
    /// behind an 18443 listener resolves to nothing and answers 404.
    ///
    /// This is the router's rule rather than anything new to HTTP/3 — HTTP/1.1
    /// on a non-default port has always obeyed it. It is documented here because
    /// HTTP/3 is the first listener commonly run off-port.
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

/// Parse a non-negative integer environment value.
///
/// Returns an explicit error (never panics) on a value that is not a
/// non-negative integer, so a typo becomes a hard startup failure rather than a
/// silently ignored override.
fn parse_env_usize(key: &str, raw: &str) -> anyhow::Result<usize> {
    raw.trim()
        .parse::<usize>()
        .map_err(|e| anyhow::anyhow!("environment variable {key} has invalid integer value '{raw}': {e}"))
}

/// Parse an unsigned-64 environment override, naming the key on failure.
fn parse_env_u64(key: &str, raw: &str) -> anyhow::Result<u64> {
    raw.trim()
        .parse::<u64>()
        .map_err(|e| anyhow::anyhow!("environment variable {key} has invalid integer value '{raw}': {e}"))
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
/// | `PRXWAF_WORKER_THREADS` | `proxy.worker_threads` | integer, `0` = follow available CPUs |
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

    // Sizing the data plane is a per-deployment decision, not a per-image one:
    // the same container image runs under a 1-CPU quota on a laptop and 32 CPUs
    // in production. Overriding from the environment keeps that out of the
    // baked-in TOML.
    if let Some(v) = get("PRXWAF_WORKER_THREADS") {
        config.proxy.worker_threads = Some(parse_env_usize("PRXWAF_WORKER_THREADS", &v)?);
    }

    // The upgrade socket has to sit somewhere both processes of a handover can
    // reach, which under a supervisor is whatever runtime directory that
    // supervisor allocated — a path the unit file knows and the baked-in TOML
    // does not.
    if let Some(v) = get("PRXWAF_UPGRADE_SOCK") {
        config.proxy.upgrade_sock = Some(v);
    }

    // How long a stop is allowed to take is a property of the platform doing
    // the stopping — a supervisor's kill timeout, an orchestrator's
    // terminationGracePeriodSeconds — and those live beside the deployment, not
    // in the image's TOML.
    if let Some(v) = get("PRXWAF_DRAIN_TIMEOUT_SECS") {
        config.proxy.drain_timeout_secs = parse_env_u64("PRXWAF_DRAIN_TIMEOUT_SECS", &v)?;
    }

    // Where the scrape endpoint lives is a property of the deployment, not of
    // the image: the same container is scraped over a pod-local port in
    // Kubernetes and over loopback on a bare host. Same reasoning as the worker
    // count above — keep it out of the baked-in TOML.
    if let Some(v) = get("PRXWAF_METRICS_ENABLED") {
        config.metrics.enabled = parse_env_bool("PRXWAF_METRICS_ENABLED", &v)?;
    }
    if let Some(v) = get("PRXWAF_METRICS_LISTEN_ADDR") {
        config.metrics.listen_addr = v;
    }
    if let Some(v) = get("PRXWAF_METRICS_MAX_HOST_LABELS") {
        config.metrics.max_host_labels = parse_env_usize("PRXWAF_METRICS_MAX_HOST_LABELS", &v)?;
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
        // `AppConfig::default()` — the compiled default, which is what this test
        // round-trips. `configs/default.toml` ships `enabled = true`; a real
        // install runs the lane.
        assert!(
            !cfg.content_security.enabled,
            "semantic lane off in the compiled default"
        );
    }

    /// `start_status = false` on a `[[hosts]]` entry must survive
    /// deserialization. It did not for the whole life of the config-file host
    /// path: `HostEntry` had no such field, serde dropped the key without a
    /// word, and an operator who wrote it got a site that kept serving. The
    /// assert is on the parsed value rather than on a proxy response because
    /// this is the exact step that used to lose it.
    #[test]
    fn host_start_status_false_survives_parsing() {
        let dir = std::env::temp_dir();
        let path = format!("{}/prx-waf-start-status-{}.toml", dir.display(), std::process::id());
        // The serialized default already carries an empty `hosts = []`; a second
        // `[[hosts]]` array would be a duplicate key, so fill that one in.
        let serialized = toml::to_string(&AppConfig::default()).expect("serialize default");
        let toml_text = serialized.replace(
            "hosts = []",
            "hosts = [\n\
             { host = \"closed.example\", port = 80, remote_host = \"127.0.0.1\", \
             remote_port = 8080, start_status = false },\n\
             { host = \"open.example\", port = 80, remote_host = \"127.0.0.1\", \
             remote_port = 8080 },\n]",
        );
        assert_ne!(
            toml_text, serialized,
            "serialized default no longer carries `hosts = []`"
        );
        std::fs::write(&path, toml_text).expect("write temp config");
        let result = load_config(&path);
        let _ = std::fs::remove_file(&path);
        let cfg = result.expect("valid config must load");
        let closed = cfg.hosts.first().expect("first host entry");
        let open = cfg.hosts.get(1).expect("second host entry");
        assert_eq!(closed.host, "closed.example");
        assert!(!closed.start_status, "start_status = false must reach HostEntry");
        // Omitting the key keeps the historical behaviour: the site serves.
        assert!(open.start_status, "an absent start_status must default to serving");
    }

    /// `upstream_ssl` must survive deserialization in both directions, and its
    /// absence must stay `None` rather than becoming a `false` that would
    /// silently take TLS off an origin connection that had it.
    #[test]
    fn host_upstream_ssl_survives_parsing() {
        let dir = std::env::temp_dir();
        let path = format!("{}/prx-waf-upstream-ssl-{}.toml", dir.display(), std::process::id());
        let serialized = toml::to_string(&AppConfig::default()).expect("serialize default");
        let toml_text = serialized.replace(
            "hosts = []",
            "hosts = [\n\
             { host = \"edge.example\", port = 443, remote_host = \"127.0.0.1\", \
             remote_port = 8080, ssl = true, upstream_ssl = false },\n\
             { host = \"inherit.example\", port = 443, remote_host = \"127.0.0.1\", \
             remote_port = 8443, ssl = true },\n]",
        );
        assert_ne!(
            toml_text, serialized,
            "serialized default no longer carries `hosts = []`"
        );
        std::fs::write(&path, toml_text).expect("write temp config");
        let result = load_config(&path);
        let _ = std::fs::remove_file(&path);
        let cfg = result.expect("valid config must load");
        let split = cfg.hosts.first().expect("first host entry");
        let inherit = cfg.hosts.get(1).expect("second host entry");
        assert_eq!(split.ssl, Some(true));
        assert_eq!(
            split.upstream_ssl,
            Some(false),
            "upstream_ssl = false must reach HostEntry"
        );
        assert!(
            inherit.upstream_ssl.is_none(),
            "an absent upstream_ssl must stay None so it follows ssl"
        );
    }

    /// `block_page_template` on a `[[hosts]]` entry must survive
    /// deserialization. Same failure mode as `start_status`: `HostEntry` had no
    /// field, serde discarded the key silently, and the operator got the
    /// built-in 403 page they had written a replacement for.
    #[test]
    fn host_block_page_template_survives_parsing() {
        let dir = std::env::temp_dir();
        let path = format!("{}/prx-waf-block-page-{}.toml", dir.display(), std::process::id());
        let serialized = toml::to_string(&AppConfig::default()).expect("serialize default");
        let toml_text = serialized.replace(
            "hosts = []",
            "hosts = [\n\
             { host = \"custom.example\", port = 80, remote_host = \"127.0.0.1\", \
             remote_port = 8080, block_page_template = \"denied: {{rule_name}}\" },\n\
             { host = \"plain.example\", port = 80, remote_host = \"127.0.0.1\", \
             remote_port = 8080 },\n]",
        );
        assert_ne!(
            toml_text, serialized,
            "serialized default no longer carries `hosts = []`"
        );
        std::fs::write(&path, toml_text).expect("write temp config");
        let result = load_config(&path);
        let _ = std::fs::remove_file(&path);
        let cfg = result.expect("valid config must load");
        let custom = cfg.hosts.first().expect("first host entry");
        let plain = cfg.hosts.get(1).expect("second host entry");
        assert_eq!(
            custom.block_page_template.as_deref(),
            Some("denied: {{rule_name}}"),
            "block_page_template must reach HostEntry"
        );
        assert!(
            plain.block_page_template.is_none(),
            "an absent block_page_template must leave the built-in template in place"
        );
    }
}

#[cfg(test)]
mod worker_thread_tests {
    use super::*;

    /// The shipped posture: no `worker_threads` key, so the data plane spreads
    /// over every CPU the process may use. This is the whole point of the key —
    /// a default install must not be pinned to one core.
    #[test]
    fn worker_threads_absent_follows_available_cpus() {
        let plan = WorkerThreadPlan::resolve(None, Some(16));
        assert_eq!(plan.threads, 16);
        assert_eq!(plan.source, WorkerThreadSource::DefaultFollowsCpus);
        assert!(!plan.is_single_threaded_on_a_wider_host());
    }

    /// `0` is the explicit spelling of the default, so an operator can write
    /// the key down without freezing a number into it.
    #[test]
    fn worker_threads_zero_follows_available_cpus() {
        let plan = WorkerThreadPlan::resolve(Some(0), Some(8));
        assert_eq!(plan.threads, 8);
        assert_eq!(plan.source, WorkerThreadSource::ExplicitFollowsCpus);
    }

    /// A positive value is taken verbatim — above the CPU count as well as
    /// below it. Oversubscribing is a legitimate ask (blocking work in the
    /// path) and second-guessing it would make the key mean something other
    /// than what it says.
    #[test]
    fn worker_threads_positive_is_taken_verbatim() {
        for (configured, cpus) in [(4_usize, 16_usize), (32, 4)] {
            let plan = WorkerThreadPlan::resolve(Some(configured), Some(cpus));
            assert_eq!(plan.threads, configured);
            assert_eq!(plan.source, WorkerThreadSource::Fixed);
        }
    }

    /// Detection failing must degrade to the pre-`worker_threads` behaviour —
    /// one thread — and never panic or guess.
    #[test]
    fn worker_threads_falls_back_to_one_when_cpu_detection_fails() {
        let plan = WorkerThreadPlan::resolve(None, None);
        assert_eq!(plan.threads, 1);
        assert_eq!(plan.available_cpus, None);
        assert!(
            plan.is_single_threaded_on_a_wider_host(),
            "must be broadcast as a warning"
        );
    }

    /// A fixed `1` on a multi-core host is the ceiling this key exists to lift,
    /// so it has to be recognisable as such by the startup broadcast.
    #[test]
    fn fixed_single_thread_on_a_multicore_host_is_flagged() {
        assert!(WorkerThreadPlan::resolve(Some(1), Some(16)).is_single_threaded_on_a_wider_host());
        assert!(
            !WorkerThreadPlan::resolve(Some(1), Some(1)).is_single_threaded_on_a_wider_host(),
            "one thread on a one-CPU host is not a ceiling worth warning about"
        );
    }

    /// Detection on the test host must produce a usable, positive count.
    #[test]
    fn detection_yields_at_least_one_thread() {
        assert!(ProxyConfig::default().worker_thread_plan().threads >= 1);
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

    /// `PRXWAF_WORKER_THREADS` sizes the data plane from the environment, so
    /// one container image can run under different CPU budgets. `0` survives as
    /// `Some(0)` — "follow the CPUs" — and is not confused with "unset".
    #[test]
    fn worker_threads_env_override_applies() {
        let mut cfg = AppConfig::default();
        apply_env_overrides_from(&mut cfg, getter(&[("PRXWAF_WORKER_THREADS", "6")])).expect("override should apply");
        assert_eq!(cfg.proxy.worker_threads, Some(6));
        assert_eq!(cfg.proxy.worker_thread_plan().threads, 6);

        let mut cfg = AppConfig::default();
        apply_env_overrides_from(&mut cfg, getter(&[("PRXWAF_WORKER_THREADS", "0")])).expect("override should apply");
        assert_eq!(cfg.proxy.worker_threads, Some(0));
        assert_eq!(
            cfg.proxy.worker_thread_plan().source,
            WorkerThreadSource::ExplicitFollowsCpus
        );
    }

    /// A typo must fail startup rather than be dropped: a silently ignored
    /// `PRXWAF_WORKER_THREADS=eight` would leave the operator believing the
    /// data plane is sized when it is not.
    #[test]
    fn worker_threads_env_override_rejects_non_numeric() {
        let mut cfg = AppConfig::default();
        let err = apply_env_overrides_from(&mut cfg, getter(&[("PRXWAF_WORKER_THREADS", "eight")]))
            .expect_err("non-numeric must be rejected");
        assert!(err.to_string().contains("PRXWAF_WORKER_THREADS"), "unhelpful: {err}");
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

#[cfg(test)]
mod http2_config_tests {
    use super::*;

    /// The shipped defaults must reproduce exactly what the listener ran with
    /// before this table existed — the values pinned in
    /// `pingora-core`'s `default_h2_options` and `h2`'s reset ceiling — so that
    /// leaving `[proxy.http2]` out is a genuine no-op.
    #[test]
    fn defaults_match_the_pre_existing_listener() {
        let h2 = Http2Config::default();
        assert_eq!(h2.max_concurrent_streams, 100);
        assert_eq!(h2.max_header_list_size_bytes, 64 * 1024);
        assert_eq!(h2.max_pending_accept_reset_streams, 20);
        h2.validate().expect("the shipped defaults must validate");
    }

    /// An omitted table deserialises to those same defaults, and a table that
    /// sets only one field leaves the rest at their defaults.
    #[test]
    fn partial_table_keeps_other_defaults() {
        let none: ProxyConfig = toml::from_str("listen_addr = \"0.0.0.0:80\"\nlisten_addr_tls = \"\"")
            .expect("minimal proxy config parses");
        assert_eq!(none.http2.max_pending_accept_reset_streams, 20);

        let partial: ProxyConfig = toml::from_str(
            "listen_addr = \"0.0.0.0:80\"\nlisten_addr_tls = \"\"\n\
             [http2]\nmax_pending_accept_reset_streams = 3",
        )
        .expect("partial http2 table parses");
        assert_eq!(partial.http2.max_pending_accept_reset_streams, 3);
        assert_eq!(partial.http2.max_concurrent_streams, 100);
        assert_eq!(partial.http2.max_header_list_size_bytes, 64 * 1024);
    }

    /// Values that would wedge the listener are rejected rather than served.
    #[test]
    fn wedging_values_are_rejected() {
        let zero_streams = Http2Config {
            max_concurrent_streams: 0,
            ..Http2Config::default()
        };
        assert!(zero_streams.validate().is_err());

        let zero_resets = Http2Config {
            max_pending_accept_reset_streams: 0,
            ..Http2Config::default()
        };
        assert!(zero_resets.validate().is_err());

        let tiny_headers = Http2Config {
            max_header_list_size_bytes: 512,
            ..Http2Config::default()
        };
        assert!(tiny_headers.validate().is_err());
    }

    /// A tightened-but-sane configuration validates: hardening is the operator's
    /// to choose above the footgun floor.
    #[test]
    fn tightened_but_sane_config_validates() {
        let hardened = Http2Config {
            max_concurrent_streams: 10,
            max_header_list_size_bytes: 8 * 1024,
            max_pending_accept_reset_streams: 3,
        };
        hardened.validate().expect("a tightened config must be allowed");
    }
}
