use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Host / site configuration
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Host {
    pub id: Uuid,
    pub code: String,
    pub host: String,
    pub port: i32,
    pub ssl: bool,
    pub guard_status: bool,
    pub remote_host: String,
    pub remote_port: i32,
    pub remote_ip: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub remarks: Option<String>,
    pub start_status: bool,
    pub exclude_url_log: Option<String>,
    pub is_enable_load_balance: bool,
    pub load_balance_stage: i32,
    pub defense_json: Option<serde_json::Value>,
    pub log_only_mode: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// IP allowlist entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AllowIp {
    pub id: Uuid,
    pub host_code: String,
    pub ip_cidr: String,
    pub remarks: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// IP blocklist entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct BlockIp {
    pub id: Uuid,
    pub host_code: String,
    pub ip_cidr: String,
    pub remarks: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// URL allowlist entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AllowUrl {
    pub id: Uuid,
    pub host_code: String,
    pub url_pattern: String,
    pub match_type: String,
    pub remarks: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// URL blocklist entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct BlockUrl {
    pub id: Uuid,
    pub host_code: String,
    pub url_pattern: String,
    pub match_type: String,
    pub remarks: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Attack log entry (Phase 1 — IP / URL blacklist hits)
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AttackLog {
    pub id: Uuid,
    pub host_code: String,
    pub host: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub rule_id: Option<String>,
    pub rule_name: String,
    pub action: String,
    pub phase: String,
    pub detail: Option<String>,
    pub request_headers: Option<serde_json::Value>,
    pub geo_info: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

/// Security event entry (Phase 2 — attack detection)
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SecurityEvent {
    pub id: Uuid,
    pub host_code: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub rule_id: Option<String>,
    pub rule_name: String,
    pub action: String,
    pub detail: Option<String>,
    pub geo_info: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

/// SSL Certificate entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Certificate {
    pub id: Uuid,
    pub host_code: String,
    pub domain: String,
    pub cert_pem: Option<String>,
    pub key_pem: Option<String>,
    pub chain_pem: Option<String>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub auto_renew: bool,
    pub acme_account: Option<serde_json::Value>,
    pub status: String,
    pub error_msg: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Custom WAF rule entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CustomRule {
    pub id: Uuid,
    pub host_code: String,
    pub name: String,
    pub description: Option<String>,
    pub priority: i32,
    pub enabled: bool,
    pub condition_op: String,
    pub conditions: serde_json::Value,
    pub action: String,
    pub action_status: i32,
    pub action_msg: Option<String>,
    pub script: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Sensitive pattern entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SensitivePattern {
    pub id: Uuid,
    pub host_code: String,
    pub pattern: String,
    pub pattern_type: String,
    pub check_request: bool,
    pub check_response: bool,
    pub action: String,
    pub remarks: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Hotlink configuration entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct HotlinkConfig {
    pub id: Uuid,
    pub host_code: String,
    pub enabled: bool,
    pub allow_empty_referer: bool,
    pub allowed_domains: serde_json::Value,
    pub redirect_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Load balancer backend entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct LbBackend {
    pub id: Uuid,
    pub host_code: String,
    pub backend_host: String,
    pub backend_port: i32,
    pub weight: i32,
    pub enabled: bool,
    pub health_check_url: Option<String>,
    pub health_check_interval_secs: i32,
    pub last_health_check: Option<DateTime<Utc>>,
    pub is_healthy: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ─── Request / Input types ────────────────────────────────────────────────────

/// Create host request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateHost {
    pub host: String,
    pub port: i32,
    pub ssl: bool,
    pub guard_status: bool,
    pub remote_host: String,
    pub remote_port: i32,
    pub remote_ip: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub remarks: Option<String>,
    pub start_status: bool,
    pub log_only_mode: bool,
}

/// Update host request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateHost {
    pub host: Option<String>,
    pub port: Option<i32>,
    pub ssl: Option<bool>,
    pub guard_status: Option<bool>,
    pub remote_host: Option<String>,
    pub remote_port: Option<i32>,
    pub remote_ip: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub remarks: Option<String>,
    pub start_status: Option<bool>,
    pub log_only_mode: Option<bool>,
}

/// Create IP rule request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateIpRule {
    pub host_code: String,
    pub ip_cidr: String,
    pub remarks: Option<String>,
}

/// Create URL rule request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUrlRule {
    pub host_code: String,
    pub url_pattern: String,
    pub match_type: String,
    pub remarks: Option<String>,
}

/// Attack log query parameters
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AttackLogQuery {
    pub host_code: Option<String>,
    pub client_ip: Option<String>,
    pub action: Option<String>,
    pub country: Option<String>,
    pub iso_code: Option<String>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

/// Create security event (used internally by the engine)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSecurityEvent {
    pub host_code: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub rule_id: Option<String>,
    pub rule_name: String,
    pub action: String,
    pub detail: Option<String>,
    pub geo_info: Option<serde_json::Value>,
}

/// Security event query parameters
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityEventQuery {
    pub host_code: Option<String>,
    pub client_ip: Option<String>,
    pub rule_name: Option<String>,
    pub action: Option<String>,
    pub country: Option<String>,
    pub iso_code: Option<String>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

/// Create custom rule request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCustomRule {
    pub host_code: String,
    pub name: String,
    pub description: Option<String>,
    pub priority: Option<i32>,
    pub enabled: Option<bool>,
    pub condition_op: Option<String>,
    pub conditions: serde_json::Value,
    pub action: Option<String>,
    pub action_status: Option<i32>,
    pub action_msg: Option<String>,
    pub script: Option<String>,
}

/// Create sensitive pattern request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSensitivePattern {
    pub host_code: String,
    pub pattern: String,
    pub pattern_type: Option<String>,
    pub check_request: Option<bool>,
    pub check_response: Option<bool>,
    pub action: Option<String>,
    pub remarks: Option<String>,
}

/// Create/update hotlink config request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertHotlinkConfig {
    pub host_code: String,
    pub enabled: Option<bool>,
    pub allow_empty_referer: Option<bool>,
    pub allowed_domains: Option<Vec<String>>,
    pub redirect_url: Option<String>,
}

/// Create LB backend request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateLbBackend {
    pub host_code: String,
    pub backend_host: String,
    pub backend_port: i32,
    pub weight: Option<i32>,
    pub enabled: Option<bool>,
    pub health_check_url: Option<String>,
    pub health_check_interval_secs: Option<i32>,
}

/// Update certificate PEM data (issued by ACME or manual upload)
#[derive(Debug, Clone)]
pub struct UpdateCertificatePem<'a> {
    pub id: Uuid,
    pub cert_pem: &'a str,
    pub key_pem: &'a str,
    pub chain_pem: Option<&'a str>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub issuer: &'a str,
    pub subject: &'a str,
}

/// Create certificate request (manual upload)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCertificate {
    pub host_code: String,
    pub domain: String,
    pub cert_pem: Option<String>,
    pub key_pem: Option<String>,
    pub chain_pem: Option<String>,
    pub auto_renew: Option<bool>,
}

// ─── Phase 4: Auth ────────────────────────────────────────────────────────────

/// Admin user
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AdminUser {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: String,
    pub is_active: bool,
    #[serde(skip_serializing)]
    pub totp_secret: Option<String>,
    pub totp_enabled: bool,
    pub last_login: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Refresh token entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    pub created_at: DateTime<Utc>,
}

/// Create admin user request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAdminUser {
    pub username: String,
    pub email: Option<String>,
    pub password: String,
    pub role: Option<String>,
}

// ─── Phase 4: Statistics ──────────────────────────────────────────────────────

/// Aggregated request statistics row
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RequestStat {
    pub id: Uuid,
    pub host_code: String,
    pub period_start: DateTime<Utc>,
    pub period_type: String,
    pub total_requests: i64,
    pub blocked_requests: i64,
    pub allowed_requests: i64,
    pub stats_json: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Stats overview (aggregated from existing tables)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsOverview {
    pub total_requests: i64,
    pub total_blocked: i64,
    pub total_allowed: i64,
    pub hosts_count: i64,
    pub top_ips: Vec<TopEntry>,
    pub top_rules: Vec<TopEntry>,
    pub top_countries: Vec<TopEntry>,
    pub top_isps: Vec<TopEntry>,
}

/// GeoIP distribution statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoStats {
    pub top_countries: Vec<TopEntry>,
    pub top_cities: Vec<TopEntry>,
    pub top_isps: Vec<TopEntry>,
    pub country_distribution: Vec<GeoDistEntry>,
}

/// GeoIP country distribution entry (for map visualization)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoDistEntry {
    pub iso_code: String,
    pub country: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopEntry {
    pub key: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesPoint {
    pub ts: DateTime<Utc>,
    pub total: i64,
    pub blocked: i64,
}

// ─── Phase 4: Notifications ───────────────────────────────────────────────────

/// Notification configuration entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct NotificationConfig {
    pub id: Uuid,
    pub name: String,
    pub host_code: Option<String>,
    pub event_type: String,
    pub channel_type: String,
    pub config_json: serde_json::Value,
    pub enabled: bool,
    pub rate_limit_secs: i32,
    pub last_triggered: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Notification log entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct NotificationLog {
    pub id: Uuid,
    pub config_id: Option<Uuid>,
    pub event_type: String,
    pub channel_type: String,
    pub status: String,
    pub message: Option<String>,
    pub error_msg: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Create notification config request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNotificationConfig {
    pub name: String,
    pub host_code: Option<String>,
    pub event_type: String,
    pub channel_type: String,
    pub config_json: serde_json::Value,
    pub enabled: Option<bool>,
    pub rate_limit_secs: Option<i32>,
}

// ─── Phase 5: WASM Plugins ────────────────────────────────────────────────────

/// WASM plugin metadata (binary is stored separately)
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct WasmPluginRow {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub author: Option<String>,
    pub wasm_binary: Vec<u8>,
    pub enabled: bool,
    pub config_json: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Create WASM plugin request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateWasmPlugin {
    pub name: String,
    pub version: Option<String>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub wasm_binary: Vec<u8>,
    pub enabled: Option<bool>,
    pub config_json: Option<serde_json::Value>,
}

// ─── Phase 5: Tunnels ─────────────────────────────────────────────────────────

/// Tunnel configuration row
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct TunnelRow {
    pub id: Uuid,
    pub name: String,
    pub token_hash: String,
    pub target_host: String,
    pub target_port: i32,
    pub enabled: bool,
    pub status: String,
    pub last_seen: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Create tunnel request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTunnel {
    pub name: String,
    /// Plain-text pre-shared key; will be hashed before storage
    pub token: String,
    pub target_host: String,
    pub target_port: i32,
    pub enabled: Option<bool>,
}

// ─── Phase 5: Audit Log ───────────────────────────────────────────────────────

/// Admin audit log entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuditLogEntry {
    pub id: i64,
    pub admin_username: Option<String>,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub detail: Option<serde_json::Value>,
    pub ip_addr: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Query parameters for audit log listing
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditLogQuery {
    pub admin_username: Option<String>,
    pub action: Option<String>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

// ─── Phase 6: CrowdSec ────────────────────────────────────────────────────────

/// CrowdSec integration configuration stored in database
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CrowdSecConfigRow {
    pub id: i32,
    pub host_id: Option<Uuid>,
    pub enabled: bool,
    pub mode: String,
    pub lapi_url: Option<String>,
    /// AES-256-GCM encrypted API key (base64 encoded)
    pub api_key_encrypted: Option<String>,
    pub appsec_endpoint: Option<String>,
    /// AES-256-GCM encrypted AppSec API key (base64 encoded)
    pub appsec_key_encrypted: Option<String>,
    pub update_frequency_secs: i32,
    pub fallback_action: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Upsert CrowdSec config request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertCrowdSecConfig {
    pub host_id: Option<Uuid>,
    pub enabled: bool,
    pub mode: String,
    pub lapi_url: Option<String>,
    /// Plaintext API key (will be encrypted before storage)
    pub api_key: Option<String>,
    pub appsec_endpoint: Option<String>,
    /// Plaintext AppSec API key (will be encrypted before storage)
    pub appsec_key: Option<String>,
    pub update_frequency_secs: Option<i32>,
    pub fallback_action: Option<String>,
}

/// A persisted CrowdSec event / detection log
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CrowdSecEventRow {
    pub id: i64,
    pub host_id: Option<Uuid>,
    pub client_ip: Option<String>,
    pub decision_type: Option<String>,
    pub scenario: Option<String>,
    pub action_taken: Option<String>,
    pub request_path: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Insert a new CrowdSec event
#[derive(Debug, Clone)]
pub struct CreateCrowdSecEvent {
    pub host_id: Option<Uuid>,
    pub client_ip: String,
    pub decision_type: String,
    pub scenario: String,
    pub action_taken: String,
    pub request_path: Option<String>,
}

/// Query params for listing CrowdSec events
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CrowdSecEventQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}
