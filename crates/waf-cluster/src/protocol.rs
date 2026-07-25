use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use waf_common::config::NodeRole;

/// Top-level cluster message envelope dispatched over QUIC streams
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClusterMessage {
    Heartbeat(Heartbeat),
    ElectionVote(ElectionVote),
    ElectionResult(ElectionResult),
    JoinRequest(JoinRequest),
    JoinResponse(JoinResponse),
    NodeLeave { node_id: String },
    RuleSyncRequest(RuleSyncRequest),
    RuleSyncResponse(RuleSyncResponse),
    ConfigSync(ConfigSync),
    EventBatch(EventBatch),
    StatsBatch(StatsBatch),
    ApiForward(ApiForward),
    ApiForwardResponse(ApiForwardResponse),
}

/// Periodic liveness + stats message sent by every node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    pub sequence: u64,
    pub timestamp_ms: u64,
    pub node_id: String,
    pub role: NodeRole,
    pub uptime_secs: u64,
    pub cpu_percent: f64,
    pub memory_used_bytes: u64,
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub rules_version: u64,
    pub config_version: u64,
}

/// One voter's cryptographic proof that it granted its vote (H-12).
///
/// The voter signs `(term, candidate_id)` with the Ed25519 key behind its mTLS
/// identity and ships its cluster-CA-issued leaf certificate alongside, so any
/// node holding the CA certificate can validate the chain, recover the voter's
/// `node_id` from the certificate SAN and check the signature. There is
/// deliberately no self-declared voter field: the identity is whatever the
/// certificate proves.
///
/// See [`crate::crypto::vote`] for the signed payload and its domain separation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedGrant {
    /// Voter's leaf certificate, DER, base64.
    pub cert_b64: String,
    /// Any intermediate CA certificates between the leaf and the cluster root,
    /// DER, base64. Empty for the single-level PKI this crate generates; carried
    /// so an externally provisioned two-level PKI still verifies. Untrusted
    /// input — path validation still has to end at the configured root.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain_b64: Vec<String>,
    /// Ed25519 signature over the grant payload, base64.
    pub signature_b64: String,
}

/// Vote cast by a candidate during an election, or a vote-grant echo from a peer.
///
/// When `voter_id` is `None` → this is a vote **request** from the candidate.
/// When `voter_id` is `Some(id)` → this is a vote **grant** from `id`, echoed back
/// to the candidate through the bidirectional stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElectionVote {
    pub term: u64,
    pub candidate_id: String,
    pub last_log_index: u64,
    /// Present only in vote-grant responses; identifies the voter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub voter_id: Option<String>,
    /// Present only in vote-grant responses: the signed proof of the grant.
    ///
    /// Optional on the wire so that a grant from a pre-H-12 peer still parses
    /// and can be rejected with a diagnosable reason instead of tearing down the
    /// stream on a deserialization error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<SignedGrant>,
}

/// Broadcast by the winner after receiving a majority of votes.
///
/// `grants` is the election's **quorum certificate**: one [`SignedGrant`] per
/// voter, including the winner's own vote for itself. It replaces the pre-H-12
/// `voter_ids` name list, which was an unverifiable self-declaration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElectionResult {
    pub term: u64,
    pub elected_id: String,
    /// Defaults to empty so a pre-H-12 announcement still parses — and is then
    /// rejected for want of a quorum, which is the intended fail-closed
    /// behaviour for a partially upgraded cluster.
    #[serde(default)]
    pub grants: Vec<SignedGrant>,
}

/// Initial join handshake from a new worker to main
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinRequest {
    pub token: String,
    pub csr_pem: String,
    pub node_info: NodeInfo,
}

/// Main's response to a `JoinRequest`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinResponse {
    pub accepted: bool,
    pub reason: Option<String>,
    pub node_cert_pem: String,
    pub ca_cert_pem: String,
    pub cluster_state: ClusterState,
    /// AES-GCM encrypted CA private key (base64-encoded), included when the
    /// main has a `ca_passphrase` configured.  Workers store this so a new
    /// main can take over CA duties after failover.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_ca_key_b64: Option<String>,
}

/// Static metadata advertised by a node during join
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub hostname: String,
    pub version: String,
    pub listen_addr: String,
    /// Feature flags: `["waf", "proxy", "api"]`
    pub capabilities: Vec<String>,
}

/// Worker requests a rule sync from main
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSyncRequest {
    /// Worker's current rule registry version
    pub current_version: u64,
}

/// Main's reply carrying either an incremental diff or a full lz4-compressed snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSyncResponse {
    pub version: u64,
    pub sync_type: SyncType,
    /// Incremental changes (empty when `sync_type` == Full)
    pub changes: Vec<RuleChange>,
    /// lz4-compressed JSON of Vec<Rule> (empty when `sync_type` == Incremental)
    pub snapshot_lz4: Vec<u8>,
}

/// Whether a rule sync is incremental or a full snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncType {
    Incremental,
    Full,
}

/// Single rule delta entry in an incremental sync
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleChange {
    pub op: ChangeOp,
    pub rule_id: String,
    /// Serialized Rule struct; None when op == Delete
    pub rule_json: Option<serde_json::Value>,
}

/// Operation type for an incremental rule change
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeOp {
    Upsert,
    Delete,
}

/// Config sync payload — full TOML string with version stamp
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSync {
    pub version: u64,
    pub config_toml: String,
}

/// Batch of security events forwarded from a worker to main
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventBatch {
    pub node_id: String,
    pub events: Vec<SecurityEvent>,
}

/// A single WAF security event captured on a worker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub timestamp_ms: u64,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub host: String,
    pub rule_id: Option<String>,
    pub action: String,
    pub geo_country: String,
    pub node_id: String,
}

/// Aggregated stats pushed from a worker to main (sent as unreliable QUIC datagrams)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsBatch {
    pub node_id: String,
    pub timestamp_ms: u64,
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub allowed_requests: u64,
    pub top_ips: HashMap<String, u64>,
    pub top_rules: HashMap<String, u64>,
    pub top_countries: HashMap<String, u64>,
}

/// Snapshot of cluster membership visible to all nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterState {
    pub main_node_id: String,
    pub nodes: Vec<NodeInfo>,
    pub rules_version: u64,
    pub config_version: u64,
    pub term: u64,
}

/// API write request forwarded from a worker to main
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiForward {
    pub request_id: String,
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
    pub headers: HashMap<String, String>,
}

/// Main's reply to a forwarded API request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiForwardResponse {
    pub request_id: String,
    pub status: u16,
    pub body: Vec<u8>,
}
