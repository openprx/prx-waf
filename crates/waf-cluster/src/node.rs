//! Cluster node state machine.
//!
//! `NodeState` is the shared, thread-safe runtime state for a single cluster
//! node.  All transport handlers, the election loop, and the health monitor
//! access it through an `Arc<NodeState>`.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use parking_lot::{Mutex as ParkingMutex, RwLock as ParkingRwLock};
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::RwLock;
use tokio::sync::mpsc;
use tracing::{info, warn};
use waf_common::config::{ClusterConfig, NodeRole};

use waf_engine::{Rule, RuleRegistry, RuleReloader};

use crate::cluster_forward::PendingForwards;
use crate::election::ElectionManager;
use crate::health::HeartbeatTracker;
use crate::protocol::{ChangeOp, ClusterMessage, ConfigSync, RuleChange, RuleSyncResponse, SyncType};
use crate::sync::config::ConfigSyncer;
use crate::sync::rules::RuleChangelog;
use crate::sync::{ApiForwardHandler, NoopRuleReloader};

/// Number of recent rule changes the main node retains for incremental sync.
const RULE_CHANGELOG_CAPACITY: usize = 1_024;

/// Whether this node has a live database connection or must forward writes.
#[derive(Debug, Clone)]
pub enum StorageMode {
    /// Node has its own `PostgreSQL` connection (main, or worker with local DB).
    Full,
    /// Node has no DB — all write operations are forwarded to main.
    ForwardOnly,
}

/// Known peer in the cluster.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub node_id: String,
    pub addr: SocketAddr,
    pub role: NodeRole,
    /// Unix timestamp (ms) of the last received heartbeat from this peer.
    pub last_seen_ms: u64,
}

/// Live runtime state for this cluster node.
pub struct NodeState {
    pub node_id: String,
    pub role: RwLock<NodeRole>,
    pub term: RwLock<u64>,
    pub config: ClusterConfig,
    pub peers: RwLock<Vec<PeerInfo>>,
    pub storage_mode: StorageMode,
    pub rules_version: RwLock<u64>,
    pub config_version: RwLock<u64>,
    // ── P3: election + failure detection ─────────────────────────────────────
    /// Shared Raft-lite election state machine.
    pub election: Arc<ElectionManager>,
    /// Per-peer phi-accrual failure detector (short-lived lock, never held across await).
    pub heartbeat_tracker: ParkingMutex<HeartbeatTracker>,
    /// Outbound channels to all connected peers; used for broadcast.
    peer_channels: ParkingMutex<Vec<mpsc::Sender<ClusterMessage>>>,
    // ── P3: CA key replication ────────────────────────────────────────────────
    /// CA private key PEM held in memory by the main node (never log).
    pub ca_key_pem: ParkingMutex<Option<String>>,
    /// AES-GCM encrypted CA private key stored by worker nodes for failover.
    pub ca_key_encrypted: ParkingMutex<Option<Vec<u8>>>,
    // ── Data-plane synchronisation ────────────────────────────────────────────
    /// Shared rule registry that synced rules are applied into (worker side) and
    /// served from (main side). Behind an `Arc<RwLock>` so a hot-reload swap is
    /// visible to any data-plane reader holding a clone.
    pub rule_registry: Arc<ParkingRwLock<RuleRegistry>>,
    /// Ring buffer of recent rule changes maintained by the main node so workers
    /// can be answered with an incremental delta instead of a full snapshot.
    pub rule_changelog: TokioMutex<RuleChangelog>,
    /// Config version follower (worker) / builder (main).
    pub config_syncer: TokioMutex<ConfigSyncer>,
    /// Latest config the main advertises to workers. `None` until set.
    config_broadcast: ParkingMutex<Option<ConfigSync>>,
    /// In-flight API write forwards awaiting a response (worker side).
    pub pending_forwards: PendingForwards,
    /// Cryptographically authenticated identity of the current cluster Main,
    /// learned from an accepted `JoinResponse` or an authenticated
    /// `ElectionResult`. Rule/config pushes are accepted only from this identity
    /// (H-9). `None` until the node has joined / seen an election result.
    main_node_id: RwLock<Option<String>>,
    /// Hook fired after synced rules are applied. Defaults to a no-op; the data
    /// plane (`WafEngine`) is attached via [`NodeState::attach_rule_reloader`].
    rule_reloader: ParkingMutex<Arc<dyn RuleReloader>>,
    /// Executor for forwarded API writes (main side). `None` until attached.
    api_forward_handler: ParkingMutex<Option<Arc<dyn ApiForwardHandler>>>,
}

impl NodeState {
    /// Create a new node state from configuration.
    ///
    /// The public call signature is backward-compatible with P1/P2 code.
    pub fn new(config: ClusterConfig, storage_mode: StorageMode) -> Result<Self> {
        let node_id = if config.node_id.is_empty() {
            format!("node-{}", random_suffix())
        } else {
            config.node_id.clone()
        };

        let initial_role = match config.role.as_str() {
            "main" => NodeRole::Main,
            // "worker", "auto", or anything else — starts as Worker, election decides
            _ => NodeRole::Worker,
        };

        let election = Arc::new(ElectionManager::new(
            node_id.clone(),
            config.election.timeout_min_ms,
            config.election.timeout_max_ms,
        ));
        // M-16: constrain vote eligibility to the declared membership (if any).
        election.set_members(&config.members);

        let heartbeat_tracker = ParkingMutex::new(HeartbeatTracker::new(
            config.election.phi_suspect,
            config.election.phi_dead,
        ));

        info!(node_id = %node_id, role = ?initial_role, "Cluster node initialized");

        let node_id_for_sync = node_id.clone();

        Ok(Self {
            node_id,
            role: RwLock::new(initial_role),
            term: RwLock::new(0),
            config,
            peers: RwLock::new(Vec::new()),
            storage_mode,
            rules_version: RwLock::new(0),
            config_version: RwLock::new(0),
            election,
            heartbeat_tracker,
            peer_channels: ParkingMutex::new(Vec::new()),
            ca_key_pem: ParkingMutex::new(None),
            ca_key_encrypted: ParkingMutex::new(None),
            rule_registry: Arc::new(ParkingRwLock::new(RuleRegistry::new())),
            rule_changelog: TokioMutex::new(RuleChangelog::new(RULE_CHANGELOG_CAPACITY)),
            config_syncer: TokioMutex::new(ConfigSyncer::new(node_id_for_sync)),
            config_broadcast: ParkingMutex::new(None),
            pending_forwards: PendingForwards::new(),
            main_node_id: RwLock::new(None),
            rule_reloader: ParkingMutex::new(Arc::new(NoopRuleReloader)),
            api_forward_handler: ParkingMutex::new(None),
        })
    }

    // ── Role state machine ────────────────────────────────────────────────────

    /// Read the current role without blocking.
    pub async fn current_role(&self) -> NodeRole {
        *self.role.read().await
    }

    /// Transition to a new role, logging the change.
    pub async fn transition_to(&self, new_role: NodeRole) {
        let mut role = self.role.write().await;
        info!(
            node_id = %self.node_id,
            from = ?*role,
            to = ?new_role,
            "Node role transition"
        );
        *role = new_role;
    }

    /// Promote this node to Main.
    ///
    /// Transitions role to Main and logs. If the node had an encrypted CA key
    /// stored (from a previous `JoinResponse`), it is already available for use.
    pub async fn promote_to_main(&self) {
        self.transition_to(NodeRole::Main).await;
        info!(
            node_id = %self.node_id,
            term = self.election.current_term_sync(),
            "Promoted to Main"
        );
        // If we have an encrypted CA key, it can be decrypted now using the
        // cluster passphrase from config (done by the caller when signing certs).
    }

    /// Demote this node back to Worker (called when a new election is won by another).
    pub async fn demote_to_worker(&self) {
        let current = *self.role.read().await;
        if current != NodeRole::Worker {
            self.transition_to(NodeRole::Worker).await;
            warn!(
                node_id = %self.node_id,
                "Demoted to Worker"
            );
        }
    }

    // ── Term ──────────────────────────────────────────────────────────────────

    /// Read the current Raft term.
    pub async fn current_term(&self) -> u64 {
        *self.term.read().await
    }

    /// Increment the Raft term and return the new value.
    pub async fn increment_term(&self) -> u64 {
        let mut term = self.term.write().await;
        *term += 1;
        *term
    }

    // ── Fencing ───────────────────────────────────────────────────────────────

    /// Returns `true` if `incoming_term` is at least the current term.
    ///
    /// Used to reject stale-term leaders (split-brain prevention).
    pub fn fencing_check(&self, incoming_term: u64) -> bool {
        self.election.is_valid_term(incoming_term)
    }

    // ── Cluster topology ──────────────────────────────────────────────────────

    /// Total number of nodes in the cluster (peers + self).
    pub async fn total_nodes(&self) -> usize {
        self.peers.read().await.len() + 1
    }

    /// Cluster size used to compute election quorum (M-16).
    ///
    /// When a fixed `members` list is configured, quorum is derived from its
    /// declared size — which does not shrink when peers are evicted — so a
    /// partitioned minority can never observe a majority. Otherwise this falls
    /// back to the live view (`total_nodes`).
    pub async fn quorum_total(&self) -> usize {
        if self.config.members.is_empty() {
            self.total_nodes().await
        } else {
            self.config.members.len()
        }
    }

    /// Add a peer or update its `last_seen` timestamp if already known.
    pub async fn add_or_update_peer(&self, peer: PeerInfo) {
        let mut peers = self.peers.write().await;
        if let Some(existing) = peers.iter_mut().find(|p| p.node_id == peer.node_id) {
            existing.last_seen_ms = peer.last_seen_ms;
            existing.role = peer.role;
            existing.addr = peer.addr;
        } else {
            info!(
                node_id = %peer.node_id,
                addr = %peer.addr,
                role = ?peer.role,
                "New peer registered"
            );
            peers.push(peer);
        }
    }

    /// Remove a peer by `node_id`. Returns `true` if found and removed.
    pub async fn remove_peer(&self, node_id: &str) -> bool {
        let mut peers = self.peers.write().await;
        let before = peers.len();
        peers.retain(|p| p.node_id != node_id);
        let removed = peers.len() < before;
        drop(peers);
        if removed {
            info!(node_id = %node_id, "Peer removed from cluster");
        }
        removed
    }

    // ── Broadcast ─────────────────────────────────────────────────────────────

    /// Register an outbound channel to a peer.
    ///
    /// Called by `ClusterNode::run()` for each dialled seed.
    pub fn add_peer_channel(&self, tx: mpsc::Sender<ClusterMessage>) {
        self.peer_channels.lock().push(tx);
    }

    /// Broadcast `msg` to all registered peer channels (non-blocking).
    ///
    /// Full or closed channels are silently skipped.
    pub fn broadcast(&self, msg: &ClusterMessage) {
        let channels = self.peer_channels.lock();
        for tx in channels.iter() {
            match tx.try_send(msg.clone()) {
                Ok(()) | Err(mpsc::error::TrySendError::Full(_) | mpsc::error::TrySendError::Closed(_)) => {
                    // Back-pressure or disconnected: silently skip.
                }
            }
        }
    }

    // ── Version tracking ──────────────────────────────────────────────────────

    /// Update `rules_version` and return it.
    pub async fn set_rules_version(&self, version: u64) -> u64 {
        let mut rv = self.rules_version.write().await;
        *rv = version;
        version
    }

    /// Update `config_version` and return it.
    pub async fn set_config_version(&self, version: u64) -> u64 {
        let mut cv = self.config_version.write().await;
        *cv = version;
        version
    }

    // ── Data-plane synchronisation ────────────────────────────────────────────

    /// Attach the data-plane rule reloader (the running `WafEngine`).
    ///
    /// Called by the cluster↔engine wiring in `main.rs`. Until attached, applied
    /// rule syncs land in [`Self::rule_registry`] with a no-op engine hook.
    pub fn attach_rule_reloader(&self, reloader: Arc<dyn RuleReloader>) {
        *self.rule_reloader.lock() = reloader;
    }

    /// Clone the currently attached rule reloader.
    pub fn rule_reloader(&self) -> Arc<dyn RuleReloader> {
        Arc::clone(&self.rule_reloader.lock())
    }

    /// Attach the handler that executes forwarded API writes on the main node.
    pub fn attach_api_forward_handler(&self, handler: Arc<dyn ApiForwardHandler>) {
        *self.api_forward_handler.lock() = Some(handler);
    }

    /// Clone the currently attached API forward handler, if any.
    pub fn api_forward_handler(&self) -> Option<Arc<dyn ApiForwardHandler>> {
        self.api_forward_handler.lock().clone()
    }

    /// Record the cryptographically authenticated identity of the current Main.
    ///
    /// The caller must have already verified this identity against the peer's
    /// mTLS certificate (H-9) — via an accepted `JoinResponse` whose
    /// `main_node_id` matched the peer, or an `ElectionResult` whose `elected_id`
    /// matched the peer.
    pub async fn set_main_node_id(&self, id: String) {
        let mut guard = self.main_node_id.write().await;
        if guard.as_deref() != Some(id.as_str()) {
            info!(main = %id, "Recorded authenticated cluster Main identity");
        }
        *guard = Some(id);
    }

    /// Returns `true` when `id` is the recorded authenticated Main identity.
    ///
    /// Used to gate acceptance of rule/config pushes so a worker only ever
    /// applies rule state pushed by the real Main (H-9).
    pub async fn is_current_main(&self, id: &str) -> bool {
        self.main_node_id.read().await.as_deref() == Some(id)
    }

    /// Set the config payload the main advertises to workers.
    pub fn set_config_broadcast(&self, sync: ConfigSync) {
        *self.config_broadcast.lock() = Some(sync);
    }

    /// Clone the config payload the main currently advertises, if any.
    pub fn config_broadcast(&self) -> Option<ConfigSync> {
        self.config_broadcast.lock().clone()
    }

    /// Record an authoritative rule change on the main node.
    ///
    /// Updates the shared registry, appends the change to the changelog (so
    /// workers can be answered with an incremental delta), bumps `rules_version`,
    /// and broadcasts an incremental push to any dialed peers. `rule` is `None`
    /// for a delete.
    pub async fn record_rule_change(&self, op: ChangeOp, rule_id: String, rule: Option<Rule>) {
        {
            let mut reg = self.rule_registry.write();
            match op {
                ChangeOp::Delete => {
                    reg.remove(&rule_id);
                }
                ChangeOp::Upsert => {
                    if let Some(r) = rule.clone() {
                        reg.insert(r);
                    }
                }
            }
        }

        let version = {
            let mut changelog = self.rule_changelog.lock().await;
            changelog.record_change(op, rule_id.clone(), rule.as_ref());
            changelog.current_version()
        };
        self.set_rules_version(version).await;

        let rule_json = rule.as_ref().and_then(|r| serde_json::to_value(r).ok());
        let push = ClusterMessage::RuleSyncResponse(RuleSyncResponse {
            version,
            sync_type: SyncType::Incremental,
            changes: vec![RuleChange { op, rule_id, rule_json }],
            snapshot_lz4: Vec::new(),
        });
        self.broadcast(&push);
    }
}

fn random_suffix() -> String {
    format!("{:08x}", rand::random::<u32>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use waf_common::config::ClusterConfig;

    fn test_config(node_id: &str, role: &str) -> ClusterConfig {
        use waf_common::config::ClusterElectionConfig;
        ClusterConfig {
            node_id: node_id.to_string(),
            role: role.to_string(),
            election: ClusterElectionConfig {
                timeout_min_ms: 150,
                timeout_max_ms: 300,
                phi_suspect: 5.0,
                phi_dead: 8.0,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn test_peer(node_id: &str, last_seen_ms: u64) -> PeerInfo {
        PeerInfo {
            node_id: node_id.to_string(),
            addr: "127.0.0.1:9001".parse().unwrap(),
            role: NodeRole::Worker,
            last_seen_ms,
        }
    }

    // ── Node creation (5) ────────────────────────────────────────────────────

    #[tokio::test]
    async fn node_new_default_id_generated() {
        let config = test_config("", "main");
        let node = NodeState::new(config, StorageMode::Full).unwrap();
        assert!(!node.node_id.is_empty());
        assert!(node.node_id.starts_with("node-"));
    }

    #[tokio::test]
    async fn node_new_custom_id() {
        let config = test_config("my-node", "main");
        let node = NodeState::new(config, StorageMode::Full).unwrap();
        assert_eq!(node.node_id, "my-node");
    }

    #[tokio::test]
    async fn node_initial_role_main() {
        let config = test_config("n1", "main");
        let node = NodeState::new(config, StorageMode::Full).unwrap();
        assert_eq!(node.current_role().await, NodeRole::Main);
    }

    #[tokio::test]
    async fn node_initial_role_worker() {
        let config = test_config("n1", "worker");
        let node = NodeState::new(config, StorageMode::Full).unwrap();
        assert_eq!(node.current_role().await, NodeRole::Worker);
    }

    #[tokio::test]
    async fn node_initial_role_auto() {
        let config = test_config("n1", "auto");
        let node = NodeState::new(config, StorageMode::Full).unwrap();
        // "auto" defaults to Worker; election decides the winner later
        assert_eq!(node.current_role().await, NodeRole::Worker);
    }

    // ── Peer management (4) ──────────────────────────────────────────────────

    #[tokio::test]
    async fn add_peer_new() {
        let config = test_config("n1", "main");
        let node = NodeState::new(config, StorageMode::Full).unwrap();
        node.add_or_update_peer(test_peer("n2", 1000)).await;
        assert_eq!(node.total_nodes().await, 2);
    }

    #[tokio::test]
    async fn add_peer_update_existing() {
        let config = test_config("n1", "main");
        let node = NodeState::new(config, StorageMode::Full).unwrap();
        node.add_or_update_peer(test_peer("n2", 1000)).await;
        node.add_or_update_peer(test_peer("n2", 2000)).await;
        // Still only one peer
        assert_eq!(node.total_nodes().await, 2);
        let last_seen = {
            let peers = node.peers.read().await;
            peers.first().map(|p| p.last_seen_ms)
        };
        assert_eq!(last_seen, Some(2000));
    }

    #[tokio::test]
    async fn remove_peer_existing() {
        let config = test_config("n1", "main");
        let node = NodeState::new(config, StorageMode::Full).unwrap();
        node.add_or_update_peer(test_peer("n2", 1000)).await;
        let removed = node.remove_peer("n2").await;
        assert!(removed);
        assert_eq!(node.total_nodes().await, 1);
    }

    #[tokio::test]
    async fn remove_peer_nonexistent() {
        let config = test_config("n1", "main");
        let node = NodeState::new(config, StorageMode::Full).unwrap();
        let removed = node.remove_peer("ghost").await;
        assert!(!removed);
    }

    // ── Role transitions (4) ─────────────────────────────────────────────────

    #[tokio::test]
    async fn total_nodes_includes_self() {
        let config = test_config("n1", "main");
        let node = NodeState::new(config, StorageMode::Full).unwrap();
        assert_eq!(node.total_nodes().await, 1);
    }

    #[tokio::test]
    async fn quorum_total_uses_declared_members() {
        let mut config = test_config("n1", "main");
        config.members = vec!["n1", "n2", "n3", "n4", "n5"]
            .into_iter()
            .map(String::from)
            .collect();
        let node = NodeState::new(config, StorageMode::Full).unwrap();
        // Only one peer is live, but quorum is derived from the declared size.
        node.add_or_update_peer(test_peer("n2", 1000)).await;
        assert_eq!(node.total_nodes().await, 2, "live view shrinks to 2");
        assert_eq!(node.quorum_total().await, 5, "quorum stays at declared size");
        // A 2-node partition is therefore never a majority of 5.
        assert!(!ElectionManager::is_majority(
            node.total_nodes().await,
            node.quorum_total().await
        ));
    }

    #[tokio::test]
    async fn quorum_total_falls_back_to_live_view_without_members() {
        let config = test_config("n1", "main");
        let node = NodeState::new(config, StorageMode::Full).unwrap();
        node.add_or_update_peer(test_peer("n2", 1000)).await;
        assert_eq!(node.quorum_total().await, 2);
    }

    #[tokio::test]
    async fn promote_to_main() {
        let config = test_config("n1", "worker");
        let node = NodeState::new(config, StorageMode::Full).unwrap();
        assert_eq!(node.current_role().await, NodeRole::Worker);
        node.promote_to_main().await;
        assert_eq!(node.current_role().await, NodeRole::Main);
    }

    #[tokio::test]
    async fn demote_to_worker() {
        let config = test_config("n1", "main");
        let node = NodeState::new(config, StorageMode::Full).unwrap();
        assert_eq!(node.current_role().await, NodeRole::Main);
        node.demote_to_worker().await;
        assert_eq!(node.current_role().await, NodeRole::Worker);
    }

    #[tokio::test]
    async fn demote_already_worker_noop() {
        let config = test_config("n1", "worker");
        let node = NodeState::new(config, StorageMode::Full).unwrap();
        // Should not crash or change state
        node.demote_to_worker().await;
        assert_eq!(node.current_role().await, NodeRole::Worker);
    }

    // ── Version tracking (2) ─────────────────────────────────────────────────

    #[tokio::test]
    async fn set_rules_version() {
        let config = test_config("n1", "main");
        let node = NodeState::new(config, StorageMode::Full).unwrap();
        let returned = node.set_rules_version(42).await;
        assert_eq!(returned, 42);
        let stored = *node.rules_version.read().await;
        assert_eq!(stored, 42);
    }

    #[tokio::test]
    async fn set_config_version() {
        let config = test_config("n1", "main");
        let node = NodeState::new(config, StorageMode::Full).unwrap();
        let returned = node.set_config_version(99).await;
        assert_eq!(returned, 99);
        let stored = *node.config_version.read().await;
        assert_eq!(stored, 99);
    }

    // ── Term and fencing (3) ─────────────────────────────────────────────────

    #[tokio::test]
    async fn increment_term_monotonic() {
        let config = test_config("n1", "main");
        let node = NodeState::new(config, StorageMode::Full).unwrap();
        // initial term is 0; each increment adds 1
        let t1 = node.increment_term().await;
        let t2 = node.increment_term().await;
        let t3 = node.increment_term().await;
        assert_eq!(t1, 1);
        assert_eq!(t2, 2);
        assert_eq!(t3, 3);
    }

    #[tokio::test]
    async fn fencing_check_accepts_current_term() {
        let config = test_config("n1", "main");
        let node = NodeState::new(config, StorageMode::Full).unwrap();
        // Advance the election manager's term to 2
        node.election.advance_term(2);
        // incoming term == current election term → accepted
        assert!(node.fencing_check(2));
    }

    #[tokio::test]
    async fn fencing_check_rejects_stale_term() {
        let config = test_config("n1", "main");
        let node = NodeState::new(config, StorageMode::Full).unwrap();
        // Advance the election manager's term to 2
        node.election.advance_term(2);
        // stale terms are rejected
        assert!(!node.fencing_check(1));
        assert!(!node.fencing_check(0));
        // future term is accepted (not stale)
        assert!(node.fencing_check(3));
    }

    // ── Broadcast (2) ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn add_peer_channel_and_broadcast() {
        use crate::protocol::{ClusterMessage, Heartbeat};
        use waf_common::config::NodeRole;

        let config = test_config("n1", "main");
        let node = NodeState::new(config, StorageMode::Full).unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        node.add_peer_channel(tx);

        let msg = ClusterMessage::Heartbeat(Heartbeat {
            sequence: 1,
            timestamp_ms: 1000,
            node_id: "n1".to_string(),
            role: NodeRole::Main,
            uptime_secs: 10,
            cpu_percent: 0.5,
            memory_used_bytes: 1024,
            total_requests: 100,
            blocked_requests: 5,
            rules_version: 1,
            config_version: 1,
        });

        node.broadcast(&msg);

        let received = rx.recv().await.expect("expected a message on the channel");
        // Verify we got a Heartbeat variant back
        assert!(matches!(received, ClusterMessage::Heartbeat(_)));
    }

    #[tokio::test]
    async fn broadcast_skips_closed_channel() {
        use crate::protocol::{ClusterMessage, Heartbeat};
        use waf_common::config::NodeRole;

        let config = test_config("n1", "main");
        let node = NodeState::new(config, StorageMode::Full).unwrap();

        let (tx, rx) = tokio::sync::mpsc::channel(16);
        node.add_peer_channel(tx);
        // Drop the receiver to close the channel
        drop(rx);

        let msg = ClusterMessage::Heartbeat(Heartbeat {
            sequence: 2,
            timestamp_ms: 2000,
            node_id: "n1".to_string(),
            role: NodeRole::Main,
            uptime_secs: 20,
            cpu_percent: 1.0,
            memory_used_bytes: 2048,
            total_requests: 200,
            blocked_requests: 10,
            rules_version: 2,
            config_version: 2,
        });

        // Should not panic even though channel is closed
        node.broadcast(&msg);
    }

    // ── CA key initial state (1) ─────────────────────────────────────────────

    #[tokio::test]
    async fn initial_ca_keys_none() {
        let config = test_config("n1", "main");
        let node = NodeState::new(config, StorageMode::Full).unwrap();
        assert!(node.ca_key_pem.lock().is_none());
        assert!(node.ca_key_encrypted.lock().is_none());
    }
}
