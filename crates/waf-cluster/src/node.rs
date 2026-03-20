//! Cluster node state machine.
//!
//! `NodeState` is the shared, thread-safe runtime state for a single cluster
//! node.  All transport handlers, the election loop, and the health monitor
//! access it through an `Arc<NodeState>`.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use parking_lot::Mutex as ParkingMutex;
use tokio::sync::RwLock;
use tokio::sync::mpsc;
use tracing::{info, warn};
use waf_common::config::{ClusterConfig, NodeRole};

use crate::election::ElectionManager;
use crate::health::HeartbeatTracker;
use crate::protocol::ClusterMessage;

/// Whether this node has a live database connection or must forward writes.
#[derive(Debug, Clone)]
pub enum StorageMode {
    /// Node has its own PostgreSQL connection (main, or worker with local DB).
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
            "worker" => NodeRole::Worker,
            _ => NodeRole::Worker, // "auto" — starts as Worker, election decides
        };

        let election = Arc::new(ElectionManager::new(
            node_id.clone(),
            config.election.timeout_min_ms,
            config.election.timeout_max_ms,
        ));

        let heartbeat_tracker = ParkingMutex::new(HeartbeatTracker::new(
            config.election.phi_suspect,
            config.election.phi_dead,
        ));

        info!(node_id = %node_id, role = ?initial_role, "Cluster node initialized");

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
    /// stored (from a previous JoinResponse), it is already available for use.
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
    pub async fn broadcast(&self, msg: ClusterMessage) {
        let channels = self.peer_channels.lock();
        for tx in channels.iter() {
            match tx.try_send(msg.clone()) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // Back-pressure: drop this beat; peer is catching up.
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    // Peer disconnected; reconnect is handled by ClusterClient.
                }
            }
        }
    }

    // ── Version tracking ──────────────────────────────────────────────────────

    /// Update rules_version and return it.
    pub async fn set_rules_version(&self, version: u64) -> u64 {
        let mut rv = self.rules_version.write().await;
        *rv = version;
        version
    }

    /// Update config_version and return it.
    pub async fn set_config_version(&self, version: u64) -> u64 {
        let mut cv = self.config_version.write().await;
        *cv = version;
        version
    }
}

fn random_suffix() -> String {
    format!("{:08x}", rand::random::<u32>())
}
