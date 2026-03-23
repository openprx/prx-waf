//! Cluster health monitoring: phi-accrual failure detection and heartbeat sending.

pub mod detector;

pub use detector::{HeartbeatTracker, PhiAccrualDetector};

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::node::NodeState;
use crate::protocol::{ClusterMessage, Heartbeat};

/// Broadcast periodic heartbeats to all connected peer channels.
///
/// Sends a [`ClusterMessage::Heartbeat`] to every sender in `peer_senders` on
/// each `interval_ms` tick.  Full channels and closed channels are handled
/// gracefully without stopping the loop.
///
/// Runs until the process exits (tokio task cancellation).
pub async fn run_heartbeat_sender(
    node_state: Arc<NodeState>,
    interval_ms: u64,
    peer_senders: Vec<mpsc::Sender<ClusterMessage>>,
) {
    let mut ticker = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms.max(1)));
    let mut sequence: u64 = 0;
    let start_ms = now_unix_ms();

    loop {
        ticker.tick().await;
        sequence += 1;

        let now_ms = now_unix_ms();
        let role = node_state.current_role().await;
        let rules_version = *node_state.rules_version.read().await;
        let config_version = *node_state.config_version.read().await;

        let hb = Heartbeat {
            sequence,
            timestamp_ms: now_ms,
            node_id: node_state.node_id.clone(),
            role,
            uptime_secs: now_ms.saturating_sub(start_ms) / 1000,
            cpu_percent: 0.0,
            memory_used_bytes: 0,
            total_requests: 0,
            blocked_requests: 0,
            rules_version,
            config_version,
        };

        let msg = ClusterMessage::Heartbeat(hb);

        for sender in &peer_senders {
            match sender.try_send(msg.clone()) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    debug!(
                        node_id = %node_state.node_id,
                        "Heartbeat channel full; dropping heartbeat"
                    );
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    debug!(
                        node_id = %node_state.node_id,
                        "Heartbeat channel closed"
                    );
                }
            }
        }
    }
}

/// Periodically scan peers and evict those detected as dead by the
/// phi-accrual failure detector.
///
/// On each tick the function:
/// 1. Snapshots the current peer list (async read lock, short-lived).
/// 2. Queries the `HeartbeatTracker` (sync lock, short-lived) for dead peers.
/// 3. Removes dead peers from `NodeState` and cleans up tracker state.
///
/// Runs until the tokio task is cancelled.
pub async fn run_peer_eviction(node_state: Arc<NodeState>, check_interval_ms: u64) {
    let mut ticker = tokio::time::interval(tokio::time::Duration::from_millis(check_interval_ms.max(1000)));

    loop {
        ticker.tick().await;

        let now_ms = now_unix_ms();

        // Step 1: snapshot peer node IDs (async read lock, released immediately).
        let peer_ids: Vec<String> = node_state
            .peers
            .read()
            .await
            .iter()
            .map(|p| p.node_id.clone())
            .collect();

        if peer_ids.is_empty() {
            continue;
        }

        // Step 2: determine which peers are dead (sync lock, short-lived).
        let dead_ids: Vec<String> = {
            let tracker = node_state.heartbeat_tracker.lock();
            peer_ids
                .into_iter()
                .filter(|id| tracker.is_peer_dead(id, now_ms))
                .collect()
        };

        // Step 3: evict dead peers and clean up tracker entries.
        for node_id in &dead_ids {
            if node_state.remove_peer(node_id).await {
                warn!(node_id = %node_id, "Evicted dead peer from cluster");
            }
            // Remove stale detector state so a rejoining node starts fresh.
            node_state.heartbeat_tracker.lock().remove(node_id);
        }
    }
}

#[allow(clippy::cast_possible_truncation)]
pub(crate) fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
