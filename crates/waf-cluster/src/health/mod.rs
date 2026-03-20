//! Cluster health monitoring: phi-accrual failure detection and heartbeat sending.

pub mod detector;

pub use detector::{HeartbeatTracker, PhiAccrualDetector};

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tracing::debug;

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

pub(crate) fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
