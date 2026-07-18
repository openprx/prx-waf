//! Background sync schedulers started by [`crate::ClusterNode::run`].
//!
//! * Workers periodically **pull** rules from the cluster ([`run_rule_pull_loop`]).
//!   The pull works in any topology because a worker always dials the main, so
//!   its `RuleSyncRequest` reaches the main and the response returns on the same
//!   bidirectional stream.
//! * The main periodically **broadcasts** its current config version
//!   ([`run_config_broadcast_loop`]). Broadcast reaches peers the main has dialed
//!   (a full-mesh deployment); in a star topology config still travels at join
//!   time via `ClusterState`.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::MissedTickBehavior;
use tracing::debug;
use waf_common::config::NodeRole;

use crate::node::NodeState;
use crate::protocol::{ClusterMessage, RuleSyncRequest};

/// Default interval between worker rule pulls / main config broadcasts (ms).
pub const SYNC_INTERVAL_MS: u64 = 5_000;

/// Worker-side loop: periodically ask the cluster for newer rules.
///
/// Only nodes that are **not** currently Main pull — the Main is the
/// authoritative source. The request carries the worker's current registry
/// version so the main can answer with an incremental delta when possible.
pub async fn run_rule_pull_loop(node_state: Arc<NodeState>, interval_ms: u64) {
    let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms.max(1_000)));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        if node_state.current_role().await == NodeRole::Main {
            continue;
        }
        let current_version = node_state.rule_registry.read().version;
        node_state.broadcast(&ClusterMessage::RuleSyncRequest(RuleSyncRequest { current_version }));
        debug!(current_version, "Worker requested rule sync from cluster");
    }
}

/// Main-side loop: broadcast the latest config version to dialed peers.
pub async fn run_config_broadcast_loop(node_state: Arc<NodeState>, interval_ms: u64) {
    let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms.max(1_000)));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        if node_state.current_role().await != NodeRole::Main {
            continue;
        }
        if let Some(cfg) = node_state.config_broadcast() {
            node_state.broadcast(&ClusterMessage::ConfigSync(cfg));
        }
    }
}
