use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tracing::debug;
use waf_common::config::{ClusterConfig, NodeRole};

use crate::node::NodeState;
use crate::protocol::{ClusterMessage, JoinRequest, NodeInfo};

/// How often a node without a live, verified Main re-runs the join handshake.
pub const REJOIN_INTERVAL_MS: u64 = 5_000;

/// Static seed-based peer discovery.
///
/// Reads the `seeds` list from `ClusterConfig` and resolves each entry to a
/// `SocketAddr`. mDNS auto-discovery is deferred to a future release.
pub struct StaticSeeds {
    seeds: Vec<SocketAddr>,
}

impl StaticSeeds {
    /// Build the seed list from configuration, returning an error if any
    /// address cannot be parsed.
    pub fn from_config(config: &ClusterConfig) -> Result<Self> {
        let seeds = config
            .seeds
            .iter()
            .map(|s| {
                s.parse::<SocketAddr>()
                    .map_err(|e| anyhow::anyhow!("invalid seed address {s:?}: {e}"))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { seeds })
    }

    /// Return the resolved peer addresses.
    pub fn peers(&self) -> &[SocketAddr] {
        &self.seeds
    }
}

/// Build the `JoinRequest` this node presents to a Main.
pub(crate) fn join_request_for(node_state: &NodeState) -> ClusterMessage {
    ClusterMessage::JoinRequest(JoinRequest {
        token: node_state.config.join_token.clone(),
        csr_pem: String::new(),
        node_info: NodeInfo {
            node_id: node_state.node_id.clone(),
            hostname: node_state.node_id.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            listen_addr: node_state.config.listen_addr.clone(),
            capabilities: vec!["waf".to_string()],
        },
    })
}

/// Periodically re-run the join handshake while this node has no live, verified
/// Main.
///
/// # Why (H-11 liveness)
///
/// Since H-11 a node only recognises a new Main from an `ElectionResult` it can
/// corroborate with its own vote. A node that missed the vote round (message
/// loss, or it voted for the losing candidate in a split vote) therefore keeps
/// running with the rules it has instead of adopting an unprovable leader — but
/// it must be able to catch up without forcing a disruptive new election.
///
/// The join handshake is that catch-up path: it is answered only by a node that
/// really is the Main (N-M), it is cheap, idempotent, and invisible to the rest
/// of the cluster. Runs until the tokio task is cancelled.
pub async fn run_rejoin_loop(node_state: Arc<NodeState>, interval_ms: u64) {
    let mut ticker = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms.max(500)));
    loop {
        ticker.tick().await;

        if node_state.current_role().await == NodeRole::Main {
            continue;
        }
        if node_state.verified_main_is_live().await {
            continue;
        }
        debug!(
            node_id = %node_state.node_id,
            "No live verified cluster Main — re-running the join handshake"
        );
        node_state.broadcast(&join_request_for(&node_state));
    }
}
