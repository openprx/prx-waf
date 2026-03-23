//! Integration tests for `run_peer_eviction`.
//!
//! Verifies that the peer-eviction task correctly removes dead peers (those whose
//! phi value exceeds `phi_dead`) and leaves healthy peers untouched.
//!
//! All tests use `#[tokio::test(start_paused = true)]` so that
//! `tokio::time::interval` (used inside `run_peer_eviction`) responds to
//! `tokio::time::advance()` instead of real wall-clock time.  This makes the
//! suite fully deterministic and eliminates all timing-related flakiness.
//!
//! NOTE: `now_unix_ms()` inside the eviction loop uses `SystemTime::now()`
//! (real wall clock).  Heartbeats recorded at timestamps far in the past
//! (e.g. 0 and 100 ms) will always appear stale relative to the current
//! wall-clock reading, so dead-peer detection works without any trickery.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use waf_cluster::health::run_peer_eviction;
use waf_cluster::node::{NodeState, PeerInfo, StorageMode};
use waf_common::config::{ClusterConfig, ClusterElectionConfig, NodeRole};

// ─── Helper ───────────────────────────────────────────────────────────────────

/// Build a `NodeState` suitable for eviction tests.
///
/// Uses low phi thresholds so that a peer silent for a few seconds is quickly
/// declared dead, and a short election timeout so startup is fast.
fn test_node() -> Arc<NodeState> {
    let c = ClusterConfig {
        node_id: "main-node".to_string(),
        role: "main".to_string(),
        election: ClusterElectionConfig {
            timeout_min_ms: 150,
            timeout_max_ms: 300,
            heartbeat_interval_ms: 50,
            phi_suspect: 3.0,
            phi_dead: 5.0,
        },
        ..Default::default()
    };
    Arc::new(NodeState::new(c, StorageMode::Full).unwrap())
}

/// Add a peer to `node_state`'s peer list.
async fn add_peer(node_state: &Arc<NodeState>, node_id: &str, port: u16) {
    node_state
        .add_or_update_peer(PeerInfo {
            node_id: node_id.to_string(),
            addr: format!("127.0.0.1:{port}").parse::<SocketAddr>().unwrap(),
            role: NodeRole::Worker,
            last_seen_ms: 0,
        })
        .await;
}

/// Return the node IDs currently in the peer list.
async fn peer_ids(node_state: &Arc<NodeState>) -> Vec<String> {
    node_state
        .peers
        .read()
        .await
        .iter()
        .map(|p| p.node_id.clone())
        .collect()
}

/// Current wall-clock time in Unix milliseconds.
fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

/// A peer whose last heartbeat was recorded far in the past (relative to
/// wall-clock now) must be evicted by `run_peer_eviction` after the eviction
/// loop fires.
///
/// With `start_paused = true`, the `tokio::time::interval` inside
/// `run_peer_eviction` does not tick until we call `tokio::time::advance()`.
/// Advancing by ≥ 1 second (the minimum check interval clamped by the impl)
/// triggers one eviction check.  Because the heartbeats were recorded at t=0
/// and t=100 ms, the real wall-clock is tens of seconds ahead, so phi is huge.
#[tokio::test(start_paused = true)]
async fn eviction_removes_dead_peers() {
    let node_state = test_node();

    // Add the peer to the topology.
    add_peer(&node_state, "dead-peer", 9001).await;

    // Seed the tracker with two heartbeats anchored at the distant past so
    // that the current wall-clock time yields a huge elapsed value.
    {
        let mut tracker = node_state.heartbeat_tracker.lock();
        tracker.record("dead-peer", 0);
        tracker.record("dead-peer", 100);
    }

    // Spawn the eviction task.
    let state_clone = Arc::clone(&node_state);
    tokio::spawn(async move {
        run_peer_eviction(state_clone, 100).await;
    });

    // Advance virtual time by 2 s so the interval fires at least once, then
    // yield so the spawned task gets to run.
    tokio::time::advance(std::time::Duration::from_secs(2)).await;
    tokio::task::yield_now().await;

    assert!(
        !peer_ids(&node_state).await.contains(&"dead-peer".to_string()),
        "dead-peer must have been removed from the cluster peer list"
    );
}

/// A peer that has fresh heartbeats (timestamps close to wall-clock now) must
/// not be evicted.
///
/// We record two heartbeats at `now - 100 ms` and `now`, which gives a mean
/// inter-arrival of 100 ms.  After advancing 2 s of virtual time, the eviction
/// loop fires but the elapsed time since the last heartbeat (still ≈ wall-clock
/// now) is tiny, keeping phi well below `phi_dead`.
#[tokio::test(start_paused = true)]
async fn eviction_keeps_healthy_peers() {
    let node_state = test_node();

    // Add the healthy peer.
    add_peer(&node_state, "healthy-peer", 9002).await;

    // Record two fresh heartbeats close to the current wall-clock.
    let base_ms = now_ms();
    {
        let mut tracker = node_state.heartbeat_tracker.lock();
        tracker.record("healthy-peer", base_ms.saturating_sub(100));
        tracker.record("healthy-peer", base_ms);
    }

    // Spawn the eviction task.
    let state_evict = Arc::clone(&node_state);
    tokio::spawn(async move {
        run_peer_eviction(state_evict, 100).await;
    });

    // Advance virtual time so the interval fires, then yield.
    tokio::time::advance(std::time::Duration::from_secs(2)).await;
    tokio::task::yield_now().await;

    assert!(
        peer_ids(&node_state).await.contains(&"healthy-peer".to_string()),
        "healthy-peer must remain in the cluster after eviction check with fresh heartbeats"
    );
}

/// After eviction, the heartbeat tracker must no longer hold state for the
/// removed peer.  `phi_for` must return 0.0 once the peer has been cleaned up.
#[tokio::test(start_paused = true)]
async fn eviction_cleans_tracker_state() {
    let node_state = test_node();

    // Add the peer and seed stale tracker data (same as eviction_removes_dead_peers).
    add_peer(&node_state, "stale-peer", 9003).await;
    {
        let mut tracker = node_state.heartbeat_tracker.lock();
        tracker.record("stale-peer", 0);
        tracker.record("stale-peer", 100);
    }

    // Spawn eviction.
    let state_clone = Arc::clone(&node_state);
    tokio::spawn(async move {
        run_peer_eviction(state_clone, 100).await;
    });

    // Advance virtual time so the interval fires, then yield.
    tokio::time::advance(std::time::Duration::from_secs(2)).await;
    tokio::task::yield_now().await;

    // The peer should be gone.
    assert!(
        !peer_ids(&node_state).await.contains(&"stale-peer".to_string()),
        "stale-peer must have been evicted"
    );

    // After eviction the tracker must have removed the entry.
    let phi = node_state.heartbeat_tracker.lock().phi_for("stale-peer", 100_000);

    assert!(
        phi < f64::EPSILON,
        "tracker must not hold state for evicted peer (phi_for returned {phi})"
    );
}
