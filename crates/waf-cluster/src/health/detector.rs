//! Phi-accrual failure detector (Cassandra-style).
//!
//! Tracks heartbeat inter-arrival times per peer and computes a suspicion
//! level φ. Uses an exponential distribution model.
//!
//! - φ > `phi_suspect` → node may be failing (emit warning)
//! - φ > `phi_dead`    → node declared dead (trigger election if main)

use std::collections::{HashMap, VecDeque};

use tracing::warn;

/// Per-peer phi-accrual failure detector.
pub struct PhiAccrualDetector {
    node_id: String,
    /// Ring buffer of heartbeat arrival timestamps (Unix ms)
    window: VecDeque<u64>,
    max_window: usize,
    phi_suspect: f64,
    phi_dead: f64,
}

impl PhiAccrualDetector {
    /// Create a new detector for the given `node_id`.
    pub const fn new(node_id: String, phi_suspect: f64, phi_dead: f64) -> Self {
        Self {
            node_id,
            window: VecDeque::new(),
            max_window: 100,
            phi_suspect,
            phi_dead,
        }
    }

    /// Record a heartbeat arrival at `timestamp_ms`.
    pub fn record_heartbeat(&mut self, timestamp_ms: u64) {
        if self.window.len() >= self.max_window {
            self.window.pop_front();
        }
        self.window.push_back(timestamp_ms);
    }

    /// Compute the phi suspicion value at `now_ms`.
    ///
    /// Returns 0.0 when insufficient data is available.
    /// Uses an exponential distribution: φ = −log₁₀(exp(−t / mean)).
    #[allow(clippy::cast_precision_loss)]
    pub fn phi(&self, now_ms: u64) -> f64 {
        if self.window.len() < 2 {
            return 0.0;
        }
        let Some(last) = self.window.back().copied() else {
            return 0.0;
        };
        let elapsed = now_ms.saturating_sub(last) as f64;

        let intervals: Vec<f64> = self
            .window
            .iter()
            .zip(self.window.iter().skip(1))
            .map(|(a, b)| b.saturating_sub(*a) as f64)
            .filter(|&d| d > 0.0)
            .collect();

        if intervals.is_empty() {
            return 0.0;
        }

        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        if mean <= 0.0 {
            return f64::INFINITY;
        }

        // P(t > elapsed) ≈ exp(−elapsed / mean) for exponential distribution
        let prob = (-elapsed / mean).exp();
        if prob <= 0.0 {
            return f64::INFINITY;
        }
        -prob.log10()
    }

    /// Returns `true` when φ exceeds the suspect threshold.
    pub fn is_suspected(&self, now_ms: u64) -> bool {
        self.phi(now_ms) > self.phi_suspect
    }

    /// Returns `true` when φ exceeds the dead threshold.
    pub fn is_dead(&self, now_ms: u64) -> bool {
        let phi = self.phi(now_ms);
        if phi > self.phi_dead {
            warn!(
                node_id = %self.node_id,
                phi = phi,
                "Node declared dead by phi-accrual detector"
            );
            true
        } else {
            false
        }
    }
}

// ─── Multi-peer heartbeat tracker ────────────────────────────────────────────

/// Tracks heartbeat arrivals for every peer and drives the phi-accrual
/// failure detector for each one.
pub struct HeartbeatTracker {
    peers: HashMap<String, PhiAccrualDetector>,
    phi_suspect: f64,
    phi_dead: f64,
}

impl HeartbeatTracker {
    /// Create a new tracker with the given phi thresholds.
    pub fn new(phi_suspect: f64, phi_dead: f64) -> Self {
        Self {
            peers: HashMap::new(),
            phi_suspect,
            phi_dead,
        }
    }

    /// Record a heartbeat arrival for `node_id` at `now_ms`.
    pub fn record(&mut self, node_id: &str, now_ms: u64) {
        let phi_suspect = self.phi_suspect;
        let phi_dead = self.phi_dead;
        self.peers
            .entry(node_id.to_string())
            .or_insert_with(|| PhiAccrualDetector::new(node_id.to_string(), phi_suspect, phi_dead))
            .record_heartbeat(now_ms);
    }

    /// Return the phi suspicion value for `node_id` at `now_ms`, or 0.0 if unknown.
    pub fn phi_for(&self, node_id: &str, now_ms: u64) -> f64 {
        self.peers.get(node_id).map_or(0.0, |d| d.phi(now_ms))
    }

    /// Return `true` if `node_id`'s phi exceeds the dead threshold.
    pub fn is_peer_dead(&self, node_id: &str, now_ms: u64) -> bool {
        self.peers.get(node_id).is_some_and(|d| d.is_dead(now_ms))
    }

    /// Return the node IDs whose phi value exceeds the dead threshold.
    pub fn dead_nodes(&self, now_ms: u64) -> Vec<String> {
        self.peers
            .iter()
            .filter(|(_, d)| d.is_dead(now_ms))
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Remove a peer from tracking (on graceful leave).
    pub fn remove(&mut self, node_id: &str) {
        self.peers.remove(node_id);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::{HeartbeatTracker, PhiAccrualDetector};

    // ── PhiAccrualDetector tests ─────────────────────────────────────────────

    /// A brand-new detector with no recorded heartbeats returns phi == 0.0
    /// because it has insufficient data (fewer than 2 samples).
    #[test]
    fn phi_detector_initial_zero() {
        let det = PhiAccrualDetector::new("node-1".to_string(), 8.0, 12.0);
        let now = 1_000_000_u64;
        assert!(det.phi(now) < f64::EPSILON, "fresh detector must return phi == 0.0");
    }

    /// After four heartbeats at a regular 100 ms cadence, phi at t+50 ms
    /// (well inside the expected interval) must be low — below 1.0.
    #[test]
    fn phi_detector_regular_heartbeats() {
        let mut det = PhiAccrualDetector::new("node-1".to_string(), 8.0, 12.0);
        // Record at t = 0, 100, 200, 300 ms.
        det.record_heartbeat(0);
        det.record_heartbeat(100);
        det.record_heartbeat(200);
        det.record_heartbeat(300);

        // At t = 350 ms (50 ms after last), phi should be very low.
        let phi = det.phi(350);
        assert!(phi < 1.0, "phi should be low for a healthy peer (got {phi})");
    }

    /// After three heartbeats (t=0, 100, 200), phi at t=500 (300 ms since last)
    /// must exceed phi at t=250 (50 ms since last) — missed heartbeats raise phi.
    #[test]
    fn phi_detector_missed_heartbeat_phi_rises() {
        let mut det = PhiAccrualDetector::new("node-1".to_string(), 8.0, 12.0);
        det.record_heartbeat(0);
        det.record_heartbeat(100);
        det.record_heartbeat(200);

        let phi_soon = det.phi(250); // 50 ms since last — healthy
        let phi_late = det.phi(500); // 300 ms since last — missed one interval
        assert!(
            phi_late > phi_soon,
            "phi at t=500 ({phi_late}) must exceed phi at t=250 ({phi_soon})"
        );
    }

    /// After only two heartbeats (t=0, 100), a long silence (t=10000, i.e. 9.9 s)
    /// must produce a very high phi value (> 5.0), signalling a dead node.
    #[test]
    fn phi_detector_long_silence_phi_very_high() {
        let mut det = PhiAccrualDetector::new("node-1".to_string(), 8.0, 12.0);
        det.record_heartbeat(0);
        det.record_heartbeat(100);

        let phi = det.phi(10_000);
        assert!(phi > 5.0, "phi after long silence should be very high (got {phi})");
    }

    // ── HeartbeatTracker tests ───────────────────────────────────────────────

    /// Recording a single heartbeat for a peer provides insufficient data for phi
    /// (< 2 samples), so `is_peer_dead` must return false at the same timestamp.
    #[test]
    fn tracker_new_peer_not_suspect() {
        let mut tracker = HeartbeatTracker::new(3.0, 5.0);
        tracker.record("peer1", 1_000);

        // Only one sample — detector cannot compute phi yet.
        assert!(
            !tracker.is_peer_dead("peer1", 1_000),
            "single-sample peer must not be declared dead"
        );
    }

    /// Five heartbeats at a regular 100 ms cadence: the peer must not be dead
    /// shortly (50 ms) after the last heartbeat.
    #[test]
    fn tracker_healthy_peer_not_suspect() {
        let mut tracker = HeartbeatTracker::new(3.0, 5.0);
        for i in 0u64..5 {
            tracker.record("peer1", i * 100);
        }
        // 50 ms after the last heartbeat at 400 ms.
        assert!(!tracker.is_peer_dead("peer1", 450), "healthy peer must not be dead");
    }

    /// After three heartbeats at t=0, 100, 200, checking at t=2000 (1.8 s later)
    /// should yield a phi value above the suspect threshold (3.0).
    #[test]
    fn tracker_stale_peer_suspect() {
        let mut tracker = HeartbeatTracker::new(3.0, 5.0);
        tracker.record("peer1", 0);
        tracker.record("peer1", 100);
        tracker.record("peer1", 200);

        let phi = tracker.phi_for("peer1", 2_000);
        assert!(
            phi > 3.0,
            "phi at t=2000 should exceed suspect threshold 3.0 (got {phi})"
        );
    }

    /// After two heartbeats at t=0, 100, checking at `t=50_000` (49.9 s later)
    /// must result in `is_peer_dead` returning true (phi >> `phi_dead=5.0`).
    #[test]
    fn tracker_very_stale_peer_dead() {
        let mut tracker = HeartbeatTracker::new(3.0, 5.0);
        tracker.record("peer1", 0);
        tracker.record("peer1", 100);

        assert!(
            tracker.is_peer_dead("peer1", 50_000),
            "peer silent for ~50 s must be declared dead"
        );
    }

    /// After removing a peer, `phi_for` must return 0.0 (no entry in tracker).
    #[test]
    fn tracker_remove_cleans_state() {
        let mut tracker = HeartbeatTracker::new(3.0, 5.0);
        tracker.record("peer1", 0);
        tracker.record("peer1", 100);
        tracker.record("peer1", 200);

        tracker.remove("peer1");

        assert!(
            tracker.phi_for("peer1", 10_000) < f64::EPSILON,
            "phi_for a removed peer must be 0.0"
        );
    }

    /// Two independent peers: "peer1" receives regular heartbeats, "peer2" does
    /// not.  "peer1" must not be dead; "peer2" has no tracker entry so phi == 0.0.
    #[test]
    fn tracker_multiple_peers_independent() {
        let mut tracker = HeartbeatTracker::new(3.0, 5.0);

        // Healthy peer1 at regular intervals.
        for i in 0u64..5 {
            tracker.record("peer1", i * 100);
        }

        // peer2 was never recorded — phi_for returns 0.0 (unknown peer).
        assert!(!tracker.is_peer_dead("peer1", 450), "peer1 must not be dead");
        assert!(
            tracker.phi_for("peer2", 50_000) < f64::EPSILON,
            "unknown peer2 phi must be 0.0"
        );
        assert!(!tracker.is_peer_dead("peer2", 50_000), "unknown peer2 must not be dead");
    }

    /// After recording, removing, and re-recording a peer, the detector is fresh
    /// (only one new sample).  `phi_for` must return 0.0 because < 2 heartbeats
    /// have been recorded since the fresh start.
    #[test]
    fn tracker_record_after_remove_fresh_start() {
        let mut tracker = HeartbeatTracker::new(3.0, 5.0);

        // Initial heartbeats.
        tracker.record("peer1", 0);
        tracker.record("peer1", 100);
        tracker.record("peer1", 200);

        // Evict the peer.
        tracker.remove("peer1");

        // Re-record a single heartbeat — detector starts fresh.
        tracker.record("peer1", 300);

        // Only one sample after fresh start → phi == 0.0.
        assert!(
            tracker.phi_for("peer1", 10_000) < f64::EPSILON,
            "fresh-start peer with 1 heartbeat must return phi == 0.0"
        );
    }

    /// Recording 150 heartbeats (exceeding `max_window` = 100) must not cause
    /// unbounded growth — the window is capped and phi remains computable.
    #[test]
    fn phi_detector_window_overflow() {
        let mut det = PhiAccrualDetector::new("node-1".to_string(), 8.0, 12.0);

        // Record 150 heartbeats at a regular 100 ms cadence.
        for i in 0u64..150 {
            det.record_heartbeat(i * 100);
        }

        // Window must not exceed max_window (100).
        assert!(
            det.window.len() <= 100,
            "window grew beyond max_window (len={})",
            det.window.len()
        );

        // phi must still be computable (not NaN or inf) right after the last heartbeat.
        let phi = det.phi(150 * 100);
        assert!(phi.is_finite(), "phi must be finite after window overflow (got {phi})");
        assert!(
            phi < 1.0,
            "phi should be low immediately after last heartbeat (got {phi})"
        );
    }

    /// `dead_nodes` must return exactly the peers whose phi exceeds the dead
    /// threshold while leaving fresh peers out of the result.
    ///
    /// `peer1` and `peer2` receive continuous heartbeats (100 ms cadence) up to
    /// just before the check time; `peer3` has only two stale heartbeats near
    /// the origin.  At the check time `peer3` has been silent for ~50 s
    /// (phi >> `phi_dead`) while `peer1` and `peer2` remain healthy.
    #[test]
    fn tracker_dead_nodes_returns_correct_list() {
        let mut tracker = HeartbeatTracker::new(3.0, 5.0);

        // Peers 1 and 2: continuous heartbeats at 100 ms cadence up to t = 49_900.
        for i in 0u64..500 {
            tracker.record("peer1", i * 100);
            tracker.record("peer2", i * 100);
        }
        // peer3: only two stale heartbeats.
        tracker.record("peer3", 0);
        tracker.record("peer3", 100);

        // At t = 50_000, peer3 is clearly dead; peer1/peer2 are healthy.
        let dead = tracker.dead_nodes(50_000);
        assert!(
            dead.contains(&"peer3".to_string()),
            "peer3 must appear in dead_nodes (got {dead:?})"
        );
        assert!(
            !dead.contains(&"peer1".to_string()),
            "peer1 must not appear in dead_nodes (got {dead:?})"
        );
        assert!(
            !dead.contains(&"peer2".to_string()),
            "peer2 must not appear in dead_nodes (got {dead:?})"
        );
    }

    /// With `phi_suspect` = 3.0 and `phi_dead` = 8.0, a moderate silence puts the
    /// detector into the suspected-but-not-dead zone: `is_suspected` returns
    /// true while `is_dead` returns false.
    #[test]
    fn phi_detector_is_suspected_vs_is_dead() {
        // phi_suspect = 3.0, phi_dead = 8.0 — wide gap for the test.
        let mut det = PhiAccrualDetector::new("node-1".to_string(), 3.0, 8.0);

        // Heartbeats at 100 ms cadence: t = 0, 100, 200, 300, 400.
        for i in 0u64..5 {
            det.record_heartbeat(i * 100);
        }

        // mean inter-arrival = 100 ms.
        // phi(t) = -log10(exp(-elapsed/mean)) = elapsed / (mean * ln(10))
        // phi_suspect (3.0) crossed at elapsed ≈ 691 ms (≈ 6.9 × mean).
        // phi_dead    (8.0) crossed at elapsed ≈ 1842 ms (≈ 18.4 × mean).
        //
        // At t = 1200 ms (800 ms since last heartbeat at 400):
        //   phi ≈ 800 / (100 * 2.302) ≈ 3.47 → suspected, not dead.
        let now_ms = 1_200_u64;
        let phi = det.phi(now_ms);
        assert!(phi > 3.0, "phi at t=1200 must exceed phi_suspect=3.0 (got {phi})");
        assert!(phi < 8.0, "phi at t=1200 must be below phi_dead=8.0 (got {phi})");
        assert!(det.is_suspected(now_ms), "node must be suspected at t=1200");
        assert!(!det.is_dead(now_ms), "node must not be dead at t=1200");
    }

    /// A detector with exactly one recorded heartbeat must return phi == 0.0
    /// because at least two samples are needed to compute inter-arrival intervals.
    #[test]
    fn phi_detector_single_heartbeat_returns_zero() {
        let mut det = PhiAccrualDetector::new("node-1".to_string(), 8.0, 12.0);
        det.record_heartbeat(1_000);

        // Even after a very long silence, phi must be 0.0 with only one sample.
        let phi = det.phi(1_000_000);
        assert!(
            phi < f64::EPSILON,
            "single-heartbeat detector must return phi == 0.0 (got {phi})"
        );
    }
}
