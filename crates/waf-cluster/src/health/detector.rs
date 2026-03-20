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
    pub fn new(node_id: String, phi_suspect: f64, phi_dead: f64) -> Self {
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
    pub fn phi(&self, now_ms: u64) -> f64 {
        if self.window.len() < 2 {
            return 0.0;
        }
        let last = match self.window.back().copied() {
            Some(t) => t,
            None => return 0.0,
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
        self.peers
            .get(node_id)
            .map(|d| d.phi(now_ms))
            .unwrap_or(0.0)
    }

    /// Return `true` if `node_id`'s phi exceeds the dead threshold.
    pub fn is_peer_dead(&self, node_id: &str, now_ms: u64) -> bool {
        self.peers
            .get(node_id)
            .map(|d| d.is_dead(now_ms))
            .unwrap_or(false)
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
