use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::node::NodeState;
use crate::protocol::{ClusterMessage, Heartbeat};

/// Phi-accrual failure detector (Cassandra-style).
///
/// Tracks heartbeat inter-arrival times and computes a suspicion level φ.
/// φ > `phi_suspect` → node may be failing.
/// φ > `phi_dead`    → node declared dead, trigger election if it was main.
pub struct PhiAccrualDetector {
    node_id: String,
    /// Ring buffer of heartbeat timestamps (Unix ms)
    window: VecDeque<u64>,
    max_window: usize,
    phi_suspect: f64,
    phi_dead: f64,
}

impl PhiAccrualDetector {
    pub fn new(node_id: String, phi_suspect: f64, phi_dead: f64) -> Self {
        Self {
            node_id,
            window: VecDeque::new(),
            max_window: 100,
            phi_suspect,
            phi_dead,
        }
    }

    /// Record a heartbeat arrival at `timestamp_ms`
    pub fn record_heartbeat(&mut self, timestamp_ms: u64) {
        if self.window.len() >= self.max_window {
            self.window.pop_front();
        }
        self.window.push_back(timestamp_ms);
    }

    /// Compute the phi suspicion value at `now_ms`.
    /// Returns 0.0 if insufficient data.
    pub fn phi(&self, now_ms: u64) -> f64 {
        if self.window.len() < 2 {
            return 0.0;
        }
        let last = self.window.back().copied().unwrap_or(0);
        let elapsed = now_ms.saturating_sub(last) as f64;

        let intervals: Vec<f64> = self
            .window
            .iter()
            .zip(self.window.iter().skip(1))
            .map(|(a, b)| b.saturating_sub(*a) as f64)
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

    /// Returns true when φ exceeds the suspect threshold.
    pub fn is_suspected(&self, now_ms: u64) -> bool {
        self.phi(now_ms) > self.phi_suspect
    }

    /// Returns true when φ exceeds the dead threshold, logging a warning.
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
    let mut ticker =
        tokio::time::interval(tokio::time::Duration::from_millis(interval_ms.max(1)));
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
            // System resource metrics and counters wired up in P3
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

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
