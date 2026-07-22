//! Canary rollout bucketing + anomaly-rate circuit breaker (plan v2.2 §13.3).
//!
//! * **Canary** — a deterministic hash of `host_code + stable request key +
//!   rollout_salt`, bucketed into `0..10000`. `bucket < rollout_bps` selects the
//!   request for `enforce` while the lane is otherwise `log_only`. The hash is
//!   FNV-1a (fixed algorithm, no `RandomState`) so bucketing is identical across
//!   nodes and restarts.
//! * **Circuit breaker** — a runtime state machine that flips semantic
//!   enforcement back to `log_only` when the anomaly rate crosses a threshold.
//!   The counting window is a **fixed / tumbling** window (it resets wholesale
//!   at each boundary in [`CircuitBreaker::roll_window`]), not a rolling
//!   sliding window. It only mutates **runtime** state; it never rewrites the
//!   TOML, and a process restart resets it to `Closed`. It is not a
//!   false-positive auto-revert (there is no online FP truth); it reacts to an
//!   anomaly-rate spike.
//!
//!   Because a fresh breaker starts `Closed`, "restart from `log_only`" is
//!   **not** provided by the breaker alone — it is provided by an independent
//!   restart shadow latch in
//!   [`super::ContentSecuritySubsystem::resolve_action`], which holds
//!   enforcement to shadow until a health warmup window elapses since process
//!   start (codex A-4). The anomaly source here ("a block outcome is a sample")
//!   is a placeholder heuristic pending real-traffic calibration (plan §13.3).

use std::time::{Duration, Instant};

use waf_common::content_security_config::SemanticBreakerConfig;

/// Number of canary buckets (basis points).
const BUCKETS: u32 = 10_000;

/// FNV-1a 64-bit over the concatenation of the inputs (with separators), so the
/// bucket is stable across nodes/restarts for a given key + salt.
fn fnv1a(parts: &[&str]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            hash ^= 0xff;
            hash = hash.wrapping_mul(PRIME);
        }
        for &b in part.as_bytes() {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(PRIME);
        }
    }
    hash
}

/// Deterministic canary bucket in `0..10000` (plan §13.3).
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn canary_bucket(host_code: &str, request_key: &str, rollout_salt: &str) -> u16 {
    (fnv1a(&[host_code, request_key, rollout_salt]) % u64::from(BUCKETS)) as u16
}

/// Whether a bucket falls inside the rollout width.
#[must_use]
pub fn in_canary(bucket: u16, rollout_bps: u32) -> bool {
    u32::from(bucket) < rollout_bps
}

/// Compiled breaker parameters.
#[derive(Debug, Clone, Copy)]
pub struct BreakerConfig {
    pub window: Duration,
    pub min_samples: u32,
    pub anomaly_rate_threshold: f64,
    pub cooldown: Duration,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self::from_config(&SemanticBreakerConfig::default())
    }
}

impl BreakerConfig {
    #[must_use]
    pub const fn from_config(cfg: &SemanticBreakerConfig) -> Self {
        Self {
            window: Duration::from_secs(cfg.window_secs),
            min_samples: cfg.min_samples,
            anomaly_rate_threshold: cfg.anomaly_rate_threshold,
            cooldown: Duration::from_secs(cfg.cooldown_secs),
        }
    }
}

/// Breaker runtime state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    /// Enforcing normally.
    Closed,
    /// Tripped — enforcement suppressed until cooldown elapses.
    Open,
    /// Cooldown elapsed — allowing a small probe to test recovery.
    HalfOpen,
}

/// Anomaly-rate circuit breaker (plan §13.3). All transitions are time-driven
/// through an injected `Instant` so it is deterministically testable.
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    cfg: BreakerConfig,
    state: BreakerState,
    window_start: Instant,
    samples: u32,
    anomalies: u32,
    opened_at: Option<Instant>,
}

impl CircuitBreaker {
    #[must_use]
    pub const fn new(cfg: BreakerConfig, now: Instant) -> Self {
        Self {
            cfg,
            state: BreakerState::Closed,
            window_start: now,
            samples: 0,
            anomalies: 0,
            opened_at: None,
        }
    }

    #[must_use]
    pub const fn state(&self) -> BreakerState {
        self.state
    }

    fn roll_window(&mut self, now: Instant) {
        if now.duration_since(self.window_start) >= self.cfg.window {
            self.window_start = now;
            self.samples = 0;
            self.anomalies = 0;
        }
    }

    fn anomaly_rate(&self) -> f64 {
        if self.samples == 0 {
            0.0
        } else {
            f64::from(self.anomalies) / f64::from(self.samples)
        }
    }

    /// Record one observed request outcome (`is_anomaly` = the request tripped
    /// an anomaly heuristic, e.g. an unexpected semantic block rate or upstream
    /// 5xx shift). Drives Closed→Open and HalfOpen→{Closed,Open} transitions.
    pub fn record(&mut self, is_anomaly: bool, now: Instant) {
        self.roll_window(now);
        self.samples = self.samples.saturating_add(1);
        if is_anomaly {
            self.anomalies = self.anomalies.saturating_add(1);
        }

        match self.state {
            BreakerState::Closed => {
                if self.samples >= self.cfg.min_samples && self.anomaly_rate() >= self.cfg.anomaly_rate_threshold {
                    self.state = BreakerState::Open;
                    self.opened_at = Some(now);
                }
            }
            BreakerState::HalfOpen => {
                if is_anomaly {
                    // Probe failed — re-open and restart cooldown.
                    self.state = BreakerState::Open;
                    self.opened_at = Some(now);
                } else if self.samples >= self.cfg.min_samples && self.anomaly_rate() < self.cfg.anomaly_rate_threshold
                {
                    // Probe healthy — fully recover.
                    self.state = BreakerState::Closed;
                    self.opened_at = None;
                }
            }
            BreakerState::Open => {}
        }
    }

    /// Whether enforcement is currently allowed. An `Open` breaker transitions
    /// to `HalfOpen` (and allows a probe) once the cooldown elapses.
    pub fn allows_enforcement(&mut self, now: Instant) -> bool {
        match self.state {
            BreakerState::Closed | BreakerState::HalfOpen => true,
            BreakerState::Open => {
                if let Some(opened) = self.opened_at
                    && now.duration_since(opened) >= self.cfg.cooldown
                {
                    self.state = BreakerState::HalfOpen;
                    // Reset the window so the probe is measured cleanly.
                    self.window_start = now;
                    self.samples = 0;
                    self.anomalies = 0;
                    return true;
                }
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canary_bucket_is_deterministic_and_in_range() {
        let a = canary_bucket("host1", "1.2.3.4", "salt");
        let b = canary_bucket("host1", "1.2.3.4", "salt");
        assert_eq!(a, b, "same inputs must bucket identically");
        assert!(a < 10_000);
    }

    #[test]
    fn canary_salt_changes_bucket() {
        let a = canary_bucket("host1", "1.2.3.4", "saltA");
        let b = canary_bucket("host1", "1.2.3.4", "saltB");
        // Overwhelmingly likely to differ; assert not universally equal.
        assert_ne!(a, b);
    }

    #[test]
    fn rollout_zero_admits_no_request() {
        for key in ["a", "b", "c", "d", "e"] {
            let bucket = canary_bucket("h", key, "s");
            assert!(!in_canary(bucket, 0));
        }
    }

    #[test]
    fn rollout_full_admits_every_request() {
        for key in ["a", "b", "c", "d", "e"] {
            let bucket = canary_bucket("h", key, "s");
            assert!(in_canary(bucket, 10_000));
        }
    }

    fn fast_cfg() -> BreakerConfig {
        BreakerConfig {
            window: Duration::from_secs(45),
            min_samples: 4,
            anomaly_rate_threshold: 0.5,
            cooldown: Duration::from_secs(10),
        }
    }

    #[test]
    fn breaker_opens_on_high_anomaly_rate() {
        let t0 = Instant::now();
        let mut b = CircuitBreaker::new(fast_cfg(), t0);
        for _ in 0..4 {
            b.record(true, t0);
        }
        assert_eq!(b.state(), BreakerState::Open);
        assert!(!b.allows_enforcement(t0), "open breaker suppresses enforcement");
    }

    #[test]
    fn breaker_stays_closed_below_min_samples() {
        let t0 = Instant::now();
        let mut b = CircuitBreaker::new(fast_cfg(), t0);
        b.record(true, t0);
        b.record(true, t0);
        assert_eq!(b.state(), BreakerState::Closed, "min_samples not reached");
        assert!(b.allows_enforcement(t0));
    }

    #[test]
    fn breaker_half_opens_after_cooldown_then_recovers() {
        let t0 = Instant::now();
        let mut b = CircuitBreaker::new(fast_cfg(), t0);
        for _ in 0..4 {
            b.record(true, t0);
        }
        assert_eq!(b.state(), BreakerState::Open);

        let t1 = t0 + Duration::from_secs(11);
        assert!(b.allows_enforcement(t1), "cooldown elapsed → half-open probe allowed");
        assert_eq!(b.state(), BreakerState::HalfOpen);

        // Healthy probe traffic → recover to Closed.
        for _ in 0..4 {
            b.record(false, t1);
        }
        assert_eq!(b.state(), BreakerState::Closed);
    }

    #[test]
    fn breaker_reopens_on_failed_probe() {
        let t0 = Instant::now();
        let mut b = CircuitBreaker::new(fast_cfg(), t0);
        for _ in 0..4 {
            b.record(true, t0);
        }
        let t1 = t0 + Duration::from_secs(11);
        assert!(b.allows_enforcement(t1));
        assert_eq!(b.state(), BreakerState::HalfOpen);
        b.record(true, t1); // probe fails
        assert_eq!(b.state(), BreakerState::Open);
    }
}
