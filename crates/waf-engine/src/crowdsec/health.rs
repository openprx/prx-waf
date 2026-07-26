//! Whether the LAPI bouncer currently has a usable answer to give.
//!
//! The bouncer's request-path question is "is this IP banned?", and
//! [`super::CrowdSecChecker::check`] answers it with `Option<DetectionResult>`.
//! That type cannot distinguish **"this IP is clean"** from **"I have no idea,
//! I never got the ban list"** — and those two are the difference between a
//! working WAF and a fail-open one. This flag carries that distinction from the
//! sync task (which is the only place that knows) to the request path (which is
//! the only place that can act on it), so `crowdsec.fallback_action` has
//! something to be applied to.
//!
//! # What counts as degraded
//!
//! Degraded means **the bouncer has nothing to enforce and did not get that
//! answer from `CrowdSec`**:
//!
//! | last pull | cached decisions | degraded | why |
//! |---|---|---|---|
//! | succeeded | any | no | LAPI answered. An empty set means "nobody is banned", which is a real answer. |
//! | failed / not yet attempted | > 0 | **no** | Decisions are still being enforced from memory. Possibly stale, but the bouncer is doing its job. |
//! | failed / not yet attempted | 0 | **yes** | No IP can match. Every previously banned client is being let through. |
//!
//! The third row is exactly the state [`super::sync::run_decision_sync`]
//! already reports at `error!` ("the decision cache is EMPTY, so the bouncer
//! matches no IP at all"). This type is that same condition, published to the
//! request path instead of only to the log.
//!
//! The second row is deliberately **not** degraded. A stale-but-populated cache
//! is a nuisance, not an outage; treating it as degraded would let
//! `fallback_action = "block"` turn a brief LAPI hiccup into a total refusal of
//! service while the WAF was still perfectly capable of enforcing every ban it
//! knew about. Staleness has no expression here on purpose — bounding it would
//! need an operator-supplied tolerance ("stale beyond N seconds is degraded"),
//! which is a separate configuration decision, not a default.

use std::sync::atomic::{AtomicBool, Ordering};

/// Lock-free degraded-state flag shared by the `CrowdSec` sync task (writer)
/// and the WAF request path (reader).
///
/// Reads are a single relaxed atomic load, so the request path pays O(1) and no
/// contention. `Relaxed` is sufficient: the flag is advisory and orders no other
/// memory — a reader that observes the previous value for a few nanoseconds
/// simply applies the previous posture to one request, which is indistinguishable
/// from that request having arrived a moment earlier.
#[derive(Debug)]
pub struct CrowdSecHealth {
    degraded: AtomicBool,
}

impl CrowdSecHealth {
    /// A process that has not yet contacted LAPI and has nothing cached — the
    /// honest starting state. [`super::init_crowdsec`] immediately re-evaluates
    /// it against whatever the durable mirror restored, before the proxy binds.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            degraded: AtomicBool::new(true),
        }
    }

    /// Recompute the flag from the two facts that define it.
    ///
    /// * `pull_ok` — the most recent LAPI pull returned a decision set. `false`
    ///   also covers "no pull has been attempted yet" (startup).
    /// * `cached` — decisions currently enforceable from the in-memory cache.
    ///
    /// Called once per pull attempt and once at startup, never on the request
    /// path.
    pub fn observe(&self, pull_ok: bool, cached: u64) {
        self.degraded.store(!pull_ok && cached == 0, Ordering::Relaxed);
    }

    /// Whether a cache miss right now means "clean" (`false`) or "unknown"
    /// (`true`). See the module docs for the exact definition.
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Relaxed)
    }
}

impl Default for CrowdSecHealth {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_process_has_not_heard_from_lapi_yet() {
        assert!(
            CrowdSecHealth::new().is_degraded(),
            "before the first pull with nothing cached, a miss means 'unknown', not 'clean'"
        );
    }

    #[test]
    fn a_successful_pull_clears_degradation_even_with_an_empty_result() {
        let health = CrowdSecHealth::new();
        health.observe(true, 0);
        assert!(
            !health.is_degraded(),
            "LAPI answering 'nobody is banned' is a real answer, not an outage"
        );
    }

    /// The self-inflicted-outage guard: a failed pull while decisions are still
    /// being enforced must not trip `fallback_action`.
    #[test]
    fn a_failed_pull_with_a_populated_cache_is_not_degraded() {
        let health = CrowdSecHealth::new();
        health.observe(true, 120);
        health.observe(false, 120);
        assert!(
            !health.is_degraded(),
            "stale-but-enforcing is a nuisance, not a reason to refuse every request"
        );
    }

    #[test]
    fn a_failed_pull_with_an_empty_cache_is_the_fail_open_state() {
        let health = CrowdSecHealth::new();
        health.observe(true, 5);
        health.observe(false, 0);
        assert!(
            health.is_degraded(),
            "no IP can match; this is exactly what fallback_action exists for"
        );
    }

    #[test]
    fn recovery_clears_a_previously_degraded_flag() {
        let health = CrowdSecHealth::new();
        health.observe(false, 0);
        assert!(health.is_degraded());
        health.observe(true, 7);
        assert!(!health.is_degraded(), "the flag must not latch");
    }
}
