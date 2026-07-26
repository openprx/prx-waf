use std::sync::Arc;

use waf_common::{DetectionResult, Phase, RequestCtx};

use crate::checks::Check;

use super::cache::DecisionCache;
use super::config::{CrowdSecConfig, CrowdSecMode, FallbackAction};
use super::health::CrowdSecHealth;

/// `CrowdSec` bouncer WAF checker.
///
/// Performs a synchronous lookup against the in-memory `DecisionCache`.
/// Runs early in the pipeline (after Phase 1-4 IP/URL checks) so that
/// banned IPs are blocked before expensive pattern matching.
pub struct CrowdSecChecker {
    pub cache: Arc<DecisionCache>,
    pub config: CrowdSecConfig,
    /// Whether a cache miss currently means "clean" or "I never got the list".
    /// Written by the sync task, read by [`Self::fallback_for_miss`].
    health: Arc<CrowdSecHealth>,
}

impl CrowdSecChecker {
    #[must_use]
    pub fn new(cache: Arc<DecisionCache>, config: CrowdSecConfig) -> Self {
        Self {
            cache,
            config,
            health: Arc::new(CrowdSecHealth::new()),
        }
    }

    /// The degraded-state flag to hand to the sync task, which is the only
    /// writer. Cloning the `Arc` is how the two ends of the signal are joined;
    /// see [`super::init_crowdsec`].
    #[must_use]
    pub const fn health(&self) -> &Arc<CrowdSecHealth> {
        &self.health
    }

    /// What to do about a request that [`Check::check`] did **not** match.
    ///
    /// `None` — the miss was a real "this IP is clean"; carry on. This is the
    /// answer on the default path (`fallback_action = "allow"`), returned
    /// without ever touching the health flag, so the shipped configuration pays
    /// nothing more than one comparison against an immutable config field.
    ///
    /// `Some(action)` — the bouncer has no decision set at all and could not get
    /// one from LAPI, so the miss carries no information. The caller applies the
    /// operator's configured [`FallbackAction`]. `Allow` never reaches here (it
    /// is filtered above), but the caller still matches it exhaustively so the
    /// three postures stay visible in one place.
    ///
    /// In `mode = "appsec"` the decision cache is not consulted on the request
    /// path at all, so there is no bouncer miss to interpret and no fallback to
    /// apply — `AppSec` outages are governed by its own `failure_action`.
    #[must_use]
    pub fn fallback_for_miss(&self) -> Option<&FallbackAction> {
        if self.config.fallback_action == FallbackAction::Allow || self.config.mode == CrowdSecMode::Appsec {
            return None;
        }
        if self.health.is_degraded() {
            Some(&self.config.fallback_action)
        } else {
            None
        }
    }
}

/// Why a request was judged without the bouncer having anything to judge with.
const LAPI_UNAVAILABLE_DETAIL: &str = "CrowdSec LAPI is unreachable and the decision cache is empty, so no IP can \
                                       match; applying the configured crowdsec.fallback_action";

/// Build a `DetectionResult` describing a LAPI bouncer outage.
///
/// Used when `fallback_action` is `Block` (fail closed) or `Log` (record only).
/// The counterpart to [`super::appsec::appsec_unavailable_detection`], kept
/// distinct so an operator reading an event log can tell which of the two
/// independent `CrowdSec` paths went dark.
#[must_use]
pub fn lapi_unavailable_detection() -> DetectionResult {
    DetectionResult {
        rule_id: Some("crowdsec:lapi-unavailable".to_string()),
        rule_name: "CrowdSec LAPI Unavailable".to_string(),
        phase: Phase::CrowdSec,
        detail: LAPI_UNAVAILABLE_DETAIL.to_string(),
    }
}

impl Check for CrowdSecChecker {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        // Skip if mode is AppSec-only (no local cache checks)
        if self.config.mode == CrowdSecMode::Appsec {
            return None;
        }

        if let Some(cached) = self.cache.check_ip(&ctx.client_ip) {
            let type_lower = cached.decision.type_.to_lowercase();
            let rule_name = match type_lower.as_str() {
                "captcha" => "CrowdSec Captcha",
                "throttle" => "CrowdSec Throttle",
                _ => "CrowdSec Ban",
            };

            return Some(DetectionResult {
                rule_id: Some(format!("crowdsec:{}", cached.decision.scenario)),
                rule_name: rule_name.to_string(),
                phase: Phase::CrowdSec,
                detail: format!(
                    "CrowdSec decision: {} for {} (scenario: {}, origin: {})",
                    cached.decision.type_, ctx.client_ip, cached.decision.scenario, cached.decision.origin,
                ),
            });
        }

        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn checker(fallback: FallbackAction, mode: CrowdSecMode) -> CrowdSecChecker {
        CrowdSecChecker::new(
            Arc::new(DecisionCache::new(0)),
            CrowdSecConfig {
                enabled: true,
                mode,
                fallback_action: fallback,
                ..CrowdSecConfig::default()
            },
        )
    }

    /// The compatibility guarantee of this whole feature: an operator who never
    /// set `fallback_action` sees no change, in either health state.
    #[test]
    fn the_default_posture_never_applies_a_fallback() {
        let cs = checker(FallbackAction::Allow, CrowdSecMode::Bouncer);
        assert!(cs.health().is_degraded(), "precondition: a fresh process is degraded");
        assert!(
            cs.fallback_for_miss().is_none(),
            "fallback_action defaults to allow; a degraded bouncer must still fail open"
        );
        cs.health().observe(true, 0);
        assert!(cs.fallback_for_miss().is_none());
    }

    #[test]
    fn block_applies_only_while_degraded() {
        let cs = checker(FallbackAction::Block, CrowdSecMode::Bouncer);
        assert_eq!(cs.fallback_for_miss(), Some(&FallbackAction::Block));

        cs.health().observe(true, 3);
        assert!(
            cs.fallback_for_miss().is_none(),
            "a healthy bouncer must not charge the fallback to every clean request"
        );

        cs.health().observe(false, 3);
        assert!(
            cs.fallback_for_miss().is_none(),
            "a failed pull that still has decisions to enforce is not an outage"
        );

        cs.health().observe(false, 0);
        assert_eq!(cs.fallback_for_miss(), Some(&FallbackAction::Block));
    }

    #[test]
    fn log_is_reported_as_its_own_action() {
        let cs = checker(FallbackAction::Log, CrowdSecMode::Bouncer);
        assert_eq!(cs.fallback_for_miss(), Some(&FallbackAction::Log));
    }

    /// `mode = "appsec"` never consults the decision cache, so there is no
    /// bouncer miss for `fallback_action` to interpret.
    #[test]
    fn appsec_only_mode_has_no_bouncer_fallback() {
        let cs = checker(FallbackAction::Block, CrowdSecMode::Appsec);
        assert!(cs.health().is_degraded());
        assert!(cs.fallback_for_miss().is_none());
    }

    #[test]
    fn the_outage_detection_names_the_lapi_path_not_appsec() {
        let result = lapi_unavailable_detection();
        assert_eq!(result.rule_id.as_deref(), Some("crowdsec:lapi-unavailable"));
        assert_eq!(result.phase, Phase::CrowdSec);
        assert!(
            result.detail.contains("fallback_action"),
            "the event must name the setting that produced it: {}",
            result.detail
        );
    }
}
