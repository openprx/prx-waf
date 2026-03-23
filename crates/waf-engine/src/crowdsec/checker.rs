use std::sync::Arc;

use waf_common::{DetectionResult, Phase, RequestCtx};

use crate::checks::Check;

use super::cache::DecisionCache;
use super::config::{CrowdSecConfig, CrowdSecMode};

/// `CrowdSec` bouncer WAF checker.
///
/// Performs a synchronous lookup against the in-memory `DecisionCache`.
/// Runs early in the pipeline (after Phase 1-4 IP/URL checks) so that
/// banned IPs are blocked before expensive pattern matching.
pub struct CrowdSecChecker {
    pub cache: Arc<DecisionCache>,
    pub config: CrowdSecConfig,
}

impl CrowdSecChecker {
    pub const fn new(cache: Arc<DecisionCache>, config: CrowdSecConfig) -> Self {
        Self { cache, config }
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
