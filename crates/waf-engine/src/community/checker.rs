use std::sync::Arc;

use waf_common::{DetectionResult, Phase, RequestCtx};

use crate::checks::Check;

use super::blocklist::CommunityBlocklistSync;

/// WAF checker that looks up the client IP against the community blocklist.
///
/// Runs as part of the detection pipeline, similar to `CrowdSecChecker`,
/// performing a synchronous O(1) DashMap lookup.
pub struct CommunityChecker {
    blocklist: Arc<CommunityBlocklistSync>,
}

impl CommunityChecker {
    pub fn new(blocklist: Arc<CommunityBlocklistSync>) -> Self {
        Self { blocklist }
    }
}

impl Check for CommunityChecker {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        let decision = self.blocklist.check_ip(&ctx.client_ip)?;

        Some(DetectionResult {
            rule_id: Some(format!("community:{}", decision.source)),
            rule_name: "Community Blocklist".to_string(),
            phase: Phase::Community,
            detail: format!(
                "Community blocklist hit for {} (reason: {}, source: {})",
                ctx.client_ip, decision.reason, decision.source,
            ),
        })
    }
}
