use std::time::Instant;

use dashmap::DashMap;
use waf_common::{DetectionResult, Phase, RequestCtx};

use super::Check;

/// Per-IP token bucket state.
struct BucketState {
    /// Available tokens (fractional).
    tokens: f64,
    /// Last time the bucket was refilled.
    last_check: Instant,
    /// Consecutive rate-limit violations for this IP.
    violation_count: u32,
    /// Timestamp until which this IP is auto-banned; `None` if not banned.
    banned_until: Option<Instant>,
}

/// CC / rate-limit protection using the token bucket algorithm.
///
/// State is stored per `(host_code, client_ip)` key in a `DashMap` so it is
/// safe to call from multiple threads simultaneously.
pub struct CcCheck {
    buckets: DashMap<String, BucketState>,
}

impl CcCheck {
    pub fn new() -> Self {
        Self {
            buckets: DashMap::new(),
        }
    }
}

impl Default for CcCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for CcCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        let dc = &ctx.host_config.defense_config;
        if !dc.cc {
            return None;
        }

        let rps = dc.cc_rps;
        let burst = dc.cc_burst as f64;
        let ban_threshold = dc.cc_ban_threshold;
        let ban_duration_secs = dc.cc_ban_duration_secs;

        // Key: one bucket per (host_code, client_ip)
        let key = format!("{}:{}", ctx.host_config.code, ctx.client_ip);

        // Obtain or create the bucket entry.  DashMap's entry API holds the
        // shard lock for the duration of the operation, giving us atomic RMW.
        let mut entry = self.buckets.entry(key).or_insert_with(|| BucketState {
            tokens: burst,
            last_check: Instant::now(),
            violation_count: 0,
            banned_until: None,
        });

        let state = entry.value_mut();
        let now = Instant::now();

        // Check if the IP is currently auto-banned.
        if let Some(banned_until) = state.banned_until {
            if now < banned_until {
                let remaining = banned_until.duration_since(now).as_secs();
                return Some(DetectionResult {
                    rule_id: Some("CC-BAN".to_string()),
                    rule_name: "Rate Limit (banned)".to_string(),
                    phase: Phase::RateLimit,
                    detail: format!(
                        "IP auto-banned due to repeated rate-limit violations; {} second(s) remaining",
                        remaining
                    ),
                });
            } else {
                // Ban expired — reset state.
                state.banned_until = None;
                state.violation_count = 0;
                state.tokens = burst;
                state.last_check = now;
            }
        }

        // Refill tokens based on elapsed time.
        let elapsed = now.duration_since(state.last_check).as_secs_f64();
        state.tokens = (state.tokens + elapsed * rps).min(burst);
        state.last_check = now;

        if state.tokens >= 1.0 {
            // Request is within the rate limit — consume one token.
            state.tokens -= 1.0;
            None
        } else {
            // Rate limit exceeded.
            state.violation_count += 1;

            if state.violation_count >= ban_threshold {
                // Auto-ban the IP.
                state.banned_until = Some(now + std::time::Duration::from_secs(ban_duration_secs));
                return Some(DetectionResult {
                    rule_id: Some("CC-BAN".to_string()),
                    rule_name: "Rate Limit (auto-ban triggered)".to_string(),
                    phase: Phase::RateLimit,
                    detail: format!(
                        "IP auto-banned for {} seconds after {} violations",
                        ban_duration_secs, state.violation_count
                    ),
                });
            }

            Some(DetectionResult {
                rule_id: Some("CC-001".to_string()),
                rule_name: "Rate Limit".to_string(),
                phase: Phase::RateLimit,
                detail: format!(
                    "Request rate exceeded {:.0} req/s (violation #{}/{})",
                    rps, state.violation_count, ban_threshold
                ),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Arc;
    use waf_common::{DefenseConfig, HostConfig};

    fn make_ctx_with_rps(rps: f64, burst: u32) -> RequestCtx {
        RequestCtx {
            req_id: "test".to_string(),
            client_ip: "10.0.0.1".parse::<IpAddr>().unwrap(),
            client_port: 0,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: "/".to_string(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config: Arc::new(HostConfig {
                code: "test-host".to_string(),
                defense_config: DefenseConfig {
                    cc: true,
                    cc_rps: rps,
                    cc_burst: burst,
                    cc_ban_threshold: 100,
                    cc_ban_duration_secs: 60,
                    ..DefenseConfig::default()
                },
                ..HostConfig::default()
            }),
            geo: None,
        }
    }

    #[test]
    fn allows_requests_within_burst() {
        let checker = CcCheck::new();
        // burst = 5, rps = 1; first 5 requests should pass
        let ctx = make_ctx_with_rps(1.0, 5);
        for i in 0..5 {
            assert!(
                checker.check(&ctx).is_none(),
                "Request {} should be allowed (within burst)",
                i + 1
            );
        }
    }

    #[test]
    fn blocks_after_burst_exhausted() {
        let checker = CcCheck::new();
        // burst = 3, rps = 0.01 (effectively no refill during test)
        let ctx = make_ctx_with_rps(0.01, 3);
        for _ in 0..3 {
            let _ = checker.check(&ctx);
        }
        // 4th request should be rate-limited
        assert!(
            checker.check(&ctx).is_some(),
            "Should be rate limited after burst exhausted"
        );
    }
}
