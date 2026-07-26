use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use waf_common::net::RateLimitKey;
use waf_common::{DetectionResult, Phase, RequestCtx};

use super::Check;

/// One bucket per protected host and per client, where "client" is
/// [`RateLimitKey`] — an IPv4 address or an IPv6 `/64`.
///
/// The pair is stored as a tuple rather than a formatted string on purpose. The
/// previous key was `format!("{host_code}:{client_ip}")`, and a colon is the one
/// character an IPv6 address is full of, so `("a", "b::1")` and `("a:b", ":1")`
/// hashed to the same bucket. A tuple has no separator to be ambiguous about.
type BucketKey = (String, RateLimitKey);

/// Maximum number of entries in the rate-limiter map.
/// Beyond this limit, stale entries are forcefully evicted.
const MAX_ENTRIES: usize = 100_000;

/// Entries idle for longer than this duration are eligible for eviction.
const ENTRY_TTL: Duration = Duration::from_mins(10);

/// How often the background cleanup task runs.
const CLEANUP_INTERVAL: Duration = Duration::from_mins(1);

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
/// State is stored per [`BucketKey`] in a `DashMap` so it is safe to call from
/// multiple threads simultaneously.
///
/// A background cleanup task evicts entries that have been idle for longer
/// than [`ENTRY_TTL`] and enforces [`MAX_ENTRIES`] to prevent unbounded
/// memory growth from IP-rotating attackers. That cap is the reason the key
/// aggregates IPv6 to a `/64`: a client rotating inside its own routed prefix
/// would otherwise mint a fresh entry per request, reach [`MAX_ENTRIES`], and
/// push the [`cleanup`](Self::cleanup) oldest-first sweep into evicting the
/// steady legitimate clients instead — never accumulating a `violation_count`
/// of its own, so `CC-BAN` could not fire either.
pub struct CcCheck {
    buckets: Arc<DashMap<BucketKey, BucketState>>,
}

impl CcCheck {
    pub fn new() -> Self {
        let buckets = Arc::new(DashMap::new());

        // Spawn background cleanup task if a Tokio runtime is available.
        // In unit tests without a runtime this gracefully degrades to
        // no background cleanup (which is acceptable for tests).
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let buckets_bg = Arc::clone(&buckets);
            handle.spawn(async move {
                let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
                loop {
                    interval.tick().await;
                    Self::cleanup(&buckets_bg);
                }
            });
        }

        Self { buckets }
    }

    /// Remove expired entries and enforce the maximum entry count.
    fn cleanup(buckets: &DashMap<BucketKey, BucketState>) {
        let now = Instant::now();

        // Remove entries whose last_check is older than ENTRY_TTL
        // and whose ban has expired (or was never set).
        buckets.retain(|_key, state| {
            let idle = now.duration_since(state.last_check);
            let still_banned = state.banned_until.is_some_and(|b| now < b);

            // Keep if still banned or recently active
            still_banned || idle < ENTRY_TTL
        });

        // If still over the limit after TTL eviction, remove oldest entries
        if buckets.len() > MAX_ENTRIES {
            // Collect keys with their last_check time, sorted oldest first
            let mut entries: Vec<(BucketKey, Instant)> = buckets
                .iter()
                .map(|e| (e.key().clone(), e.value().last_check))
                .collect();
            entries.sort_by_key(|(_k, t)| *t);

            let to_remove = buckets.len().saturating_sub(MAX_ENTRIES);
            for (key, _) in entries.into_iter().take(to_remove) {
                buckets.remove(&key);
            }
        }
    }
}

impl Default for CcCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for CcCheck {
    #[allow(clippy::significant_drop_tightening)] // lock must be held for atomic read-modify-write
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        let dc = &ctx.host_config.defense_config;
        if !dc.cc {
            return None;
        }

        let rps = dc.cc_rps;
        let burst = f64::from(dc.cc_burst);
        let ban_threshold = dc.cc_ban_threshold;
        let ban_duration_secs = dc.cc_ban_duration_secs;

        // One bucket per (host, client). IPv4 is the address; IPv6 is the /64
        // the address sits in, because that is the smallest unit a client
        // cannot mint more of for free. See `waf_common::net::RateLimitKey`.
        let key: BucketKey = (
            ctx.host_config.code.clone(),
            RateLimitKey::from_client_ip(ctx.client_ip),
        );

        // Obtain or create the bucket entry.  DashMap's entry API holds the
        // shard lock for the duration of the operation, giving us atomic RMW.
        let mut state = self.buckets.entry(key).or_insert_with(|| BucketState {
            tokens: burst,
            last_check: Instant::now(),
            violation_count: 0,
            banned_until: None,
        });
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
                        "IP auto-banned due to repeated rate-limit violations; {remaining} second(s) remaining"
                    ),
                });
            }
            // Ban expired — reset state.
            state.banned_until = None;
            state.violation_count = 0;
            state.tokens = burst;
            state.last_check = now;
        }

        // Refill tokens based on elapsed time.
        let elapsed = now.duration_since(state.last_check).as_secs_f64();
        state.tokens = elapsed.mul_add(rps, state.tokens).min(burst);
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
                        "IP auto-banned for {ban_duration_secs} seconds after {} violations",
                        state.violation_count
                    ),
                });
            }

            Some(DetectionResult {
                rule_id: Some("CC-001".to_string()),
                rule_name: "Rate Limit".to_string(),
                phase: Phase::RateLimit,
                detail: format!(
                    "Request rate exceeded {rps:.0} req/s (violation #{}/{ban_threshold})",
                    state.violation_count
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
        make_ctx(rps, burst, "10.0.0.1")
    }

    fn make_ctx(rps: f64, burst: u32, client_ip: &str) -> RequestCtx {
        RequestCtx {
            req_id: "test".to_string(),
            client_ip: client_ip.parse::<IpAddr>().unwrap(),
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

    /// IPv4 accounting is untouched by /64 aggregation: two neighbouring
    /// addresses still hold independent budgets.
    #[test]
    fn ipv4_addresses_keep_independent_budgets() {
        let checker = CcCheck::new();
        let a = make_ctx(0.01, 3, "203.0.113.9");
        let b = make_ctx(0.01, 3, "203.0.113.10");

        for _ in 0..3 {
            assert!(checker.check(&a).is_none());
        }
        assert!(checker.check(&a).is_some(), "203.0.113.9 must exhaust its own burst");
        assert!(
            checker.check(&b).is_none(),
            "203.0.113.10 must be unaffected — IPv4 is still accounted per address"
        );
        assert_eq!(checker.buckets.len(), 2);
    }

    /// The bug this aggregation exists to fix: a client rotating addresses
    /// inside its own routed /64 must spend one shared budget, not a fresh one
    /// per request.
    #[test]
    fn ipv6_rotation_within_a_64_shares_one_budget() {
        let checker = CcCheck::new();
        let burst = 3;

        // Three requests from three *different* addresses drain the shared burst.
        for i in 0..burst {
            let ctx = make_ctx(0.01, burst, &format!("2001:db8:1:2::{i:x}"));
            assert!(checker.check(&ctx).is_none(), "request {i} is inside the burst");
        }

        let next = make_ctx(0.01, burst, "2001:db8:1:2:dead:beef:cafe:1");
        let hit = checker
            .check(&next)
            .expect("a fourth, freshly-minted address must be limited");
        assert_eq!(hit.rule_id.as_deref(), Some("CC-001"));
        assert_eq!(checker.buckets.len(), 1, "2^64 addresses, one bucket");
    }

    /// Aggregation stops at /64 — an adjacent prefix is a different client.
    #[test]
    fn ipv6_distinct_64s_stay_independent() {
        let checker = CcCheck::new();
        let a = make_ctx(0.01, 3, "2001:db8:1:2::1");
        let b = make_ctx(0.01, 3, "2001:db8:1:3::1");

        for _ in 0..3 {
            assert!(checker.check(&a).is_none());
        }
        assert!(checker.check(&a).is_some());
        assert!(
            checker.check(&b).is_none(),
            "2001:db8:1:3::/64 is a different network and must not inherit the limit"
        );
        assert_eq!(checker.buckets.len(), 2);
    }

    /// `CC-BAN` was unreachable over IPv6: each rotated address created a fresh
    /// bucket whose `violation_count` restarted at zero.
    #[test]
    fn ipv6_rotation_reaches_the_ban_threshold() {
        let base = make_ctx(0.01, 1, "2001:db8:1:2::0");
        let mut host = (*base.host_config).clone();
        // The fixture's threshold is 100; lower it so the test exercises the
        // threshold rather than the loop bound.
        host.defense_config.cc_ban_threshold = 5;
        let host = Arc::new(host);

        let checker = CcCheck::new();
        let mut banned = None;
        for i in 0..64_u32 {
            let mut ctx = make_ctx(0.01, 1, &format!("2001:db8:1:2::{i:x}"));
            ctx.host_config = Arc::clone(&host);
            if let Some(r) = checker.check(&ctx)
                && r.rule_id.as_deref() == Some("CC-BAN")
            {
                banned = Some(i);
                break;
            }
        }
        // Burst of 1 is spent by request #0; violations 1..=5 follow, and the
        // 5th trips the threshold.
        assert_eq!(
            banned,
            Some(5),
            "CC-BAN must fire on the 5th violation from a /64 rotating its host bits"
        );
    }

    /// The eviction failure mode: with a per-address key a rotation flood grows
    /// the map one entry per request until [`MAX_ENTRIES`] forces the
    /// oldest-first sweep, which discards *legitimate* clients' state. With a
    /// /64 key the flood occupies a single entry, so the sweep never has cause
    /// to run and the steady client survives with its bucket intact.
    #[test]
    fn ipv6_rotation_flood_cannot_evict_a_steady_client() {
        let checker = CcCheck::new();

        // A steady, well-behaved IPv4 client establishes its bucket first.
        let steady = make_ctx(1000.0, 10, "203.0.113.9");
        assert!(checker.check(&steady).is_none());

        // 20 000 requests, each from an address never seen before, all from one
        // routed /64.
        for i in 0..20_000_u32 {
            let ctx = make_ctx(0.01, 1, &format!("2001:db8:1:2::{i:x}"));
            let _ = checker.check(&ctx);
        }

        assert_eq!(
            checker.buckets.len(),
            2,
            "20 000 rotated addresses must occupy one entry, beside the steady client's"
        );
        assert!(
            checker.buckets.len() < MAX_ENTRIES,
            "the oldest-first eviction sweep must have no reason to run"
        );

        // Run the sweep anyway: the steady client must still be there.
        CcCheck::cleanup(&checker.buckets);
        let steady_key = (
            "test-host".to_string(),
            RateLimitKey::from_client_ip("203.0.113.9".parse().unwrap()),
        );
        assert!(
            checker.buckets.contains_key(&steady_key),
            "the steady client's state must survive the flood"
        );
        assert!(
            checker.check(&steady).is_none(),
            "and it must still be served without being rate-limited"
        );
    }
}
