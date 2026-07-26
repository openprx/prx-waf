//! Security-hardening middleware and helpers.
//!
//! - Security response headers (`X-Frame-Options`, CSP, HSTS, `X-Content-Type-Options`)
//! - Request body size enforcement
//! - IP-based admin access control
//! - Simple in-process per-IP rate limiting

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use waf_common::net::RateLimitKey;

use axum::{
    Json,
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::IntoResponse,
};
use serde_json::json;

use crate::error::ApiResult;
use crate::state::AppState;
use axum::{extract::Query, extract::State};
use waf_storage::models::AuditLogQuery;

// ─── Security headers middleware ──────────────────────────────────────────────

/// Adds security headers to every management API response.
pub async fn security_headers_middleware(req: Request<Body>, next: Next) -> impl IntoResponse {
    use axum::http::HeaderValue;

    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    headers.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
    headers.insert("X-XSS-Protection", HeaderValue::from_static("1; mode=block"));
    headers.insert(
        "Strict-Transport-Security",
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(
        "Content-Security-Policy",
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'",
        ),
    );
    headers.insert(
        "Referrer-Policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    response
}

// ─── Rate limiter ──────────────────────────────────────────────────────────────

/// Maximum number of per-IP entries before forced LRU eviction.
const API_RATE_MAX_ENTRIES: usize = 50_000;

/// Entries idle longer than this are evicted during periodic cleanup.
const API_RATE_TTL: std::time::Duration = std::time::Duration::from_mins(10);

/// Token-bucket entry per IP
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

/// Simple in-process per-client rate limiter (token bucket algorithm).
///
/// Includes periodic cleanup of stale entries to prevent unbounded memory
/// growth when facing large numbers of unique source IPs.
///
/// # Unit of account
///
/// Buckets are keyed by [`RateLimitKey`], not by the raw address: an IPv4
/// address stands for itself, an IPv6 address stands for its `/64`. The
/// derivation happens inside [`check`](Self::check) rather than at the call
/// sites so that no caller can forget it — this limiter backs both the general
/// management-API throttle and the login brute-force throttle, and the latter
/// is the one place where a per-address key would have made the limit purely
/// decorative over IPv6.
pub struct ApiRateLimiter {
    buckets: Mutex<HashMap<RateLimitKey, Bucket>>,
    rps: f64,
    burst: f64,
}

impl ApiRateLimiter {
    pub fn new(rps: u32) -> Arc<Self> {
        let limiter = Arc::new(Self {
            buckets: Mutex::new(HashMap::new()),
            rps: f64::from(rps),
            burst: f64::from(rps.saturating_mul(5).max(10)),
        });

        // Spawn background cleanup task (runs every 60 seconds)
        let limiter_bg = Arc::clone(&limiter);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_mins(1));
            loop {
                interval.tick().await;
                limiter_bg.cleanup();
            }
        });

        limiter
    }

    /// Returns `true` if the request is allowed, `false` if rate-limited.
    ///
    /// `ip` is a client address; the bucket it spends from is
    /// [`RateLimitKey::from_client_ip`] of that address.
    #[allow(clippy::significant_drop_tightening)] // lock must span all bucket operations
    pub fn check(&self, ip: IpAddr) -> bool {
        if self.rps == 0.0 {
            return true;
        }
        let key = RateLimitKey::from_client_ip(ip);
        let now = Instant::now();
        let mut map = self.buckets.lock();
        let bucket = map.entry(key).or_insert(Bucket {
            tokens: self.burst,
            last_refill: now,
        });

        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = elapsed.mul_add(self.rps, bucket.tokens).min(self.burst);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Evict entries that have been idle longer than [`API_RATE_TTL`] and
    /// enforce [`API_RATE_MAX_ENTRIES`] by removing oldest entries first.
    fn cleanup(&self) {
        let now = Instant::now();
        let mut map = self.buckets.lock();

        // Remove stale entries
        map.retain(|_key, bucket| now.duration_since(bucket.last_refill) < API_RATE_TTL);

        // If still over limit, evict oldest entries
        if map.len() > API_RATE_MAX_ENTRIES {
            let mut entries: Vec<(RateLimitKey, Instant)> = map.iter().map(|(k, b)| (*k, b.last_refill)).collect();
            entries.sort_by_key(|&(_key, t)| t);

            let to_remove = map.len().saturating_sub(API_RATE_MAX_ENTRIES);
            for (key, _) in entries.into_iter().take(to_remove) {
                map.remove(&key);
            }
        }
    }
}

// ─── Client address extraction ────────────────────────────────────────────────

/// Canonical client address of a management-API connection.
///
/// # Normalization boundary
///
/// This is **the** point where a client address enters the management API, and
/// therefore the only place in this crate that folds IPv4-mapped IPv6
/// (`::ffff:a.b.c.d` — what a `[::]` listener reports for an IPv4 client) down
/// to plain IPv4. [`is_admin_ip_allowed`] does not fold again; see
/// [`waf_common::net`] for the invariant and for what this fixes.
///
/// Handlers that take an `axum::extract::ConnectInfo<SocketAddr>` extractor
/// rather than a whole `Request` — [`crate::auth::login`] is the only one —
/// call this directly. Reaching for `peer_addr.ip()` instead is what left the
/// login throttle outside the boundary: on a `[::]` listener the same IPv4
/// client spelled two ways occupied two separate brute-force budgets.
#[must_use]
pub const fn canonical_peer_ip(peer: std::net::SocketAddr) -> IpAddr {
    waf_common::net::canonicalize_client_ip(peer.ip())
}

/// Canonical client address of a management-API request.
///
/// Falls back to `0.0.0.0` when axum did not attach `ConnectInfo`, which only
/// happens for synthetically constructed requests — a real connection always
/// has a peer.
fn request_client_ip(req: &Request<Body>) -> IpAddr {
    req.extensions()
        .get::<axum::extract::connect_info::ConnectInfo<std::net::SocketAddr>>()
        .map_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), |ci| {
            canonical_peer_ip(ci.0)
        })
}

// ─── IP allowlist check ───────────────────────────────────────────────────────

/// Returns `true` when the IP is permitted by the allowlist.
/// An empty allowlist allows all addresses.
///
/// `ip` is expected to be canonical (see [`request_client_ip`]): an
/// IPv4-mapped IPv6 address will not match a plain-IPv4 entry, because neither
/// string equality nor `ipnet` containment crosses address families.
pub fn is_admin_ip_allowed(ip: &IpAddr, allowlist: &[String]) -> bool {
    if allowlist.is_empty() {
        return true;
    }
    let ip_str = ip.to_string();
    for entry in allowlist {
        if entry == &ip_str {
            return true;
        }
        // CIDR check via ipnet
        if let Ok(net) = entry.parse::<ipnet::IpNet>()
            && net.contains(ip)
        {
            return true;
        }
    }
    false
}

// ─── GET /api/audit-log ───────────────────────────────────────────────────────

pub async fn list_audit_log(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AuditLogQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let (entries, total) = state.db.list_audit_log(&query).await?;
    Ok(Json(json!({
        "entries": entries,
        "total": total,
    })))
}

// ─── Admin IP allowlist middleware ────────────────────────────────────────────

/// Rejects requests from IPs not in the admin allowlist.
/// If the allowlist is empty, all IPs are allowed.
pub async fn admin_ip_check_middleware(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    let ip = request_client_ip(&req);

    if !is_admin_ip_allowed(&ip, &state.security_config.admin_ip_allowlist) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "IP address not allowed" })),
        )
            .into_response();
    }

    next.run(req).await.into_response()
}

// ─── API rate limit middleware ────────────────────────────────────────────────

/// Enforces per-IP rate limiting on the management API.
/// Returns 429 Too Many Requests when the limit is exceeded.
pub async fn rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    if let Some(ref limiter) = state.rate_limiter {
        let ip = request_client_ip(&req);

        if !limiter.check(ip) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({ "error": "Rate limit exceeded" })),
            )
                .into_response();
        }
    }

    next.run(req).await.into_response()
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use axum::{Router, middleware, routing::get};
    #[allow(unused_imports)]
    use tower::ServiceExt;

    // ── IP allowlist tests ────────────────────────────────────────────────────

    /// Empty allowlist means every IP is permitted.
    #[test]
    fn admin_ip_empty_allowlist_allows_all() {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert!(is_admin_ip_allowed(&ip, &[]));
    }

    /// An IP that exactly matches an allowlist entry is permitted.
    #[test]
    fn admin_ip_allowed_ip_passes() {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let allowlist = vec!["1.2.3.4".to_owned()];
        assert!(is_admin_ip_allowed(&ip, &allowlist));
    }

    /// An IP that does not match any allowlist entry is rejected.
    #[test]
    fn admin_ip_blocked_ip_rejected() {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
        let allowlist = vec!["1.2.3.4".to_owned()];
        assert!(!is_admin_ip_allowed(&ip, &allowlist));
    }

    /// Loopback IPv4 passes when it is explicitly listed.
    #[test]
    fn admin_ip_loopback_in_allowlist() {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let allowlist = vec!["127.0.0.1".to_owned()];
        assert!(is_admin_ip_allowed(&ip, &allowlist));
    }

    /// Loopback IPv6 (`::1`) passes when it is explicitly listed.
    #[test]
    fn admin_ip_ipv6_loopback_check() {
        let ip: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let allowlist = vec!["::1".to_owned()];
        assert!(is_admin_ip_allowed(&ip, &allowlist));
    }

    /// CIDR entries are matched correctly: addresses inside the range pass,
    /// addresses outside are rejected.
    #[test]
    fn admin_ip_cidr_matching() {
        let allowlist = vec!["10.0.0.0/8".to_owned()];

        let inside: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        assert!(is_admin_ip_allowed(&inside, &allowlist));

        let outside: IpAddr = IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1));
        assert!(!is_admin_ip_allowed(&outside, &allowlist));
    }

    // ── Rate limiter tests ────────────────────────────────────────────────────

    /// Requests well under the burst limit are all allowed.
    #[tokio::test]
    async fn rate_limiter_allows_under_limit() {
        let limiter = ApiRateLimiter::new(100);
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        for _ in 0..5 {
            assert!(limiter.check(ip));
        }
    }

    /// After the burst budget is exhausted (rps=1, burst=10), the 11th request
    /// is rejected.
    #[tokio::test]
    async fn rate_limiter_blocks_over_limit() {
        let limiter = ApiRateLimiter::new(1); // burst = max(1*5, 10) = 10
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        // Exhaust the 10-token burst
        for _ in 0..10 {
            assert!(limiter.check(ip));
        }
        // 11th call must be rate-limited
        assert!(!limiter.check(ip));
    }

    /// Exhausting one IP's budget does not affect a different IP.
    #[tokio::test]
    async fn rate_limiter_different_ips_independent() {
        let limiter = ApiRateLimiter::new(1); // burst = 10
        let ip1: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Exhaust ip1
        for _ in 0..11 {
            let _ = limiter.check(ip1);
        }
        assert!(!limiter.check(ip1));

        // ip2 is unaffected
        assert!(limiter.check(ip2));
    }

    /// An IPv6 client rotating inside its own routed /64 spends one budget.
    /// Keyed on the full address this loop would never be limited at all.
    #[tokio::test]
    async fn rate_limiter_ipv6_shares_one_budget_per_64() {
        let limiter = ApiRateLimiter::new(1); // burst = 10
        for i in 0..10_u16 {
            let ip: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, i));
            assert!(limiter.check(ip), "address #{i} is inside the shared burst");
        }
        let fresh: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0xdead, 0xbeef, 0xcafe, 1));
        assert!(
            !limiter.check(fresh),
            "an 11th never-seen address in the same /64 must find the budget spent"
        );
    }

    /// Aggregation stops at /64: the neighbouring prefix keeps its own budget.
    #[tokio::test]
    async fn rate_limiter_distinct_ipv6_64s_independent() {
        let limiter = ApiRateLimiter::new(1); // burst = 10
        let inside: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 1));
        for _ in 0..11 {
            let _ = limiter.check(inside);
        }
        assert!(!limiter.check(inside));

        for (label, other) in [
            ("adjacent /64", Ipv6Addr::new(0x2001, 0xdb8, 1, 3, 0, 0, 0, 1)),
            ("different /48", Ipv6Addr::new(0x2001, 0xdb8, 2, 2, 0, 0, 0, 1)),
            ("different /32", Ipv6Addr::new(0x2001, 0xdb9, 1, 2, 0, 0, 0, 1)),
        ] {
            assert!(
                limiter.check(IpAddr::V6(other)),
                "{label} must not inherit the exhausted budget"
            );
        }
    }

    /// An IPv4 client reaching a `[::]` listener spends the same budget it would
    /// have spent on an `0.0.0.0` listener — it does not get a second one, and it
    /// is emphatically not merged with every other IPv4 client into `::/64`.
    #[tokio::test]
    async fn rate_limiter_mapped_ipv4_shares_the_plain_budget() {
        let limiter = ApiRateLimiter::new(1); // burst = 10
        let plain: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let mapped: IpAddr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xcb00, 0x7109));

        for _ in 0..10 {
            assert!(limiter.check(plain));
        }
        assert!(
            !limiter.check(mapped),
            "the mapped spelling must not be a fresh brute-force budget"
        );

        // A different IPv4 client, also arriving mapped, is still its own client.
        let other_mapped: IpAddr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xcb00, 0x710a));
        assert!(
            limiter.check(other_mapped),
            "mapped IPv4 addresses must not collapse into a single ::/64 bucket"
        );
    }

    /// rps=0 means unlimited — every call returns true regardless of volume.
    #[tokio::test]
    async fn rate_limiter_zero_rps_allows_all() {
        let limiter = ApiRateLimiter::new(0);
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
        for _ in 0..100 {
            assert!(limiter.check(ip));
        }
    }

    // ── Security headers tests ────────────────────────────────────────────────

    /// `X-Content-Type-Options` and `X-Frame-Options` headers must be present.
    #[tokio::test]
    async fn security_headers_present() {
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(middleware::from_fn(security_headers_middleware));

        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let resp: axum::response::Response = app.oneshot(req).await.unwrap();

        assert!(
            resp.headers().contains_key("x-content-type-options"),
            "X-Content-Type-Options header missing"
        );
        assert!(
            resp.headers().contains_key("x-frame-options"),
            "X-Frame-Options header missing"
        );
    }

    /// `Content-Security-Policy` header must be present.
    #[tokio::test]
    async fn security_headers_csp_present() {
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(middleware::from_fn(security_headers_middleware));

        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let resp: axum::response::Response = app.oneshot(req).await.unwrap();

        assert!(
            resp.headers().contains_key("content-security-policy"),
            "Content-Security-Policy header missing"
        );
    }

    /// All security header values must match their expected strings exactly.
    #[tokio::test]
    async fn security_headers_values_correct() {
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(middleware::from_fn(security_headers_middleware));

        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp: axum::response::Response = app.oneshot(req).await.unwrap();
        let headers = resp.headers();

        assert_eq!(headers.get("x-frame-options").unwrap().to_str().unwrap(), "DENY");
        assert_eq!(
            headers.get("x-content-type-options").unwrap().to_str().unwrap(),
            "nosniff"
        );
        assert_eq!(
            headers.get("x-xss-protection").unwrap().to_str().unwrap(),
            "1; mode=block"
        );
        assert_eq!(
            headers.get("strict-transport-security").unwrap().to_str().unwrap(),
            "max-age=31536000; includeSubDomains"
        );
        assert_eq!(
            headers.get("referrer-policy").unwrap().to_str().unwrap(),
            "strict-origin-when-cross-origin"
        );
    }

    /// CSP header value must start with `default-src 'self'` and contain both
    /// `script-src` and `style-src` directives.
    #[tokio::test]
    async fn security_headers_csp_value() {
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(middleware::from_fn(security_headers_middleware));

        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp: axum::response::Response = app.oneshot(req).await.unwrap();

        let csp = resp.headers().get("content-security-policy").unwrap().to_str().unwrap();

        assert!(
            csp.starts_with("default-src 'self'"),
            "CSP must start with \"default-src 'self'\", got: {csp}"
        );
        assert!(csp.contains("script-src"), "CSP missing script-src directive");
        assert!(csp.contains("style-src"), "CSP missing style-src directive");
    }

    /// After consuming some tokens, sleeping allows the bucket to refill.
    #[tokio::test]
    async fn rate_limiter_token_refill() {
        let limiter = ApiRateLimiter::new(100); // rps=100, burst=500
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 10, 1));

        // Consume 200 tokens (well within burst of 500)
        for _ in 0..200 {
            assert!(limiter.check(ip));
        }

        // Sleep 100 ms — should refill ~10 tokens (100 rps * 0.1 s)
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // At least one more token should now be available
        assert!(limiter.check(ip), "Expected tokens to refill after 100 ms sleep");
    }

    /// Exhausting all burst tokens causes the next call to fail; after sleeping
    /// long enough for at least one token to refill, calls succeed again.
    #[tokio::test]
    async fn rate_limiter_burst_exhaustion_then_recovery() {
        // rps=2, burst = max(2*5, 10) = 10
        let limiter = ApiRateLimiter::new(2);
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 10, 2));

        // Exhaust burst
        for _ in 0..10 {
            assert!(limiter.check(ip));
        }
        assert!(!limiter.check(ip), "Burst should be exhausted");

        // Sleep 600 ms — rps=2 means 1 token every 500 ms, so ~1 token refills
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;

        assert!(limiter.check(ip), "Expected at least one token after recovery sleep");
    }

    /// Concurrent `check()` calls from 10 tasks on the same IP must not panic
    /// and the total number of allowed calls must not exceed the burst limit.
    #[tokio::test]
    async fn rate_limiter_concurrent_check() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // rps=2, burst=10
        let limiter = ApiRateLimiter::new(2);
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 10, 3));
        let allowed = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::with_capacity(10);
        for _ in 0..10 {
            let lim = Arc::clone(&limiter);
            let counter = Arc::clone(&allowed);
            handles.push(tokio::spawn(async move {
                if lim.check(ip) {
                    counter.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        let total_allowed = allowed.load(Ordering::Relaxed);
        // Must not exceed burst (10) and must not panic
        assert!(
            total_allowed <= 10,
            "Concurrent check allowed {total_allowed} requests, exceeding burst of 10"
        );
    }

    /// Multiple exact entries and one CIDR entry: verify each combination.
    #[test]
    fn admin_ip_multiple_entries() {
        let allowlist = vec!["1.2.3.4".to_owned(), "5.6.7.8".to_owned(), "10.0.0.0/8".to_owned()];

        // Exact match first entry
        assert!(is_admin_ip_allowed(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), &allowlist));
        // Exact match second entry
        assert!(is_admin_ip_allowed(&IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)), &allowlist));
        // Inside CIDR range
        assert!(is_admin_ip_allowed(
            &IpAddr::V4(Ipv4Addr::new(10, 99, 0, 1)),
            &allowlist
        ));
        // Outside all entries
        assert!(!is_admin_ip_allowed(
            &IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1)),
            &allowlist
        ));
        // Partial match is not enough (e.g., 1.2.3.5 ≠ 1.2.3.4 and not in CIDR)
        assert!(!is_admin_ip_allowed(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 5)), &allowlist));
    }

    /// An IPv4 client reaching a `[::]` listener must be allowlisted by the
    /// plain-IPv4 entry an operator wrote.
    ///
    /// # Why this test used to assert the opposite
    ///
    /// Its previous form was named the same, asserted
    /// `!is_admin_ip_allowed(::ffff:192.168.1.1, ["192.168.1.1"])`, and said in
    /// its doc comment that it "documents the actual behavior". That was true
    /// of [`is_admin_ip_allowed`] read in isolation — neither string equality
    /// nor `ipnet` containment crosses address families — and, taken alone, the
    /// resulting lockout is merely annoying: the operator adds the mapped
    /// spelling and moves on.
    ///
    /// What made it the wrong thing to freeze into a test is that the *same*
    /// unfolded address flows into the IP blacklist, the threat-intel feeds and
    /// the `CrowdSec` decision cache, where the identical non-match fails **open**
    /// instead of closed: a banned IPv4 attacker is admitted the moment a
    /// listener is switched to `[::]`. One mechanism, two directions, and only
    /// the harmless direction had ever been examined.
    ///
    /// So the fold now happens at ingress ([`request_client_ip`] here,
    /// `gateway::proxy::WafProxy::extract_client_ip` and
    /// `gateway::http3` on the data plane) and this test asserts the
    /// end-to-end property that matters: the address this function actually
    /// receives is canonical, and it matches.
    #[test]
    fn admin_ip_ipv4_mapped_ipv6() {
        let allowlist = vec!["192.168.1.1".to_owned()];

        // Plain IPv4 address — must match
        let ipv4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(
            is_admin_ip_allowed(&ipv4, &allowlist),
            "Plain IPv4 192.168.1.1 should match"
        );

        // What a `[::]` listener hands up for that same IPv4 client. After
        // canonicalization it is indistinguishable from the line above.
        let ipv4_mapped: IpAddr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0101));
        let canonical = waf_common::net::canonicalize_client_ip(ipv4_mapped);
        assert_eq!(canonical, ipv4, "the mapped form must fold to plain IPv4");
        assert!(
            is_admin_ip_allowed(&canonical, &allowlist),
            "an IPv4 client on a [::] listener must match its plain-IPv4 allowlist entry"
        );

        // The un-normalized form still does not match, and that is deliberate:
        // this function is not the fold point. If a mapped address ever reaches
        // it, some producer skipped the boundary and the invariant is broken —
        // better a loud lockout here than a silent blocklist bypass elsewhere.
        assert!(
            !is_admin_ip_allowed(&ipv4_mapped, &allowlist),
            "is_admin_ip_allowed must not fold; normalization belongs at ingress"
        );
    }

    /// A genuine IPv6 client is unaffected by the fold: it still needs an IPv6
    /// allowlist entry, and a plain-IPv4 entry still does not admit it.
    #[test]
    fn admin_ip_genuine_ipv6_unaffected() {
        let v6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(waf_common::net::canonicalize_client_ip(v6), v6);
        assert!(!is_admin_ip_allowed(&v6, &["192.168.1.1".to_owned()]));
        assert!(is_admin_ip_allowed(&v6, &["2001:db8::1".to_owned()]));
        assert!(is_admin_ip_allowed(&v6, &["2001:db8::/32".to_owned()]));

        let loopback6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(waf_common::net::canonicalize_client_ip(loopback6), loopback6);
        assert!(is_admin_ip_allowed(&loopback6, &["::1".to_owned()]));
        assert!(!is_admin_ip_allowed(&loopback6, &["127.0.0.1".to_owned()]));
    }
}
