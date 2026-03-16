//! Security-hardening middleware and helpers.
//!
//! - Security response headers (X-Frame-Options, CSP, HSTS, X-Content-Type-Options)
//! - Request body size enforcement
//! - IP-based admin access control
//! - Simple in-process per-IP rate limiting

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::IntoResponse,
    Json,
};
use serde_json::json;

// ─── Security headers middleware ──────────────────────────────────────────────

/// Adds security headers to every management API response.
pub async fn security_headers_middleware(
    req: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    headers.insert(
        "X-Frame-Options",
        "DENY".parse().unwrap(),
    );
    headers.insert(
        "X-Content-Type-Options",
        "nosniff".parse().unwrap(),
    );
    headers.insert(
        "X-XSS-Protection",
        "1; mode=block".parse().unwrap(),
    );
    headers.insert(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains".parse().unwrap(),
    );
    headers.insert(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'"
            .parse()
            .unwrap(),
    );
    headers.insert(
        "Referrer-Policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );

    response
}

// ─── Rate limiter ──────────────────────────────────────────────────────────────

/// Token-bucket entry per IP
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

/// Simple in-process per-IP rate limiter (token bucket algorithm).
pub struct ApiRateLimiter {
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
    rps: f64,
    burst: f64,
}

impl ApiRateLimiter {
    pub fn new(rps: u32) -> Arc<Self> {
        Arc::new(Self {
            buckets: Mutex::new(HashMap::new()),
            rps: rps as f64,
            burst: (rps * 5).max(10) as f64,
        })
    }

    /// Returns `true` if the request is allowed, `false` if rate-limited.
    pub fn check(&self, ip: IpAddr) -> bool {
        if self.rps == 0.0 {
            return true;
        }
        let now = Instant::now();
        let mut map = self.buckets.lock().unwrap();
        let bucket = map.entry(ip).or_insert(Bucket {
            tokens: self.burst,
            last_refill: now,
        });

        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rps).min(self.burst);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// ─── IP allowlist check ───────────────────────────────────────────────────────

/// Returns `true` when the IP is permitted by the allowlist.
/// An empty allowlist allows all addresses.
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
        if let Ok(net) = entry.parse::<ipnet::IpNet>() {
            if net.contains(ip) {
                return true;
            }
        }
    }
    false
}

// ─── GET /api/audit-log ───────────────────────────────────────────────────────

use crate::state::AppState;
use axum::{extract::State, extract::Query};
use waf_storage::models::AuditLogQuery;

pub async fn list_audit_log(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AuditLogQuery>,
) -> impl IntoResponse {
    match state.db.list_audit_log(&query).await {
        Ok((entries, total)) => (
            StatusCode::OK,
            Json(json!({
                "entries": entries,
                "total": total,
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}
