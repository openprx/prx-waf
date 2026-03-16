pub mod anti_hotlink;
pub mod bot;
pub mod cc;
pub mod dir_traversal;
pub mod owasp;
pub mod rce;
pub mod scanner;
pub mod sensitive;
pub mod sql_injection;
pub mod xss;

pub use anti_hotlink::AntiHotlinkCheck;
pub use bot::BotCheck;
pub use cc::CcCheck;
pub use dir_traversal::DirTraversalCheck;
pub use owasp::OWASPCheck;
pub use rce::RceCheck;
pub use scanner::ScannerCheck;
pub use sensitive::SensitiveCheck;
pub use sql_injection::SqlInjectionCheck;
pub use xss::XssCheck;

use waf_common::{DetectionResult, RequestCtx};

/// Trait implemented by every WAF checker module.
///
/// Each checker is stateless (detection patterns) or uses interior mutability
/// (CC rate limiter). The pipeline calls `check()` in sequence and
/// short-circuits on the first `Some(result)`.
pub trait Check: Send + Sync {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult>;
}

// ─── Shared utilities ─────────────────────────────────────────────────────────

/// Decode a percent-encoded string (URL decoding, ASCII only).
pub(crate) fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Collect all strings to inspect from the request context.
///
/// Returns a list of `(location, value)` pairs so error messages can
/// indicate where the pattern was found.
pub(crate) fn request_targets(ctx: &RequestCtx) -> Vec<(&'static str, String)> {
    let mut targets: Vec<(&'static str, String)> = Vec::new();

    // Raw and decoded path
    targets.push(("path", ctx.path.clone()));
    targets.push(("path(decoded)", url_decode(&ctx.path)));

    // Raw and decoded query string
    if !ctx.query.is_empty() {
        targets.push(("query", ctx.query.clone()));
        targets.push(("query(decoded)", url_decode(&ctx.query)));
    }

    // Cookie header
    if let Some(cookie) = ctx.headers.get("cookie") {
        targets.push(("cookie", cookie.clone()));
        targets.push(("cookie(decoded)", url_decode(cookie)));
    }

    // Request body preview (best-effort UTF-8)
    if !ctx.body_preview.is_empty() {
        let body_str = String::from_utf8_lossy(&ctx.body_preview).into_owned();
        targets.push(("body", body_str.clone()));
        targets.push(("body(decoded)", url_decode(&body_str)));
    }

    targets
}
