pub mod anti_hotlink;
pub mod bot;
pub mod cc;
pub mod content_security;
pub mod dir_traversal;
pub mod geo;
pub mod owasp;
pub mod rce;
pub mod scanner;
pub mod sensitive;
pub mod sql_injection;
pub mod xss;

pub use anti_hotlink::AntiHotlinkCheck;
pub use bot::BotCheck;
pub use cc::CcCheck;
pub use content_security::{
    AttackKind, ContentInspectionState, ContentSecuritySubsystem, ContentVerdict, EnforcementMode, InspectionScope,
    RuntimeContentSecurityConfig, SemanticAction, SemanticVerdict,
};
pub use dir_traversal::DirTraversalCheck;
pub use geo::{GeoCheck, GeoRule, GeoRuleMode};
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
#[allow(clippy::indexing_slicing)] // bounds checked by loop guard: i < len, i+2 < len
pub(crate) fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = char::from(bytes[i + 1]).to_digit(16);
            let lo = char::from(bytes[i + 2]).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                #[allow(clippy::cast_possible_truncation)]
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

/// Iteratively URL-decode until the result stabilises or the iteration cap is reached.
///
/// This catches double/triple/…-encoded evasion attempts such as:
///   `%253Cscript%253E` → (pass 1) `%3Cscript%3E` → (pass 2) `<script>`
///
/// `MAX_DECODE_PASSES` bounds how many times the value is re-decoded. This is
/// a deliberate trade-off: too low and a deeply re-encoded payload slips
/// through with a residual encoded layer un-inspected; too high (or
/// unbounded) lets a crafted input force excessive per-request CPU work
/// (decode-loop `DoS`). 5 passes covers realistic multi-encoding depths while
/// keeping worst-case per-request work small and constant.
pub(crate) const MAX_DECODE_PASSES: usize = 5;

pub(crate) fn url_decode_recursive(input: &str) -> String {
    let mut current = url_decode(input);
    for _ in 1..MAX_DECODE_PASSES {
        let next = url_decode(&current);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

/// Curated request headers that are commonly abused for injection payloads
/// (`H-5`).  Only these headers are scanned — not every arbitrary header — to
/// bound work and false positives.
const SCANNED_HEADERS: &[&str] = &[
    "user-agent",
    "referer",
    "x-forwarded-for",
    "x-real-ip",
    "x-original-url",
    "x-forwarded-host",
    "forwarded",
];

/// Static `<header>(decoded)` location label for a scanned header.
fn header_decoded_label(name: &str) -> &'static str {
    match name {
        "user-agent" => "user-agent(decoded)",
        "referer" => "referer(decoded)",
        "x-forwarded-for" => "x-forwarded-for(decoded)",
        "x-real-ip" => "x-real-ip(decoded)",
        "x-original-url" => "x-original-url(decoded)",
        "x-forwarded-host" => "x-forwarded-host(decoded)",
        "forwarded" => "forwarded(decoded)",
        _ => "header(decoded)",
    }
}

/// Collect all strings to inspect from the request context.
///
/// Returns a list of `(location, value)` pairs so error messages can
/// indicate where the pattern was found.
///
/// Path / query / cookie / body are included in three forms: raw,
/// single-decoded, and recursively-decoded (up to 3 passes) so that
/// double/triple-encoded evasion attempts are caught alongside the plain
/// variants.  A curated set of request headers ([`SCANNED_HEADERS`]) is
/// additionally scanned in raw + single-decoded form.
pub(crate) fn request_targets(ctx: &RequestCtx) -> Vec<(&'static str, String)> {
    let mut targets = Vec::new();

    // Raw, decoded, and recursively-decoded path
    targets.push(("path", ctx.path.clone()));
    let path_decoded = url_decode(&ctx.path);
    let path_recursive = url_decode_recursive(&ctx.path);
    if path_decoded != ctx.path {
        targets.push(("path(decoded)", path_decoded.clone()));
    }
    if path_recursive != path_decoded {
        targets.push(("path(decoded-recursive)", path_recursive));
    }

    // Raw, decoded, and recursively-decoded query string
    if !ctx.query.is_empty() {
        targets.push(("query", ctx.query.clone()));
        let query_decoded = url_decode(&ctx.query);
        let query_recursive = url_decode_recursive(&ctx.query);
        if query_decoded != ctx.query {
            targets.push(("query(decoded)", query_decoded.clone()));
        }
        if query_recursive != query_decoded {
            targets.push(("query(decoded-recursive)", query_recursive));
        }
    }

    // Cookie header
    if let Some(cookie) = ctx.headers.get("cookie") {
        targets.push(("cookie", cookie.clone()));
        let cookie_decoded = url_decode(cookie);
        let cookie_recursive = url_decode_recursive(cookie);
        if cookie_decoded != *cookie {
            targets.push(("cookie(decoded)", cookie_decoded.clone()));
        }
        if cookie_recursive != cookie_decoded {
            targets.push(("cookie(decoded-recursive)", cookie_recursive));
        }
    }

    // Request body preview (best-effort UTF-8)
    if !ctx.body_preview.is_empty() {
        let body_str = String::from_utf8_lossy(&ctx.body_preview).into_owned();
        targets.push(("body", body_str.clone()));
        let body_decoded = url_decode(&body_str);
        let body_recursive = url_decode_recursive(&body_str);
        if body_decoded != body_str {
            targets.push(("body(decoded)", body_decoded.clone()));
        }
        if body_recursive != body_decoded {
            targets.push(("body(decoded-recursive)", body_recursive));
        }
    }

    // Curated request headers (raw + single decode) — H-5.
    for name in SCANNED_HEADERS {
        let Some(value) = ctx.headers.get(*name) else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        targets.push((*name, value.clone()));
        let decoded = url_decode(value);
        if decoded != *value {
            targets.push((header_decoded_label(name), decoded));
        }
    }

    targets
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::sync::Arc;
    use waf_common::HostConfig;

    fn ctx_with_headers(headers: HashMap<String, String>) -> RequestCtx {
        RequestCtx {
            req_id: "t".to_string(),
            client_ip: "127.0.0.1".parse().expect("valid ip literal"),
            client_port: 0,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: "/".to_string(),
            query: String::new(),
            headers,
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config: Arc::new(HostConfig::default()),
            geo: None,
        }
    }

    #[test]
    fn request_targets_scans_curated_headers() {
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "sqlmap/1.0".to_string());
        headers.insert("x-forwarded-for".to_string(), "1.2.3.4".to_string());
        // A header not on the allowlist must be ignored.
        headers.insert("x-custom".to_string(), "ignored".to_string());
        let ctx = ctx_with_headers(headers);
        let targets = request_targets(&ctx);
        assert!(targets.iter().any(|(loc, v)| *loc == "user-agent" && v == "sqlmap/1.0"));
        assert!(
            targets
                .iter()
                .any(|(loc, v)| *loc == "x-forwarded-for" && v == "1.2.3.4")
        );
        assert!(!targets.iter().any(|(_, v)| v == "ignored"));
    }

    #[test]
    fn request_targets_decodes_curated_headers() {
        let mut headers = HashMap::new();
        headers.insert("referer".to_string(), "%3Cscript%3E".to_string());
        let ctx = ctx_with_headers(headers);
        let targets = request_targets(&ctx);
        assert!(
            targets
                .iter()
                .any(|(loc, v)| *loc == "referer(decoded)" && v == "<script>")
        );
    }

    #[test]
    fn test_url_decode_recursive_double_encoded() {
        // %253C = %25 → %, 3C → <  (two passes needed)
        assert_eq!(url_decode_recursive("%253Cscript%253E"), "<script>");
    }

    #[test]
    fn test_url_decode_recursive_triple_encoded() {
        // %25253C → %253C → %3C → <  (three passes needed)
        assert_eq!(url_decode_recursive("%25253Cscript%25253E"), "<script>");
    }

    #[test]
    fn test_url_decode_recursive_normal_input() {
        // Plain text must pass through unchanged.
        assert_eq!(url_decode_recursive("hello world"), "hello world");
    }

    #[test]
    fn test_url_decode_recursive_single_encoded() {
        // Standard %3C → <  (one pass)
        assert_eq!(url_decode_recursive("%3Cscript%3E"), "<script>");
    }

    #[test]
    fn test_url_decode_recursive_quadruple_encoded() {
        // Depth-4 encoding is now within MAX_DECODE_PASSES=5, so it fully resolves.
        // %2525253C: pass1 → %25253C, pass2 → %253C, pass3 → %3C, pass4 → <
        assert_eq!(url_decode_recursive("%2525253C"), "<");
    }

    #[test]
    fn test_url_decode_recursive_max_passes_exceeded() {
        // Depth-6 encoding exceeds MAX_DECODE_PASSES=5; the loop stops after 5
        // passes, leaving one encoded layer (%3C) un-decoded rather than
        // resolving all the way to `<`.
        assert_eq!(url_decode_recursive("%25252525253C"), "%3C");
    }
}
