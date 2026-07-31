//! Sensitive word / data-leak detection using Aho-Corasick multi-pattern search.
//!
//! Scans the request path, query string, **every request header** and the body
//! preview for configured patterns. Patterns are loaded from `PostgreSQL` per
//! host and cached in memory.
//!
//! Built-in patterns detect private-key material and AWS credential markers;
//! per-host word lists are whatever the operator configured through
//! `/api/sensitive-patterns`.
//!
//! # Two tiers, because two pattern sets have two false-positive profiles
//!
//! Headers used to be exempt entirely, which meant an API key, a token or a
//! private key travelling in `X-Api-Key` or any custom header was invisible.
//! Scanning them all with *both* pattern sets is not the fix either: see
//! [`CREDENTIAL_HEADERS`].

use std::fmt;
use std::sync::Arc;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use dashmap::DashMap;
use tracing;

use waf_common::{DetectionResult, Phase, RequestCtx};

use super::Check;

// ── Built-in sensitive data patterns ─────────────────────────────────────────

/// Default patterns for data-leak detection (applied globally, all hosts).
static BUILTIN_PATTERNS: &[&str] = &[
    // Private key markers
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    // AWS credentials
    "AKIAIOSFODNN7EXAMPLE",
    "aws_secret_access_key",
    "aws_access_key_id",
];

// ── Header scanning policy ───────────────────────────────────────────────────

/// Headers whose value **is** a credential by construction, scanned with the
/// built-in patterns only — never with the per-host word list.
///
/// The split is not squeamishness about looking at `Authorization`; it is the
/// only way to scan it at all. The two pattern sets have opposite
/// false-positive profiles:
///
/// * [`BUILTIN_PATTERNS`] are seven long literals — four PEM banners and three
///   AWS key names. A `Bearer` JWT, a session cookie or an HMAC signature does
///   not contain `-----BEGIN RSA PRIVATE KEY-----`, so running these over
///   `Authorization` costs one automaton pass and finds a real leak when there
///   is one: a private key pasted into a header is a private key wherever it
///   travelled.
/// * Per-host patterns are free-form operator words, and the words an operator
///   actually enters into a "sensitive words" box are `token`, `secret`, `key`,
///   `session`, `password`. Every one of those matches a normal
///   `Authorization: Bearer …` or `Cookie: sessionid=…` on **every request**.
///   That is not a tuning problem an operator can be expected to discover from
///   a flood of blocks on their own login flow.
///
/// So the tier is a property of the field, not of the operator's diligence.
/// Everything not listed here gets both sets: a custom `X-Internal-Id` header
/// is exactly where an operator's word list belongs.
///
/// **Residual, stated rather than hidden:** the client picks its own header
/// names, so a client that wants its value exempt from the per-host word list
/// can send it as `X-Api-Key`. The built-in tier still applies, and a client
/// that controls the request could equally have put the value in a body field
/// the word list never covered — this narrows no boundary that was closed.
const CREDENTIAL_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "api-key",
    "apikey",
    "x-api-key",
    "x-apikey",
    "x-auth-token",
    "x-access-token",
    "x-session-token",
    "x-csrf-token",
    "x-xsrf-token",
    "x-amz-security-token",
    "x-goog-api-key",
];

/// Whether `name` (already lower-cased by the header fold) is credential-tier.
fn is_credential_header(name: &str) -> bool {
    CREDENTIAL_HEADERS.contains(&name)
}

/// Most headers inspected in one request.
///
/// A browser sends 12–20; an API client with tracing headers reaches ~30. 64 is
/// well clear of both and bounds the per-request work at a constant an attacker
/// cannot grow by adding header lines.
const MAX_HEADERS_SCANNED: usize = 64;

/// Largest single header value inspected, in bytes.
///
/// Half the gateway's fold ceiling (`gateway::context::MAX_FOLDED_HEADER_BYTES`,
/// 32 KiB) and double the 8 KiB per-header limit every origin enforces, so a
/// realistic value — including a fat cookie jar — is inspected end to end while
/// one absurd header cannot eat the whole request budget below.
const MAX_HEADER_VALUE_BYTES: usize = 16 * 1024;

/// Total header bytes inspected per request.
///
/// The bound that actually matters: with it, header scanning costs at most one
/// Aho-Corasick pass over 64 KiB regardless of how many header lines arrive.
/// Real requests carry 2–4 KiB of headers in total, so this never binds on
/// traffic — it binds on abuse.
const MAX_HEADER_SCAN_BYTES: usize = 64 * 1024;

/// Longest header name reproduced in a detection detail.
const MAX_HEADER_LABEL_LEN: usize = 64;

// Over-budget values are **skipped, not truncated** — the same rule
// [`super::Lane1BodyBudget`] applies to an over-budget body, so an operator
// learns one rule rather than two, and a payload cannot be hidden behind
// `MAX_HEADER_VALUE_BYTES` of padding at the front of the same header.

/// Build the `header:<name>` location label for a detection detail.
///
/// The name arrives off the wire. `http::HeaderName` already rejects anything
/// outside the RFC 9110 token set, but this string lands in a Postgres row, an
/// admin-UI cell and — through
/// [`crate::community::CommunityReporter`] — an off-box HTTP body, so it is
/// re-checked here rather than trusted transitively: anything outside
/// `[a-z0-9-_]` becomes `_`, and the name is capped at
/// [`MAX_HEADER_LABEL_LEN`].
fn header_label(name: &str) -> String {
    let mut out = String::with_capacity("header:".len() + name.len().min(MAX_HEADER_LABEL_LEN));
    out.push_str("header:");
    for c in name.chars().take(MAX_HEADER_LABEL_LEN) {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
            out.push(c.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    out
}

// ── What fired, in a form that is safe to write down ─────────────────────────

/// Which pattern set may be applied to a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PatternTier {
    /// [`BUILTIN_PATTERNS`] only — see [`CREDENTIAL_HEADERS`].
    BuiltinOnly,
    /// Built-ins plus the host's configured word list.
    Full,
}

/// The identity of a matched pattern, rendered for a detection detail.
///
/// A detail string is not a debug print: it is persisted to `security_events`,
/// shown in the admin UI and pushed to the shared community feed by
/// [`crate::community::CommunityReporter`], which puts it on the wire to a
/// third party.
///
/// * [`Self::Builtin`] carries the literal, because a built-in pattern is a
///   compile-time constant in this file — publishing `aws_secret_access_key`
///   discloses nothing that `git log` does not.
/// * [`Self::Custom`] carries a **position, never the text**. A per-host
///   pattern is the operator's own needle, and for this feature the needle
///   routinely *is* the secret: an operator blocking their own leaked API key
///   pastes the key in as the pattern. Emitting it would have re-leaked, to the
///   audit log and off the box, the exact string the check exists to stop. The
///   index is the pattern's 1-based position in the host's list, which
///   `GET /api/sensitive-patterns?host_code=…` returns in the same
///   (`created_at`) order, so an operator can still resolve which rule fired.
///
/// Neither variant ever carries matched request bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PatternHit {
    Builtin(&'static str),
    Custom(usize),
}

impl fmt::Display for PatternHit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Builtin(p) => write!(f, "'{p}'"),
            Self::Custom(idx) => write!(f, "custom #{idx}"),
        }
    }
}

// ── Per-host pattern set ──────────────────────────────────────────────────────

struct HostPatterns {
    /// Compiled Aho-Corasick automaton (request patterns)
    request_ac: AhoCorasick,
    /// How many patterns the automaton was built from. The pattern *text* is
    /// deliberately not retained: nothing may render it (see [`PatternHit`]),
    /// and a copy that exists is a copy that can be logged by accident.
    pattern_count: usize,
}

impl HostPatterns {
    fn build(patterns: &[String]) -> Option<Self> {
        if patterns.is_empty() {
            return None;
        }
        let ac = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostFirst)
            .ascii_case_insensitive(true)
            .build(patterns)
            .ok()?;
        Some(Self {
            request_ac: ac,
            pattern_count: patterns.len(),
        })
    }

    /// 1-based index of the first matching pattern, or `None`.
    fn find_in(&self, text: &str) -> Option<usize> {
        let m = self.request_ac.find(text)?;
        let idx = m.pattern().as_usize();
        (idx < self.pattern_count).then(|| idx.saturating_add(1))
    }
}

// ── Built-in automaton ────────────────────────────────────────────────────────

fn builtin_ac() -> Option<Arc<AhoCorasick>> {
    match AhoCorasickBuilder::new()
        .match_kind(MatchKind::LeftmostFirst)
        .ascii_case_insensitive(true)
        .build(BUILTIN_PATTERNS)
    {
        Ok(ac) => Some(Arc::new(ac)),
        Err(e) => {
            tracing::error!("BUG: builtin sensitive patterns failed to compile: {e}");
            None
        }
    }
}

// ── SensitiveCheck ───────────────────────────────────────────────────────────

/// WAF checker for sensitive word / data-leak detection.
pub struct SensitiveCheck {
    /// Global built-in patterns (None if compile failed — WAF degrades gracefully)
    builtin: Option<Arc<AhoCorasick>>,
    /// Per-host patterns: `host_code` → `HostPatterns`
    per_host: Arc<DashMap<String, HostPatterns>>,
}

impl SensitiveCheck {
    pub fn new() -> Self {
        Self {
            builtin: builtin_ac(),
            per_host: Arc::new(DashMap::new()),
        }
    }

    /// Reload patterns for a host (called from engine reload).
    pub fn load_host(&self, host_code: &str, patterns: &[String]) {
        if let Some(hp) = HostPatterns::build(patterns) {
            self.per_host.insert(host_code.to_string(), hp);
        } else {
            self.per_host.remove(host_code);
        }
    }

    /// Remove all patterns for a host.
    pub fn clear_host(&self, host_code: &str) {
        self.per_host.remove(host_code);
    }

    /// Scan one field with the pattern sets `tier` admits.
    fn scan(&self, text: &str, host_code: &str, tier: PatternTier) -> Option<PatternHit> {
        // Check built-in patterns (skipped gracefully if automaton failed to compile)
        if let Some(ac) = &self.builtin
            && let Some(m) = ac.find(text)
            && let Some(pat) = BUILTIN_PATTERNS.get(m.pattern().as_usize())
        {
            return Some(PatternHit::Builtin(pat));
        }

        // Check per-host patterns — not on a credential-tier field.
        if tier == PatternTier::Full
            && let Some(hp) = self.per_host.get(host_code)
            && let Some(idx) = hp.find_in(text)
        {
            return Some(PatternHit::Custom(idx));
        }

        None
    }

    /// Scan every request header, cheapest surface first.
    ///
    /// Header names are inspected in **sorted order**, not `HashMap` order. That
    /// is not tidiness: the byte and count budgets below make the scan stop
    /// somewhere, and with `HashMap` iteration order "somewhere" would differ
    /// between two runs of the same request, so which pattern a multi-hit
    /// request reports — and, at the cap, whether it reports one at all — would
    /// be non-deterministic. A security control that answers differently on
    /// identical input cannot be regression-tested, and `tests/lane2/baseline.json`
    /// is a zero-tolerance ratchet.
    fn scan_headers(&self, ctx: &RequestCtx, host_code: &str) -> Option<DetectionResult> {
        if ctx.headers.is_empty() {
            return None;
        }
        let mut names: Vec<&str> = ctx.headers.keys().map(String::as_str).collect();
        names.sort_unstable();

        let mut remaining = MAX_HEADER_SCAN_BYTES;
        for name in names.into_iter().take(MAX_HEADERS_SCANNED) {
            let Some(value) = ctx.headers.get(name) else {
                continue;
            };
            if value.is_empty() || value.len() > MAX_HEADER_VALUE_BYTES {
                continue;
            }
            let Some(left) = remaining.checked_sub(value.len()) else {
                break;
            };
            remaining = left;

            let tier = if is_credential_header(name) {
                PatternTier::BuiltinOnly
            } else {
                PatternTier::Full
            };
            if let Some(hit) = self.scan(value, host_code, tier) {
                return Some(Self::result(&hit, &header_label(name)));
            }
        }
        None
    }

    /// Build the detection result. The single place a detail string is
    /// constructed, so the "no matched bytes, ever" rule has one site to hold.
    fn result(hit: &PatternHit, location: &str) -> DetectionResult {
        DetectionResult {
            rule_id: None,
            rule_name: "Sensitive Data Detection".to_string(),
            phase: Phase::Sensitive,
            detail: format!("Sensitive pattern {hit} found in {location}"),
        }
    }
}

impl Default for SensitiveCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for SensitiveCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        if !ctx.host_config.defense_config.sensitive {
            return None;
        }

        let host_code = &ctx.host_config.code;
        let targets = [("path", ctx.path.as_str()), ("query", ctx.query.as_str())];

        for (location, text) in &targets {
            if let Some(hit) = self.scan(text, host_code, PatternTier::Full) {
                return Some(Self::result(&hit, location));
            }
        }

        // Headers before the body: bounded at 64 KiB total by construction,
        // where a body preview is up to 68 KiB per window on its own.
        if let Some(result) = self.scan_headers(ctx, host_code) {
            return Some(result);
        }

        // Scan body preview
        if !ctx.body_preview.is_empty() {
            let body = String::from_utf8_lossy(&ctx.body_preview);
            if let Some(hit) = self.scan(&body, host_code, PatternTier::Full) {
                return Some(Self::result(&hit, "body"));
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::sync::Arc;
    use waf_common::{DefenseConfig, HostConfig};

    /// A private key, spelled out once so no test hard-codes a different banner.
    const PEM: &str = "-----BEGIN RSA PRIVATE KEY-----";

    fn make_ctx_with_headers(path: &str, body: &[u8], headers: &[(&str, &str)]) -> RequestCtx {
        let mut ctx = make_ctx(path, body);
        ctx.headers = headers
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        ctx
    }

    fn make_ctx(path: &str, body: &[u8]) -> RequestCtx {
        let dc = DefenseConfig {
            sensitive: true,
            ..DefenseConfig::default()
        };
        let host_config = Arc::new(HostConfig {
            code: "test".into(),
            host: "example.com".into(),
            defense_config: dc,
            ..HostConfig::default()
        });
        RequestCtx {
            req_id: "test".into(),
            client_ip: "1.2.3.4".parse().unwrap(),
            client_port: 0,
            method: "GET".into(),
            host: "example.com".into(),
            port: 80,
            path: path.into(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::copy_from_slice(body),
            content_length: body.len() as u64,
            is_tls: false,
            host_config,
            geo: None,
        }
    }

    #[test]
    fn test_private_key_detection() {
        let checker = SensitiveCheck::new();
        let ctx = make_ctx("/upload", b"-----BEGIN RSA PRIVATE KEY-----\nMIIEo...");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn test_custom_word() {
        let checker = SensitiveCheck::new();
        checker.load_host("test", &["super_secret_token".to_string()]);
        let ctx = make_ctx("/api?token=super_secret_token", b"");
        let result = checker.check(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn test_no_match() {
        let checker = SensitiveCheck::new();
        let ctx = make_ctx("/public/page", b"Hello world");
        assert!(checker.check(&ctx).is_none());
    }

    // ── Header scanning ──────────────────────────────────────────────────────

    #[test]
    fn builtin_pattern_in_custom_header_is_detected() {
        let checker = SensitiveCheck::new();
        let ctx = make_ctx_with_headers("/", b"", &[("x-debug-dump", &format!("{PEM}MIIEo"))]);
        let detail = checker.check(&ctx).expect("header hit").detail;
        assert!(detail.contains("header:x-debug-dump"), "{detail}");
    }

    #[test]
    fn builtin_pattern_in_authorization_is_detected() {
        // Credential tier is not an exemption from the built-ins: a PEM key
        // pasted into `Authorization` is still a leaked key.
        let checker = SensitiveCheck::new();
        let ctx = make_ctx_with_headers("/", b"", &[("authorization", &format!("Bearer {PEM}"))]);
        let detail = checker.check(&ctx).expect("authorization hit").detail;
        assert!(detail.contains("header:authorization"), "{detail}");
    }

    #[test]
    fn ordinary_bearer_token_is_not_flagged() {
        let checker = SensitiveCheck::new();
        let ctx = make_ctx_with_headers(
            "/api/me",
            b"",
            &[
                (
                    "authorization",
                    "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abc",
                ),
                ("cookie", "sessionid=8f2a1c9b; csrftoken=deadbeef"),
                ("user-agent", "Mozilla/5.0"),
            ],
        );
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn custom_word_applies_to_ordinary_headers_but_not_credential_headers() {
        let checker = SensitiveCheck::new();
        // The word an operator actually types into a "sensitive words" box.
        checker.load_host("test", &["token".to_string()]);

        // Credential-tier: the word list is not applied, so a normal
        // `Authorization` / `Cookie` does not fire.
        let creds = make_ctx_with_headers(
            "/",
            b"",
            &[
                ("authorization", "Bearer token-abc"),
                ("cookie", "csrftoken=xyz"),
                ("x-api-key", "token-abc"),
            ],
        );
        assert!(checker.check(&creds).is_none());

        // Ordinary header: the word list is applied.
        let custom = make_ctx_with_headers("/", b"", &[("x-internal-note", "token-abc")]);
        assert!(checker.check(&custom).is_some());
    }

    #[test]
    fn header_over_the_value_cap_is_skipped_not_truncated() {
        let checker = SensitiveCheck::new();
        let mut value = "a".repeat(MAX_HEADER_VALUE_BYTES);
        value.push_str(PEM);
        let ctx = make_ctx_with_headers("/", b"", &[("x-blob", &value)]);
        assert!(checker.check(&ctx).is_none());

        // One byte under the cap and the same payload is found.
        let mut ok = "a".repeat(MAX_HEADER_VALUE_BYTES - PEM.len());
        ok.push_str(PEM);
        let ctx = make_ctx_with_headers("/", b"", &[("x-blob", &ok)]);
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn header_count_cap_bounds_the_scan() {
        let checker = SensitiveCheck::new();
        // Names sort before `zzz-payload`, so the cap is reached first and the
        // payload header is never inspected.
        let mut owned: Vec<(String, String)> = (0..MAX_HEADERS_SCANNED)
            .map(|i| (format!("x-pad-{i:04}"), "filler".to_string()))
            .collect();
        owned.push(("zzz-payload".to_string(), PEM.to_string()));
        let borrowed: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let ctx = make_ctx_with_headers("/", b"", &borrowed);
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn header_total_byte_budget_bounds_the_scan() {
        let checker = SensitiveCheck::new();
        // Four 16 KiB values exhaust the 64 KiB request budget before the
        // (later-sorting) payload header is reached.
        let filler = "a".repeat(MAX_HEADER_VALUE_BYTES);
        let mut owned: Vec<(String, String)> = (0..4).map(|i| (format!("x-pad-{i}"), filler.clone())).collect();
        owned.push(("zzz-payload".to_string(), PEM.to_string()));
        let borrowed: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let ctx = make_ctx_with_headers("/", b"", &borrowed);
        assert!(checker.check(&ctx).is_none());
        // The four fillers really do exhaust the request budget — if the two
        // constants drift apart this test would otherwise start passing for the
        // wrong reason.
        const { assert!(4 * MAX_HEADER_VALUE_BYTES >= MAX_HEADER_SCAN_BYTES) };
    }

    // ── The detail string must never carry what leaked ───────────────────────

    #[test]
    fn detail_never_contains_the_operator_pattern_or_the_matched_value() {
        let checker = SensitiveCheck::new();
        let secret = "AKIA-CUSTOMER-4419-LIVE";
        checker.load_host("test", &["decoy".to_string(), secret.to_string()]);

        for ctx in [
            make_ctx(&format!("/p/{secret}"), b""),
            make_ctx_with_headers("/", b"", &[("x-internal-note", secret)]),
            make_ctx("/", format!("payload={secret}").as_bytes()),
        ] {
            let detail = checker.check(&ctx).expect("custom hit").detail;
            assert!(!detail.contains(secret), "pattern text leaked into detail: {detail}");
            // The 1-based position is what an operator gets instead.
            assert!(detail.contains("custom #2"), "{detail}");
        }
    }

    #[test]
    fn detail_header_label_is_sanitised() {
        // Defence in depth: `HeaderName` would have rejected these bytes, but the
        // label is re-checked because it leaves the box.
        assert_eq!(header_label("X-Weird\nName: x"), "header:x-weird_name__x");
        assert_eq!(
            header_label(&"a".repeat(200)).len(),
            "header:".len() + MAX_HEADER_LABEL_LEN
        );
    }

    #[test]
    fn builtin_detail_still_names_the_literal() {
        // Built-in patterns are compile-time constants in this file; naming them
        // discloses nothing, and operators read them.
        let checker = SensitiveCheck::new();
        let ctx = make_ctx("/", PEM.as_bytes());
        let detail = checker.check(&ctx).expect("builtin hit").detail;
        assert_eq!(detail, format!("Sensitive pattern '{PEM}' found in body"));
    }

    #[test]
    fn header_scan_is_order_independent() {
        // Same headers, different insertion order → same verdict and same detail.
        let checker = SensitiveCheck::new();
        let a = make_ctx_with_headers("/", b"", &[("x-a", PEM), ("x-b", PEM), ("x-c", "clean")]);
        let b = make_ctx_with_headers("/", b"", &[("x-c", "clean"), ("x-b", PEM), ("x-a", PEM)]);
        assert_eq!(checker.check(&a).map(|r| r.detail), checker.check(&b).map(|r| r.detail));
    }
}
