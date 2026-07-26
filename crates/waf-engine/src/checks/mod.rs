pub mod anti_hotlink;
pub(crate) mod body_processors;
pub mod bot;
pub mod cc;
pub mod content_security;
pub mod dir_traversal;
pub mod geo;
pub(crate) mod multipart;
pub mod owasp;
pub mod rce;
pub mod scanner;
pub mod sensitive;
pub mod sql_injection;
pub mod xss;

pub use anti_hotlink::AntiHotlinkCheck;
pub use bot::{
    BUILTIN_BAD_BOTS, BUILTIN_GOOD_BOTS, BotAction, BotCheck, BotMatch, BotPatternError, BotPatternLoadReport,
    BuiltinBotRule, MAX_USER_PATTERN_LEN, MAX_USER_PATTERNS, UserBotPattern, user_rule_id, validate_user_pattern,
};
pub use cc::CcCheck;
pub use content_security::{
    AttackKind, ContentInspectionState, ContentSecuritySubsystem, ContentVerdict, EnforcementMode, InspectionScope,
    RuntimeContentSecurityConfig, SemanticAction, SemanticVerdict,
};
pub use dir_traversal::DirTraversalCheck;
// `Lane1BodyBudget` is defined in this module (see below) and re-exported by
// `waf_engine`'s prelude alongside the detectors it governs.
pub use geo::{GeoCheck, GeoRule, GeoRuleMode};
pub use owasp::{OWASPCheck, OverrideLoadReport, RuleDescriptor, RuleOverrideError, RuleOverrideSpec, RuleState};
pub use rce::RceCheck;
pub use scanner::ScannerCheck;
pub use sensitive::SensitiveCheck;
pub use sql_injection::SqlInjectionCheck;
pub use xss::XssCheck;

use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use waf_common::{DetectionResult, RequestCtx, ResponseCtx};

/// Trait implemented by every WAF checker module.
///
/// Each checker is stateless (detection patterns) or uses interior mutability
/// (CC rate limiter). The pipeline calls `check()` in sequence and
/// short-circuits on the first `Some(result)`.
pub trait Check: Send + Sync {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult>;
}

// ─── Response phase ───────────────────────────────────────────────────────────

/// Trait implemented by every **response-phase** WAF checker.
///
/// The counterpart of [`Check`] for `ModSecurity`'s `phase:3` / `phase:4`: the
/// implementor is shown the upstream status, the response headers and (in the
/// body phase) one bounded window of the response body, wrapped in a
/// [`ResponseCtx`] that also carries the request that provoked it.
///
/// # Why this is not just `Check`
///
/// [`Check::check`] takes `&RequestCtx`, which structurally cannot carry a
/// status code or a response body — a response-phase rule expressed through it
/// would have to smuggle its inputs through a request field, which is how a
/// detector ends up matching the wrong surface. A second trait keeps the two
/// phases' inputs honest and lets the gateway decide, by type, which pipeline a
/// checker belongs to.
///
/// # Sync on purpose
///
/// Pingora's `upstream_response_body_filter` is a **synchronous** callback, so
/// the response pipeline has no `.await` point available to it. Keeping this
/// trait sync makes that a compile-time fact rather than a runtime surprise;
/// anything that must do I/O has to hand the work off to a spawned task.
pub trait ResponseCheck: Send + Sync {
    /// Inspect one response context. `None` means "nothing found".
    fn check(&self, ctx: &ResponseCtx) -> Option<DetectionResult>;
}

/// Forward through a shared handle, so a checker the engine already owns behind
/// an [`Arc`] can be registered here without a second copy of its compiled rule
/// set.
///
/// [`OWASPCheck`] is the case that matters: the request pipeline holds it as
/// `Arc<OWASPCheck>` and the response pipeline needs the *same* instance —
/// re-loading the rules would double the memory and, worse, let the two phases
/// drift onto different rule files after a reload.
impl<T: ResponseCheck + ?Sized> ResponseCheck for std::sync::Arc<T> {
    fn check(&self, ctx: &ResponseCtx) -> Option<DetectionResult> {
        (**self).check(ctx)
    }
}

/// The registered response-phase checkers.
///
/// **Empty unless something registers.** [`Self::is_empty`] is what the gateway
/// tests before it does any response-phase work at all, so with no registered
/// checker the response path is byte-for-byte the one that shipped before
/// response inspection existed. `main.rs` registers the CRS check here exactly
/// when it has response-phase rules loaded
/// ([`OWASPCheck::response_rule_count`]), which keeps that invariant true for a
/// deployment whose rule set contains no `RESPONSE-95x` file.
#[derive(Default)]
pub struct ResponseCheckSet {
    checks: Vec<Box<dyn ResponseCheck>>,
}

impl ResponseCheckSet {
    /// An empty set — no response-phase inspection happens.
    #[must_use]
    pub const fn new() -> Self {
        Self { checks: Vec::new() }
    }

    /// Build a set from an explicit checker list.
    #[must_use]
    pub fn from_checks(checks: Vec<Box<dyn ResponseCheck>>) -> Self {
        Self { checks }
    }

    /// Register one more checker.
    pub fn push(&mut self, check: Box<dyn ResponseCheck>) {
        self.checks.push(check);
    }

    /// `true` when no checker is registered — the gateway's fast path.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.checks.is_empty()
    }

    /// Number of registered checkers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.checks.len()
    }

    /// Run the checkers in order and return the first finding.
    ///
    /// Same first-match-wins short-circuit as the request-phase pipeline, so a
    /// clean response costs one pass and a dirty one stops early.
    #[must_use]
    pub fn evaluate(&self, ctx: &ResponseCtx) -> Option<DetectionResult> {
        self.checks.iter().find_map(|check| check.check(ctx))
    }
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

// ─── Lane 1 body budget ───────────────────────────────────────────────────────

/// How large a request body the four frozen Lane 1 detectors (`SQLi` → XSS →
/// RCE → traversal) are willing to read.
///
/// # Why Lane 1 needs one
///
/// Lane 2 bounds its own work with `[content_security.budget]` and the CRS body
/// processors decline anything over their hardcoded 64 KiB
/// (`body_processors::MAX_BODY_BYTES`). Lane 1 had no equivalent, so its cost
/// tracked body size all the way to the 10 MiB inspection ceiling: measured at
/// **+21.5 ms of CPU on a 64 KiB upload and +102 ms on a 1 MiB body**, against
/// Lane 2's +74 µs and +20 µs on the same requests (`tests/perf/RESULTS.md`).
/// The proxy is single-threaded, so that is the throughput of the whole process.
///
/// # One budget, not one per detector
///
/// All four detectors derive their input from the single
/// [`request_targets`] collector, and the measurements show they share no work —
/// the per-detector deltas sum to the whole within 1–7%. Capping the collector
/// therefore removes the cost from all four at once, and it keeps the coverage
/// story describable: either Lane 1 read this body or it did not. Per-detector
/// caps would produce a matrix of "sqli saw the body, xss did not" states that
/// nothing downstream can reason about — and per-detector *control* already
/// exists as the per-host `defense_config.sqli` / `.xss` toggles.
///
/// # Skip, not truncate
///
/// Over budget, the body contributes **no** targets at all; it is not scanned as
/// a prefix. That is strictly worse for detection than truncation and is chosen
/// anyway, for two reasons. First, truncation cannot be made to bound the work:
/// the gateway feeds the body as a sequence of ≤68 KiB windows
/// (`BODY_PREVIEW_LIMIT` + `BODY_WINDOW_OVERLAP`), each in its own `RequestCtx`,
/// so "scan the first N bytes of each window" would still cost N × window-count
/// on a large body — the exact term the budget exists to remove. Bounding the
/// *request* instead of the window needs cumulative cross-window state, which
/// the frozen `Check::check(&RequestCtx)` signature cannot carry. Second, skip
/// is what this codebase already does at the same boundary
/// (`body_processors.rs:130`, `:226`), so an operator learns one rule rather
/// than two.
///
/// # Default
///
/// [`Self::DEFAULT`] — 64 KiB, the same boundary the CRS body processors already
/// draw. An unbounded Lane 1 is not a tuning preference an operator can be left
/// to discover: it is a denial of service reachable by posting a large body, no
/// detector evasion required. [`Self::UNLIMITED`] stays available for an operator
/// who deliberately chooses the coverage over the bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lane1BodyBudget {
    /// Largest body Lane 1 will read, in bytes. `0` = unlimited.
    max_body_bytes: usize,
}

impl Default for Lane1BodyBudget {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl Lane1BodyBudget {
    /// No cap — every byte the gateway hands over is inspected. The behaviour of
    /// every prx-waf that shipped before this budget existed, and what
    /// `max_body_bytes = 0` still selects.
    pub const UNLIMITED: Self = Self { max_body_bytes: 0 };

    /// The shipped default: 64 KiB, aligned with the CRS body processors'
    /// `MAX_BODY_BYTES` so both detection chains stop reading a body at the same
    /// size.
    pub const DEFAULT: Self = Self {
        max_body_bytes: waf_common::content_security_config::DEFAULT_LANE1_MAX_BODY_BYTES,
    };

    /// Build a budget from an operator-supplied byte count. `0` = unlimited.
    #[must_use]
    pub const fn from_bytes(max_body_bytes: usize) -> Self {
        Self { max_body_bytes }
    }

    /// The configured cap in bytes; `0` when unlimited.
    #[must_use]
    pub const fn max_body_bytes(self) -> usize {
        self.max_body_bytes
    }

    /// `true` when no cap is configured.
    #[must_use]
    pub const fn is_unlimited(self) -> bool {
        self.max_body_bytes == 0
    }

    /// Whether this request's body may be read. **O(1)** — two integer
    /// comparisons, no allocation, no scan.
    ///
    /// Two terms, because either one alone is evadable:
    ///
    /// * **the declared `Content-Length`** decides the whole request the same way
    ///   for every window, so a 1 MiB body is skipped from its first window
    ///   rather than after the first 64 KiB have already been paid for;
    /// * **this window's own length**, because a chunked request declares no
    ///   `Content-Length` (the gateway records `0`) and would otherwise walk past
    ///   the budget one window at a time.
    ///
    /// The residual gap is stated rather than papered over: with a budget at or
    /// above the 68 KiB maximum window, a **chunked** body of unknown length
    /// satisfies both terms and is scanned in full. Budgets below the 64 KiB
    /// window size are unaffected by this.
    fn admits_body(self, ctx: &RequestCtx) -> bool {
        if self.max_body_bytes == 0 {
            return true;
        }
        if ctx.body_preview.len() > self.max_body_bytes {
            return false;
        }
        usize::try_from(ctx.content_length).is_ok_and(|declared| declared <= self.max_body_bytes)
    }

    /// Whether this request **carries** a body that the budget will withhold from
    /// the Lane 1 detectors.
    ///
    /// [`Self::admits_body`] answers a detector's question ("may I read this?")
    /// and says `true` for a request with no body at all. This answers the
    /// subsystem's question ("was something withheld?"), which is what
    /// [`super::content_security::ContentSecuritySubsystem::evaluate_scoped`]
    /// needs to mark the verdict `degraded`: a body that does not exist was not
    /// missed.
    pub(crate) fn withholds_body(self, ctx: &RequestCtx) -> bool {
        !ctx.body_preview.is_empty() && !self.admits_body(ctx)
    }
}

/// Sentinel for "no WARN has been emitted yet", so the first skip is reported
/// immediately instead of waiting out an interval.
const LANE1_SKIP_NEVER_WARNED: u64 = u64::MAX;

/// How often the aggregate skip WARN is repeated. Matches the audit-log sink's
/// drop-report cadence (`audit_log.rs:80`).
const LANE1_SKIP_WARN_INTERVAL_SECS: u64 = 30;

/// Body inspections Lane 1 declined because the budget said so.
///
/// Log-only, exactly like the queue-drop counters in `audit_log.rs` /
/// `semantic_sink.rs` / `notify.rs`: an over-budget body must never be a *silent*
/// coverage hole.
///
/// **Unit: detector invocations, not requests.** Each of the four Lane 1
/// detectors collects its own targets, and the gateway inspects a large body
/// window by window, so one oversized request contributes up to
/// `4 × window_count`. Read it as a rate signal ("is this firing, and is it
/// getting worse"), not as a request count.
static LANE1_BODY_SKIPS: AtomicU64 = AtomicU64::new(0);

/// Seconds since [`PROCESS_EPOCH`] at the last emitted WARN.
static LANE1_BODY_SKIP_LAST_WARN: AtomicU64 = AtomicU64::new(LANE1_SKIP_NEVER_WARNED);

/// Monotonic anchor for the WARN throttle. `Instant` cannot live in an atomic;
/// seconds since this anchor can.
static PROCESS_EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

/// How many Lane 1 body inspections the budget has skipped since process start
/// (telemetry / tests). Never reset. See [`LANE1_BODY_SKIPS`] for the unit —
/// it counts detector invocations, not requests.
#[must_use]
pub fn lane1_body_skips() -> u64 {
    LANE1_BODY_SKIPS.load(Ordering::Relaxed)
}

/// Count an over-budget body and, at most once every
/// [`LANE1_SKIP_WARN_INTERVAL_SECS`], say so out loud.
///
/// `#[cold]`: only reachable when a budget is configured *and* exceeded, so the
/// common path never touches any of this.
#[cold]
fn record_lane1_body_skip(ctx: &RequestCtx, budget: Lane1BodyBudget) {
    let total = LANE1_BODY_SKIPS.fetch_add(1, Ordering::Relaxed).saturating_add(1);

    let now = PROCESS_EPOCH.elapsed().as_secs();
    let last = LANE1_BODY_SKIP_LAST_WARN.load(Ordering::Relaxed);
    if last != LANE1_SKIP_NEVER_WARNED && now.saturating_sub(last) < LANE1_SKIP_WARN_INTERVAL_SECS {
        return;
    }
    // Lost race: another thread is emitting this interval's line. One is enough.
    if LANE1_BODY_SKIP_LAST_WARN
        .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        return;
    }

    tracing::warn!(
        skipped_inspections = total,
        budget_bytes = budget.max_body_bytes(),
        window_bytes = ctx.body_preview.len(),
        content_length = ctx.content_length,
        host = %ctx.host,
        path = %ctx.path,
        "Lane 1 body budget exceeded: the request body was NOT inspected by the sqli/xss/rce/traversal \
         detectors (content_security.lane1.max_body_bytes, default 65536). The verdict is marked \
         degraded. Path, query, cookies and headers were still inspected, as were CRS and Lane 2."
    );
}

/// Collect all strings to inspect from the request context.
///
/// Returns a list of `(location, value)` pairs so error messages can
/// indicate where the pattern was found.
///
/// Path / query / cookie / body are included in three forms: raw,
/// single-decoded, and recursively-decoded (up to [`MAX_DECODE_PASSES`]
/// passes, currently 5) so that
/// double/triple-encoded evasion attempts are caught alongside the plain
/// variants.  A curated set of request headers ([`SCANNED_HEADERS`]) is
/// additionally scanned in raw + single-decoded form.
///
/// `body_budget` gates **only** the three body-derived entries; every other
/// surface is collected unconditionally. [`Lane1BodyBudget::UNLIMITED`]
/// reproduces the pre-budget target set byte for byte; the shipped default
/// ([`Lane1BodyBudget::DEFAULT`], 64 KiB) drops all three for a larger body.
pub(crate) fn request_targets(ctx: &RequestCtx, body_budget: Lane1BodyBudget) -> Vec<(&'static str, String)> {
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

    // Request body preview (best-effort UTF-8), subject to the Lane 1 body
    // budget. The admission test comes first so an over-budget body costs one
    // comparison instead of a lossy-UTF-8 copy plus up to five decode passes.
    if !ctx.body_preview.is_empty() {
        if body_budget.admits_body(ctx) {
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
        } else {
            record_lane1_body_skip(ctx, body_budget);
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

    /// A ctx carrying a body, with `content_length` set the way the gateway sets
    /// it (the declared total, not this window's length) unless overridden.
    fn ctx_with_body(body: Vec<u8>, declared_len: Option<u64>) -> RequestCtx {
        let mut ctx = ctx_with_headers(HashMap::new());
        ctx.path = "/upload".to_string();
        ctx.query = "id=1".to_string();
        ctx.content_length = declared_len.unwrap_or(body.len() as u64);
        ctx.body_preview = Bytes::from(body);
        ctx
    }

    /// 1 MiB of filler with the marker at the very end — the shape that proves
    /// coverage is not quietly truncated somewhere.
    fn one_mib_body_with_trailing_marker(marker: &str) -> Vec<u8> {
        let mut body = vec![b'a'; 1024 * 1024];
        body.extend_from_slice(marker.as_bytes());
        body
    }

    /// The shipped default is 64 KiB — the same boundary the CRS body processors
    /// draw (`body_processors::MAX_BODY_BYTES`), so both detection chains stop
    /// reading a body at the same size. Pinned because the number is quoted in
    /// `configs/default.toml`, `docs/dos-budget.md` §2.2 and
    /// `tests/perf/RESULTS.md`, and a silent change would make all three wrong.
    #[test]
    fn the_default_budget_is_sixty_four_kib() {
        assert_eq!(Lane1BodyBudget::DEFAULT.max_body_bytes(), 64 * 1024);
        assert_eq!(Lane1BodyBudget::default(), Lane1BodyBudget::DEFAULT);
        assert!(!Lane1BodyBudget::default().is_unlimited());
        assert_eq!(
            waf_common::content_security_config::Lane1BudgetConfig::default().max_body_bytes,
            64 * 1024,
            "the serialized config default must agree with the compiled one, or a config \
             that omits the key would behave differently from one that spells it out"
        );
    }

    /// `0` keeps meaning *unlimited*, not *zero*. An operator who deliberately
    /// wants every byte inspected — accepting the CPU that comes with it — must
    /// still be able to say so.
    #[test]
    fn zero_still_means_unlimited() {
        assert!(Lane1BodyBudget::UNLIMITED.is_unlimited());
        assert!(Lane1BodyBudget::from_bytes(0).is_unlimited());
        assert!(!Lane1BodyBudget::from_bytes(1).is_unlimited());

        // And it is not merely a flag: the body is actually read.
        let ctx = ctx_with_body(one_mib_body_with_trailing_marker("NEEDLE"), None);
        let targets = request_targets(&ctx, Lane1BodyBudget::from_bytes(0));
        assert!(
            targets.iter().any(|(loc, v)| *loc == "body" && v.ends_with("NEEDLE")),
            "an explicit 0 must inspect a 1 MiB body to its last byte"
        );
    }

    /// The pre-budget behaviour, still reachable: with no cap a 1 MiB body is
    /// read to its last byte.
    #[test]
    fn unlimited_budget_reads_a_one_mib_body_to_its_last_byte() {
        let ctx = ctx_with_body(one_mib_body_with_trailing_marker("NEEDLE"), None);
        let targets = request_targets(&ctx, Lane1BodyBudget::UNLIMITED);
        assert!(
            targets.iter().any(|(loc, v)| *loc == "body" && v.ends_with("NEEDLE")),
            "unlimited must still see the tail of a 1 MiB body"
        );
    }

    #[test]
    fn budget_admits_a_body_at_or_under_the_cap() {
        let ctx = ctx_with_body(b"user=admin&note=NEEDLE".to_vec(), None);
        let targets = request_targets(&ctx, Lane1BodyBudget::from_bytes(64 * 1024));
        assert!(
            targets.iter().any(|(loc, v)| *loc == "body" && v.contains("NEEDLE")),
            "a body inside the budget must still be inspected"
        );
    }

    /// Over budget → the body contributes nothing, and everything else still
    /// does. Skip, not truncate: no prefix of the body appears either.
    #[test]
    fn budget_skips_an_over_cap_body_but_keeps_every_other_surface() {
        let ctx = ctx_with_body(one_mib_body_with_trailing_marker("NEEDLE"), None);
        let targets = request_targets(&ctx, Lane1BodyBudget::from_bytes(64 * 1024));
        assert!(
            !targets.iter().any(|(loc, _)| loc.starts_with("body")),
            "an over-budget body must contribute no target at all"
        );
        assert!(
            targets.iter().any(|(loc, v)| *loc == "path" && v == "/upload"),
            "path must still be inspected"
        );
        assert!(
            targets.iter().any(|(loc, v)| *loc == "query" && v == "id=1"),
            "query must still be inspected"
        );
    }

    /// The declared `Content-Length` decides the whole request, so the *first*
    /// window of a large body is skipped rather than paid for. Without this term
    /// a 1 MiB body would still cost one full 64 KiB scan.
    #[test]
    fn declared_content_length_skips_the_first_window_too() {
        // A small window (what the gateway hands over first) of a body the client
        // declared as 1 MiB.
        let ctx = ctx_with_body(vec![b'a'; 4096], Some(1024 * 1024));
        let targets = request_targets(&ctx, Lane1BodyBudget::from_bytes(64 * 1024));
        assert!(
            !targets.iter().any(|(loc, _)| loc.starts_with("body")),
            "a declared-oversized body must be skipped from its first window"
        );
    }

    /// A chunked request declares no length (the gateway records `0`), so the
    /// window's own size has to carry the decision.
    #[test]
    fn undeclared_length_falls_back_to_the_window_size() {
        let ctx = ctx_with_body(vec![b'a'; 64 * 1024], Some(0));
        assert!(
            !request_targets(&ctx, Lane1BodyBudget::from_bytes(16 * 1024))
                .iter()
                .any(|(loc, _)| loc.starts_with("body")),
            "a window larger than the budget must be skipped even with no Content-Length"
        );
    }

    /// An over-budget body is a coverage hole; it must be counted, never silent.
    #[test]
    fn every_skip_is_counted() {
        let before = lane1_body_skips();
        let ctx = ctx_with_body(vec![b'a'; 32 * 1024], None);
        let _ = request_targets(&ctx, Lane1BodyBudget::from_bytes(1024));
        assert!(
            lane1_body_skips() > before,
            "the skip counter must advance (before={before}, after={})",
            lane1_body_skips()
        );
    }

    #[test]
    fn request_targets_scans_curated_headers() {
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "sqlmap/1.0".to_string());
        headers.insert("x-forwarded-for".to_string(), "1.2.3.4".to_string());
        // A header not on the allowlist must be ignored.
        headers.insert("x-custom".to_string(), "ignored".to_string());
        let ctx = ctx_with_headers(headers);
        let targets = request_targets(&ctx, Lane1BodyBudget::UNLIMITED);
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
        let targets = request_targets(&ctx, Lane1BodyBudget::UNLIMITED);
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
