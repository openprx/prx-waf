use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use bytes::{Bytes, BytesMut};
use http::HeaderMap;
use tracing::warn;
use waf_common::{HostConfig, RequestCtx};
use waf_engine::ContentInspectionState;

use crate::lb::Backend;

// ─── Request header folding ───────────────────────────────────────────────────
//
// A `HeaderMap` yields one item **per value**, so a request that repeats a
// header name (`Cookie: a=1` + `Cookie: b=2`) produces two items with the same
// key. Folding that into a `HashMap` with a plain `insert` makes the last line
// win and silently hides every earlier value from the detection pipeline — a
// trivial WAF bypass, because origins re-join those lines per RFC and act on
// all of them. The helpers below fold **every** value of a repeated name into
// one RFC-shaped value so the flat `RequestCtx::headers` map the detectors read
// still carries the complete request.

/// Maximum number of same-named header lines folded into a single value.
///
/// Repeating a header hundreds of times is an amplification vector (each line
/// multiplies the bytes every detector must scan), so the fold is bounded and
/// a request that exceeds the bound is refused rather than truncated —
/// truncation would itself be a bypass (junk lines first, payload last).
pub const MAX_HEADER_VALUES_PER_NAME: usize = 64;

/// Maximum folded length, in bytes, of one header name's value.
///
/// 32 KiB is far above what any real client sends for a single header (common
/// origin limits sit at 8–16 KiB for *all* headers combined) and well above the
/// largest realistic `Cookie` jar, so this only trips on abuse.
pub const MAX_FOLDED_HEADER_BYTES: usize = 32 * 1024;

/// Outcome of folding a parsed [`HeaderMap`] into the flat map consumed by the
/// WAF detectors.
#[derive(Debug, Default)]
pub struct FoldedHeaders {
    /// Lower-cased header name → folded value (all lines of that name).
    pub headers: HashMap<String, String>,
    /// Name of the first header that blew [`MAX_HEADER_VALUES_PER_NAME`] or
    /// [`MAX_FOLDED_HEADER_BYTES`]. `Some` means the folded value is incomplete
    /// and the request must be refused (`431`) instead of inspected partially.
    pub overflow: Option<String>,
    /// `true` when the request carried more than one `Host` header line. RFC
    /// 9112 §3.2 requires such a request to be rejected: the WAF routes on one
    /// of them and the origin may pick the other.
    pub duplicate_host: bool,
}

/// Separator used when several lines of the same header name are folded.
///
/// RFC 6265 §5.4 joins cookie-pairs with `"; "`; every other repeatable header
/// is a comma-separated list per RFC 9110 §5.3. Using the RFC separator means
/// the folded value is byte-identical to what an origin reconstructs, so the
/// detectors see exactly the string the backend will parse.
const fn fold_separator(name: &str) -> &'static str {
    if matches!(name.as_bytes(), b"cookie") {
        "; "
    } else {
        ", "
    }
}

/// Fold a parsed [`HeaderMap`] into the flat `name → value` map used by
/// [`RequestCtx`], preserving **every** value of a repeated header name.
#[must_use]
pub fn fold_request_headers(headers: &HeaderMap) -> FoldedHeaders {
    // (line count, folded value) per name; the count drives the fold bound.
    let mut folded: HashMap<String, (usize, String)> = HashMap::with_capacity(headers.keys_len());
    let mut overflow: Option<String> = None;
    let mut host_lines: usize = 0;

    for (name, value) in headers {
        // `http::HeaderName` always stores its name lower-cased, so the map key
        // needs no re-casing.
        let name = name.as_str();
        if name == "host" {
            host_lines = host_lines.saturating_add(1);
        }
        let Ok(v) = std::str::from_utf8(value.as_bytes()) else {
            continue;
        };

        if let Some((count, acc)) = folded.get_mut(name) {
            *count = count.saturating_add(1);
            let sep = fold_separator(name);
            let folded_len = acc.len().saturating_add(sep.len()).saturating_add(v.len());
            if *count > MAX_HEADER_VALUES_PER_NAME || folded_len > MAX_FOLDED_HEADER_BYTES {
                if overflow.is_none() {
                    overflow = Some(name.to_string());
                }
                continue;
            }
            acc.push_str(sep);
            acc.push_str(v);
            continue;
        }

        folded.insert(name.to_string(), (1, v.to_string()));
    }

    FoldedHeaders {
        headers: folded.into_iter().map(|(k, (_, v))| (k, v)).collect(),
        overflow,
        duplicate_host: host_lines > 1,
    }
}

/// Right-most non-empty `X-Forwarded-For` entry across **all** `XFF` lines.
///
/// `HeaderMap::get` returns only the first line, so with a spoofed
/// `X-Forwarded-For: <attacker>` ahead of the real one the "right-most entry"
/// rule (M-1) would read the attacker's value. Walking every line and taking
/// the last non-empty segment restores the intended semantics: the closest
/// trusted hop always appends last.
#[must_use]
pub fn rightmost_forwarded_for(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| std::str::from_utf8(v.as_bytes()).ok())
        .flat_map(|s| s.split(',').map(str::trim))
        .rfind(|seg| !seg.is_empty())
}

// ─── Request body inspection policy ───────────────────────────────────────────

/// Bytes buffered per body inspection window (64 KiB).
///
/// This is a *window* size, not a total: the body is inspected window by
/// window, so it bounds peak memory rather than detection coverage.
pub const BODY_PREVIEW_LIMIT: usize = 64 * 1024;

/// Bytes of the previous window replayed at the head of the next one.
///
/// Without an overlap a payload straddling a window boundary would be split
/// across two scans and matched by neither. 4 KiB comfortably exceeds the
/// longest signature the detectors carry.
pub const BODY_WINDOW_OVERLAP: usize = 4 * 1024;

/// Default ceiling on how many request-body bytes are inspected (10 MiB).
///
/// Deliberately equal to the HTTP/3 body buffer ceiling so the two protocol
/// paths enforce the same limit.
pub const MAX_INSPECTED_BODY_BYTES: usize = 10 * 1024 * 1024;

/// What to do with a request body larger than
/// [`BodyInspectionPolicy::max_total_bytes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BodyOverflowAction {
    /// Refuse the request with `413 Payload Too Large` (fail-closed, default).
    #[default]
    Reject,
    /// Log a warning and forward the remaining bytes **uninspected**.
    /// Fail-open — only for deployments that must accept bodies larger than the
    /// inspection ceiling (bulk uploads) and accept the residual risk.
    LogAndForward,
}

impl BodyOverflowAction {
    /// Parse an operator-supplied spelling; `None` when unrecognised.
    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "reject" | "block" | "413" => Some(Self::Reject),
            "log" | "log_and_forward" | "forward" | "allow" => Some(Self::LogAndForward),
            _ => None,
        }
    }
}

/// How request bodies are inspected.
///
/// Both protocol paths read one process-wide instance
/// ([`body_inspection_policy`]) so HTTP/1.1 and HTTP/3 can never drift apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyInspectionPolicy {
    /// Bytes buffered before a window is scanned (peak-memory bound).
    pub window_bytes: usize,
    /// Bytes of the previous window replayed at the head of the next.
    pub overlap_bytes: usize,
    /// Total body bytes inspected before `overflow` applies. `0` = no ceiling.
    pub max_total_bytes: usize,
    /// Behaviour once `max_total_bytes` is exceeded.
    pub overflow: BodyOverflowAction,
}

impl Default for BodyInspectionPolicy {
    fn default() -> Self {
        Self {
            window_bytes: BODY_PREVIEW_LIMIT,
            overlap_bytes: BODY_WINDOW_OVERLAP,
            max_total_bytes: MAX_INSPECTED_BODY_BYTES,
            overflow: BodyOverflowAction::Reject,
        }
    }
}

impl BodyInspectionPolicy {
    /// Build the policy from the environment, falling back to the safe default.
    ///
    /// | Variable | Meaning |
    /// |----------|---------|
    /// | `PRXWAF_BODY_INSPECT_MAX_BYTES` | inspected-byte ceiling (`0` = unlimited) |
    /// | `PRXWAF_BODY_INSPECT_OVERFLOW` | `reject` (default) or `log` |
    ///
    /// An unparseable value keeps the safe default and logs a warning — a typo
    /// must never quietly turn the WAF fail-open.
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_env_source(|key| std::env::var(key).ok())
    }

    /// Core of [`Self::from_env`], parameterised over the environment source so
    /// it is testable without mutating the process environment.
    fn from_env_source<F>(get_raw: F) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        let mut policy = Self::default();
        let get = |key: &str| get_raw(key).filter(|v| !v.trim().is_empty());

        if let Some(raw) = get("PRXWAF_BODY_INSPECT_MAX_BYTES") {
            match raw.trim().parse::<usize>() {
                Ok(v) => policy.max_total_bytes = v,
                Err(e) => warn!("PRXWAF_BODY_INSPECT_MAX_BYTES='{raw}' is not a byte count ({e}); keeping default"),
            }
        }
        if let Some(raw) = get("PRXWAF_BODY_INSPECT_OVERFLOW") {
            match BodyOverflowAction::parse(&raw) {
                Some(v) => policy.overflow = v,
                None => {
                    warn!("PRXWAF_BODY_INSPECT_OVERFLOW='{raw}' is not 'reject' or 'log'; keeping fail-closed default");
                }
            }
        }

        policy.normalise()
    }

    /// Clamp the policy into a self-consistent shape (never zero-sized windows,
    /// overlap strictly smaller than the window).
    fn normalise(mut self) -> Self {
        self.window_bytes = self.window_bytes.max(1);
        self.overlap_bytes = self.overlap_bytes.min(self.window_bytes.saturating_sub(1));
        self
    }
}

/// Process-wide body inspection policy, resolved once from the environment.
static BODY_POLICY: OnceLock<BodyInspectionPolicy> = OnceLock::new();

/// The active body inspection policy (shared by HTTP/1.1 and HTTP/3).
pub fn body_inspection_policy() -> &'static BodyInspectionPolicy {
    BODY_POLICY.get_or_init(BodyInspectionPolicy::from_env)
}

/// What the caller must do with one request-body chunk.
///
/// The order is fixed: scan `inspect` first, and only when it comes back clean
/// hand `forward` to the upstream. Nothing ever leaves the WAF before it has
/// been scanned.
#[derive(Debug, Default)]
pub struct BodyStep {
    /// Bytes to scan (previous-window overlap + the new window), if any.
    pub inspect: Option<Bytes>,
    /// Bytes cleared to travel upstream once `inspect` comes back clean.
    pub forward: Option<Bytes>,
    /// The body exceeded the inspected-byte ceiling under
    /// [`BodyOverflowAction::Reject`]: refuse with `413`, forward nothing.
    pub reject: bool,
    /// Set on the single step where the ceiling was crossed, so the caller can
    /// emit exactly one operator-visible record per request.
    pub over_cap: bool,
}

/// Streaming request-body inspector.
///
/// Buffers the body into windows, hands each window to the detectors **before**
/// it is forwarded, and carries an overlap between windows so a payload split
/// across a boundary is still seen contiguously. Peak buffering is one window
/// plus the largest single chunk the transport delivers.
#[derive(Debug)]
pub struct BodyInspector {
    policy: BodyInspectionPolicy,
    /// Buffered bytes not yet scanned nor forwarded.
    pending: BytesMut,
    /// Tail of the previous window, replayed at the head of the next scan.
    carry: BytesMut,
    /// Total body bytes seen so far.
    total: usize,
    /// Ceiling crossed under [`BodyOverflowAction::LogAndForward`]: everything
    /// from here on is passed through without inspection.
    passthrough: bool,
}

impl Default for BodyInspector {
    fn default() -> Self {
        Self::with_policy(*body_inspection_policy())
    }
}

impl BodyInspector {
    /// Build an inspector with an explicit policy (used by tests / embedders).
    #[must_use]
    pub fn with_policy(policy: BodyInspectionPolicy) -> Self {
        Self {
            policy: policy.normalise(),
            pending: BytesMut::new(),
            carry: BytesMut::new(),
            total: 0,
            passthrough: false,
        }
    }

    /// Total request-body bytes seen so far.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.total
    }

    /// Feed one transport chunk (`None` = no new data) and learn what to do.
    pub fn push(&mut self, chunk: Option<Bytes>, end_of_stream: bool) -> BodyStep {
        // Past the ceiling under the fail-open policy: relay untouched.
        if self.passthrough {
            return BodyStep {
                forward: chunk,
                ..BodyStep::default()
            };
        }

        if let Some(c) = &chunk {
            self.total = self.total.saturating_add(c.len());
            self.pending.extend_from_slice(c);
        }

        let mut over_cap = false;
        if self.policy.max_total_bytes > 0 && self.total > self.policy.max_total_bytes {
            over_cap = true;
            if self.policy.overflow == BodyOverflowAction::Reject {
                // Fail-closed: nothing more is forwarded, the caller answers 413.
                self.pending.clear();
                return BodyStep {
                    reject: true,
                    over_cap: true,
                    ..BodyStep::default()
                };
            }
            // Fail-open: scan what is already buffered, then relay the rest.
            self.passthrough = true;
        }

        let window_ready = self.pending.len() >= self.policy.window_bytes;
        if self.pending.is_empty() || !(window_ready || end_of_stream || self.passthrough) {
            // Hold the bytes back until a full window (or the stream) completes.
            return BodyStep {
                over_cap,
                ..BodyStep::default()
            };
        }

        let window = self.pending.split().freeze();
        let inspect = if self.carry.is_empty() {
            window.clone()
        } else {
            let mut joined = BytesMut::with_capacity(self.carry.len().saturating_add(window.len()));
            joined.extend_from_slice(&self.carry);
            joined.extend_from_slice(&window);
            joined.freeze()
        };

        // Retain this window's tail as the next window's overlap.
        self.carry.clear();
        let keep = self.policy.overlap_bytes.min(window.len());
        if let Some(tail) = window.get(window.len().saturating_sub(keep)..) {
            self.carry.extend_from_slice(tail);
        }

        BodyStep {
            inspect: Some(inspect),
            forward: Some(window),
            reject: false,
            over_cap,
        }
    }
}

/// Overlapping windows over an already-buffered body.
///
/// The HTTP/3 path buffers the whole body before forwarding it, so it walks the
/// buffer with this iterator instead of the streaming [`BodyInspector`]; both
/// produce the same window size and the same overlap, which is what keeps the
/// two protocol paths' detection coverage identical.
pub struct BodyWindows<'a> {
    data: &'a [u8],
    pos: usize,
    window: usize,
    overlap: usize,
}

impl<'a> BodyWindows<'a> {
    /// Walk `data` in `window`-sized windows, each prefixed with the previous
    /// window's last `overlap` bytes.
    #[must_use]
    pub fn new(data: &'a [u8], window: usize, overlap: usize) -> Self {
        let window = window.max(1);
        Self {
            data,
            pos: 0,
            window,
            overlap: overlap.min(window.saturating_sub(1)),
        }
    }

    /// Walk `data` using the process-wide body inspection policy.
    #[must_use]
    pub fn with_policy(data: &'a [u8], policy: &BodyInspectionPolicy) -> Self {
        Self::new(data, policy.window_bytes, policy.overlap_bytes)
    }
}

impl<'a> Iterator for BodyWindows<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.data.len() {
            return None;
        }
        let start = self.pos.saturating_sub(self.overlap);
        let end = self.pos.saturating_add(self.window).min(self.data.len());
        let slice = self.data.get(start..end)?;
        self.pos = end;
        Some(slice)
    }
}

// ─── Per-request proxy state ──────────────────────────────────────────────────

/// Maximum response body size (bytes) that is eligible for caching. Larger
/// responses are streamed through un-cached so a single big object cannot
/// balloon per-request memory. 8 MiB.
pub const CACHE_BODY_LIMIT: usize = 8 * 1024 * 1024;

/// Per-request state stored in the Pingora session context
#[derive(Default)]
pub struct GatewayCtx {
    /// Built `RequestCtx` for WAF pipeline
    pub request_ctx: Option<RequestCtx>,
    /// Resolved upstream address (host:port)
    pub upstream_addr: Option<String>,
    /// Matched host config
    pub host_config: Option<Arc<HostConfig>>,
    /// Streaming request-body inspector: buffers the body window by window and
    /// releases each window to the upstream only after it has been scanned.
    pub body_inspector: BodyInspector,
    /// Lane 2 semantic work-budget state, shared across the header and body
    /// phases of this request (plan §12.3 — HTTP/1.1 owns it in `GatewayCtx`;
    /// HTTP/3 uses a local instance). Initialised from the engine's compiled
    /// budget in `request_filter`.
    pub content_inspection: ContentInspectionState,
    // ── Load balancing ─────────────────────────────────────────────────────────
    /// Backend chosen by the load balancer for this request. Held so its active
    /// connection counter can be released in `logging` (Least-Connections
    /// accounting). `None` for single-backend hosts.
    pub selected_backend: Option<Backend>,
    // ── Response cache ─────────────────────────────────────────────────────────
    /// Cache key for a cacheable request that missed. `Some` iff the request is
    /// eligible for caching (cache enabled, safe method, no credentials) and was
    /// not served from cache — meaning the upstream response is a store
    /// candidate.
    pub cache_key: Option<String>,
    /// Upstream status captured for a potential cache store.
    pub cache_status: u16,
    /// Upstream response headers captured for a potential cache store.
    pub cache_headers: Vec<(String, String)>,
    /// Upstream `Cache-Control` value captured for a potential cache store.
    pub cache_control: Option<String>,
    /// Whether the captured upstream response is eligible to be stored (set in
    /// the response-header phase, before body accumulation).
    pub cache_store: bool,
    /// Accumulated upstream response body for the pending cache store.
    pub cache_body: BytesMut,
    // ── Response-phase WAF ─────────────────────────────────────────────────────
    /// Armed response-body inspector, or `None` when this response is not
    /// inspected.
    ///
    /// `None` is the overwhelmingly common state and the one this round ships
    /// in: [`crate::proxy::WafProxy`] only arms an inspector when a
    /// response-phase detector is registered *and* the response clears
    /// [`crate::response::gate`]. While it is `None` the response path costs one
    /// `Option` test per chunk and behaves exactly as it did before the response
    /// phase existed.
    pub response_inspection: Option<crate::response::ResponseInspector>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            let name: http::HeaderName = name.parse().expect("valid header name");
            let value = HeaderValue::from_str(value).expect("valid header value");
            map.append(name, value);
        }
        map
    }

    // ── Bypass 1: duplicate headers ──────────────────────────────────────────

    /// Attack scenario: the `SQLi` payload rides the **first** `Cookie` line and a
    /// harmless second line follows. The origin re-joins both per RFC 6265, so
    /// the WAF must see both — the pre-fix `insert` kept only `y=1`.
    #[test]
    fn duplicate_cookie_first_line_payload_survives_folding() {
        let payload = "x=' UNION SELECT password FROM users--";
        let map = header_map(&[("cookie", payload), ("cookie", "y=1")]);

        let folded = fold_request_headers(&map);
        let cookie = folded.headers.get("cookie").expect("cookie folded");

        assert!(
            cookie.contains("UNION SELECT password FROM users"),
            "payload from the first Cookie line was dropped: {cookie}"
        );
        assert!(cookie.contains("y=1"), "second Cookie line was dropped: {cookie}");
        assert_eq!(cookie, "x=' UNION SELECT password FROM users--; y=1");
        assert!(folded.overflow.is_none());
        assert!(!folded.duplicate_host);
    }

    #[test]
    fn duplicate_non_cookie_headers_fold_with_comma() {
        let map = header_map(&[("x-forwarded-for", "9.9.9.9"), ("x-forwarded-for", "10.0.0.1")]);
        let folded = fold_request_headers(&map);
        assert_eq!(
            folded.headers.get("x-forwarded-for").map(String::as_str),
            Some("9.9.9.9, 10.0.0.1")
        );
    }

    /// Negative control: ordinary single-valued traffic folds to exactly the
    /// value that was sent (no separators, no duplication, no overflow).
    #[test]
    fn single_valued_headers_are_unchanged() {
        let map = header_map(&[
            ("host", "example.com"),
            ("user-agent", "Mozilla/5.0"),
            ("cookie", "session=abc123"),
        ]);
        let folded = fold_request_headers(&map);
        assert_eq!(folded.headers.get("host").map(String::as_str), Some("example.com"));
        assert_eq!(
            folded.headers.get("user-agent").map(String::as_str),
            Some("Mozilla/5.0")
        );
        assert_eq!(folded.headers.get("cookie").map(String::as_str), Some("session=abc123"));
        assert!(folded.overflow.is_none());
        assert!(!folded.duplicate_host);
    }

    #[test]
    fn header_flood_is_reported_as_overflow() {
        let pairs: Vec<(&str, &str)> = std::iter::repeat_n(("cookie", "a=1"), MAX_HEADER_VALUES_PER_NAME + 5).collect();
        let folded = fold_request_headers(&header_map(&pairs));
        assert_eq!(folded.overflow.as_deref(), Some("cookie"));
    }

    #[test]
    fn oversized_fold_is_reported_as_overflow() {
        let chunk = "b".repeat(8 * 1024);
        let pairs: Vec<(&str, &str)> = std::iter::repeat_n(("x-forwarded-for", chunk.as_str()), 6).collect();
        let folded = fold_request_headers(&header_map(&pairs));
        assert_eq!(folded.overflow.as_deref(), Some("x-forwarded-for"));
    }

    #[test]
    fn duplicate_host_is_flagged() {
        let folded = fold_request_headers(&header_map(&[("host", "good.example"), ("host", "evil.example")]));
        assert!(folded.duplicate_host);
    }

    #[test]
    fn rightmost_forwarded_for_spans_all_lines() {
        // Spoofed line first, real proxy-appended line last.
        let map = header_map(&[("x-forwarded-for", "1.1.1.1"), ("x-forwarded-for", "2.2.2.2, 3.3.3.3")]);
        assert_eq!(rightmost_forwarded_for(&map), Some("3.3.3.3"));
        // Single line keeps the documented right-most semantics.
        let map = header_map(&[("x-forwarded-for", "1.1.1.1, 2.2.2.2")]);
        assert_eq!(rightmost_forwarded_for(&map), Some("2.2.2.2"));
        // Absent header stays `None`.
        assert_eq!(rightmost_forwarded_for(&HeaderMap::new()), None);
    }

    // ── Bypass 3: body inspection ────────────────────────────────────────────

    fn test_policy(overflow: BodyOverflowAction) -> BodyInspectionPolicy {
        BodyInspectionPolicy {
            window_bytes: 64 * 1024,
            overlap_bytes: 1024,
            max_total_bytes: 256 * 1024,
            overflow,
        }
    }

    /// Attack scenario: 64 KiB of harmless filler followed by the real payload.
    /// Pre-fix the filler completed the preview, the inspector latched
    /// `body_inspected = true`, and every later chunk was forwarded unscanned.
    #[test]
    fn payload_after_64kib_filler_is_still_inspected() {
        let mut inspector = BodyInspector::with_policy(test_policy(BodyOverflowAction::Reject));
        let filler = Bytes::from(vec![b'A'; 64 * 1024]);
        let payload = Bytes::from_static(b"' UNION SELECT password FROM users--");

        let first = inspector.push(Some(filler), false);
        assert!(first.inspect.is_some(), "first window must be inspected");
        assert!(!first.reject);

        let second = inspector.push(Some(payload.clone()), true);
        let inspected = second.inspect.expect("trailing chunk must be inspected");
        assert!(
            inspected.windows(payload.len()).any(|w| w == payload),
            "payload after the 64 KiB filler was never handed to the detectors"
        );
        // And it is only cleared for the upstream as part of that same window.
        assert_eq!(second.forward.as_deref(), Some(payload.as_ref()));
    }

    /// No byte may reach the upstream before it has been scanned.
    #[test]
    fn bytes_are_withheld_until_their_window_is_inspected() {
        let mut inspector = BodyInspector::with_policy(test_policy(BodyOverflowAction::Reject));
        let step = inspector.push(Some(Bytes::from_static(b"partial")), false);
        assert!(step.forward.is_none(), "un-inspected bytes were released upstream");
        assert!(step.inspect.is_none());

        let step = inspector.push(None, true);
        assert_eq!(step.inspect.as_deref(), Some(b"partial".as_ref()));
        assert_eq!(step.forward.as_deref(), Some(b"partial".as_ref()));
    }

    /// A payload split across a window boundary is still seen contiguously.
    #[test]
    fn window_overlap_catches_boundary_straddling_payload() {
        let policy = BodyInspectionPolicy {
            window_bytes: 1024,
            overlap_bytes: 64,
            max_total_bytes: 0,
            overflow: BodyOverflowAction::Reject,
        };
        let mut inspector = BodyInspector::with_policy(policy);
        let mut first = vec![b'A'; 1020];
        first.extend_from_slice(b"' UN");
        let _ = inspector.push(Some(Bytes::from(first)), false);
        let second = inspector.push(Some(Bytes::from_static(b"ION SELECT 1--")), true);
        let inspected = second.inspect.expect("second window");
        let text = String::from_utf8_lossy(&inspected);
        assert!(
            text.contains("' UNION SELECT 1--"),
            "boundary payload was split: {text}"
        );
    }

    /// Fail-closed default: past the ceiling the request is refused, and the
    /// over-limit bytes are never released upstream.
    #[test]
    fn body_over_ceiling_is_rejected_by_default() {
        let mut inspector = BodyInspector::with_policy(test_policy(BodyOverflowAction::Reject));
        let mut rejected = false;
        for _ in 0..8 {
            let step = inspector.push(Some(Bytes::from(vec![b'A'; 64 * 1024])), false);
            if step.reject {
                assert!(step.forward.is_none(), "rejected body must not be forwarded");
                assert!(step.over_cap);
                rejected = true;
                break;
            }
        }
        assert!(rejected, "body past the inspection ceiling was silently allowed");
    }

    /// Opt-in fail-open: the overflow is still surfaced exactly once so the
    /// operator can see that uninspected bytes were relayed.
    #[test]
    fn log_and_forward_reports_the_overflow_once() {
        let mut inspector = BodyInspector::with_policy(test_policy(BodyOverflowAction::LogAndForward));
        let mut over_cap_steps = 0;
        for _ in 0..8 {
            let step = inspector.push(Some(Bytes::from(vec![b'A'; 64 * 1024])), false);
            assert!(!step.reject);
            if step.over_cap {
                over_cap_steps += 1;
            }
        }
        assert_eq!(over_cap_steps, 1, "the ceiling crossing must be reported exactly once");
    }

    /// Negative control: a small, ordinary body is inspected once and forwarded
    /// intact.
    #[test]
    fn small_body_is_inspected_once_and_forwarded_intact() {
        let mut inspector = BodyInspector::with_policy(test_policy(BodyOverflowAction::Reject));
        let step = inspector.push(Some(Bytes::from_static(b"user=alice&role=viewer")), true);
        assert_eq!(step.inspect.as_deref(), Some(b"user=alice&role=viewer".as_ref()));
        assert_eq!(step.forward.as_deref(), Some(b"user=alice&role=viewer".as_ref()));
        assert!(!step.reject);
        assert!(!step.over_cap);
    }

    #[test]
    fn body_windows_cover_every_byte_with_overlap() {
        let data: Vec<u8> = (0..250u32).map(|i| u8::try_from(i % 256).unwrap_or(0)).collect();
        let windows: Vec<&[u8]> = BodyWindows::new(&data, 100, 10).collect();
        assert_eq!(windows.len(), 3);
        assert_eq!(windows.first().map(|w| w.len()), Some(100));
        // Windows 2 and 3 carry the 10-byte overlap from their predecessor.
        assert_eq!(windows.get(1).map(|w| w.len()), Some(110));
        assert_eq!(windows.get(2).map(|w| w.len()), Some(60));
        // Concatenating the non-overlapping parts reproduces the input.
        let mut joined = Vec::new();
        joined.extend_from_slice(windows.first().copied().unwrap_or_default());
        joined.extend_from_slice(
            windows
                .get(1)
                .copied()
                .unwrap_or_default()
                .get(10..)
                .unwrap_or_default(),
        );
        joined.extend_from_slice(
            windows
                .get(2)
                .copied()
                .unwrap_or_default()
                .get(10..)
                .unwrap_or_default(),
        );
        assert_eq!(joined, data);
    }

    #[test]
    fn body_windows_on_empty_input_yield_nothing() {
        assert_eq!(BodyWindows::new(&[], 100, 10).count(), 0);
    }

    // ── Policy plumbing ──────────────────────────────────────────────────────

    #[test]
    fn default_policy_is_fail_closed() {
        let policy = BodyInspectionPolicy::default();
        assert_eq!(policy.overflow, BodyOverflowAction::Reject);
        assert_eq!(policy.max_total_bytes, MAX_INSPECTED_BODY_BYTES);
        assert_eq!(policy.window_bytes, BODY_PREVIEW_LIMIT);
    }

    #[test]
    fn env_overrides_are_honoured_and_bad_values_keep_the_default() {
        let policy = BodyInspectionPolicy::from_env_source(|key| match key {
            "PRXWAF_BODY_INSPECT_MAX_BYTES" => Some("1048576".to_string()),
            "PRXWAF_BODY_INSPECT_OVERFLOW" => Some("log".to_string()),
            _ => None,
        });
        assert_eq!(policy.max_total_bytes, 1024 * 1024);
        assert_eq!(policy.overflow, BodyOverflowAction::LogAndForward);

        let policy = BodyInspectionPolicy::from_env_source(|key| match key {
            "PRXWAF_BODY_INSPECT_MAX_BYTES" => Some("not-a-number".to_string()),
            "PRXWAF_BODY_INSPECT_OVERFLOW" => Some("maybe".to_string()),
            _ => None,
        });
        assert_eq!(policy.max_total_bytes, MAX_INSPECTED_BODY_BYTES);
        assert_eq!(policy.overflow, BodyOverflowAction::Reject);
    }
}
