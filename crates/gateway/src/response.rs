//! Response-phase WAF inspection for the HTTP/1.1 proxy path.
//!
//! # The constraint that shapes everything here
//!
//! A response status line cannot be taken back. Pingora's proxy loop pulls
//! upstream `HttpTask`s in batches, runs `response_filter` over each one and
//! then hands the batch straight to `write_response_tasks`
//! (`pingora-proxy-0.8.0/src/proxy_h1.rs`, the `task = rx.recv()` arm). A
//! `HttpTask::Header` therefore reaches the downstream socket in the same turn
//! it is filtered, and **no `ProxyHttp` hook can suppress or defer it** — the
//! header is already on the wire before `upstream_response_body_filter` sees
//! byte one of the body. Buffering the whole response and *then* answering
//! `403` is consequently not reachable through the stock filter model; it would
//! need either a patched `pingora-proxy` that lets a filter hold a header task,
//! or a manual fetch-buffer-respond path of the kind [`crate::http3`] already
//! runs.
//!
//! This is not a prx-waf peculiarity. The reference implementation has the same
//! shape: `ModSecurity-nginx`'s header filter forwards the response headers as
//! soon as phase 3 clears them and its body filter forwards each chunk it does
//! not veto, deferring the phase-4 verdict to `last_buf`. What lets it still
//! answer `403` is nginx's `proxy_buffering on` usually delivering the whole
//! origin response into the filter chain before the write filter flushes to the
//! client — a property of nginx's buffering, not of the rule engine, and one
//! that the connector's own source shows breaking down for streamed backends.
//!
//! # What this module does instead
//!
//! It withholds bytes rather than status codes. Response body chunks are held
//! back, scanned, and only then released — the same discipline
//! [`crate::context::BodyInspector`] applies to request bodies. A finding
//! inside the inspected prefix therefore leaks **zero** body bytes to the
//! client, and aborting the stream leaves an HTTP message that the client is
//! required to treat as failed (RFC 9112 §8: a message shorter than its
//! declared `Content-Length`, or a chunked body without its terminating chunk,
//! is incomplete and must not be handled as complete). Losing the ability to
//! *say* `403` costs a status code; it does not cost containment.
//!
//! One nuance is worth stating precisely, because it is easy to over-claim.
//! Pingora filters a whole batch of upstream tasks into a vector and writes the
//! vector afterwards, so aborting from the body filter drops any header still
//! sitting in that same batch — and `fail_to_proxy` then emits a real `403`.
//! For a small response from a fast origin (an error page, a stack trace: what
//! the CRS `RESPONSE-95x` rules are for) that is the likely outcome. For a
//! streamed or large one it is not. It is a property of upstream timing, not a
//! contract, and nothing here depends on which way it goes.
//!
//! Because a truncated response is nonetheless a visibly broken one, enforcing
//! is opt-in: the default mode observes and logs.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use http::HeaderMap;
use tracing::warn;
use waf_common::metrics::{self, BudgetEvent};
use waf_common::{RequestCtx, ResponseCtx, is_inspectable_response_media_type, is_opaque_content_encoding};

use crate::context::{MAX_FOLDED_HEADER_BYTES, MAX_HEADER_VALUES_PER_NAME};

/// Bytes buffered per response inspection window (64 KiB).
///
/// A *window*, not a total: the body is scanned window by window, so this bounds
/// peak memory and — in [`ResponseInspectMode::Enforce`] — how many bytes may be
/// held back before they are released. Matches
/// [`crate::context::BODY_PREVIEW_LIMIT`] so both directions cost the same.
pub const RESPONSE_WINDOW_BYTES: usize = 64 * 1024;

/// Bytes of the previous window replayed at the head of the next one.
///
/// Without it a signature straddling a window boundary would be split across
/// two scans and matched by neither.
pub const RESPONSE_WINDOW_OVERLAP: usize = 4 * 1024;

/// Default ceiling on how many response-body bytes are inspected (512 KiB).
///
/// Deliberately `ModSecurity`'s `SecResponseBodyLimit` default — its
/// `modsecurity.conf-recommended` reads *"Buffer response bodies of up to 512 KB
/// in length"* / `SecResponseBodyLimit 524288`. Past the ceiling the behaviour
/// is upstream's `SecResponseBodyLimitAction ProcessPartial`: scan the prefix,
/// stream the remainder uninspected. `Reject` is not offered — upstream can
/// reject because it decides before the response is flushed, and we cannot (see
/// the module docs), so a "reject" here would only ever be a truncation
/// mislabelled as a refusal.
pub const MAX_INSPECTED_RESPONSE_BYTES: usize = 512 * 1024;

/// Longest a chunk may be withheld while a window fills, in
/// [`ResponseInspectMode::Enforce`].
///
/// The ceiling is only consulted when the *next* chunk arrives — a synchronous
/// filter has no timer of its own — so it converts a trickling origin from
/// "held until 64 KiB accumulates" into "held for at most one inter-chunk gap".
/// See [`ResponseInspectionPolicy::window_bytes`] for the way out for origins
/// that cannot tolerate even that.
pub const RESPONSE_FLUSH_AFTER: Duration = Duration::from_millis(100);

/// What a response-phase finding is allowed to do to the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResponseInspectMode {
    /// Scan and log; never touch the bytes. Chunks are forwarded downstream
    /// untouched and are copied — not moved — into the inspection window, so
    /// this adds no latency and cannot truncate anything.
    ///
    /// The default. A response-phase false positive under
    /// [`Self::Enforce`] is a broken page with a `200 OK` status on it, which
    /// is indistinguishable from a WAF bug to everyone downstream; that is not
    /// a thing to switch on for an operator who did not ask for it.
    #[default]
    Observe,
    /// Withhold each chunk until its window has been scanned, and abort the
    /// response on a finding. Contains the leak (no inspected byte reaches the
    /// client) at the cost of a truncated HTTP message and up to one window of
    /// added latency.
    Enforce,
}

impl ResponseInspectMode {
    /// Parse an operator-supplied spelling; `None` when unrecognised.
    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "observe" | "log" | "detect" | "off" => Some(Self::Observe),
            "enforce" | "block" | "truncate" => Some(Self::Enforce),
            _ => None,
        }
    }
}

/// How response bodies are inspected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseInspectionPolicy {
    /// What a finding may do to the stream.
    pub mode: ResponseInspectMode,
    /// Bytes buffered before a window is scanned.
    ///
    /// Setting this to `1` degenerates to per-chunk scanning: every chunk is
    /// scanned and released as it arrives, so nothing is ever held waiting for
    /// more data. That is the escape hatch for an origin that streams inside an
    /// inspectable media type (a chunked `application/json` long-poll), at the
    /// cost of one detector pass per chunk instead of one per 64 KiB. Detection
    /// coverage is unaffected — [`Self::overlap_bytes`] is what carries a
    /// signature across a boundary, not the window size.
    pub window_bytes: usize,
    /// Bytes of the previous window replayed at the head of the next.
    pub overlap_bytes: usize,
    /// Total response-body bytes inspected before the rest is streamed
    /// uninspected. `0` = no ceiling.
    pub max_total_bytes: usize,
    /// Longest a chunk is withheld while a window fills (enforce mode only).
    pub flush_after: Duration,
}

impl Default for ResponseInspectionPolicy {
    fn default() -> Self {
        Self {
            mode: ResponseInspectMode::Observe,
            window_bytes: RESPONSE_WINDOW_BYTES,
            overlap_bytes: RESPONSE_WINDOW_OVERLAP,
            max_total_bytes: MAX_INSPECTED_RESPONSE_BYTES,
            flush_after: RESPONSE_FLUSH_AFTER,
        }
    }
}

impl ResponseInspectionPolicy {
    /// Build the policy from the environment, falling back to the safe default.
    ///
    /// | Variable | Meaning |
    /// |----------|---------|
    /// | `PRXWAF_RESPONSE_INSPECT_MODE` | `observe` (default) or `enforce` |
    /// | `PRXWAF_RESPONSE_INSPECT_MAX_BYTES` | inspected-byte ceiling (`0` = unlimited) |
    /// | `PRXWAF_RESPONSE_INSPECT_WINDOW_BYTES` | window size (`1` = scan per chunk) |
    /// | `PRXWAF_RESPONSE_INSPECT_FLUSH_MS` | longest a chunk is withheld |
    ///
    /// The environment is used rather than the TOML config on purpose: this is
    /// the same shape (and the same fail-safe-on-typo rule) as
    /// [`crate::context::BodyInspectionPolicy`], which is the request-side
    /// counterpart, so the two directions are configured the same way.
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

        if let Some(raw) = get("PRXWAF_RESPONSE_INSPECT_MODE") {
            if let Some(v) = ResponseInspectMode::parse(&raw) {
                policy.mode = v;
            } else {
                warn!("PRXWAF_RESPONSE_INSPECT_MODE='{raw}' is not 'observe' or 'enforce'; keeping 'observe'");
            }
        }
        if let Some(raw) = get("PRXWAF_RESPONSE_INSPECT_MAX_BYTES") {
            match raw.trim().parse::<usize>() {
                Ok(v) => policy.max_total_bytes = v,
                Err(e) => {
                    warn!("PRXWAF_RESPONSE_INSPECT_MAX_BYTES='{raw}' is not a byte count ({e}); keeping default");
                }
            }
        }
        if let Some(raw) = get("PRXWAF_RESPONSE_INSPECT_WINDOW_BYTES") {
            match raw.trim().parse::<usize>() {
                Ok(v) => policy.window_bytes = v,
                Err(e) => {
                    warn!("PRXWAF_RESPONSE_INSPECT_WINDOW_BYTES='{raw}' is not a byte count ({e}); keeping default");
                }
            }
        }
        if let Some(raw) = get("PRXWAF_RESPONSE_INSPECT_FLUSH_MS") {
            match raw.trim().parse::<u64>() {
                Ok(v) => policy.flush_after = Duration::from_millis(v),
                Err(e) => {
                    warn!("PRXWAF_RESPONSE_INSPECT_FLUSH_MS='{raw}' is not a millisecond count ({e}); keeping default");
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

/// Process-wide response inspection policy, resolved once from the environment.
static RESPONSE_POLICY: std::sync::OnceLock<ResponseInspectionPolicy> = std::sync::OnceLock::new();

/// The active response inspection policy.
pub fn response_inspection_policy() -> &'static ResponseInspectionPolicy {
    RESPONSE_POLICY.get_or_init(ResponseInspectionPolicy::from_env)
}

/// Whether a response is inspected, and if not, why.
///
/// Every variant other than [`Self::Inspect`] means the response streams exactly
/// as it did before this module existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseGate {
    /// Buffer and scan this response.
    Inspect,
    /// No response-phase detector is registered. The zero-cost fast path, and
    /// the state this round ships in.
    NoDetectors,
    /// The host has WAF guarding switched off.
    GuardDisabled,
    /// The status carries no body (`1xx` / `204` / `304`), so there is nothing
    /// to scan.
    NoBody,
    /// The media type is not one the detectors can read — a binary download, or
    /// a `text/event-stream` that must never be buffered.
    MediaType,
    /// The body is compressed, so scanning it would match plaintext patterns
    /// against opaque bytes.
    ContentEncoding,
}

impl ResponseGate {
    /// `true` when the response is to be inspected.
    #[must_use]
    pub const fn is_inspect(self) -> bool {
        matches!(self, Self::Inspect)
    }

    /// Operator-facing reason, for the one `debug!` line a skipped response
    /// costs.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::NoDetectors => "no response-phase detector registered",
            Self::GuardDisabled => "WAF guarding disabled for this host",
            Self::NoBody => "status carries no body",
            Self::MediaType => "media type is not inspectable",
            Self::ContentEncoding => "response body is compressed",
        }
    }
}

/// Decide whether a response is inspected.
///
/// A pure function of the four things the decision actually depends on, so it
/// can be exhaustively tested without a session, a header map or a running
/// engine. `has_detectors` is threaded in rather than read from a global for the
/// same reason; the gateway passes `!response_checks.is_empty()`.
#[must_use]
pub fn gate(
    has_detectors: bool,
    guard_status: bool,
    status: u16,
    content_type: Option<&str>,
    content_encoding: Option<&str>,
) -> ResponseGate {
    if !has_detectors {
        return ResponseGate::NoDetectors;
    }
    if !guard_status {
        return ResponseGate::GuardDisabled;
    }
    // RFC 9110 §15.2 / §15.4.5: these statuses never carry a body.
    if (100..200).contains(&status) || status == 204 || status == 304 {
        return ResponseGate::NoBody;
    }
    if is_opaque_content_encoding(content_encoding) {
        return ResponseGate::ContentEncoding;
    }
    if !is_inspectable_response_media_type(content_type) {
        return ResponseGate::MediaType;
    }
    ResponseGate::Inspect
}

/// Fold a response [`HeaderMap`] into the flat map the detectors read.
///
/// Same folding rules as [`crate::context::fold_request_headers`] — every value
/// of a repeated name is kept, because `Set-Cookie` in particular is routinely
/// repeated and dropping all but one line would hide exactly the header a
/// leak-detection rule is looking at. Unlike the request side an overflow does
/// not refuse anything: the response has already been produced, and the honest
/// answer to "this header is absurdly long" is to stop appending, not to break
/// a page the origin considers valid.
#[must_use]
pub fn fold_response_headers(headers: &HeaderMap) -> HashMap<String, String> {
    let mut folded: HashMap<String, (usize, String)> = HashMap::with_capacity(headers.keys_len());

    for (name, value) in headers {
        // `http::HeaderName` always stores its name lower-cased.
        let name = name.as_str();
        let Ok(v) = std::str::from_utf8(value.as_bytes()) else {
            continue;
        };

        if let Some((count, acc)) = folded.get_mut(name) {
            *count = count.saturating_add(1);
            let folded_len = acc.len().saturating_add(2).saturating_add(v.len());
            if *count > MAX_HEADER_VALUES_PER_NAME || folded_len > MAX_FOLDED_HEADER_BYTES {
                continue;
            }
            acc.push_str(", ");
            acc.push_str(v);
            continue;
        }

        folded.insert(name.to_string(), (1, v.to_string()));
    }

    folded.into_iter().map(|(k, (_, v))| (k, v)).collect()
}

/// What the caller must do with one response-body chunk.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ResponseStep {
    /// Bytes to scan (previous-window overlap + the new window), if any.
    pub inspect: Option<Bytes>,
    /// `true` when bytes beyond this window will never be scanned, because the
    /// inspected-byte ceiling was reached. Surfaces as
    /// [`ResponseCtx::body_truncated`].
    pub truncated: bool,
    /// Set on the single step where the ceiling was crossed, so the caller can
    /// emit exactly one operator-visible record per response.
    pub over_cap: bool,
}

/// Streaming response-body inspector.
///
/// Mirrors [`crate::context::BodyInspector`] and diverges from it in exactly one
/// respect: the request side can refuse an over-large body with `413`, and this
/// side cannot refuse anything, because the status is already gone. Its ceiling
/// therefore always behaves like `ProcessPartial`.
#[derive(Debug)]
pub struct ResponseInspector {
    policy: ResponseInspectionPolicy,
    status: u16,
    headers: HashMap<String, String>,
    /// Buffered bytes not yet scanned.
    pending: BytesMut,
    /// Tail of the previous window, replayed at the head of the next scan.
    carry: BytesMut,
    /// Total body bytes seen so far.
    total: usize,
    /// When the oldest currently-buffered byte arrived; drives
    /// [`ResponseInspectionPolicy::flush_after`]. `None` when nothing is held.
    holding_since: Option<Instant>,
    /// Ceiling crossed: everything from here on streams uninspected.
    passthrough: bool,
}

impl ResponseInspector {
    /// Arm an inspector for a response that passed [`gate`].
    #[must_use]
    pub fn new(policy: ResponseInspectionPolicy, status: u16, headers: HashMap<String, String>) -> Self {
        Self {
            policy: policy.normalise(),
            status,
            headers,
            pending: BytesMut::new(),
            carry: BytesMut::new(),
            total: 0,
            holding_since: None,
            passthrough: false,
        }
    }

    /// The mode this inspector runs in.
    #[must_use]
    pub const fn mode(&self) -> ResponseInspectMode {
        self.policy.mode
    }

    /// Total response-body bytes seen so far.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.total
    }

    /// Feed one downstream-bound chunk and learn what to scan.
    ///
    /// `body` is the chunk Pingora is about to write downstream, and this is the
    /// only place it may be altered:
    ///
    /// * [`ResponseInspectMode::Observe`] never writes to `body`. The chunk is
    ///   *copied* into the window and travels on in the same turn, so the client
    ///   sees byte-identical timing to a build with no response phase at all.
    /// * [`ResponseInspectMode::Enforce`] takes the chunk out of `body` and puts
    ///   it back only once its window has been scanned. As on the request side,
    ///   a withheld chunk must be an **empty** `Bytes` rather than `None` —
    ///   Pingora reads `None` as end-of-body and would terminate the response
    ///   early.
    pub fn push(&mut self, body: &mut Option<Bytes>, end_of_stream: bool) -> ResponseStep {
        let enforcing = self.policy.mode == ResponseInspectMode::Enforce;

        // Past the ceiling: relay untouched, scan nothing.
        if self.passthrough {
            return ResponseStep::default();
        }

        let chunk = if enforcing {
            let taken = body.take();
            *body = withheld_body(end_of_stream);
            taken
        } else {
            body.clone()
        };

        if let Some(c) = &chunk
            && !c.is_empty()
        {
            if self.holding_since.is_none() {
                self.holding_since = Some(Instant::now());
            }
            self.total = self.total.saturating_add(c.len());
            self.pending.extend_from_slice(c);
        }

        let over_cap = self.policy.max_total_bytes > 0 && self.total > self.policy.max_total_bytes;
        let window_ready = self.pending.len() >= self.policy.window_bytes;
        let deadline_hit = self
            .holding_since
            .is_some_and(|t| t.elapsed() >= self.policy.flush_after);

        if self.pending.is_empty() || !(window_ready || end_of_stream || over_cap || deadline_hit) {
            // Hold the bytes back until a window (or the stream) completes. In
            // observe mode nothing is being held in the first place.
            return ResponseStep::default();
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

        self.holding_since = None;
        if over_cap {
            // From here the rest of the body is delivered uninspected. Counted
            // once per response, not per chunk: `passthrough` latches, and this
            // is the transition, so a 100 MiB response contributes 1.
            metrics::record_budget_event(BudgetEvent::ResponseBodyTruncated);
            self.passthrough = true;
        }

        // Enforce mode: the window has been formed, so release it — but only
        // after the caller has scanned `inspect` and come back clean. The caller
        // does that by dropping the whole response on a finding; there is no
        // path that writes these bytes downstream ahead of the scan, because
        // `body` was emptied above and is only refilled here.
        if enforcing {
            *body = release_body(Some(window), end_of_stream);
        }

        ResponseStep {
            inspect: Some(inspect),
            truncated: over_cap,
            over_cap,
        }
    }

    /// Build the [`ResponseCtx`] for one inspection window.
    #[must_use]
    pub fn context(&self, request: &RequestCtx, window: Bytes, truncated: bool) -> ResponseCtx {
        ResponseCtx {
            request: request.clone(),
            status: self.status,
            headers: self.headers.clone(),
            body_preview: window,
            body_truncated: truncated,
        }
    }
}

/// Body value that withholds the current chunk from the downstream.
///
/// Pingora reads `None` as "the body is finished", so a chunk that is merely
/// being buffered for inspection has to be an **empty** `Bytes`. Same reasoning
/// (and same shape) as the request-side helper in [`crate::proxy`].
const fn withheld_body(end_of_stream: bool) -> Option<Bytes> {
    if end_of_stream { None } else { Some(Bytes::new()) }
}

/// Body value that releases `forward` (already inspected) to the downstream,
/// falling back to [`withheld_body`] when there is nothing to release yet.
fn release_body(forward: Option<Bytes>, end_of_stream: bool) -> Option<Bytes> {
    forward.or_else(|| withheld_body(end_of_stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn enforcing(window: usize, cap: usize) -> ResponseInspectionPolicy {
        ResponseInspectionPolicy {
            mode: ResponseInspectMode::Enforce,
            window_bytes: window,
            overlap_bytes: 64.min(window.saturating_sub(1)),
            max_total_bytes: cap,
            // Effectively disable the deadline so the window logic is what is
            // under test; the deadline gets its own test.
            flush_after: Duration::from_hours(1),
        }
    }

    fn observing(window: usize, cap: usize) -> ResponseInspectionPolicy {
        ResponseInspectionPolicy {
            mode: ResponseInspectMode::Observe,
            ..enforcing(window, cap)
        }
    }

    // ── The gate ─────────────────────────────────────────────────────────────

    #[test]
    fn no_detectors_short_circuits_every_other_condition() {
        // The invariant this whole round rests on: with nothing registered, the
        // gate closes before it even looks at the response.
        assert_eq!(
            gate(false, true, 200, Some("text/html"), None),
            ResponseGate::NoDetectors
        );
        assert!(!gate(false, true, 200, Some("text/html"), None).is_inspect());
    }

    #[test]
    fn gate_admits_a_plain_html_response() {
        let ct = Some("text/html; charset=utf-8");
        assert_eq!(gate(true, true, 200, ct, None), ResponseGate::Inspect);
        // A 500 is exactly what CRS 950100 exists to catch, so it must pass.
        assert_eq!(gate(true, true, 500, ct, None), ResponseGate::Inspect);
        assert_eq!(
            gate(true, true, 200, ct, Some("identity")),
            ResponseGate::Inspect,
            "`identity` is not compression"
        );
    }

    #[test]
    fn gate_rejects_what_must_never_be_buffered() {
        assert_eq!(
            gate(true, true, 200, Some("text/event-stream"), None),
            ResponseGate::MediaType,
            "SSE must not be buffered"
        );
        assert_eq!(
            gate(true, true, 200, Some("application/octet-stream"), None),
            ResponseGate::MediaType,
        );
        assert_eq!(gate(true, true, 200, Some("video/mp4"), None), ResponseGate::MediaType);
        assert_eq!(
            gate(true, true, 200, Some("text/html"), Some("gzip")),
            ResponseGate::ContentEncoding,
        );
        assert_eq!(gate(true, true, 204, None, None), ResponseGate::NoBody);
        assert_eq!(gate(true, true, 304, None, None), ResponseGate::NoBody);
        assert_eq!(gate(true, true, 101, None, None), ResponseGate::NoBody);
        assert_eq!(
            gate(true, false, 200, Some("text/html"), None),
            ResponseGate::GuardDisabled,
        );
        // No Content-Type at all is not inspected.
        assert_eq!(gate(true, true, 200, None, None), ResponseGate::MediaType);
    }

    // ── Observe mode: the stream must be untouched ───────────────────────────

    #[test]
    fn observe_never_alters_the_body() {
        let mut inspector = ResponseInspector::new(observing(1024, 0), 200, headers(&[]));
        let chunk = Bytes::from_static(b"<html>hello</html>");

        let mut body = Some(chunk.clone());
        let step = inspector.push(&mut body, false);
        // Forwarded verbatim, in the same turn, before any scan result exists.
        assert_eq!(body, Some(chunk.clone()));
        assert!(step.inspect.is_none(), "window is not full yet");

        let mut body = None;
        let step = inspector.push(&mut body, true);
        assert_eq!(body, None, "end of stream must stay end of stream");
        assert_eq!(step.inspect.as_deref(), Some(chunk.as_ref()));
    }

    #[test]
    fn observe_leaves_a_none_chunk_alone() {
        // Pingora may deliver `Body(None, false)`. Observe mode must not turn
        // that into an empty chunk — that is a wire-level change.
        let mut inspector = ResponseInspector::new(observing(1024, 0), 200, headers(&[]));
        let mut body = None;
        let _ = inspector.push(&mut body, false);
        assert_eq!(body, None);
    }

    // ── Enforce mode: nothing leaves before it is scanned ────────────────────

    #[test]
    fn enforce_withholds_bytes_until_their_window_is_scanned() {
        let mut inspector = ResponseInspector::new(enforcing(1024, 0), 200, headers(&[]));

        let mut body = Some(Bytes::from_static(b"partial"));
        let step = inspector.push(&mut body, false);
        assert_eq!(body, Some(Bytes::new()), "un-scanned bytes were released to the client");
        assert!(step.inspect.is_none());

        let mut body = None;
        let step = inspector.push(&mut body, true);
        assert_eq!(step.inspect.as_deref(), Some(b"partial".as_ref()));
        assert_eq!(body.as_deref(), Some(b"partial".as_ref()), "released after the scan");
    }

    #[test]
    fn enforce_forwards_every_byte_exactly_once_and_in_order() {
        // The cache accumulator downstream of this filter depends on it.
        let mut inspector = ResponseInspector::new(enforcing(16, 0), 200, headers(&[]));
        let mut forwarded = Vec::new();
        let source: Vec<u8> = (0..200u32).map(|i| u8::try_from(i % 251).unwrap_or(0)).collect();

        for (i, piece) in source.chunks(7).enumerate() {
            let last = (i + 1) * 7 >= source.len();
            let mut body = Some(Bytes::copy_from_slice(piece));
            let _ = inspector.push(&mut body, last);
            if let Some(out) = body {
                forwarded.extend_from_slice(&out);
            }
        }
        assert_eq!(forwarded, source, "bytes were dropped, duplicated or reordered");
    }

    #[test]
    fn window_overlap_catches_a_boundary_straddling_leak() {
        let mut inspector = ResponseInspector::new(enforcing(1024, 0), 200, headers(&[]));
        let mut first = vec![b'x'; 1020];
        first.extend_from_slice(b"ORA-");
        let mut body = Some(Bytes::from(first));
        let _ = inspector.push(&mut body, false);

        let mut body = Some(Bytes::from_static(b"00933: SQL command not properly ended"));
        let step = inspector.push(&mut body, true);
        let scanned = step.inspect.expect("second window");
        let text = String::from_utf8_lossy(&scanned);
        assert!(
            text.contains("ORA-00933: SQL command not properly ended"),
            "the leak was split across windows: {text}"
        );
    }

    // ── The ceiling behaves like ProcessPartial ──────────────────────────────

    #[test]
    fn over_ceiling_streams_the_remainder_uninspected_and_says_so_once() {
        let mut inspector = ResponseInspector::new(enforcing(1024, 4096), 200, headers(&[]));
        let mut over_cap_steps = 0;
        let mut truncated_steps = 0;
        let mut forwarded = 0usize;

        for _ in 0..16 {
            let mut body = Some(Bytes::from(vec![b'A'; 1024]));
            let step = inspector.push(&mut body, false);
            forwarded += body.map_or(0, |b| b.len());
            if step.over_cap {
                over_cap_steps += 1;
            }
            if step.truncated {
                truncated_steps += 1;
            }
        }

        assert_eq!(over_cap_steps, 1, "the ceiling crossing must be reported exactly once");
        assert_eq!(truncated_steps, 1);
        assert_eq!(
            forwarded,
            16 * 1024,
            "a response past the ceiling must still be delivered in full"
        );
    }

    #[test]
    fn a_response_under_the_ceiling_is_never_flagged_truncated() {
        let mut inspector = ResponseInspector::new(enforcing(1024, 4096), 200, headers(&[]));
        let mut body = Some(Bytes::from(vec![b'A'; 512]));
        let step = inspector.push(&mut body, true);
        assert!(step.inspect.is_some());
        assert!(!step.truncated);
        assert!(!step.over_cap);
    }

    // ── The streaming escape hatches ─────────────────────────────────────────

    #[test]
    fn a_one_byte_window_scans_and_releases_every_chunk_immediately() {
        // The documented way out for a chunked JSON stream: nothing is ever
        // held waiting for a later chunk.
        let policy = ResponseInspectionPolicy {
            window_bytes: 1,
            ..enforcing(1, 0)
        };
        let mut inspector = ResponseInspector::new(policy, 200, headers(&[]));
        for i in 0..5u8 {
            let chunk = Bytes::copy_from_slice(&[b'a' + i]);
            let mut body = Some(chunk.clone());
            let step = inspector.push(&mut body, false);
            assert!(step.inspect.is_some(), "chunk {i} was not scanned on arrival");
            assert_eq!(body, Some(chunk), "chunk {i} was held back");
        }
    }

    #[test]
    fn the_flush_deadline_releases_a_partial_window() {
        let policy = ResponseInspectionPolicy {
            flush_after: Duration::ZERO,
            ..enforcing(64 * 1024, 0)
        };
        let mut inspector = ResponseInspector::new(policy, 200, headers(&[]));
        // Far short of the 64 KiB window, but the deadline has already expired.
        let chunk = Bytes::from_static(b"{\"partial\":true}");
        let mut body = Some(chunk.clone());
        let step = inspector.push(&mut body, false);
        assert!(step.inspect.is_some(), "the deadline did not force a scan");
        assert_eq!(body, Some(chunk), "the deadline did not release the chunk");
    }

    // ── Header folding ───────────────────────────────────────────────────────

    #[test]
    fn repeated_response_headers_are_all_kept() {
        let mut map = HeaderMap::new();
        map.append("set-cookie", HeaderValue::from_static("a=1"));
        map.append("set-cookie", HeaderValue::from_static("b=2"));
        map.append("content-type", HeaderValue::from_static("text/html"));
        let folded = fold_response_headers(&map);
        assert_eq!(folded.get("set-cookie").map(String::as_str), Some("a=1, b=2"));
        assert_eq!(folded.get("content-type").map(String::as_str), Some("text/html"));
    }

    #[test]
    fn header_folding_is_bounded_but_never_refuses() {
        let mut map = HeaderMap::new();
        for _ in 0..(MAX_HEADER_VALUES_PER_NAME + 10) {
            map.append("x-trace", HeaderValue::from_static("v"));
        }
        let folded = fold_response_headers(&map);
        let value = folded.get("x-trace").map(String::as_str).unwrap_or_default();
        assert!(!value.is_empty(), "the header was dropped instead of bounded");
        assert!(value.len() <= MAX_FOLDED_HEADER_BYTES);
    }

    // ── Policy plumbing ──────────────────────────────────────────────────────

    #[test]
    fn the_default_policy_observes() {
        let policy = ResponseInspectionPolicy::default();
        assert_eq!(policy.mode, ResponseInspectMode::Observe);
        assert_eq!(policy.max_total_bytes, MAX_INSPECTED_RESPONSE_BYTES);
        assert_eq!(policy.window_bytes, RESPONSE_WINDOW_BYTES);
        // ModSecurity's SecResponseBodyLimit default, to the byte.
        assert_eq!(MAX_INSPECTED_RESPONSE_BYTES, 524_288);
    }

    #[test]
    fn env_overrides_are_honoured_and_bad_values_keep_the_default() {
        let policy = ResponseInspectionPolicy::from_env_source(|key| match key {
            "PRXWAF_RESPONSE_INSPECT_MODE" => Some("enforce".to_string()),
            "PRXWAF_RESPONSE_INSPECT_MAX_BYTES" => Some("1024".to_string()),
            "PRXWAF_RESPONSE_INSPECT_WINDOW_BYTES" => Some("1".to_string()),
            "PRXWAF_RESPONSE_INSPECT_FLUSH_MS" => Some("25".to_string()),
            _ => None,
        });
        assert_eq!(policy.mode, ResponseInspectMode::Enforce);
        assert_eq!(policy.max_total_bytes, 1024);
        assert_eq!(policy.window_bytes, 1);
        assert_eq!(policy.overlap_bytes, 0, "overlap is clamped below the window");
        assert_eq!(policy.flush_after, Duration::from_millis(25));

        // A typo must never quietly switch enforcement on.
        let policy = ResponseInspectionPolicy::from_env_source(|key| match key {
            "PRXWAF_RESPONSE_INSPECT_MODE" => Some("enfroce".to_string()),
            "PRXWAF_RESPONSE_INSPECT_MAX_BYTES" => Some("lots".to_string()),
            _ => None,
        });
        assert_eq!(policy.mode, ResponseInspectMode::Observe);
        assert_eq!(policy.max_total_bytes, MAX_INSPECTED_RESPONSE_BYTES);
    }

    #[test]
    fn withheld_chunk_is_empty_not_none() {
        assert_eq!(withheld_body(false), Some(Bytes::new()));
        assert_eq!(withheld_body(true), None);
        assert_eq!(release_body(None, false), Some(Bytes::new()));
        assert_eq!(release_body(None, true), None);
    }
}
