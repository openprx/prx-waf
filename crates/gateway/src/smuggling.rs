//! HTTP request-smuggling structural detection (gateway header phase).
//!
//! HTTP request smuggling (a.k.a. request de-synchronisation) exploits the
//! fact that a front-end proxy and a back-end origin can disagree on where one
//! request ends and the next begins. The classic desync primitives live
//! entirely in the **request framing headers** — `Content-Length` (CL) and
//! `Transfer-Encoding` (TE) — so this detector inspects the parsed request
//! [`http::HeaderMap`] for the structural indicators that betray a smuggling
//! attempt *as it reaches the WAF*.
//!
//! ## Posture — shadow / log-only
//! This detector never changes the request's allow/block decision. When an
//! indicator is present it emits a structured `tracing::warn` record and the
//! request continues down the normal pipeline unchanged. This mirrors the Lane
//! 2 semantic-engine "shadow" philosophy: observe first, do not risk enforcing
//! on a hot, per-request path.
//!
//! ## Honest coverage boundary
//! Pingora's HTTP/1.1 parser (and the `http` crate's `HeaderName`/`HeaderValue`
//! validation) already reject or normalise a number of raw wire-level smuggling
//! vectors before they ever reach `request_filter`:
//!
//! * **Bare CR / LF inside a header name or value** cannot survive parsing — a
//!   CRLF terminates the header line, and `HeaderValue` refuses to hold raw
//!   `\r`/`\n`. So header-splitting via embedded CRLF is *not* reachable here
//!   and is intentionally **not** implemented (implementing it would be dead
//!   code that can never fire).
//! * **A space before the colon** (`Transfer-Encoding : chunked`) is rejected
//!   at parse time and never becomes a `HeaderName`.
//!
//! What *does* remain observable in the parsed `HeaderMap` — and is what this
//! detector targets — is the **structure** of the framing headers:
//! duplicated `Content-Length`, conflicting `Content-Length` values, CL and TE
//! coexisting, duplicated `Transfer-Encoding`, and an obfuscated / non-canonical
//! `Transfer-Encoding` coding. These can legitimately be present in the map
//! because the `http` crate stores multiple same-named header lines as multiple
//! values, and preserves each value's raw bytes.
//!
//! ## Hot-path cost
//! [`detect`] runs on every request. It performs at most two `get_all` walks
//! (`content-length`, `transfer-encoding`) — O(number of those specific header
//! lines), which is normally 0–1 each. It allocates nothing for a clean request
//! (the returned `Vec` only allocates once an indicator is actually pushed) and
//! never touches the request body.

use std::net::IpAddr;

use http::HeaderMap;
use http::header::{CONTENT_LENGTH, TRANSFER_ENCODING};
use tracing::warn;

/// A single structural request-smuggling indicator found in the request
/// headers. Each variant maps to one recognised desync primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmugglingIndicator {
    /// More than one `Content-Length` header line was present (or a single
    /// value carried a comma-separated list). RFC 7230 §3.3.2 forbids this;
    /// front-end and back-end may pick different values → CL.CL desync.
    DuplicateContentLength,
    /// Two `Content-Length` header lines carried **conflicting** numeric
    /// values — the strongest CL.CL desync signal.
    ConflictingContentLength,
    /// Both `Content-Length` and `Transfer-Encoding` were present. RFC 7230
    /// §3.3.3 says TE wins and CL must be dropped, but proxies disagree in
    /// practice → the classic CL.TE / TE.CL desync.
    ContentLengthAndTransferEncoding,
    /// More than one `Transfer-Encoding` header line was present, a common way
    /// to hide a second `chunked` coding from one of the two servers.
    DuplicateTransferEncoding,
    /// A `Transfer-Encoding` value was not a clean, lone `chunked` token (e.g.
    /// `xchunked`, `chunked, identity`, `identity`, or odd casing/whitespace) —
    /// obfuscation used to make only one server honour chunked framing.
    ObfuscatedTransferEncoding,
}

impl SmugglingIndicator {
    /// Stable, lower-kebab identifier for structured logging / metrics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DuplicateContentLength => "duplicate-content-length",
            Self::ConflictingContentLength => "conflicting-content-length",
            Self::ContentLengthAndTransferEncoding => "content-length-and-transfer-encoding",
            Self::DuplicateTransferEncoding => "duplicate-transfer-encoding",
            Self::ObfuscatedTransferEncoding => "obfuscated-transfer-encoding",
        }
    }
}

/// Inspect the parsed request headers for structural smuggling indicators.
///
/// Pure and side-effect free so it can be unit-tested against a hand-built
/// [`HeaderMap`]. Returns an empty `Vec` (no allocation) for a clean request.
#[must_use]
pub fn detect(headers: &HeaderMap) -> Vec<SmugglingIndicator> {
    let mut findings = Vec::new();

    // ── Content-Length structure ─────────────────────────────────────────────
    let mut cl_count: usize = 0;
    let mut first_cl: Option<&[u8]> = None;
    let mut cl_conflict = false;
    let mut cl_list_in_value = false;
    for value in &headers.get_all(CONTENT_LENGTH) {
        cl_count += 1;
        let bytes = value.as_bytes();
        // A single value may itself smuggle a list, e.g. `Content-Length: 5, 6`.
        if bytes.contains(&b',') {
            cl_list_in_value = true;
        }
        match first_cl {
            None => first_cl = Some(bytes),
            Some(prev) if prev != bytes => cl_conflict = true,
            Some(_) => {}
        }
    }
    let has_cl = cl_count > 0;
    if cl_count > 1 || cl_list_in_value {
        findings.push(SmugglingIndicator::DuplicateContentLength);
    }
    if cl_conflict {
        findings.push(SmugglingIndicator::ConflictingContentLength);
    }

    // ── Transfer-Encoding structure ──────────────────────────────────────────
    let mut te_count: usize = 0;
    let mut te_obfuscated = false;
    for value in &headers.get_all(TRANSFER_ENCODING) {
        te_count += 1;
        if !is_canonical_chunked(value.as_bytes()) {
            te_obfuscated = true;
        }
    }
    let has_te = te_count > 0;
    if te_count > 1 {
        findings.push(SmugglingIndicator::DuplicateTransferEncoding);
    }
    if te_obfuscated {
        findings.push(SmugglingIndicator::ObfuscatedTransferEncoding);
    }

    // ── CL + TE coexistence (evaluated last so it reads after the specifics) ──
    if has_cl && has_te {
        findings.push(SmugglingIndicator::ContentLengthAndTransferEncoding);
    }

    findings
}

/// Whether a `Transfer-Encoding` value is exactly the canonical, lone `chunked`
/// token (ASCII-case-insensitive, surrounded only by optional whitespace).
///
/// Anything else — `xchunked`, `chunked, identity`, `identity`, `gzip, chunked`,
/// embedded control bytes, etc. — is treated as obfuscated. Under the log-only
/// posture a rare false positive (e.g. a legitimate `gzip, chunked`) only
/// produces a log line, never a block; tightening this is a tuning knob.
fn is_canonical_chunked(value: &[u8]) -> bool {
    let trimmed = trim_ascii_ws(value);
    trimmed.eq_ignore_ascii_case(b"chunked")
}

/// Trim leading/trailing ASCII spaces and horizontal tabs without allocating.
fn trim_ascii_ws(mut bytes: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = bytes {
        if *first == b' ' || *first == b'\t' {
            bytes = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = bytes {
        if *last == b' ' || *last == b'\t' {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

/// Emit a structured, shadow-mode log record for a set of findings.
///
/// Call only when `findings` is non-empty. The request is **not** blocked — this
/// is observation only.
pub fn log_findings(findings: &[SmugglingIndicator], client_ip: IpAddr, host: &str, path: &str) {
    // Build a compact, comma-joined indicator list for one log line.
    let mut indicators = String::new();
    for (i, f) in findings.iter().enumerate() {
        if i > 0 {
            indicators.push(',');
        }
        indicators.push_str(f.as_str());
    }
    warn!(
        target: "waf.smuggling",
        %client_ip,
        host = %host,
        path = %path,
        indicators = %indicators,
        "HTTP request-smuggling structure detected (shadow / log-only)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, HeaderName, HeaderValue};

    fn hv(s: &str) -> HeaderValue {
        HeaderValue::from_str(s).expect("valid header value")
    }

    /// Append (not overwrite) a header line so duplicates accumulate exactly as
    /// they would after wire parsing.
    fn append(map: &mut HeaderMap, name: &str, value: &str) {
        let name = HeaderName::from_bytes(name.as_bytes()).expect("valid header name");
        map.append(name, hv(value));
    }

    #[test]
    fn clean_request_has_no_findings_and_no_alloc() {
        let mut map = HeaderMap::new();
        append(&mut map, "host", "example.com");
        append(&mut map, "content-length", "42");
        let findings = detect(&map);
        assert!(findings.is_empty());
        // A clean request must not allocate the findings Vec.
        assert_eq!(findings.capacity(), 0);
    }

    #[test]
    fn clean_chunked_request_is_not_flagged() {
        let mut map = HeaderMap::new();
        append(&mut map, "transfer-encoding", "chunked");
        assert!(detect(&map).is_empty());
    }

    #[test]
    fn duplicate_content_length_same_value() {
        let mut map = HeaderMap::new();
        append(&mut map, "content-length", "10");
        append(&mut map, "content-length", "10");
        let f = detect(&map);
        assert!(f.contains(&SmugglingIndicator::DuplicateContentLength));
        // Identical values → duplicate but not conflicting.
        assert!(!f.contains(&SmugglingIndicator::ConflictingContentLength));
    }

    #[test]
    fn conflicting_content_length() {
        let mut map = HeaderMap::new();
        append(&mut map, "content-length", "10");
        append(&mut map, "content-length", "20");
        let f = detect(&map);
        assert!(f.contains(&SmugglingIndicator::DuplicateContentLength));
        assert!(f.contains(&SmugglingIndicator::ConflictingContentLength));
    }

    #[test]
    fn content_length_comma_list_in_single_value() {
        let mut map = HeaderMap::new();
        append(&mut map, "content-length", "5, 6");
        let f = detect(&map);
        assert!(f.contains(&SmugglingIndicator::DuplicateContentLength));
    }

    #[test]
    fn cl_and_te_coexistence() {
        let mut map = HeaderMap::new();
        append(&mut map, "content-length", "10");
        append(&mut map, "transfer-encoding", "chunked");
        let f = detect(&map);
        assert!(f.contains(&SmugglingIndicator::ContentLengthAndTransferEncoding));
        // TE is a clean lone chunked here → not obfuscated.
        assert!(!f.contains(&SmugglingIndicator::ObfuscatedTransferEncoding));
    }

    #[test]
    fn duplicate_transfer_encoding() {
        let mut map = HeaderMap::new();
        append(&mut map, "transfer-encoding", "chunked");
        append(&mut map, "transfer-encoding", "identity");
        let f = detect(&map);
        assert!(f.contains(&SmugglingIndicator::DuplicateTransferEncoding));
        // "identity" is not canonical chunked → obfuscated too.
        assert!(f.contains(&SmugglingIndicator::ObfuscatedTransferEncoding));
    }

    #[test]
    fn obfuscated_te_xchunked() {
        let mut map = HeaderMap::new();
        append(&mut map, "transfer-encoding", "xchunked");
        assert!(detect(&map).contains(&SmugglingIndicator::ObfuscatedTransferEncoding));
    }

    #[test]
    fn obfuscated_te_chunked_list() {
        let mut map = HeaderMap::new();
        append(&mut map, "transfer-encoding", "chunked, identity");
        assert!(detect(&map).contains(&SmugglingIndicator::ObfuscatedTransferEncoding));
    }

    #[test]
    fn te_casing_is_canonical() {
        // http preserves value bytes; case-insensitive match keeps "Chunked"
        // from being a false positive.
        let mut map = HeaderMap::new();
        append(&mut map, "transfer-encoding", "Chunked");
        assert!(detect(&map).is_empty());
    }

    #[test]
    fn te_surrounding_whitespace_is_canonical() {
        let mut map = HeaderMap::new();
        append(&mut map, "transfer-encoding", "  chunked\t");
        assert!(detect(&map).is_empty());
    }

    #[test]
    fn indicator_as_str_is_stable() {
        assert_eq!(
            SmugglingIndicator::ContentLengthAndTransferEncoding.as_str(),
            "content-length-and-transfer-encoding"
        );
    }

    #[test]
    fn trim_ascii_ws_edges() {
        assert_eq!(trim_ascii_ws(b"  ab \t"), b"ab");
        assert_eq!(trim_ascii_ws(b"ab"), b"ab");
        assert_eq!(trim_ascii_ws(b"   "), b"");
        assert_eq!(trim_ascii_ws(b""), b"");
    }
}
