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
use super::content_security::preprocess;

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
    /// [`BUILTIN_PATTERNS`] only — see [`CREDENTIAL_HEADERS`] and
    /// [`decode_children`].
    BuiltinOnly,
    /// Built-ins plus the host's configured word list.
    Full,
}

impl PatternTier {
    /// The stricter of two tiers. Used to propagate a blind decode's
    /// restriction down its descendants: a child of a guessed decode is at
    /// least as restricted as its parent, never less.
    const fn narrow(self, other: Self) -> Self {
        match (self, other) {
            (Self::Full, Self::Full) => Self::Full,
            _ => Self::BuiltinOnly,
        }
    }
}

// ── Bounded decoding ─────────────────────────────────────────────────────────

/// How many decode layers are unwrapped below the field as it arrived.
///
/// Each layer is one encoding an attacker deliberately applied. Real evasions
/// stack one, occasionally two (`base64` inside a percent-encoded parameter);
/// three leaves a layer of headroom and stops there. It is not an arbitrary
/// number in the way a recursion limit usually is, because the transforms here
/// are all **strictly non-expanding** — percent-decoding turns 3 bytes into 1,
/// an entity turns 4+ into 1, base64 turns 4 into 3 — so no depth can produce a
/// decompression bomb. What grows with depth is the **branch count**: each text
/// yields up to 1 + 1 + [`MAX_BASE64_CANDIDATES_PER_TEXT`] children, so an
/// unbounded walk is a CPU amplifier even though it is not a memory one. That
/// is what [`DecodeBudget`] bounds, and the depth cap bounds the shape.
///
/// URL decoding counts as **one** layer even though it unwraps up to
/// [`super::MAX_DECODE_PASSES`] nested percent-encodings: it is a fixed-point
/// iteration that terminates on its own with its own cap, and charging
/// `%25252541` three of the three available layers would spend the budget on the
/// one transform that cannot branch.
const MAX_DECODE_DEPTH: u8 = 3;

/// Decoded texts produced per request, across every field.
///
/// The branch bound. 48 is far above what real traffic reaches — most header
/// values contain no `%`, no `&…;` and no base64-shaped token, and so yield no
/// children at all — and far below the `1 + 6 + 36 + 216` a single field could
/// otherwise reach at depth 3.
const MAX_DERIVED_VIEWS: usize = 48;

/// Decoded bytes produced per request, across every field.
///
/// The cost bound, and the one that actually binds: every derived byte is a byte
/// two Aho-Corasick automata must walk. 128 KiB is twice the header scan budget
/// and sits in the same family as the copies `super::request_targets` already
/// makes of a 64 KiB body.
const MAX_DERIVED_BYTES: usize = 128 * 1024;

/// Decoded texts one field may produce.
///
/// The request-level budget alone would let a single decode-rich field spend all
/// 48 views before the field carrying the payload is reached — and header names
/// are sorted, so an attacker picks a name that sorts first. This does not close
/// that door (any request-level budget is exhaustible by padding, which is why
/// Lane 2 counts its own exhaustion as a degraded verdict rather than pretending
/// otherwise), but it raises the cost from one padding field to four, and it
/// keeps one strange header in a real request from blinding the decode walk for
/// every other header. Matches the Lane 2 preprocessor's `max_views_per_field`
/// default. **Only decoding is rationed: the raw scan of every field runs
/// first and is never charged**, so no budget state can hide a plaintext payload.
const MAX_DERIVED_VIEWS_PER_FIELD: usize = 12;

/// Base64-shaped tokens decoded per text.
const MAX_BASE64_CANDIDATES_PER_TEXT: usize = 4;

/// Body preview size at or below which the body joins the decode walk.
///
/// Above it the body is scanned raw, exactly as before. The asymmetry is
/// deliberate: header, path and query values are bounded at 16 KiB each and are
/// the surface that was not inspected at all, whereas the body preview arrives
/// in windows of up to 68 KiB and its cost is the term
/// [`super::Lane1BodyBudget`] exists to keep off a single-threaded proxy.
/// 8 KiB comfortably holds the material this check looks for — a PEM private key
/// is 1.7–3.2 KiB, an AWS credentials file well under 1 KiB — so the decode walk
/// covers the realistic exfiltration shape without re-introducing a cost that
/// tracks upload size.
const MAX_BODY_DECODE_BYTES: usize = 8 * 1024;

/// Per-request allowance for derived (decoded) texts.
struct DecodeBudget {
    /// Derived texts still allowed for the whole request.
    views_left: usize,
    /// Derived bytes still allowed for the whole request.
    bytes_left: usize,
    /// Derived texts still allowed for the field being walked.
    field_views: usize,
}

impl DecodeBudget {
    const fn new() -> Self {
        Self {
            views_left: MAX_DERIVED_VIEWS,
            bytes_left: MAX_DERIVED_BYTES,
            field_views: MAX_DERIVED_VIEWS_PER_FIELD,
        }
    }

    /// Reset the per-field allowance. Called once per field; the request-level
    /// counters carry over.
    const fn begin_field(&mut self) {
        self.field_views = MAX_DERIVED_VIEWS_PER_FIELD;
    }

    /// Charge one derived text of `len` bytes. `false` when any cap is
    /// reached, at which point the walk stops rather than continuing to
    /// generate work it cannot pay for.
    const fn admit(&mut self, len: usize) -> bool {
        let Some(views) = self.views_left.checked_sub(1) else {
            return false;
        };
        let Some(field_views) = self.field_views.checked_sub(1) else {
            return false;
        };
        let Some(bytes) = self.bytes_left.checked_sub(len) else {
            return false;
        };
        self.views_left = views;
        self.field_views = field_views;
        self.bytes_left = bytes;
        true
    }
}

/// One decode layer of `text`: every transform that fires, each paired with the
/// pattern tier its result may be scanned with.
///
/// The tier is the point. Percent-decoding and HTML-entity decoding are
/// **self-announcing**: `%2D` and `&#45;` say what they are, the transform is
/// exact, and its output is what the backend would have seen — so the operator's
/// word list applies to it as it applies to the raw field.
///
/// A base64 decode is a **guess**. Any token of the right alphabet and length
/// decodes to something, and a session id or an `ETag` decodes to bytes that
/// happen to be printable often enough to matter. Against the built-in patterns
/// that costs nothing: a 31-byte PEM banner does not appear in decode noise. But
/// a per-host pattern can be a short word, and matching one in guessed bytes
/// would block a request over a coincidence. So a blind base64 child is scanned
/// with the built-ins only, and [`PatternTier::narrow`] carries that restriction
/// to its own descendants — the same rule the Lane 2 preprocessor encodes as
/// `Provenance::BlindDecoded` never being hard-veto-capable while
/// `Provenance::HtmlEntityDecoded` is.
///
/// A transform that produces its input unchanged yields no child, and each is
/// gated on a cheap scan for its own marker, so a field with nothing to decode —
/// which is nearly every header of nearly every request — costs three passes over
/// the value and allocates nothing.
fn decode_children(text: &str) -> Vec<(String, PatternTier)> {
    let mut out = Vec::new();

    // Percent-decoding, iterated to its fixed point (one layer, see
    // MAX_DECODE_DEPTH). `url_decode` allocates unconditionally, so the cheap
    // "is there anything to decode" test comes first: the overwhelming majority
    // of header values contain neither `%` nor `+`, and they must not each pay
    // for a full-length copy of themselves.
    if text.bytes().any(|b| b == b'%' || b == b'+') {
        let url = super::url_decode_recursive(text);
        if url != text {
            out.push((url, PatternTier::Full));
        }
    }

    // HTML entities. Fires only when an entity actually decoded.
    if let Some(entities) = preprocess::html_entity_decode(text)
        && entities != text
    {
        out.push((entities, PatternTier::Full));
    }

    // Blind base64, gated on the decode looking like text at all.
    for token in preprocess::base64_candidate_tokens(text)
        .into_iter()
        .take(MAX_BASE64_CANDIDATES_PER_TEXT)
    {
        if let Some(decoded) = preprocess::base64_decode_token(token)
            && preprocess::looks_textual(&decoded)
            && decoded != text
        {
            out.push((decoded, PatternTier::BuiltinOnly));
        }
    }

    out
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

    /// Scan `text` as it arrived and every bounded decoding of it.
    ///
    /// Breadth-first, so a payload one layer down is found before the budget is
    /// spent chasing a deep chain of nothing. The raw field is scanned before
    /// anything is allocated: a request with no encoding pays exactly what it
    /// paid before this walk existed.
    fn scan_decoded(
        &self,
        text: &str,
        host_code: &str,
        tier: PatternTier,
        budget: &mut DecodeBudget,
    ) -> Option<PatternHit> {
        if let Some(hit) = self.scan(text, host_code, tier) {
            return Some(hit);
        }
        budget.begin_field();

        let mut pending: Vec<(String, PatternTier)> = decode_children(text)
            .into_iter()
            .map(|(t, child_tier)| (t, tier.narrow(child_tier)))
            .collect();

        for depth in 1..=MAX_DECODE_DEPTH {
            let mut frontier: Vec<(String, PatternTier)> = Vec::new();
            for (child, child_tier) in pending {
                if !budget.admit(child.len()) {
                    return None;
                }
                if let Some(hit) = self.scan(&child, host_code, child_tier) {
                    return Some(hit);
                }
                frontier.push((child, child_tier));
            }
            if depth == MAX_DECODE_DEPTH || frontier.is_empty() {
                return None;
            }
            pending = Vec::new();
            for (parent, parent_tier) in &frontier {
                for (child, child_tier) in decode_children(parent) {
                    pending.push((child, parent_tier.narrow(child_tier)));
                }
            }
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
    fn scan_headers(&self, ctx: &RequestCtx, host_code: &str, budget: &mut DecodeBudget) -> Option<DetectionResult> {
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
            if let Some(hit) = self.scan_decoded(value, host_code, tier, budget) {
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
        // One allowance for the whole request, so a wide request cannot buy more
        // decoding by spreading its payload across more fields.
        let mut budget = DecodeBudget::new();

        for (location, text) in &targets {
            if let Some(hit) = self.scan_decoded(text, host_code, PatternTier::Full, &mut budget) {
                return Some(Self::result(&hit, location));
            }
        }

        // Headers before the body: bounded at 64 KiB total by construction,
        // where a body preview is up to 68 KiB per window on its own.
        if let Some(result) = self.scan_headers(ctx, host_code, &mut budget) {
            return Some(result);
        }

        // Scan body preview. Decoding is applied only to a body small enough for
        // it to be free — see MAX_BODY_DECODE_BYTES; a larger body is scanned raw,
        // byte for byte as before.
        if !ctx.body_preview.is_empty() {
            let body = String::from_utf8_lossy(&ctx.body_preview);
            let hit = if body.len() <= MAX_BODY_DECODE_BYTES {
                self.scan_decoded(&body, host_code, PatternTier::Full, &mut budget)
            } else {
                self.scan(&body, host_code, PatternTier::Full)
            };
            if let Some(hit) = hit {
                return Some(Self::result(&hit, "body"));
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::fmt::Write as _;
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

    // ── Decoding ─────────────────────────────────────────────────────────────

    fn b64(s: &str) -> String {
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(s.as_bytes())
    }

    /// Percent-encode every byte, the crudest and most common evasion form.
    fn pct(s: &str) -> String {
        s.bytes().fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "%{b:02X}");
            acc
        })
    }

    /// Numeric HTML character references for every character.
    fn entities(s: &str) -> String {
        s.chars().fold(String::new(), |mut acc, c| {
            let _ = write!(acc, "&#{};", c as u32);
            acc
        })
    }

    #[test]
    fn url_encoded_payload_is_decoded_in_every_scope() {
        let checker = SensitiveCheck::new();
        let encoded = pct(PEM);

        for ctx in [
            make_ctx(&format!("/upload/{encoded}"), b""),
            make_ctx_with_headers("/", b"", &[("x-note", &encoded)]),
            make_ctx("/", encoded.as_bytes()),
        ] {
            assert!(checker.check(&ctx).is_some(), "missed {encoded}");
        }
    }

    #[test]
    fn double_url_encoding_is_one_decode_layer() {
        // `url_decode_recursive` runs to its fixed point, so a re-encoded `%`
        // does not cost a second layer of the depth budget.
        let checker = SensitiveCheck::new();
        let once = pct(PEM);
        let twice = once.replace('%', "%25");
        let ctx = make_ctx_with_headers("/", b"", &[("x-note", &twice)]);
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn html_entity_encoded_payload_is_decoded() {
        let checker = SensitiveCheck::new();
        let encoded = entities(PEM);
        let ctx = make_ctx_with_headers("/", b"", &[("x-note", &encoded)]);
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn base64_wrapped_payload_is_decoded() {
        let checker = SensitiveCheck::new();
        let ctx = make_ctx_with_headers("/", b"", &[("x-note", &b64(PEM))]);
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn base64_inside_url_encoding_is_decoded() {
        // The realistic two-layer evasion: a base64 blob in a percent-encoded
        // query parameter.
        let checker = SensitiveCheck::new();
        let mut ctx = make_ctx("/upload", b"");
        ctx.query = format!("blob={}", b64(PEM).replace('+', "%2B"));
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn decode_depth_cap_stops_the_walk() {
        let checker = SensitiveCheck::new();

        // Three nested base64 wrappers = three decode layers = the cap, found.
        let at_cap = b64(&b64(&b64(PEM)));
        let ctx = make_ctx_with_headers("/", b"", &[("x-note", &at_cap)]);
        assert!(
            checker.check(&ctx).is_some(),
            "depth {MAX_DECODE_DEPTH} must be reached"
        );

        // One more wrapper is past the cap.
        let past_cap = b64(&at_cap);
        let ctx = make_ctx_with_headers("/", b"", &[("x-note", &past_cap)]);
        assert!(checker.check(&ctx).is_none(), "depth cap must bound the walk");
    }

    #[test]
    fn decode_view_budget_is_shared_across_the_request() {
        // Enough decodable-but-clean headers to exhaust MAX_DERIVED_VIEWS before
        // the (later-sorting) encoded payload is reached.
        let checker = SensitiveCheck::new();
        let noise = b64("the quick brown fox jumps over the lazy dog");
        let mut owned: Vec<(String, String)> = (0..MAX_DERIVED_VIEWS)
            .map(|i| (format!("x-pad-{i:04}"), noise.clone()))
            .collect();
        owned.push(("zzz-payload".to_string(), b64(PEM)));
        let borrowed: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let ctx = make_ctx_with_headers("/", b"", &borrowed);
        assert!(checker.check(&ctx).is_none());

        // The same payload alone, with the budget intact, is found.
        let ctx = make_ctx_with_headers("/", b"", &[("zzz-payload", &b64(PEM))]);
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn one_field_cannot_spend_the_whole_request_decode_budget() {
        // A decode-rich junk header sorting before the payload must not blind the
        // walk for the header that follows it.
        let checker = SensitiveCheck::new();
        let mut junk = String::new();
        for i in 0..40 {
            let _ = write!(junk, "{}&", b64(&format!("filler token number {i} for padding")));
        }
        let ctx = make_ctx_with_headers("/", b"", &[("a-junk", &junk), ("zzz-payload", &b64(PEM))]);
        assert!(checker.check(&ctx).is_some());
        // And the junk header alone really does hit the per-field cap.
        const { assert!(MAX_DERIVED_VIEWS_PER_FIELD < MAX_DERIVED_VIEWS) };
    }

    #[test]
    fn a_blind_base64_decode_is_not_scanned_with_the_operator_word_list() {
        // A base64 decode is a guess; a per-host pattern can be a short word.
        // Matching one in guessed bytes would block over a coincidence, so the
        // word list is not applied below a blind decode — while the built-ins,
        // which are 20+ byte literals, still are.
        let checker = SensitiveCheck::new();
        checker.load_host("test", &["internal-only".to_string()]);

        let hidden = make_ctx_with_headers("/", b"", &[("x-note", &b64("internal-only marker"))]);
        assert!(checker.check(&hidden).is_none());

        // Same word, not blind-decoded: found.
        let plain = make_ctx_with_headers("/", b"", &[("x-note", "internal-only marker")]);
        assert!(checker.check(&plain).is_some());

        // Same word behind a percent-encoding, which is self-announcing and
        // therefore keeps the full tier: found.
        let url = make_ctx_with_headers("/", b"", &[("x-note", "internal%2Donly marker")]);
        assert!(checker.check(&url).is_some());

        // A built-in behind the same blind decode: still found.
        let builtin = make_ctx_with_headers("/", b"", &[("x-note", &b64(PEM))]);
        assert!(checker.check(&builtin).is_some());
    }

    #[test]
    fn oversized_body_is_scanned_raw_only() {
        let checker = SensitiveCheck::new();
        let encoded = pct(PEM);

        // Under the decode cap: the encoding is unwrapped.
        let small = format!("{}{encoded}", " ".repeat(64));
        assert!(small.len() <= MAX_BODY_DECODE_BYTES);
        assert!(checker.check(&make_ctx("/", small.as_bytes())).is_some());

        // Over it: raw scan only, so the encoded form is missed and the plain
        // form is still caught.
        let big = format!("{}{encoded}", " ".repeat(MAX_BODY_DECODE_BYTES));
        assert!(checker.check(&make_ctx("/", big.as_bytes())).is_none());
        let big_plain = format!("{}{PEM}", " ".repeat(MAX_BODY_DECODE_BYTES));
        assert!(checker.check(&make_ctx("/", big_plain.as_bytes())).is_some());
    }

    #[test]
    fn decoding_does_not_flag_ordinary_traffic() {
        let checker = SensitiveCheck::new();
        checker.load_host("test", &["secret".to_string(), "token".to_string()]);
        let mut ctx = make_ctx_with_headers(
            "/search",
            b"{\"q\":\"caf\\u00e9\",\"page\":2}",
            &[
                ("authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.7QK1"),
                (
                    "cookie",
                    "sid=Zm9vYmFyYmF6cXV1eA; theme=dark; _ga=GA1.2.1234567890.1600000000",
                ),
                ("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"),
                ("accept", "text/html,application/xhtml+xml;q=0.9"),
                ("referer", "https://example.com/list?q=caf%C3%A9&sort=desc"),
                ("if-none-match", "W/\"6c9a1f2b4d8e0a3c5f7b9d1e3a5c7f90\""),
                ("x-request-id", "b3f1c2d4-5e6a-7b8c-9d0e-1f2a3b4c5d6e"),
                ("x-amzn-trace-id", "Root=1-5759e988-bd862e3fe1be46a994272793"),
            ],
        );
        ctx.query = "q=caf%C3%A9&sort=desc&page=2".to_string();
        assert!(
            checker.check(&ctx).is_none(),
            "{:?}",
            checker.check(&ctx).map(|r| r.detail)
        );
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
