//! Lane 2 preprocessor — the **sole decode source for the semantic lane**.
//!
//! (Plan v2.2 §7.) It is physically separate from and does not touch the frozen
//! legacy `request_targets` decode path (Lane 1) or the OWASP `detect_with_decode`
//! path; all three are deliberately frozen and coexist (plan §3.4).
//!
//! P1a ships the working skeleton: scope-limited field collection + a bounded
//! recursive URL-decode chain + lowercase/truncation normalisation, every step
//! metered against the [`ContentInspectionState`] budget. Additional decoders
//! (base64/hex/html-entity/json) and comment stripping are detector-coupled and
//! land with the P1 detectors; adding them now, with no detector to consume
//! them, would be dead work. The framework here already produces one [`View`]
//! per decode round with a [`Provenance`] tag so those decoders slot in without
//! reshaping the interface.

use std::borrow::Cow;

use waf_common::RequestCtx;

use super::budget::ContentInspectionState;
use super::types::{DetectionFinding, DetectionSignal, DetectorId, InspectionScope, Provenance};

/// Per-token truncation length inside a normalised view (plan §7.5).
const MAX_TOKEN_LEN: usize = 64;

/// Curated headers scanned by Lane 2 in the header scope. Kept independent of
/// the frozen legacy `SCANNED_HEADERS` so changing one never perturbs the other.
const SEMANTIC_HEADERS: &[&str] = &[
    "user-agent",
    "referer",
    "x-forwarded-for",
    "x-real-ip",
    "x-original-url",
    "x-forwarded-host",
    "forwarded",
];

/// One decode-round view of a field for detectors to inspect (plan §3.7).
#[derive(Debug, Clone)]
pub struct View<'a> {
    /// Field location label (e.g. `"query"`, `"body"`).
    pub location: Cow<'static, str>,
    /// Decode round (0 = raw).
    pub round: u8,
    /// The (possibly decoded) text for this round.
    pub text: Cow<'a, str>,
    /// Lowercased, per-token-truncated, token-count-bounded normalisation.
    pub lower_trunc: String,
    /// Where this view came from — decides hard-veto eligibility (plan §6.3).
    pub provenance: Provenance,
}

impl View<'_> {
    /// Attach the **pipeline-owned** structural context to a detector's
    /// [`DetectionFinding`], producing the [`DetectionSignal`] the scorer
    /// consumes (codex A-1).
    ///
    /// `provenance`, `field` (this view's `location`) and `scope` come from the
    /// view/scope — **never** from the detector — and `detector` is the id of the
    /// registered detector, not something the finding carries. A detector
    /// inspecting a `BlindDecoded` view therefore cannot relabel its finding as
    /// hard-veto-capable `Raw`, nor spoof its detector id against the configured
    /// weight; hard-veto eligibility is always recomputed from the true
    /// `provenance` at scoring time.
    #[must_use]
    pub fn to_signal(
        &self,
        detector: DetectorId,
        scope: InspectionScope,
        finding: DetectionFinding,
    ) -> DetectionSignal {
        DetectionSignal {
            detector,
            attack: finding.attack,
            field: self.location.clone(),
            scope,
            confidence: finding.confidence,
            rule_key: finding.rule_key,
            provenance: self.provenance,
            detail: finding.detail,
        }
    }
}

/// Read-only context passed to detectors alongside a [`View`].
pub struct PreprocessCtx<'a> {
    pub scope: InspectionScope,
    pub req: &'a RequestCtx,
}

/// A Lane 2 semantic detector. **P1a ships no production implementations**; the
/// trait exists so the scoring / budget pipeline is fully wired and testable
/// (task P1a: "建地基，不建检测器").
pub trait SemanticDetector: Send + Sync {
    /// Stable identity, used to look up this detector's weight.
    fn id(&self) -> DetectorId;

    /// Inspect one view. Read-only over the request; may consume request budget
    /// (e.g. AST attempts). Returns a context-free [`DetectionFinding`] on a hit,
    /// else `None`. The detector reports only `attack`/`confidence`/`rule_key`/`detail`;
    /// the pipeline attaches `provenance`/`field`/`scope`/`detector` from the
    /// current view via [`View::to_signal`] (codex A-1), so a detector cannot
    /// forge the provenance that decides hard-veto eligibility.
    fn detect(
        &self,
        view: &View<'_>,
        ctx: &PreprocessCtx<'_>,
        state: &mut ContentInspectionState,
    ) -> Option<DetectionFinding>;
}

/// Build the normalised `lower_trunc` form: lowercase, whitespace-tokenise,
/// truncate each token, and cap the token count against the budget.
fn normalise(text: &str, max_tokens: u32) -> String {
    let mut out = String::with_capacity(text.len().min(1024));
    for (i, token) in text.split_whitespace().take(max_tokens as usize).enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let lowered = token.to_ascii_lowercase();
        let truncated = if lowered.len() > MAX_TOKEN_LEN {
            // Truncate on a char boundary at/below MAX_TOKEN_LEN.
            let mut end = MAX_TOKEN_LEN;
            while end > 0 && !lowered.is_char_boundary(end) {
                end -= 1;
            }
            lowered.get(..end).unwrap_or("")
        } else {
            lowered.as_str()
        };
        out.push_str(truncated);
    }
    out
}

/// One admittable field source for a scope, held **before** any allocation or
/// UTF-8 conversion so the per-field input cap can be applied on the raw length.
///
/// Header-scope values are already valid UTF-8 borrowed from `req` (zero-copy).
/// The body is kept as **raw bytes** rather than an eagerly-`from_utf8_lossy`-ed
/// string, so its input cap is checked against `body_preview.len()` before any
/// scan/allocation — a non-UTF-8 or oversized body is rejected without work
/// (codex A-2).
enum FieldSource<'a> {
    /// Already-UTF-8 field text (path / query / cookie / curated headers).
    Text(Cow<'static, str>, &'a str),
    /// Raw request body bytes — materialised to text only after admission.
    Body(&'a [u8]),
}

impl FieldSource<'_> {
    /// Byte length for the per-field input admission cap. Cheap for both variants
    /// (no UTF-8 conversion): a borrowed `&str` is already valid UTF-8 so its
    /// `.len()` is its byte length, and the body reports its raw byte length.
    const fn input_len(&self) -> usize {
        match self {
            Self::Text(_, s) => s.len(),
            Self::Body(bytes) => bytes.len(),
        }
    }
}

/// Collect the field sources for a scope. Header scope yields path / query /
/// cookie / curated headers; body scope yields the body only — header-phase
/// fields are not re-scanned in the body phase (plan §3.5, Lane 2
/// phase-limiting; this constraint is Lane-2-only and never touches Lane 1).
///
/// Nothing is decoded or converted here: header values borrow from `req`
/// (zero-copy) and the body stays as raw bytes so the per-field input cap runs
/// before any allocation.
fn collect_field_sources<'a>(scope: InspectionScope, req: &'a RequestCtx) -> Vec<FieldSource<'a>> {
    let mut fields: Vec<FieldSource<'a>> = Vec::new();
    match scope {
        InspectionScope::Header => {
            if !req.path.is_empty() {
                fields.push(FieldSource::Text(Cow::Borrowed("path"), req.path.as_str()));
            }
            if !req.query.is_empty() {
                fields.push(FieldSource::Text(Cow::Borrowed("query"), req.query.as_str()));
            }
            if let Some(cookie) = req.headers.get("cookie")
                && !cookie.is_empty()
            {
                fields.push(FieldSource::Text(Cow::Borrowed("cookie"), cookie.as_str()));
            }
            for name in SEMANTIC_HEADERS {
                if let Some(value) = req.headers.get(*name)
                    && !value.is_empty()
                {
                    fields.push(FieldSource::Text(Cow::Borrowed(*name), value.as_str()));
                }
            }
        }
        InspectionScope::Body => {
            if !req.body_preview.is_empty() {
                fields.push(FieldSource::Body(&req.body_preview));
            }
        }
    }
    fields
}

/// Run the Lane 2 preprocessor for one scope, producing bounded decode views.
///
/// Admission order (codex A-2): a field is first checked against the per-field
/// **input** cap on a borrowed view — an oversized field is skipped **before**
/// any clone / URL-decode / normalise allocation, so it cannot force unbudgeted
/// work. Every retained input byte **and** every normalise-output byte is then
/// metered against the total preprocess-output budget; exceeding any cap marks
/// the state degraded and stops producing more work. On a degraded request the
/// closed scoring model ([`super::scoring::score`]) fails open to the legacy
/// verdict (no positive/negative recommendation, plan §12.4). Call
/// [`ContentInspectionState::begin_phase`] before this to reset the per-phase
/// field counter.
#[must_use]
pub fn semantic_preprocessor<'a>(
    scope: InspectionScope,
    req: &'a RequestCtx,
    state: &mut ContentInspectionState,
) -> Vec<View<'a>> {
    let max_views = state.budget().max_views_per_field;
    let max_rounds = state.budget().max_decode_rounds;
    let max_tokens = state.budget().max_tokens_per_view;

    let mut views: Vec<View<'a>> = Vec::new();

    for source in collect_field_sources(scope, req) {
        if !state.try_take_field() {
            break;
        }

        // Per-field INPUT admission BEFORE any allocation / UTF-8 conversion /
        // decode. For the body this is checked against the raw byte length, so an
        // oversized OR non-UTF-8 body is rejected before `from_utf8_lossy` ever
        // scans or allocates it (codex A-2). An oversized field is skipped (the
        // scan continues); `try_admit_field_input` has already marked degraded.
        if !state.try_admit_field_input(source.input_len()) {
            continue;
        }

        // Admitted: only now materialise the field text. Body bytes become text
        // here — borrowed when valid UTF-8, owned only on lossy replacement;
        // header-scope values stay borrowed.
        let (location, raw): (Cow<'static, str>, Cow<'a, str>) = match source {
            FieldSource::Text(loc, s) => (loc, Cow::Borrowed(s)),
            FieldSource::Body(bytes) => (Cow::Borrowed("body"), String::from_utf8_lossy(bytes)),
        };

        // Round 0: raw view. Meter both the retained input bytes and the
        // normalise-output bytes against the total preprocess-output budget.
        if !state.try_take_preprocess_bytes(raw.len()) {
            break;
        }
        let lower_trunc = normalise(&raw, max_tokens);
        if !state.try_take_preprocess_bytes(lower_trunc.len()) {
            break;
        }
        views.push(View {
            location: location.clone(),
            round: 0,
            lower_trunc,
            text: raw.clone(),
            provenance: Provenance::Raw,
        });

        // Bounded URL-decode rounds. Each distinct round is a fresh view so a
        // "malicious middle round, benign final round" evasion cannot hide.
        // `views_for_field` starts at 1 (the raw view) and is compared against
        // the per-field view cap; a `while` loop (not a counted `for`) keeps the
        // stop condition explicit.
        let mut current: Cow<'a, str> = raw;
        let mut views_for_field = 1u32;
        let mut round = 1u8;
        while round <= max_rounds && views_for_field < max_views {
            let decoded = crate::checks::url_decode(current.as_ref());
            if decoded.as_str() == current.as_ref() {
                break;
            }
            if !state.try_take_preprocess_bytes(decoded.len()) {
                break;
            }
            let lower_trunc = normalise(&decoded, max_tokens);
            if !state.try_take_preprocess_bytes(lower_trunc.len()) {
                break;
            }
            views.push(View {
                location: location.clone(),
                round,
                lower_trunc,
                text: Cow::Owned(decoded.clone()),
                provenance: Provenance::UrlDecoded,
            });
            current = Cow::Owned(decoded);
            views_for_field += 1;
            round += 1;
        }
    }

    views
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use bytes::Bytes;
    use waf_common::HostConfig;

    use super::*;
    use crate::checks::content_security::budget::{Budget, ContentInspectionState};

    fn req_with(path: &str, query: &str, body: &[u8]) -> RequestCtx {
        RequestCtx {
            req_id: "t".to_string(),
            client_ip: "127.0.0.1".parse().expect("valid ip"),
            client_port: 0,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: path.to_string(),
            query: query.to_string(),
            headers: HashMap::new(),
            body_preview: Bytes::copy_from_slice(body),
            content_length: body.len() as u64,
            is_tls: false,
            host_config: Arc::new(HostConfig::default()),
            geo: None,
        }
    }

    #[test]
    fn header_scope_produces_raw_and_decoded_views() {
        let req = req_with("/a", "q=%3Cscript%3E", b"");
        let mut st = ContentInspectionState::default();
        st.begin_phase();
        let views = semantic_preprocessor(InspectionScope::Header, &req, &mut st);
        // path (raw) + query (raw + one url-decoded round).
        assert!(views.iter().any(|v| *v.location == *"path" && v.round == 0));
        assert!(
            views.iter().any(|v| *v.location == *"query"
                && v.provenance == Provenance::UrlDecoded
                && v.text.contains("<script>"))
        );
    }

    #[test]
    fn body_scope_only_yields_body() {
        let req = req_with("/a", "q=1", b"1' OR '1'='1");
        let mut st = ContentInspectionState::default();
        st.begin_phase();
        let views = semantic_preprocessor(InspectionScope::Body, &req, &mut st);
        assert!(views.iter().all(|v| *v.location == *"body"));
        assert!(!views.is_empty());
    }

    #[test]
    fn field_budget_bounds_view_production() {
        // Budget allowing a single field only.
        let budget = Budget {
            max_fields_per_phase: 1,
            ..Budget::default()
        };
        let req = req_with("/a", "q=1", b"");
        let mut st = ContentInspectionState::new(budget);
        st.begin_phase();
        let views = semantic_preprocessor(InspectionScope::Header, &req, &mut st);
        // Only the first field (path) is admitted; query is dropped and the
        // state is marked degraded.
        assert!(views.iter().all(|v| *v.location == *"path"));
        assert!(st.is_degraded());
    }

    #[test]
    fn oversized_field_is_skipped_before_allocation_and_degrades() {
        // Per-field input cap of 4 bytes: the short path ("/a", 2 bytes) is
        // admitted and produces a view; the long query (> 4 bytes) is rejected on
        // its borrowed view — no view for it — and the request is marked degraded.
        let budget = Budget {
            max_field_input_bytes: 4,
            ..Budget::default()
        };
        let req = req_with("/a", "q=aaaaaaaaaa", b"");
        let mut st = ContentInspectionState::new(budget);
        st.begin_phase();
        let views = semantic_preprocessor(InspectionScope::Header, &req, &mut st);
        assert!(
            views.iter().all(|v| *v.location == *"path"),
            "only the short field survives"
        );
        assert!(!views.is_empty(), "the admitted short field still produces a view");
        assert!(st.is_degraded(), "the oversized field must mark the request degraded");
    }

    #[test]
    fn oversized_non_utf8_body_is_skipped_before_lossy_conversion_and_degrades() {
        // codex A-2 body path: a body larger than the per-field input cap AND
        // containing invalid UTF-8. Admission runs on the raw byte length, so the
        // body is rejected BEFORE any `from_utf8_lossy` scan/allocation → no body
        // view is produced and the request is marked degraded.
        let budget = Budget {
            max_field_input_bytes: 4,
            ..Budget::default()
        };
        // 8 bytes, over the 4-byte cap, with leading invalid-UTF-8 bytes.
        let body: [u8; 8] = [0xff, 0xfe, b'A', b'B', b'C', b'D', b'E', b'F'];
        let req = req_with("/a", "q=1", &body);
        let mut st = ContentInspectionState::new(budget);
        st.begin_phase();
        let views = semantic_preprocessor(InspectionScope::Body, &req, &mut st);
        assert!(views.is_empty(), "oversized/non-UTF-8 body must produce no view");
        assert!(st.is_degraded(), "oversized body must mark the request degraded");
    }

    #[test]
    fn normalise_lowercases_and_truncates() {
        let out = normalise("SELECT   UNION", 8);
        assert_eq!(out, "select union");
    }
}
