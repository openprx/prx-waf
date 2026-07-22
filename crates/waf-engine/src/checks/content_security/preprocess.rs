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
use std::sync::LazyLock;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use regex::Regex;

use waf_common::RequestCtx;

use super::budget::ContentInspectionState;
use super::types::{DetectionFinding, DetectionSignal, DetectorId, InspectionScope, Provenance};

/// Per-token truncation length inside a normalised view (plan §7.5).
const MAX_TOKEN_LEN: usize = 64;

/// Field-value delimiters used to split a raw field into candidate encoded
/// tokens for the blind base64 / hex decoders. Deliberately excludes `+` and
/// `/` so a base64 token keeps those characters.
const fn is_field_delim(c: char) -> bool {
    matches!(
        c,
        '&' | '=' | ';' | ',' | '\'' | '"' | '<' | '>' | '(' | ')' | '|' | ' ' | '\t' | '\n' | '\r'
    )
}

/// Minimum candidate length before a token is even considered for blind
/// base64 / hex decoding (short tokens decode to noise and inflate FP).
const MIN_BLIND_TOKEN_LEN: usize = 12;
const MIN_HEX_TOKEN_LEN: usize = 8;

/// A **single strong structural marker** (codex A-4.6.2): a complete, high-signal
/// SQL structure that on its own is strong evidence of an attack — a dangerous
/// function call (`sleep(`, `load_file(`, …), `into outfile|dumpfile`, or a
/// stacked statement (`; select …`). These mirror the default-on / high-confidence
/// detector rules, so a base64 / hex wrapper around one of them (e.g.
/// `base64("sleep(5)")`) must not be able to launder it past the blind gate.
///
/// `None` only if the constant pattern somehow fails to compile (it will not);
/// the gate then simply falls back to the weak-keyword tier (no panic, iron rule).
static STRONG_STRUCTURE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(concat!(
        // Dangerous function call (call-paren form) / time-based blind.
        r"\b(load_file|benchmark|sleep|pg_sleep|updatexml|extractvalue|xp_cmdshell)\s*\(",
        r"|\bwaitfor\s+delay\b",
        // File write / exfiltration.
        r"|\binto\s+(outfile|dumpfile)\b",
        // Stacked statement.
        r"|;\s*(select|insert|update|delete|drop|create|alter|union|declare|exec|grant)\b",
    ))
    .ok()
});

/// Whether decoded bytes look like a real (SQL-ish) payload rather than random
/// noise — the gate that keeps blind base64 / hex decoding from emitting a view
/// for every high-entropy token (plan §7.2, codex A-4).
///
/// A lone punctuation mark (`;`, `--`, `/*`) is **not** sufficient — random
/// decoded bytes contain an ASCII `;` with high probability. The gate is layered
/// (codex A-4.6.2):
///   1. a high printable-ASCII ratio (real payloads are text, random bytes are not); then
///   2. a single **strong** structural marker ([`STRONG_STRUCTURE`]) passes on its
///      own — these are complete high-confidence attack structures; else
///   3. two distinct SQL **keyword** markers (structural evidence), or one keyword
///      marker together with a punctuation marker AND multiple tokens.
fn looks_structural(decoded: &str) -> bool {
    // SQL keyword markers — real structural evidence (not punctuation).
    const KEYWORDS: &[&str] = &[
        "select",
        "union",
        "insert",
        "update",
        "delete",
        "drop",
        "from",
        "where",
        " or ",
        " and ",
        "load_file",
        "outfile",
        "dumpfile",
        "sleep",
        "benchmark",
        "information_schema",
        "<script",
    ];
    // Weak punctuation markers — only count alongside a keyword.
    const PUNCT: &[&str] = &["--", "/*", "' or", ";"];

    if decoded.is_empty() {
        return false;
    }
    // 1) Printable-ratio gate: reject high-entropy binary. Bounded scan over a
    //    prefix (the candidate is already capped by the per-field input budget).
    let scanned = decoded.len().min(4096);
    let printable = decoded
        .bytes()
        .take(scanned)
        .filter(|&b| b == b'\t' || b == b'\n' || b == b'\r' || (0x20..=0x7e).contains(&b))
        .count();
    // Require ≥ 85% printable ASCII.
    if printable * 100 < scanned * 85 {
        return false;
    }

    let lower = decoded.to_ascii_lowercase();
    // Tier 2 (codex A-4.6.2): a single strong structural marker is sufficient —
    // a complete dangerous-function call / into-outfile / stacked statement is a
    // real attack even without a second keyword, so an encoded wrapper around it
    // still surfaces a BlindDecoded view.
    if STRONG_STRUCTURE.as_ref().is_some_and(|re| re.is_match(&lower)) {
        return true;
    }
    // Tier 3: weak keyword evidence needs corroboration.
    let keyword_hits = KEYWORDS.iter().filter(|m| lower.contains(**m)).count();
    if keyword_hits >= 2 {
        return true;
    }
    if keyword_hits == 1 {
        let has_punct = PUNCT.iter().any(|m| lower.contains(m));
        let multi_token = lower.split_whitespace().take(2).count() >= 2;
        return has_punct && multi_token;
    }
    false
}

/// Decode a single HTML entity body (the text between `&` and `;`) to one char.
/// Handles the common named entities plus decimal (`#39`) and hex (`#x27`)
/// numeric references. Returns `None` for anything unrecognised.
fn decode_one_entity(entity: &str) -> Option<char> {
    if let Some(rest) = entity.strip_prefix('#') {
        let code = if let Some(hexpart) = rest.strip_prefix('x').or_else(|| rest.strip_prefix('X')) {
            u32::from_str_radix(hexpart, 16).ok()?
        } else {
            rest.parse::<u32>().ok()?
        };
        return char::from_u32(code);
    }
    Some(match entity {
        "lt" => '<',
        "gt" => '>',
        "amp" => '&',
        "quot" => '"',
        "apos" => '\'',
        "sol" => '/',
        "lpar" => '(',
        "rpar" => ')',
        "colon" => ':',
        "commat" => '@',
        "num" => '#',
        "percnt" => '%',
        "equals" => '=',
        "ast" | "midast" => '*',
        _ => return None,
    })
}

/// Decode HTML entities in `s`. Returns `Some(decoded)` only when at least one
/// entity was actually decoded (so a benign field never produces a view).
fn html_entity_decode(s: &str) -> Option<String> {
    if !s.contains('&') {
        return None;
    }
    let mut out = String::with_capacity(s.len());
    let mut changed = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '&' {
            out.push(c);
            continue;
        }
        // Collect a bounded entity body up to the terminating ';'.
        let mut entity = String::new();
        let mut found_semi = false;
        for _ in 0..12 {
            match chars.peek() {
                Some(&';') => {
                    chars.next();
                    found_semi = true;
                    break;
                }
                Some(&ec) if ec != '&' && !ec.is_whitespace() => {
                    entity.push(ec);
                    chars.next();
                }
                _ => break,
            }
        }
        if found_semi && let Some(decoded) = decode_one_entity(&entity) {
            out.push(decoded);
            changed = true;
        } else {
            out.push('&');
            out.push_str(&entity);
            if found_semi {
                out.push(';');
            }
        }
    }
    changed.then_some(out)
}

/// Whether `c` is a SQL identifier/keyword character.
const fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// How a block comment flanked by two word characters is resolved (codex
/// A-4.6.1). SQL comments serve **two** obfuscation roles and a single strip
/// cannot satisfy both, so the caller produces one view per mode:
///   * [`CommentJoin::Join`] removes the comment with no separator, restoring an
///     **intra-keyword** split (`un/**/ion` → `union`).
///   * [`CommentJoin::Space`] replaces it with a single space, restoring an
///     **inter-token** separator (`union/**/select` → `union select`,
///     `into/**/outfile` → `into outfile`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommentJoin {
    Join,
    Space,
}

/// Strip SQL comments (`/* … */` incl. `/*! … */`, `MySQL` `-- ` line comments and
/// `#` line comments).
///
/// A block comment sitting **between two word characters** is resolved per
/// `word_flank` (codex A-4.6.1): [`CommentJoin::Join`] joins the two sides with
/// no separator (intra-keyword restore, `un/**/ion` → `union`);
/// [`CommentJoin::Space`] inserts a space (inter-token separator,
/// `union/**/select` → `union select`). Any comment **not** flanked by two word
/// characters — and every line comment — always becomes a single space so
/// surrounding tokens stay separated, regardless of `word_flank`.
/// Returns `Some` only when a comment was actually removed.
fn strip_sql_comments(s: &str, word_flank: CommentJoin) -> Option<String> {
    if !(s.contains("/*") || s.contains("--") || s.contains('#')) {
        return None;
    }
    let mut out = String::with_capacity(s.len());
    let mut changed = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '/' if chars.peek() == Some(&'*') => {
                chars.next(); // consume '*'
                changed = true;
                // Consume through the closing '*/'.
                let mut prev_star = false;
                for nc in chars.by_ref() {
                    if prev_star && nc == '/' {
                        break;
                    }
                    prev_star = nc == '*';
                }
                // Keyword restoration (codex A-4.6.1): a comment flanked by two
                // word characters is resolved per `word_flank` — `Join` collapses
                // it (intra-keyword restore) while `Space` keeps a separator
                // (inter-token restore). Any non-word-flanked comment always
                // becomes a space so adjacent tokens stay apart.
                let prev_word = out.chars().next_back().is_some_and(is_word_char);
                let next_word = chars.peek().copied().is_some_and(is_word_char);
                let flanked = prev_word && next_word;
                if !(flanked && word_flank == CommentJoin::Join) {
                    out.push(' ');
                }
            }
            '-' if chars.peek() == Some(&'-') => {
                chars.next(); // consume second '-'
                // MySQL `-- ` comment needs whitespace / EOL after the dashes.
                match chars.peek() {
                    None => {
                        changed = true;
                        out.push(' ');
                    }
                    Some(&nc) if nc.is_whitespace() => {
                        changed = true;
                        while let Some(&c2) = chars.peek() {
                            if c2 == '\n' {
                                break;
                            }
                            chars.next();
                        }
                        out.push(' ');
                    }
                    _ => {
                        // Literal `--`, not a comment.
                        out.push('-');
                        out.push('-');
                    }
                }
            }
            '#' => {
                changed = true;
                while let Some(&c2) = chars.peek() {
                    if c2 == '\n' {
                        break;
                    }
                    chars.next();
                }
                out.push(' ');
            }
            _ => out.push(c),
        }
    }
    (changed && out != s).then_some(out)
}

/// Maximum number of candidate tokens each blind decoder inspects per field.
/// Bounds the work while defeating the "long benign token masks a short attack
/// token" evasion — the decoder no longer stops at the single longest candidate
/// (codex A-4).
const MAX_BLIND_CANDIDATES: usize = 8;

/// Try to base64-decode a single candidate token across the standard and
/// URL-safe alphabets (padded and unpadded). Returns the decoded text.
fn base64_decode_token(candidate: &str) -> Option<String> {
    let bytes = STANDARD_NO_PAD
        .decode(candidate)
        .or_else(|_| STANDARD.decode(candidate))
        .or_else(|_| URL_SAFE_NO_PAD.decode(candidate))
        .or_else(|_| URL_SAFE.decode(candidate))
        .ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Blind-decode the first **structural** base64 token in `s`. Candidates are
/// tried longest-first, but up to [`MAX_BLIND_CANDIDATES`] of them, so a long
/// benign token can no longer mask a shorter malicious one (codex A-4). The
/// alphabet includes base64url (`-`/`_`). The produced view is always tagged
/// [`Provenance::BlindDecoded`] (never hard-veto).
fn best_base64_candidate(s: &str) -> Option<String> {
    let mut candidates: Vec<&str> = s
        .split(is_field_delim)
        .filter(|t| {
            t.len() >= MIN_BLIND_TOKEN_LEN
                && t.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'-' || b == b'_')
        })
        .collect();
    // Longest-first, then bounded — inspect several candidates, not just one.
    candidates.sort_unstable_by_key(|t| std::cmp::Reverse(t.len()));
    for candidate in candidates.into_iter().take(MAX_BLIND_CANDIDATES) {
        if let Some(decoded) = base64_decode_token(candidate)
            && looks_structural(&decoded)
        {
            return Some(decoded);
        }
    }
    None
}

/// Blind-decode the first **structural** hex token in `s` (optionally
/// `0x`-prefixed). Candidates are tried longest-first, bounded by
/// [`MAX_BLIND_CANDIDATES`], so a long benign token cannot mask a shorter
/// malicious one (codex A-4).
fn best_hex_candidate(s: &str) -> Option<String> {
    let mut candidates: Vec<&str> = s
        .split(is_field_delim)
        .map(|t| t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t))
        .filter(|t| t.len() >= MIN_HEX_TOKEN_LEN && t.len() % 2 == 0 && t.bytes().all(|b| b.is_ascii_hexdigit()))
        .collect();
    candidates.sort_unstable_by_key(|t| std::cmp::Reverse(t.len()));
    for candidate in candidates.into_iter().take(MAX_BLIND_CANDIDATES) {
        if let Ok(bytes) = hex::decode(candidate) {
            let decoded = String::from_utf8_lossy(&bytes).into_owned();
            if looks_structural(&decoded) {
                return Some(decoded);
            }
        }
    }
    None
}

/// Push one additional decode/transform view, metered against the preprocess
/// output budget and the per-field view cap. Shared by the base64 / hex /
/// html-entity / comment-strip decoders (plan §7.1).
// `location` stays `&Cow` (not `&str`) so a `Cow::Borrowed` label is cloned
// cheaply without re-allocating; `ptr_arg` would push us to `&str` + `to_string`.
#[allow(clippy::too_many_arguments, clippy::ptr_arg)]
fn push_extra_view(
    views: &mut Vec<View<'_>>,
    state: &mut ContentInspectionState,
    views_for_field: &mut u32,
    max_views: u32,
    max_tokens: u32,
    location: &Cow<'static, str>,
    round: u8,
    text: String,
    provenance: Provenance,
) {
    if *views_for_field >= max_views {
        return;
    }
    if !state.try_take_preprocess_bytes(text.len()) {
        return;
    }
    let lower_trunc = normalise(&text, max_tokens);
    if !state.try_take_preprocess_bytes(lower_trunc.len()) {
        return;
    }
    views.push(View {
        location: location.clone(),
        round,
        lower_trunc,
        text: Cow::Owned(text),
        provenance,
    });
    *views_for_field += 1;
}

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

/// A non-URL transform produced from a text, with the [`Provenance`] to stamp on
/// its view and whether the lineage is "tainted" (a blind / comment-stripped /
/// synthetic ancestor was involved, so the view can never be hard-veto-capable).
struct TransformChild {
    provenance: Provenance,
    tainted: bool,
    text: String,
}

/// Apply each of the four non-URL transforms (HTML-entity decode, SQL-comment
/// strip, blind base64, blind hex) to `text`, returning the ones that fired
/// (codex A-4 transform composition).
///
/// `parent_tainted` propagates hard-veto ineligibility down the chain: a child
/// of a blind/comment lineage is stamped with a non-hard-veto provenance even if
/// the child transform itself would be capable (e.g. entity-decode). Comment
/// strip and blind base64/hex always taint.
fn transform_children(text: &str, parent_tainted: bool) -> Vec<TransformChild> {
    let mut out = Vec::new();
    if let Some(t) = html_entity_decode(text) {
        // Entity decode is hard-veto-capable on its own; a tainted parent
        // downgrades it to a non-capable provenance.
        let provenance = if parent_tainted {
            Provenance::BlindDecoded
        } else {
            Provenance::HtmlEntityDecoded
        };
        out.push(TransformChild {
            provenance,
            tainted: parent_tainted,
            text: t,
        });
    }
    // Comment strip produces up to TWO views (codex A-4.6.1): a `Join` view
    // (intra-keyword restore, `un/**/ion` → `union`) and a `Space` view
    // (inter-token restore, `union/**/select` → `union select`). Both are needed
    // because a single strip cannot serve both obfuscation roles. They coincide
    // when no comment is word-flanked, so the space view is only added when it
    // differs from the join view (avoids a redundant duplicate view).
    let comment_join = strip_sql_comments(text, CommentJoin::Join);
    let comment_space = strip_sql_comments(text, CommentJoin::Space);
    if let Some(t) = comment_join.as_ref() {
        out.push(TransformChild {
            provenance: Provenance::CommentStripped,
            tainted: true,
            text: t.clone(),
        });
    }
    if let Some(t) = comment_space
        && comment_join.as_deref() != Some(t.as_str())
    {
        out.push(TransformChild {
            provenance: Provenance::CommentStripped,
            tainted: true,
            text: t,
        });
    }
    if let Some(t) = best_base64_candidate(text) {
        out.push(TransformChild {
            provenance: Provenance::BlindDecoded,
            tainted: true,
            text: t,
        });
    }
    if let Some(t) = best_hex_candidate(text) {
        out.push(TransformChild {
            provenance: Provenance::BlindDecoded,
            tainted: true,
            text: t,
        });
    }
    out
}

/// Maximum transform-composition depth (codex A-4): depth 1 = a single transform
/// of the URL-decoded base, depth 2 = a transform of a depth-1 output. Deeper
/// chains are not explored (and are bounded anyway by the per-field view cap).
const MAX_TRANSFORM_DEPTH: u8 = 2;

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

        // ── Additional decode / transform views (plan §7.1, codex A-4) ───────
        // Run on the fully URL-decoded text so a URL-encoded wrapper around a
        // base64 / hex / entity / comment payload is seen through first. A
        // bounded composition (depth ≤ MAX_TRANSFORM_DEPTH) lets one transform's
        // output feed the next (e.g. base64 → inner comment/entity), so a nested
        // wrapper cannot hide. Every produced view is metered by
        // `push_extra_view` and bounded by the per-field view cap; blind
        // (base64/hex) and comment-stripped lineages carry a non-hard-veto
        // provenance (plan §6.3).
        //
        // Budget accounting (codex A-4.6.3, honest statement): before scanning a
        // frontier text for transforms, one **proxy charge** of that text's length
        // is taken against the preprocess-output budget. This is a single proxy
        // charge per frontier text, NOT a separate charge per decoder — the four
        // decoders (entity / comment / base64 / hex) that then run over the text
        // are not individually metered. Total work is still absolutely bounded:
        // the frontier holds at most one URL-decoded base plus a depth-bounded
        // (≤ MAX_TRANSFORM_DEPTH) fan-out, each text is capped by the per-field
        // input budget, and every retained view is separately metered by
        // `push_extra_view` and capped by the per-field view count — so this is a
        // deterministic upper bound, not per-decoder-attempt accounting.
        let decoded_base = current.as_ref().to_string();
        let mut frontier: Vec<(String, bool, u8)> = vec![(decoded_base, false, 1)];
        while let Some((text, tainted, depth)) = frontier.pop() {
            if views_for_field >= max_views || depth > MAX_TRANSFORM_DEPTH {
                continue;
            }
            // One proxy charge for scanning this text (codex A-4.6.3): a length
            // proxy for the decode work, not a per-decoder charge.
            if !state.try_take_preprocess_bytes(text.len()) {
                break;
            }
            for child in transform_children(&text, tainted) {
                if views_for_field >= max_views {
                    break;
                }
                let produced = child.text.clone();
                let child_tainted = child.tainted;
                push_extra_view(
                    &mut views,
                    state,
                    &mut views_for_field,
                    max_views,
                    max_tokens,
                    &location,
                    round,
                    child.text,
                    child.provenance,
                );
                round = round.saturating_add(1);
                if depth < MAX_TRANSFORM_DEPTH {
                    frontier.push((produced, child_tainted, depth + 1));
                }
            }
        }
    }

    views
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
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

    // ── P1b decode-chain views ───────────────────────────────────────────────

    fn body_views(body: &[u8]) -> Vec<View<'static>> {
        let req = req_with("/a", "q=1", body);
        let mut st = ContentInspectionState::default();
        st.begin_phase();
        // `req` is dropped at end of call, but body views own their text
        // (`Cow::Owned`) so they outlive it; collect into 'static by cloning.
        semantic_preprocessor(InspectionScope::Body, &req, &mut st)
            .into_iter()
            .map(|v| View {
                location: v.location,
                round: v.round,
                text: Cow::Owned(v.text.into_owned()),
                lower_trunc: v.lower_trunc,
                provenance: v.provenance,
            })
            .collect()
    }

    #[test]
    fn html_entity_view_is_produced_with_correct_provenance() {
        // `&lt;script&gt;` → a decoded view tagged HtmlEntityDecoded.
        let views = body_views(b"x=&lt;script&gt;union&#32;select");
        let v = views
            .iter()
            .find(|v| v.provenance == Provenance::HtmlEntityDecoded)
            .expect("an html-entity view must be produced");
        assert!(v.text.contains('<') && v.text.contains('>'));
    }

    #[test]
    fn comment_stripped_view_is_produced_with_correct_provenance() {
        // Intra-keyword comments obfuscate the keywords; the stripped view
        // restores them (codex A-4: `un/**/ion` → `union`, not `un ion`).
        let views = body_views(b"1 un/**/ion sel/**/ect null");
        let v = views
            .iter()
            .find(|v| v.provenance == Provenance::CommentStripped)
            .expect("a comment-stripped view must be produced");
        assert!(
            v.lower_trunc.contains("union") && v.lower_trunc.contains("select"),
            "stripping intra-keyword /**/ must restore the union select keywords: {:?}",
            v.lower_trunc
        );
    }

    #[test]
    fn comment_strip_join_and_space_modes() {
        // codex A-4.6.1: a block comment flanked by word chars is resolved per
        // mode — Join restores an intra-keyword split, Space restores an
        // inter-token separator.
        assert_eq!(
            strip_sql_comments("un/**/ion", CommentJoin::Join).as_deref(),
            Some("union"),
            "join mode restores an intra-keyword comment"
        );
        assert_eq!(
            strip_sql_comments("sel/**/ect", CommentJoin::Join).as_deref(),
            Some("select")
        );
        // Inter-token: the SAME word-flanked comment under Space keeps the tokens
        // apart, so `union/**/select` → `union select` (the form the rules need).
        assert_eq!(
            strip_sql_comments("union/**/select", CommentJoin::Space).as_deref(),
            Some("union select"),
            "space mode restores an inter-token separator"
        );
        assert_eq!(
            strip_sql_comments("into/**/outfile", CommentJoin::Space).as_deref(),
            Some("into outfile")
        );
        // A comment next to a non-word char becomes a space in BOTH modes.
        assert_eq!(
            strip_sql_comments("a/**/-b", CommentJoin::Join).as_deref(),
            Some("a -b")
        );
        assert_eq!(
            strip_sql_comments("a/**/-b", CommentJoin::Space).as_deref(),
            Some("a -b")
        );
    }

    #[test]
    fn base64url_alphabet_is_decoded() {
        // A base64url token (`-`/`_`, no padding) must still blind-decode.
        let payload = URL_SAFE_NO_PAD.encode("1 union select null,null");
        let body = format!("data={payload}");
        let views = body_views(body.as_bytes());
        assert!(
            views
                .iter()
                .any(|v| v.provenance == Provenance::BlindDecoded && v.text.contains("union")),
            "base64url token must blind-decode: {:?}",
            views
                .iter()
                .map(|v| (v.provenance, v.text.as_ref()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn shorter_attack_token_not_masked_by_longer_benign_token() {
        // codex A-4: a field with a LONG benign base64 token and a SHORTER
        // malicious one must still blind-decode the attack (bounded candidate
        // traversal, not longest-only).
        let benign = STANDARD.encode("this is a perfectly ordinary sentence with no sql at all here ok");
        let attack = STANDARD.encode("1 union select null,null");
        assert!(benign.len() > attack.len(), "benign token is the longer candidate");
        let body = format!("a={benign}&b={attack}");
        let views = body_views(body.as_bytes());
        assert!(
            views
                .iter()
                .any(|v| v.provenance == Provenance::BlindDecoded && v.text.contains("union")),
            "the shorter attack token must not be masked by the longer benign token"
        );
    }

    #[test]
    fn base64_blind_view_is_produced_and_marked_blind() {
        // base64("1 union select null") — a blind decode view, never hard-veto.
        let payload = STANDARD.encode("1 union select null,null");
        let body = format!("data={payload}");
        let views = body_views(body.as_bytes());
        let v = views
            .iter()
            .find(|v| v.provenance == Provenance::BlindDecoded)
            .expect("a base64 blind-decoded view must be produced");
        assert!(
            v.text.contains("union"),
            "decoded base64 must reveal the payload: {:?}",
            v.text
        );
    }

    #[test]
    fn hex_blind_view_is_produced_and_marked_blind() {
        // hex of "union select" (structural) → blind decode view.
        let payload = hex::encode("1 union select");
        let body = format!("id=0x{payload}");
        let views = body_views(body.as_bytes());
        let v = views
            .iter()
            .find(|v| v.provenance == Provenance::BlindDecoded)
            .expect("a hex blind-decoded view must be produced");
        assert!(
            v.text.contains("union"),
            "decoded hex must reveal the payload: {:?}",
            v.text
        );
    }

    #[test]
    fn clean_field_produces_no_extra_decode_views() {
        // A benign body: only the raw round-0 view, no entity/comment/blind views.
        let views = body_views(b"name=alice&role=admin&page=2");
        assert!(
            views.iter().all(|v| v.provenance == Provenance::Raw),
            "clean traffic must not synthesise decode views: {:?}",
            views.iter().map(|v| v.provenance).collect::<Vec<_>>()
        );
    }

    #[test]
    fn blind_decode_gate_rejects_high_entropy_noise() {
        // A long random-looking base64-charset token that decodes to non-structural
        // bytes must NOT produce a blind view (the looks_structural gate).
        let views = body_views(b"token=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo");
        assert!(
            views.iter().all(|v| v.provenance == Provenance::Raw),
            "non-structural blind decode must be gated out"
        );
    }

    // ── A-4.6.1: comment strip inter-token separator (end-to-end) ─────────────

    fn comment_stripped_lower_truncs(body: &[u8]) -> Vec<String> {
        body_views(body)
            .into_iter()
            .filter(|v| v.provenance == Provenance::CommentStripped)
            .map(|v| v.lower_trunc)
            .collect()
    }

    #[test]
    fn inter_token_comment_separator_restores_union_select() {
        // codex A-4.6.1: `union/**/select` must restore to `union select` (the
        // form the SQLi rules require) via the Space-mode comment view.
        let lts = comment_stripped_lower_truncs(b"1 union/**/select 1");
        assert!(
            lts.iter().any(|lt| lt.contains("union select")),
            "an inter-token comment must restore `union select`: {lts:?}"
        );
    }

    #[test]
    fn inter_token_comment_separator_restores_into_outfile() {
        let lts = comment_stripped_lower_truncs(b"1 into/**/outfile x");
        assert!(
            lts.iter().any(|lt| lt.contains("into outfile")),
            "an inter-token comment must restore `into outfile`: {lts:?}"
        );
    }

    #[test]
    fn intra_keyword_comments_restore_union_select_via_join() {
        // Both keywords split internally: the Join-mode view collapses each
        // intra-keyword comment, restoring `union select`.
        let lts = comment_stripped_lower_truncs(b"1 un/**/ion sel/**/ect null");
        assert!(
            lts.iter().any(|lt| lt.contains("union select")),
            "intra-keyword comments must restore `union select`: {lts:?}"
        );
    }

    // ── A-4.6.2: blind gate passes a single strong structural marker ──────────

    #[test]
    fn blind_gate_passes_base64_single_strong_marker() {
        // codex A-4.6.2: base64("load_file('/etc/passwd')") — a single strong
        // marker (dangerous fn call), no second keyword — must still blind-decode.
        // (24-byte payload → no base64 padding to be stripped by the delimiter split.)
        let payload = STANDARD.encode("load_file('/etc/passwd')");
        let views = body_views(format!("q={payload}").as_bytes());
        assert!(
            views
                .iter()
                .any(|v| v.provenance == Provenance::BlindDecoded && v.text.contains("load_file")),
            "a base64-wrapped single strong marker must surface a BlindDecoded view: {:?}",
            views
                .iter()
                .map(|v| (v.provenance, v.text.as_ref()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn blind_gate_passes_base64url_single_strong_marker() {
        // base64url (no padding) around a single dangerous-fn call.
        let payload = URL_SAFE_NO_PAD.encode("sleep(50000)");
        let views = body_views(format!("data={payload}").as_bytes());
        assert!(
            views
                .iter()
                .any(|v| v.provenance == Provenance::BlindDecoded && v.text.contains("sleep(")),
            "a base64url-wrapped sleep() call must surface a BlindDecoded view: {:?}",
            views
                .iter()
                .map(|v| (v.provenance, v.text.as_ref()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn blind_gate_passes_hex_single_strong_marker() {
        // hex around a single `into outfile` marker.
        let payload = hex::encode("into outfile '/x'");
        let views = body_views(format!("id=0x{payload}").as_bytes());
        assert!(
            views
                .iter()
                .any(|v| v.provenance == Provenance::BlindDecoded && v.text.contains("into outfile")),
            "a hex-wrapped `into outfile` must surface a BlindDecoded view: {:?}",
            views
                .iter()
                .map(|v| (v.provenance, v.text.as_ref()))
                .collect::<Vec<_>>()
        );
    }

    // ── A-4.6.3: composition depth, lineage taint, budget exhaustion ──────────

    #[test]
    fn transform_composition_depth_2_and_lineage_taint() {
        // codex A-4.6.3: base64("1 union select a&#49;") → depth-1 blind decode
        // (passes on `union select`) → depth-2 HTML-entity decode of the blind
        // output (`&#49;` → `1`). The depth-2 view proves one transform feeds the
        // next; its provenance is BlindDecoded (NOT HtmlEntityDecoded) — the blind
        // lineage taint propagates so the child can never be hard-veto-capable.
        let payload = STANDARD.encode("1 union select a&#49;"); // 21 bytes → no padding
        let views = body_views(format!("data={payload}").as_bytes());
        let depth2 = views
            .iter()
            .find(|v| v.text.contains("union select a1"))
            .expect("depth-2 entity decode of the blind output must produce a view");
        assert!(
            !depth2.text.contains("&#49;"),
            "the entity must actually be decoded at depth 2: {:?}",
            depth2.text
        );
        assert_eq!(
            depth2.provenance,
            Provenance::BlindDecoded,
            "a child of a blind lineage stays tainted (non-hard-veto), not relabelled HtmlEntityDecoded"
        );
    }

    #[test]
    fn transform_budget_exhaustion_stops_decode_work() {
        // codex A-4.6.3: a tiny output budget is consumed by the raw view, so the
        // per-frontier transform scan charge fails and NO blind view is produced —
        // the request stops doing decode work and is marked degraded.
        let budget = Budget {
            max_preprocess_output_bytes_total: 80,
            ..Budget::default()
        };
        let payload = STANDARD.encode("1 union select null,null");
        let body = format!("data={payload}"); // 37 bytes: raw+normalise ≈74 ≤80, transform charge 37 → over
        let req = req_with("/a", "q=1", body.as_bytes());
        let mut st = ContentInspectionState::new(budget);
        st.begin_phase();
        let views = semantic_preprocessor(InspectionScope::Body, &req, &mut st);
        assert!(
            views.iter().all(|v| v.provenance == Provenance::Raw),
            "an exhausted budget must stop transform decode work (no blind view): {:?}",
            views.iter().map(|v| v.provenance).collect::<Vec<_>>()
        );
        assert!(st.is_degraded(), "budget exhaustion must mark the request degraded");
    }
}
