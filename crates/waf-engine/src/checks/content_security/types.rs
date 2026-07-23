//! Lane 2 semantic content-security core types (plan v2.2 §3.7 / §6).
//!
//! These are the typed vocabulary shared by the preprocessor, detectors and the
//! closed scoring model. **P1a ships no production detectors**, so in a running
//! build no [`DetectionSignal`] is ever produced by production code; the types
//! exist so the scoring / budget / observation foundation is in place and
//! unit-tested (the detectors themselves land in P1 — task P1a: "建地基，不建
//! 检测器").

use std::borrow::Cow;

use waf_common::Phase;

/// Which request phase the Lane 2 preprocessor is operating on.
///
/// **Deliberately distinct from [`waf_common::Phase`]** (which enumerates attack
/// stages such as `SqlInjection`/`Xss` and is used in log/rule identity). Reusing
/// `Phase` for Header/Body would collide (plan §3.5 / codex §4 尚未闭合3). This
/// type only drives preprocessor field selection and the `scope` on a signal; it
/// never enters `DetectionResult.phase`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InspectionScope {
    /// Header phase: path / query / cookie / curated headers.
    Header,
    /// Body phase: request body only.
    Body,
}

impl InspectionScope {
    /// Stable lowercase label for telemetry / persistence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Header => "header",
            Self::Body => "body",
        }
    }
}

/// The attack family a semantic signal belongs to.
///
/// Each family has its own independent detector set / weight sum / thresholds /
/// hard-veto allowlist (plan §6.2), and maps onto the existing attack [`Phase`]
/// for `DetectionResult`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttackKind {
    SqlInjection,
    Rce,
    Xss,
    Traversal,
}

impl AttackKind {
    /// All families, for iterating config.
    pub const ALL: [Self; 4] = [Self::SqlInjection, Self::Rce, Self::Xss, Self::Traversal];

    /// Stable config-key spelling (`snake_case`) used in the TOML `[attacks]`
    /// map and in persistence.
    #[must_use]
    pub const fn as_config_key(self) -> &'static str {
        match self {
            Self::SqlInjection => "sql_injection",
            Self::Rce => "rce",
            Self::Xss => "xss",
            Self::Traversal => "traversal",
        }
    }

    /// Parse a config-key spelling back to an [`AttackKind`].
    #[must_use]
    pub fn from_config_key(s: &str) -> Option<Self> {
        match s {
            "sql_injection" => Some(Self::SqlInjection),
            "rce" => Some(Self::Rce),
            "xss" => Some(Self::Xss),
            "traversal" => Some(Self::Traversal),
            _ => None,
        }
    }

    /// The attack [`Phase`] used when a semantic verdict is surfaced as a
    /// [`waf_common::DetectionResult`].
    #[must_use]
    pub const fn to_phase(self) -> Phase {
        match self {
            Self::SqlInjection => Phase::SqlInjection,
            Self::Rce => Phase::Rce,
            Self::Xss => Phase::Xss,
            Self::Traversal => Phase::DirTraversal,
        }
    }
}

/// Identity of a semantic detector. P1 will populate these; P1a wires the
/// vocabulary and the config-string mapping but ships **no** implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DetectorId {
    /// OpenRASP-derived structural token rules (P1).
    StructRule,
    /// sqlparser-rs AST layer (P2).
    Ast,
    /// Self-authored shell lexer for command injection (P1+).
    Rce,
    /// Segment-aware traversal detector (T1).
    Traversal,
    /// HTML5 DOM semantic XSS detector (P-XSS-1).
    XssDom,
}

impl DetectorId {
    /// Stable config-key spelling used in the per-attack `weights` map.
    #[must_use]
    pub const fn as_config_str(self) -> &'static str {
        match self {
            Self::StructRule => "struct_rule",
            Self::Ast => "ast",
            Self::Rce => "rce",
            Self::Traversal => "traversal",
            Self::XssDom => "xss_dom",
        }
    }

    /// Parse a config-key spelling back to a [`DetectorId`]. Used by the engine
    /// runtime-config compiler to reject unknown detector ids at startup.
    #[must_use]
    pub fn from_config_str(s: &str) -> Option<Self> {
        match s {
            "struct_rule" => Some(Self::StructRule),
            "ast" => Some(Self::Ast),
            "rce" => Some(Self::Rce),
            "traversal" => Some(Self::Traversal),
            "xss_dom" => Some(Self::XssDom),
            _ => None,
        }
    }
}

/// Where a scored view came from — decides hard-veto eligibility (plan §6.3).
///
/// `BlindDecoded` / `SyntheticHpp` / `ParseError` are **never** allowed to
/// hard-veto (single-signal Block), because each can synthesise a payload the
/// backend would never see.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Provenance {
    Raw,
    UrlDecoded,
    HtmlEntityDecoded,
    JsonDecoded,
    /// base64 / hex blind decode — never hard-veto.
    BlindDecoded,
    /// SQL-comment-stripped synthetic view (inline `/**/` / `--` / `#` /
    /// `/*!…*/` removed) — never hard-veto. Comment removal can synthesise a
    /// token stream a given backend would not parse identically (dialect
    /// dependent), so a match on this view is scored but can never single-signal
    /// Block (plan §6.3 spirit for synthetic transforms).
    CommentStripped,
    /// HPP synthetic concatenation — never hard-veto.
    SyntheticHpp,
    /// Parser-differential weak signal — never hard-veto.
    ParseError,
}

impl Provenance {
    /// Stable label for telemetry / persistence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::UrlDecoded => "url_decoded",
            Self::HtmlEntityDecoded => "html_entity_decoded",
            Self::JsonDecoded => "json_decoded",
            Self::BlindDecoded => "blind_decoded",
            Self::CommentStripped => "comment_stripped",
            Self::SyntheticHpp => "synthetic_hpp",
            Self::ParseError => "parse_error",
        }
    }

    /// Whether a signal from this provenance is *structurally* allowed to be a
    /// hard-veto candidate (it must additionally be on the per-attack
    /// allowlist). Blind/synthetic/parse-error provenance is never eligible.
    #[must_use]
    pub const fn hard_veto_capable(self) -> bool {
        !matches!(
            self,
            Self::BlindDecoded | Self::CommentStripped | Self::SyntheticHpp | Self::ParseError
        )
    }
}

/// A detector's raw finding — what a detector is authoritative over, **before**
/// the pipeline attaches the structural context that a detector must not be able
/// to forge (codex A-1).
///
/// A [`SemanticDetector`](super::preprocess::SemanticDetector) reports only the
/// attack family, its confidence, the compile-time stable `rule_key` and the
/// human-readable `detail`. It does **not** — and structurally *cannot* — supply
/// `detector` / `field` / `scope` / `provenance`: those are attached by
/// [`View::to_signal`](super::preprocess::View::to_signal) from the current
/// view/scope. In particular `provenance` is always taken from the real
/// [`View`](super::preprocess::View), so a detector inspecting a `BlindDecoded`
/// view can never relabel its finding as hard-veto-capable `Raw`. Hard-veto
/// eligibility is therefore computed from the true view provenance, never from
/// anything the detector returns.
#[derive(Debug, Clone)]
pub struct DetectionFinding {
    pub attack: AttackKind,
    /// Confidence in `0..=100`.
    pub confidence: u8,
    /// Stable matching key (compile-time constant, e.g. `"sql.into_outfile"`).
    pub rule_key: &'static str,
    /// Human-readable trace text — for logs/dashboards only; **never** matched.
    pub detail: Cow<'static, str>,
}

/// A single semantic detection signal (plan §3.7 / §6.3).
///
/// `field` is the stable field identity used to group `(scope, field, attack,
/// detector)` during canonical max-aggregation. `rule_key` is a compile-time
/// stable key — the hard-veto allowlist matches on this, **never** on the
/// mutable `detail` text.
///
/// A `DetectionSignal` is only ever assembled by the pipeline via
/// [`View::to_signal`](super::preprocess::View::to_signal), which stamps
/// `detector` / `field` / `scope` / `provenance` from the current view/scope —
/// detectors return a context-free [`DetectionFinding`] and cannot populate
/// these fields. `provenance` in particular is pipeline-owned.
///
/// Hard-veto eligibility is **not** a stored field — it cannot be forged. It is
/// derived at scoring time solely from [`Provenance::hard_veto_capable`] (a
/// structural property of `provenance`) combined with the per-attack `rule_key`
/// allowlist (plan §6.3). This removes the earlier redundant public
/// `hard_veto_eligible: bool`, which a malicious/buggy caller could set
/// inconsistently with `provenance` (codex A-1).
#[derive(Debug, Clone)]
pub struct DetectionSignal {
    pub detector: DetectorId,
    pub attack: AttackKind,
    pub field: Cow<'static, str>,
    pub scope: InspectionScope,
    /// Confidence in `0..=100`.
    pub confidence: u8,
    /// Stable matching key (compile-time constant, e.g. `"sql.into_outfile"`).
    pub rule_key: &'static str,
    pub provenance: Provenance,
    /// Human-readable trace text — for logs/dashboards only; **never** matched.
    pub detail: Cow<'static, str>,
}

/// The action a semantic verdict *recommends* (not the final decision — the
/// engine applies the double log-only truth table and canary/breaker on top).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticAction {
    Block,
    Log,
    None,
}

/// Outcome of Lane 2 scoring for one evaluation (plan §3.2).
#[derive(Debug, Clone)]
pub struct SemanticVerdict {
    /// Advisory action derived from the closed score + thresholds + hard-veto.
    pub recommendation: SemanticAction,
    /// Request-level score in `0..=100` (closed formula, plan §6.1).
    pub request_score: u8,
    /// The winning signal's detection result, for `record_block` /
    /// `record_semantic_log`. `None` when no family crossed its log threshold.
    pub primary_result: Option<waf_common::DetectionResult>,
    /// All signals, for persistence / dashboards (plan §13.1).
    pub signals: Vec<DetectionSignal>,
    /// Budget was exhausted → a semantic-only miss window (plan §12.4).
    pub degraded: bool,
}
