//! Two-lane content-security subsystem (G1 skeleton).
//!
//! G1 introduces the *physical* home for content-attack detection as a single
//! owned subsystem, replacing the inline `content_checkers` loop that used to
//! live in [`crate::engine::WafEngine::inspect_content`]. It is a
//! **detection-path zero-behaviour-change** refactor:
//! [`ContentSecuritySubsystem::evaluate`] is control-flow &
//! observable-semantic equivalent to the previous loop: the same four detectors
//! (`SQLi` → XSS → RCE → Traversal), in the same construction order, each with
//! the unchanged `Check::check(&RequestCtx)` signature (no phase/scope param),
//! the same frozen [`crate::checks::request_targets`] field set and decode
//! depth, and the same first-match-wins short-circuit + fail-closed behaviour.
//!
//! Lane 1 (`legacy_veto`) is the frozen legacy layer implemented here. Lane 2
//! (`semantic_scoring`) is **not** part of G1: no scoring, no `DetectionSignal`,
//! no budget / `InspectionScope` / `ContentInspectionState`, no DB schema, no
//! canary / breaker, no `semantic_enforcement_mode` dispatch. Accordingly the
//! G1 verdict is a *staged* two-variant enum — the Lane 2 `Semantic { .. }`
//! variant and every type it would pull in are deferred to P1 (plan §3.6 / §19
//! and the four-review G1 approval §四, minimal compilable staged API).

use waf_common::{DetectionResult, RequestCtx};

use crate::checks::{Check, DirTraversalCheck, RceCheck, SqlInjectionCheck, XssCheck};

/// Outcome of a content-security evaluation (staged G1 shape: two variants).
///
/// `LegacyVeto` carries a Lane 1 (frozen four-detector) hit; the engine
/// dispatch maps it straight onto the existing `record_block` path — host
/// `log_only_mode` still decides Block vs `LogOnly`, and security-event logging
/// plus community reporting are unchanged. `None` means no content-attack hit,
/// so the engine continues its unchanged `AppSec` → custom → OWASP CRS →
/// sensitive suffix.
///
/// The Lane 2 `Semantic { .. }` variant (scoring signals, budget, double
/// log-only truth table, `record_semantic_log`) is deliberately **absent** in
/// G1 and is added in P1 when Lane 2 is wired in.
#[derive(Debug)]
pub enum ContentVerdict {
    /// Lane 1 hard veto: one of the four frozen legacy detectors matched.
    LegacyVeto {
        /// The detection produced by the first matching detector.
        result: DetectionResult,
    },
    /// No content-attack hit; fall through to the unchanged suffix pipeline.
    None,
}

/// Content-security subsystem — owns the four content-type detectors.
///
/// Ownership of the `SQLi` / XSS / RCE / traversal checkers moved here out of
/// [`crate::engine::WafEngine`] (previously the `content_checkers` field built
/// at `engine.rs:110-116`). Construction order is preserved exactly so the
/// first-match-wins precedence is control-flow & observable-semantic equivalent
/// to the former loop.
pub struct ContentSecuritySubsystem {
    /// Lane 1 detectors, in the frozen order `SQLi` → XSS → RCE → Traversal.
    legacy_checkers: Vec<Box<dyn Check>>,
}

impl ContentSecuritySubsystem {
    /// Build the subsystem with the four content detectors in their frozen
    /// construction order (mirrors the historical `engine.rs:110-116`).
    #[must_use]
    pub fn new() -> Self {
        // Frozen order — must match the historical content_checkers vector.
        let legacy_checkers: Vec<Box<dyn Check>> = vec![
            Box::new(SqlInjectionCheck::new()),
            Box::new(XssCheck::new()),
            Box::new(RceCheck::new()),
            Box::new(DirTraversalCheck::new()),
        ];
        Self { legacy_checkers }
    }

    /// Lane 1 `legacy_veto`: run the four frozen detectors in order and return
    /// the first hit as [`ContentVerdict::LegacyVeto`], else
    /// [`ContentVerdict::None`].
    ///
    /// Zero side effects: read-only over `ctx`, no IO, no logging. Every side
    /// effect (`record_block` / security-event log / community report) stays in
    /// [`crate::engine::WafEngine`]. This reproduces the former
    /// `content_checkers` loop (`engine.rs:337-341`) exactly.
    #[must_use]
    pub fn evaluate(&self, ctx: &RequestCtx) -> ContentVerdict {
        for checker in &self.legacy_checkers {
            if let Some(result) = checker.check(ctx) {
                return ContentVerdict::LegacyVeto { result };
            }
        }
        ContentVerdict::None
    }
}

impl Default for ContentSecuritySubsystem {
    fn default() -> Self {
        Self::new()
    }
}
