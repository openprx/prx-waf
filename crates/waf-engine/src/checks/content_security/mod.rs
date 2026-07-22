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
//! **P1a ships zero production detectors** ([`Self::detectors`] is empty), so
//! Lane 2 always yields an empty signal set → `request_score == 0` →
//! `recommendation == None`. Even with `enforcement_mode = enforce` the lane
//! cannot produce a block: this is the provable zero-enforcement property (task
//! P1a). The scoring / budget / config foundation is implemented and unit-tested
//! via a test-only mock detector; the budget admission + degraded fail-open are
//! enforced end-to-end. Two pieces are deliberately built but **not yet wired to
//! the engine block path** (scaffold until real detectors + calibration exist):
//! [`Self::resolve_action`] (canary/breaker-gated enforcement, with a restart
//! shadow latch) and the `semantic_observations` persistence.

pub mod budget;
pub mod canary;
pub mod config;
pub mod preprocess;
pub mod scoring;
pub mod types;

use std::time::Instant;

use parking_lot::Mutex;

use waf_common::{DetectionResult, RequestCtx};

use crate::checks::{Check, DirTraversalCheck, RceCheck, SqlInjectionCheck, XssCheck};

pub use budget::{Budget, ContentInspectionState};
pub use canary::{BreakerState, CircuitBreaker, canary_bucket, in_canary};
pub use config::{Dialect, EnforcementMode, RuntimeContentSecurityConfig};
pub use preprocess::{PreprocessCtx, SemanticDetector, View, semantic_preprocessor};
pub use scoring::{RuntimeAttackConfig, RuntimeScoringConfig, score};
pub use types::{
    AttackKind, DetectionFinding, DetectionSignal, DetectorId, InspectionScope, Provenance, SemanticAction,
    SemanticVerdict,
};

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
    /// Lane 2 semantic detectors. **Empty in P1a** (no detectors) — the loop
    /// over it always yields zero signals, guaranteeing zero enforcement.
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
        Self {
            legacy_checkers,
            config,
            detectors: Vec::new(),
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
        if !self.config.enabled {
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

    /// Resolve a Lane 2 recommendation into the effective action, applying the
    /// restart shadow latch, the enforcement mode, canary bucketing, the circuit
    /// breaker and the host `log_only_mode` downgrade (plan §13.3 / §13.4 double
    /// log-only table). `now` is injected for deterministic testing.
    ///
    /// Guarantees Lane 2 can **never** Block in `off`/`log_only` mode, within the
    /// post-restart warmup window, when the request is outside the canary, when
    /// the breaker is open, or when the host is in log-only mode. In P1a `rec` is
    /// always `None` (no detectors) and this is **not** wired to the engine block
    /// path, so it always returns `None`/at-most-`Log` in production — the
    /// zero-enforcement guarantee (codex A-4: latch added, resolver still
    /// deliberately not connected to the engine this round).
    #[must_use]
    pub fn resolve_action(
        &self,
        rec: SemanticAction,
        host_code: &str,
        request_key: &str,
        host_log_only: bool,
        now: Instant,
    ) -> SemanticAction {
        if rec == SemanticAction::None {
            return SemanticAction::None;
        }
        match self.config.enforcement_mode {
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
                if host_log_only { SemanticAction::Log } else { rec }
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
                confidence: self.confidence,
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
    fn enabled_lane_without_detectors_scores_zero() {
        // Lane enabled + enforce, but zero production detectors → Semantic with
        // score 0 and recommendation None: the zero-enforcement property.
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
    fn mock_detector_in_enforce_can_block_but_log_only_mode_downgrades() {
        // With a test detector we verify the *machinery* would block in enforce,
        // and that host log_only_mode downgrades it — proving the plumbing works
        // while production (no detectors) stays inert.
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
        let warm = sub.created_at + Duration::from_secs(301);
        assert_eq!(sub.resolve_action(rec, "h", "k", false, warm), SemanticAction::Block);
        assert_eq!(sub.resolve_action(rec, "h", "k", true, warm), SemanticAction::Log);
    }

    #[test]
    fn enforce_is_shadow_latched_until_warmup_window() {
        // codex A-4: even in enforce + 100% canary + Closed breaker, a would-be
        // Block is held to shadow Log until the health warmup window elapses since
        // subsystem start — a restart cannot resume blocking immediately.
        let mut sub = ContentSecuritySubsystem::with_config(enabled_enforce_cfg());
        sub.detectors.push(Box::new(MockSqliDetector { confidence: 100 }));

        // Inside the warmup window → shadow Log.
        let cold = sub.created_at + Duration::from_secs(1);
        assert_eq!(
            sub.resolve_action(SemanticAction::Block, "h", "k", false, cold),
            SemanticAction::Log,
            "within the restart warmup window enforcement stays shadow"
        );

        // After the warmup window (breaker.window default 300s) → Block allowed.
        let warm = sub.created_at + Duration::from_secs(301);
        assert_eq!(
            sub.resolve_action(SemanticAction::Block, "h", "k", false, warm),
            SemanticAction::Block,
            "after the warmup window enforcement is permitted"
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
            sub.resolve_action(SemanticAction::Block, "h", "k", false, sub.created_at),
            SemanticAction::Log,
            "shadow mode never blocks"
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
