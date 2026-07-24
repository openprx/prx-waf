//! Closed Lane 2 scoring model (plan v2.2 §6).
//!
//! The formula is mathematically closed — the request score is provably in
//! `0..=100` (see [`score`] and the module tests):
//!
//! ```text
//! canonical(scope, field, attack, detector) = argmax over views/wrappers of confidence
//! group(scope, field, attack)               = Σ_detector weight(attack,detector) · canonical.confidence
//! request_score                             = max over groups of group score
//! ```
//!
//! With the loader guaranteeing, per enabled attack family, `Σ weight = 1` and
//! every `confidence ∈ [0,100]`, each group score is a convex combination of the
//! detectors' confidences and therefore `≤ 100`; the outer `max` keeps it in
//! range. Detectors that produced no signal contribute `0 ≤ their max`, so the
//! bound holds for any subset of firing detectors.
//!
//! Hard-veto is an explicit per-attack allowlist keyed on the **stable
//! `rule_key`** (never on `detail`), and blind/synthetic/parse-error provenance
//! is structurally excluded (plan §6.3).
//!
//! **Primary/`request_score` contract (codex A-1).** `request_score` is the max
//! group score and is computed independently of the primary family. The
//! `primary_result` is chosen by a *total, `HashMap`-order-independent*
//! comparator: highest recommendation severity, then highest group score, then a
//! stable structural tie-break on `(attack, scope, field, rule_key)`. Because
//! `(scope, field, attack)` is the group key, that tuple is unique per group, so
//! two families firing on the same field at the same score always resolve to the
//! same primary — the security-event attack type is deterministic across
//! processes (never seeded by `HashMap` iteration order).

use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};

use waf_common::DetectionResult;
use waf_common::content_security_config::ContentSecurityConfig;

#[cfg(test)]
use super::types::Confidence;
use super::types::{AttackKind, DetectionSignal, DetectorId, InspectionScope, SemanticAction, SemanticVerdict};

/// Runtime (compiled, immutable) per-attack scoring config.
#[derive(Debug, Clone)]
pub struct RuntimeAttackConfig {
    pub enabled: bool,
    pub weights: HashMap<DetectorId, f64>,
    pub log_threshold: u8,
    pub block_threshold: u8,
    pub hard_veto_allowlist: HashSet<String>,
}

/// Runtime (compiled, immutable) scoring config for all attack families.
#[derive(Debug, Clone, Default)]
pub struct RuntimeScoringConfig {
    pub attacks: HashMap<AttackKind, RuntimeAttackConfig>,
}

impl RuntimeScoringConfig {
    /// Compile the serializable [`ContentSecurityConfig`] into the immutable
    /// runtime scoring config, resolving detector-id strings and rejecting
    /// unknown ids. Assumes [`ContentSecurityConfig::validate`] has already run
    /// (so weight sums / thresholds are known-good); this step only performs the
    /// string→enum resolution that `waf-common` must not do (plan §6.5).
    pub fn compile(cfg: &ContentSecurityConfig) -> Result<Self, String> {
        let mut attacks = HashMap::new();
        for (family_key, family) in &cfg.attacks {
            let Some(attack) = AttackKind::from_config_key(family_key) else {
                return Err(format!("unknown attack family '{family_key}'"));
            };
            let mut weights = HashMap::new();
            for (det_key, w) in &family.weights {
                let Some(det) = DetectorId::from_config_str(det_key) else {
                    return Err(format!("attack '{family_key}' references unknown detector '{det_key}'"));
                };
                weights.insert(det, *w);
            }
            attacks.insert(
                attack,
                RuntimeAttackConfig {
                    enabled: family.enabled,
                    weights,
                    log_threshold: family.log_threshold,
                    block_threshold: family.block_threshold,
                    hard_veto_allowlist: family.hard_veto_allowlist.iter().cloned().collect(),
                },
            );
        }
        Ok(Self { attacks })
    }
}

/// Clamp a floating score into a `0..=100` byte. Never panics.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn clamp_score_to_u8(x: f64) -> u8 {
    if !x.is_finite() || x <= 0.0 {
        0
    } else if x >= 100.0 {
        100
    } else {
        // 0 < x < 100 and finite: rounding lands in 0..=100, cast is exact.
        x.round() as u8
    }
}

/// A `(scope, field, attack)` accumulation group during scoring.
struct Group<'a> {
    score: f64,
    best: &'a DetectionSignal,
    best_contrib: f64,
    /// Whether any signal in this group came from a directly-observable,
    /// non-synthetic view (a [`Provenance::hard_veto_capable`] provenance). Drives
    /// the E0 / A2 `enforce_safe` gate: a group whose Block is carried **only** by
    /// blind/synthetic views must not be enforced.
    has_capable: bool,
}

/// Severity ranking so we can pick the strongest group recommendation.
const fn severity(a: SemanticAction) -> u8 {
    match a {
        SemanticAction::None => 0,
        SemanticAction::Log => 1,
        SemanticAction::Block => 2,
    }
}

/// Stable ordinal for [`AttackKind`], used only as a deterministic tie-break in
/// the request roll-up (codex A-1). The numeric value is arbitrary but fixed, so
/// two families that reach the same severity and score always resolve to the
/// same primary regardless of `HashMap` iteration order.
const fn attack_ord(a: AttackKind) -> u8 {
    match a {
        AttackKind::SqlInjection => 0,
        AttackKind::Rce => 1,
        AttackKind::Xss => 2,
        AttackKind::Traversal => 3,
        AttackKind::Xxe => 4,
    }
}

/// Stable ordinal for [`InspectionScope`] — the second component of the roll-up
/// tie-break (codex A-1).
const fn scope_ord(s: InspectionScope) -> u8 {
    match s {
        InspectionScope::Header => 0,
        InspectionScope::Body => 1,
    }
}

/// Stable ordinal for [`DetectorId`], the tie-break used when two detectors in the
/// **same** group contribute equally (codex P1c §3.1). P2 puts a second detector
/// (`ast`) in the `SqlInjection` family and P-XSS-2 a second (`xss_js`) in the
/// `Xss` family, so two detectors can fire on one field with an identical weighted
/// contribution; without this the group's representative signal (`Group::best` →
/// `primary_result`) would depend on `HashMap` iteration order. The numeric value
/// is arbitrary but fixed.
const fn detector_ord(d: DetectorId) -> u8 {
    match d {
        DetectorId::StructRule => 0,
        DetectorId::Ast => 1,
        DetectorId::Rce => 2,
        DetectorId::RceAst => 3,
        DetectorId::Traversal => 4,
        DetectorId::XssDom => 5,
        DetectorId::XssJs => 6,
        DetectorId::XxeStruct => 7,
    }
}

/// Whether a candidate detector signal should replace the group's current best,
/// under a **total, `HashMap`-order-independent** order (codex P1c §3.1): higher
/// weighted contribution wins; on an equal contribution the smaller
/// `(detector_ord, rule_key)` wins. Equal contributions are compared bit-for-bit
/// (`total_cmp`): two detectors with the same weight and confidence produce an
/// identical `f64`, so the stable structural key is what breaks the tie.
fn group_best_is_better(new_contrib: f64, new: &DetectionSignal, cur_contrib: f64, cur: &DetectionSignal) -> bool {
    match new_contrib.total_cmp(&cur_contrib) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => {
            (detector_ord(new.detector), new.rule_key) < (detector_ord(cur.detector), cur.rule_key)
        }
    }
}

/// Fully-ordered comparison key that makes the request roll-up winner
/// deterministic (codex A-1). Sorted so the **greatest** key wins:
///   1. recommendation `severity` (Block > Log);
///   2. clamped `group_score`;
///   3. a stable structural tie-break on `(attack, scope, field, rule_key)` where
///      the lexicographically *smallest* tuple wins (wrapped in [`Reverse`] so
///      "greatest key" still selects it).
///
/// `(scope, field, attack)` is the group key, so the tie-break tuple is unique
/// per group and the order is a strict total order — no two candidate groups can
/// ever compare equal, so the winner never depends on iteration order.
type WinnerKey<'a> = (u8, u8, Reverse<(u8, u8, &'a str, &'a str)>);

/// Compute the closed Lane 2 verdict for a set of signals.
///
/// Returns a [`SemanticVerdict`] whose `request_score` is guaranteed to be in
/// `0..=100`. With `signals` empty (the P1a production reality — no detectors)
/// the result is always `recommendation = None`, `request_score = 0`,
/// `primary_result = None`.
#[must_use]
pub fn score<'a>(signals: &'a [DetectionSignal], cfg: &RuntimeScoringConfig, degraded: bool) -> SemanticVerdict {
    // Budget-degraded requests fail open to the legacy verdict (plan §12.4,
    // codex A-2). Once the per-request budget is exhausted the signal set is
    // only partial, so Lane 2 must produce **no** recommendation — positive or
    // negative — and must never overwrite a legacy-only outcome. Signals are
    // retained for telemetry; `recommendation`/`primary_result` are cleared so
    // the engine dispatch is inert on a degraded request.
    if degraded {
        return SemanticVerdict {
            recommendation: SemanticAction::None,
            request_score: 0,
            primary_result: None,
            signals: signals.to_vec(),
            degraded: true,
            // A degraded verdict carries no recommendation, so it is never
            // enforceable.
            enforce_safe: false,
        };
    }

    // 1) Canonical max-aggregation: keep, per (scope, field, attack, detector),
    //    the highest-confidence signal (arg-max — keep the whole signal so
    //    detail/provenance survive for the primary-signal / hard-veto audit).
    let mut canonical: HashMap<(InspectionScope, &str, AttackKind, DetectorId), &'a DetectionSignal> = HashMap::new();
    for s in signals {
        let key = (s.scope, s.field.as_ref(), s.attack, s.detector);
        match canonical.get(&key) {
            Some(existing) if existing.confidence >= s.confidence => {}
            _ => {
                canonical.insert(key, s);
            }
        }
    }

    // 2) Per-(scope, field, attack) weighted sum + arg-max contributor.
    let mut groups: HashMap<(InspectionScope, &str, AttackKind), Group<'a>> = HashMap::new();
    // Hard-veto candidate is chosen deterministically (codex A-1): the highest
    // confidence wins, then the same stable structural tie-break as the roll-up,
    // so a multi-hit allowlisted request never records a `HashMap`-order-dependent
    // primary. Keyed by `(confidence, Reverse(stable-key))` — greatest wins.
    let mut hard_veto: Option<(WinnerKey<'a>, &'a DetectionSignal)> = None;

    for (&(scope, field, attack, detector), &sig) in &canonical {
        let Some(ac) = cfg.attacks.get(&attack) else { continue };
        if !ac.enabled {
            continue;
        }
        let w = ac.weights.get(&detector).copied().unwrap_or(0.0);
        let contrib = w * f64::from(sig.confidence.get());

        let g = groups.entry((scope, field, attack)).or_insert(Group {
            score: 0.0,
            best: sig,
            best_contrib: -1.0,
            has_capable: false,
        });
        g.score += contrib;
        // A single directly-observable (non-blind, non-synthetic) signal makes
        // the group's Block enforce-safe (E0 / A2).
        if sig.provenance.hard_veto_capable() {
            g.has_capable = true;
        }
        // Deterministic within-group representative (codex P1c §3.1): higher
        // contribution wins, equal contribution breaks on `(detector_ord,
        // rule_key)` — never on `HashMap` iteration order. The `-1.0` seed makes
        // the first admitted signal always win over the placeholder.
        if group_best_is_better(contrib, sig, g.best_contrib, g.best) {
            g.best_contrib = contrib;
            g.best = sig;
        }

        // Hard-veto — un-forgeable triple gate (plan §6.3, codex A-1):
        //   1. `provenance.hard_veto_capable()` — structural, derived here from
        //      the signal's `provenance`; blind/synthetic/parse-error provenance
        //      can NEVER hard-veto no matter what the detector claims;
        //   2. on this attack's explicit `rule_key` allowlist.
        // There is no stored `hard_veto_eligible` bool to forge — eligibility is
        // recomputed from `provenance` at scoring time.
        if sig.provenance.hard_veto_capable() && ac.hard_veto_allowlist.contains(sig.rule_key) {
            let hv_key: WinnerKey<'a> = (
                sig.confidence.get(),
                0,
                Reverse((attack_ord(attack), scope_ord(scope), field, sig.rule_key)),
            );
            if hard_veto.as_ref().is_none_or(|(k, _)| hv_key > *k) {
                hard_veto = Some((hv_key, sig));
            }
        }
    }

    // 3) Request-level roll-up (codex A-1): the winner is chosen by a total,
    //    `HashMap`-order-independent comparator ([`WinnerKey`]) so the primary
    //    signal is deterministic across processes. `request_score` is the max
    //    group score (the closed-formula request magnitude) and is computed
    //    independently of which family becomes primary; the two are related by
    //    the written contract "`request_score = max_g group_score`; `primary` is
    //    the highest-severity, then highest-scoring, then stable-key group that
    //    reached at least its Log threshold".
    let mut request_score = 0.0f64;
    let mut recommendation = SemanticAction::None;
    let mut primary: Option<&'a DetectionSignal> = None;
    let mut best_key: Option<WinnerKey<'a>> = None;
    // Non-synthetic corroboration of the winning group (E0 / A2). Captured from
    // the group that becomes primary so the enforce path can refuse to Block a
    // recommendation carried solely by blind/synthetic views.
    let mut winner_has_capable = false;

    for (&(scope, field, attack), g) in &groups {
        let Some(ac) = cfg.attacks.get(&attack) else { continue };
        let group_u = clamp_score_to_u8(g.score);
        if g.score > request_score {
            request_score = g.score;
        }
        let group_rec = if group_u >= ac.block_threshold {
            SemanticAction::Block
        } else if group_u >= ac.log_threshold {
            SemanticAction::Log
        } else {
            SemanticAction::None
        };
        // A group below its Log threshold never becomes the primary (matches the
        // "no family crossed its log threshold → primary_result is None" contract).
        if group_rec == SemanticAction::None {
            continue;
        }
        let key: WinnerKey<'a> = (
            severity(group_rec),
            group_u,
            Reverse((attack_ord(attack), scope_ord(scope), field, g.best.rule_key)),
        );
        if best_key.is_none_or(|b| key > b) {
            best_key = Some(key);
            recommendation = group_rec;
            primary = Some(g.best);
            winner_has_capable = g.has_capable;
        }
    }

    // 4) Hard-veto overrides to Block regardless of the aggregate score. A
    //    hard-veto is only reachable from a `hard_veto_capable` provenance
    //    (structurally excluded for blind/synthetic views), so a hard-veto Block
    //    is enforce-safe by construction.
    if let Some((_, sig)) = hard_veto {
        recommendation = SemanticAction::Block;
        primary = Some(sig);
        request_score = request_score.max(f64::from(sig.confidence.get()));
        winner_has_capable = true;
    }

    let primary_result = primary.map(|s| DetectionResult {
        rule_id: Some(s.rule_key.to_string()),
        rule_name: format!("{} (Semantic)", s.attack.to_phase()),
        phase: s.attack.to_phase(),
        detail: s.detail.to_string(),
    });

    SemanticVerdict {
        recommendation,
        request_score: clamp_score_to_u8(request_score),
        primary_result,
        signals: signals.to_vec(),
        degraded,
        // Only meaningful for a Block recommendation; carries the winning group's
        // non-synthetic corroboration for the E0 enforce gate (A2).
        enforce_safe: winner_has_capable,
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;
    use crate::checks::content_security::types::Provenance;

    fn sig(
        attack: AttackKind,
        detector: DetectorId,
        field: &'static str,
        conf: u8,
        rule_key: &'static str,
        provenance: Provenance,
    ) -> DetectionSignal {
        DetectionSignal {
            detector,
            attack,
            field: Cow::Borrowed(field),
            scope: InspectionScope::Body,
            confidence: Confidence::saturating(conf),
            rule_key,
            provenance,
            detail: Cow::Borrowed("test signal"),
        }
    }

    fn sqli_cfg(log_t: u8, block_t: u8, allowlist: &[&str]) -> RuntimeScoringConfig {
        let mut weights = HashMap::new();
        weights.insert(DetectorId::StructRule, 0.6);
        weights.insert(DetectorId::Ast, 0.4);
        let mut attacks = HashMap::new();
        attacks.insert(
            AttackKind::SqlInjection,
            RuntimeAttackConfig {
                enabled: true,
                weights,
                log_threshold: log_t,
                block_threshold: block_t,
                hard_veto_allowlist: allowlist.iter().map(|s| (*s).to_string()).collect(),
            },
        );
        RuntimeScoringConfig { attacks }
    }

    #[test]
    fn empty_signals_score_zero() {
        let v = score(&[], &RuntimeScoringConfig::default(), false);
        assert_eq!(v.request_score, 0);
        assert_eq!(v.recommendation, SemanticAction::None);
        assert!(v.primary_result.is_none());
    }

    #[test]
    fn max_confidence_all_detectors_bounded_by_100() {
        // Both detectors at max confidence: 0.6*100 + 0.4*100 = 100.
        let signals = [
            sig(
                AttackKind::SqlInjection,
                DetectorId::StructRule,
                "body",
                100,
                "sql.union_null",
                Provenance::Raw,
            ),
            sig(
                AttackKind::SqlInjection,
                DetectorId::Ast,
                "body",
                100,
                "sql.tautology",
                Provenance::Raw,
            ),
        ];
        let v = score(&signals, &sqli_cfg(40, 80, &[]), false);
        assert_eq!(v.request_score, 100, "closed formula caps at 100");
        assert_eq!(v.recommendation, SemanticAction::Block);
    }

    #[test]
    fn duplicate_encoding_does_not_double_count() {
        // Same detector fires twice on the same field (raw + url-decoded view):
        // canonical max keeps one, so it cannot exceed its single weighted share.
        let signals = [
            sig(
                AttackKind::SqlInjection,
                DetectorId::StructRule,
                "body",
                100,
                "sql.union_null",
                Provenance::Raw,
            ),
            sig(
                AttackKind::SqlInjection,
                DetectorId::StructRule,
                "body",
                100,
                "sql.union_null",
                Provenance::UrlDecoded,
            ),
        ];
        let v = score(&signals, &sqli_cfg(40, 80, &[]), false);
        // Only StructRule fired → 0.6*100 = 60, not 120.
        assert_eq!(v.request_score, 60);
        assert_eq!(v.recommendation, SemanticAction::Log);
    }

    fn shipped_sqli_cfg(log_t: u8) -> RuntimeScoringConfig {
        // Mirror the SHIPPED weights (struct/ast 0.5 each) — sqli_cfg above uses
        // 0.6/0.4, which does not reproduce the single-hit shadow-coverage question.
        let mut weights = HashMap::new();
        weights.insert(DetectorId::StructRule, 0.5);
        weights.insert(DetectorId::Ast, 0.5);
        let mut attacks = HashMap::new();
        attacks.insert(
            AttackKind::SqlInjection,
            RuntimeAttackConfig {
                enabled: true,
                weights,
                log_threshold: log_t,
                block_threshold: 80,
                hard_veto_allowlist: std::collections::HashSet::new(),
            },
        );
        RuntimeScoringConfig { attacks }
    }

    #[test]
    fn single_structural_hit_stays_observable_at_shipped_threshold() {
        // Shadow-coverage regression: with struct/ast weights 0.5, a single
        // structural detector firing alone scores 0.5 × conf. The lowest-confidence
        // default-on rule is version_comment (conf 70 → 35). At log_threshold 40 it
        // scored below the bar (35 < 40) and produced NO shadow observation — the
        // calibration data the shadow phase exists to collect. log_threshold 30
        // keeps it (and union_select 72→36, union_null 78→39) observable.
        let hit = [sig(
            AttackKind::SqlInjection,
            DetectorId::StructRule,
            "body",
            70,
            "sql.version_comment",
            Provenance::Raw,
        )];
        let v = score(&hit, &shipped_sqli_cfg(30), false);
        assert_eq!(v.request_score, 35, "0.5 × 70 = 35");
        assert_eq!(
            v.recommendation,
            SemanticAction::Log,
            "single default-on structural hit must stay observable in shadow"
        );
        // Regression witness: the same hit under the old threshold 40 was silent.
        let v_old = score(&hit, &shipped_sqli_cfg(40), false);
        assert_eq!(
            v_old.recommendation,
            SemanticAction::None,
            "at log_threshold 40 the single hit produced no observation (the regression this fixes)"
        );
    }

    fn shipped_xss_cfg(log_t: u8) -> RuntimeScoringConfig {
        // Mirror the SHIPPED xss weights (xss_dom/xss_js 0.5 each, P-XSS-2).
        let mut weights = HashMap::new();
        weights.insert(DetectorId::XssDom, 0.5);
        weights.insert(DetectorId::XssJs, 0.5);
        let mut attacks = HashMap::new();
        attacks.insert(
            AttackKind::Xss,
            RuntimeAttackConfig {
                enabled: true,
                weights,
                log_threshold: log_t,
                block_threshold: 80,
                hard_veto_allowlist: std::collections::HashSet::new(),
            },
        );
        RuntimeScoringConfig { attacks }
    }

    #[test]
    fn xss_two_detector_corroboration_single_log_both_block() {
        // P-XSS-2 (mirrors the SQLi corroboration): a lone XSS detector on a field
        // scores 0.5 × conf → Log; the DOM structure AND the JS token together on
        // the SAME field reach the Block threshold. Shadow still downgrades, but the
        // recommendation itself is the corroboration signal under test.
        let dom_only = [sig(
            AttackKind::Xss,
            DetectorId::XssDom,
            "body",
            85,
            "xss.event_handler",
            Provenance::Raw,
        )];
        let v = score(&dom_only, &shipped_xss_cfg(40), false);
        assert_eq!(v.request_score, 43, "0.5 × 85 = 42.5 → 43");
        assert_eq!(
            v.recommendation,
            SemanticAction::Log,
            "a lone DOM structural hit stays at Log (no corroboration)"
        );

        let js_only = [sig(
            AttackKind::Xss,
            DetectorId::XssJs,
            "body",
            85,
            "xss.js_sink",
            Provenance::Raw,
        )];
        let v = score(&js_only, &shipped_xss_cfg(40), false);
        assert_eq!(
            v.recommendation,
            SemanticAction::Log,
            "a lone JS-token hit stays at Log (no corroboration)"
        );

        // Both detectors on the same field → 0.5·85 + 0.5·85 = 85 ≥ 80 → Block.
        let corroborated = [
            sig(
                AttackKind::Xss,
                DetectorId::XssDom,
                "body",
                85,
                "xss.event_handler",
                Provenance::Raw,
            ),
            sig(
                AttackKind::Xss,
                DetectorId::XssJs,
                "body",
                85,
                "xss.js_sink",
                Provenance::Raw,
            ),
        ];
        let v = score(&corroborated, &shipped_xss_cfg(40), false);
        assert_eq!(v.request_score, 85, "0.5·85 + 0.5·85 = 85");
        assert_eq!(
            v.recommendation,
            SemanticAction::Block,
            "DOM structure + JS token corroborate → Block recommendation"
        );
        // Deterministic within-group representative: equal contribution breaks on
        // detector_ord (XssDom = 4 < XssJs = 5), so the DOM structural signal is the
        // group's primary.
        assert_eq!(
            v.primary_result.and_then(|r| r.rule_id).as_deref(),
            Some("xss.event_handler"),
            "equal-contribution tie-break picks the smaller detector_ord (xss_dom)"
        );
    }

    #[test]
    fn single_xss_default_on_construct_stays_observable_at_log_40() {
        // Threshold audit (P-XSS-2): every default-on construct's lone 0.5 × conf
        // must stay ≥ the shipped log_threshold (40) so shadow still observes it.
        // The lowest default-on construct is `xss.data_html_url` (conf 82 → 41).
        for (conf, rule, det) in [
            (82u8, "xss.data_html_url", DetectorId::XssDom),
            (85, "xss.event_handler", DetectorId::XssDom),
            (85, "xss.js_url", DetectorId::XssDom),
            (85, "xss.iframe_srcdoc", DetectorId::XssDom),
            (88, "xss.svg_onload", DetectorId::XssDom),
            (90, "xss.script_tag", DetectorId::XssDom),
            (85, "xss.js_sink", DetectorId::XssJs),
            (88, "xss.js_exfil", DetectorId::XssJs),
        ] {
            let hit = [sig(AttackKind::Xss, det, "body", conf, rule, Provenance::Raw)];
            let v = score(&hit, &shipped_xss_cfg(40), false);
            assert_eq!(
                v.recommendation,
                SemanticAction::Log,
                "single default-on {rule} (0.5 × {conf}) must stay observable at log 40, got score {}",
                v.request_score
            );
            assert!(
                v.request_score < 80,
                "and must be below Block (single detector never blocks)"
            );
        }
    }

    #[test]
    fn hard_veto_allowlisted_rulekey_blocks() {
        let signals = [sig(
            AttackKind::SqlInjection,
            DetectorId::StructRule,
            "body",
            50,
            "sql.into_outfile",
            Provenance::Raw,
        )];
        // Score 0.6*50 = 30 < block threshold 80, but allowlisted → Block.
        let v = score(&signals, &sqli_cfg(40, 80, &["sql.into_outfile"]), false);
        assert_eq!(v.recommendation, SemanticAction::Block);
    }

    #[test]
    fn non_capable_provenance_never_hard_vetoes() {
        // codex A-1 negative examples: BlindDecoded / SyntheticHpp / ParseError
        // are structurally excluded from hard-veto. Even with the exact rule_key
        // on the allowlist and a would-be-eligible signal, none may Block. There
        // is no longer any `hard_veto_eligible` bool to forge — the scorer
        // derives capability from `provenance` itself.
        for prov in [
            Provenance::BlindDecoded,
            Provenance::SyntheticHpp,
            Provenance::ParseError,
        ] {
            let signals = [sig(
                AttackKind::SqlInjection,
                DetectorId::StructRule,
                "body",
                50,
                "sql.into_outfile",
                prov,
            )];
            let v = score(&signals, &sqli_cfg(40, 80, &["sql.into_outfile"]), false);
            assert_ne!(
                v.recommendation,
                SemanticAction::Block,
                "provenance {prov:?} must never hard-veto (0.6*50=30 < block 80 → falls back to weighted score)"
            );
        }
    }

    #[test]
    fn capable_provenance_allowlisted_still_hard_vetoes() {
        // Positive control: a capable provenance (UrlDecoded) on the allowlist
        // still hard-vetoes, so the negative test above is not vacuous.
        for prov in [Provenance::Raw, Provenance::UrlDecoded, Provenance::HtmlEntityDecoded] {
            let signals = [sig(
                AttackKind::SqlInjection,
                DetectorId::StructRule,
                "body",
                50,
                "sql.into_outfile",
                prov,
            )];
            let v = score(&signals, &sqli_cfg(40, 80, &["sql.into_outfile"]), false);
            assert_eq!(
                v.recommendation,
                SemanticAction::Block,
                "capable provenance {prov:?} on the allowlist must hard-veto"
            );
        }
    }

    #[test]
    fn blind_only_block_is_not_enforce_safe() {
        // E0 / A2: a single-detector family (rce weight 1.0) whose reverse-shell
        // rule (conf 92) crosses the Block bar SOLELY on a blind-decoded view is
        // NOT enforce-safe — the enforce path must downgrade it to shadow Log.
        let cfg = three_family_cfg();
        let blind = [sig(
            AttackKind::Rce,
            DetectorId::Rce,
            "body",
            92,
            "rce.reverse_shell",
            Provenance::BlindDecoded,
        )];
        let v = score(&blind, &cfg, false);
        assert_eq!(v.recommendation, SemanticAction::Block, "92 ≥ block threshold 80");
        assert!(
            !v.enforce_safe,
            "a Block carried solely by a blind_decoded view must not be enforce-safe"
        );

        // The SAME rule on a directly-observable (UrlDecoded) view IS enforce-safe.
        let observable = [sig(
            AttackKind::Rce,
            DetectorId::Rce,
            "body",
            92,
            "rce.reverse_shell",
            Provenance::UrlDecoded,
        )];
        let v = score(&observable, &cfg, false);
        assert_eq!(v.recommendation, SemanticAction::Block);
        assert!(
            v.enforce_safe,
            "a Block corroborated by a non-synthetic (UrlDecoded) view is enforce-safe"
        );
    }

    #[test]
    fn corroborated_block_needs_one_nonsynthetic_view_to_be_enforce_safe() {
        // E0 / A2 for double-detector families: two SQLi detectors corroborate to
        // Block, but if BOTH fire only on blind views the Block is not enforce-safe.
        let cfg = shipped_sqli_cfg(40); // struct/ast 0.5/0.5
        let both_blind = [
            sig(
                AttackKind::SqlInjection,
                DetectorId::StructRule,
                "body",
                90,
                "sql.dangerous_fn",
                Provenance::BlindDecoded,
            ),
            sig(
                AttackKind::SqlInjection,
                DetectorId::Ast,
                "body",
                90,
                "ast.dangerous_fn",
                Provenance::BlindDecoded,
            ),
        ];
        let v = score(&both_blind, &cfg, false);
        assert_eq!(v.recommendation, SemanticAction::Block, "0.5·90 + 0.5·90 = 90 ≥ 80");
        assert!(
            !v.enforce_safe,
            "two blind detectors corroborate to Block but still lack a non-synthetic view"
        );

        // One of the two on a Raw view → the winning group has non-synthetic support.
        let one_observable = [
            sig(
                AttackKind::SqlInjection,
                DetectorId::StructRule,
                "body",
                90,
                "sql.dangerous_fn",
                Provenance::Raw,
            ),
            sig(
                AttackKind::SqlInjection,
                DetectorId::Ast,
                "body",
                90,
                "ast.dangerous_fn",
                Provenance::BlindDecoded,
            ),
        ];
        let v = score(&one_observable, &cfg, false);
        assert_eq!(v.recommendation, SemanticAction::Block);
        assert!(
            v.enforce_safe,
            "one non-synthetic view in the winning group makes the corroborated Block enforce-safe"
        );
    }

    #[test]
    fn disabled_family_contributes_nothing() {
        let mut cfg = sqli_cfg(40, 80, &[]);
        if let Some(ac) = cfg.attacks.get_mut(&AttackKind::SqlInjection) {
            ac.enabled = false;
        }
        let signals = [sig(
            AttackKind::SqlInjection,
            DetectorId::StructRule,
            "body",
            100,
            "sql.union_null",
            Provenance::Raw,
        )];
        let v = score(&signals, &cfg, false);
        assert_eq!(v.request_score, 0);
        assert_eq!(v.recommendation, SemanticAction::None);
    }

    #[test]
    fn degraded_flag_is_propagated() {
        let v = score(&[], &RuntimeScoringConfig::default(), true);
        assert!(v.degraded);
    }

    /// A three-family scoring config (`SQLi` / RCE / Traversal), each a single
    /// detector at weight 1.0, block threshold 80 — mirrors the shipped families.
    fn three_family_cfg() -> RuntimeScoringConfig {
        let mut attacks = HashMap::new();
        for (attack, det) in [
            (AttackKind::SqlInjection, DetectorId::StructRule),
            (AttackKind::Rce, DetectorId::Rce),
            (AttackKind::Traversal, DetectorId::Traversal),
        ] {
            let mut weights = HashMap::new();
            weights.insert(det, 1.0);
            attacks.insert(
                attack,
                RuntimeAttackConfig {
                    enabled: true,
                    weights,
                    log_threshold: 40,
                    block_threshold: 80,
                    hard_veto_allowlist: HashSet::new(),
                },
            );
        }
        RuntimeScoringConfig { attacks }
    }

    #[test]
    fn primary_is_deterministic_across_runs_equal_severity_and_score() {
        // codex A-1: three families fire on the SAME field with the SAME confidence
        // (all Block, all group score 90). The old code left the primary to
        // `HashMap` iteration order; the deterministic comparator must always pick
        // the same family — the stable structural tie-break selects the smallest
        // `attack_ord`, i.e. SQLi. Run many times (each `score` call builds fresh
        // randomly-seeded HashMaps) and assert the primary never drifts.
        let signals = [
            sig(
                AttackKind::SqlInjection,
                DetectorId::StructRule,
                "body",
                90,
                "sql.into_outfile",
                Provenance::Raw,
            ),
            sig(
                AttackKind::Rce,
                DetectorId::Rce,
                "body",
                90,
                "rce.reverse_shell",
                Provenance::Raw,
            ),
            sig(
                AttackKind::Traversal,
                DetectorId::Traversal,
                "body",
                90,
                "traversal.overlong",
                Provenance::Raw,
            ),
        ];
        let cfg = three_family_cfg();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let v = score(&signals, &cfg, false);
            assert_eq!(v.recommendation, SemanticAction::Block);
            assert_eq!(v.request_score, 90, "request score is the max group score");
            let rule = v.primary_result.expect("a Block must carry a primary").rule_id;
            seen.insert(rule);
        }
        assert_eq!(
            seen,
            std::collections::HashSet::from([Some("sql.into_outfile".to_string())]),
            "primary must be the deterministic tie-break winner (SQLi), never HashMap-order-dependent: {seen:?}"
        );
    }

    #[test]
    fn within_group_best_is_deterministic_for_equal_contribution() {
        // codex P1c §3.1 / P2: TWO detectors (`struct_rule` + `ast`) fire on the
        // SAME (scope, field, attack) group with EQUAL weighted contribution
        // (0.5·80 == 0.5·80). Group score is 0.5·80 + 0.5·80 = 80 (Block), and the
        // group's representative signal (`Group::best` → `primary_result`) must be
        // the deterministic tie-break winner (smaller detector_ord → `struct_rule`),
        // never `HashMap`-order-dependent. Run many freshly-seeded times.
        let signals = [
            sig(
                AttackKind::SqlInjection,
                DetectorId::StructRule,
                "body",
                80,
                "sql.union_null",
                Provenance::Raw,
            ),
            sig(
                AttackKind::SqlInjection,
                DetectorId::Ast,
                "body",
                80,
                "ast.union",
                Provenance::Raw,
            ),
        ];
        let cfg = sqli_cfg(40, 80, &[]); // struct_rule 0.6 / ast 0.4 → unequal; override to 0.5/0.5
        let cfg = {
            let mut c = cfg;
            if let Some(ac) = c.attacks.get_mut(&AttackKind::SqlInjection) {
                ac.weights.insert(DetectorId::StructRule, 0.5);
                ac.weights.insert(DetectorId::Ast, 0.5);
            }
            c
        };
        let mut seen = std::collections::HashSet::new();
        for _ in 0..300 {
            let v = score(&signals, &cfg, false);
            assert_eq!(v.request_score, 80, "0.5·80 + 0.5·80 = 80");
            assert_eq!(v.recommendation, SemanticAction::Block, "80 ≥ block threshold 80");
            let rule = v.primary_result.expect("Block carries a primary").rule_id;
            seen.insert(rule);
        }
        assert_eq!(
            seen,
            std::collections::HashSet::from([Some("sql.union_null".to_string())]),
            "equal-contribution group best must be the deterministic (detector_ord) winner: {seen:?}"
        );
    }

    #[test]
    fn primary_is_the_highest_scoring_family_regardless_of_order() {
        // codex A-1 (the exact reported failure): SQLi 95 / RCE 92 / Traversal 68,
        // all Block. `request_score` is 95 and the primary must ALWAYS be the
        // highest-scoring family (SQLi), never flipping to RCE across runs.
        let signals = [
            sig(
                AttackKind::SqlInjection,
                DetectorId::StructRule,
                "body",
                95,
                "sql.into_outfile",
                Provenance::Raw,
            ),
            sig(
                AttackKind::Rce,
                DetectorId::Rce,
                "body",
                92,
                "rce.reverse_shell",
                Provenance::Raw,
            ),
            sig(
                AttackKind::Traversal,
                DetectorId::Traversal,
                "body",
                68,
                "traversal.sensitive_abs",
                Provenance::Raw,
            ),
        ];
        let cfg = three_family_cfg();
        for _ in 0..200 {
            let v = score(&signals, &cfg, false);
            assert_eq!(v.request_score, 95);
            assert_eq!(
                v.primary_result.as_ref().and_then(|r| r.rule_id.as_deref()),
                Some("sql.into_outfile"),
                "the highest-scoring group must always be primary"
            );
        }
    }
}
