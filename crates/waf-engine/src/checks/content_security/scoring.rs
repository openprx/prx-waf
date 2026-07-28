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
//! **ε-slack reconciliation (codex P1a — "epsilon vs clamp口径").** The loader
//! does not enforce `Σ weight = 1` *exactly*: `WEIGHT_SUM_EPSILON` (`1e-6`)
//! admits any family whose weights sum to `1 ± 1e-6`
//! (`waf_common::ContentSecurityConfig::validate`). At the positive boundary the
//! group score is a *near*-convex combination whose raw `f64` value can reach
//! `100·(1 + 1e-6) = 100.0001` — i.e. marginally over 100, so the pure
//! convex-combination argument above is not *literally* airtight. This is a
//! documentation口径 gap, **not** an output bug: [`clamp_score_to_u8`] is the
//! load-bearing invariant. Every score that leaves this module (`request_score`
//! and every `group_u` used for a threshold comparison) passes through that
//! clamp, which maps any `x ≥ 100.0` to `100`. The two口径 are therefore
//! consistent — the weight-sum rule keeps the raw score at `≈ 100`, and the
//! clamp closes the `1e-6` slack so the emitted byte is provably in `0..=100`.
//! `epsilon_weight_slack_still_clamps_to_100` fixes this invariant.
//!
//! Hard-veto is an explicit per-attack allowlist keyed on the **stable
//! `rule_key`** (never on `detail`), and blind/synthetic/parse-error provenance
//! is structurally excluded (plan §6.3).
//!
//! **`BlindDecoded` aggregation semantics (codex P1c — enforce decision point).**
//! A `BlindDecoded` signal (base64/hex blind-decode view) is **not** a hard-veto
//! candidate — `Provenance::hard_veto_capable` excludes it, so it can never
//! single-signal Block on its own. It **does**, however, participate in the
//! ordinary weighted sum exactly like any other view: its `weight · confidence`
//! contribution counts toward the group score, so a `BlindDecoded` hit at high
//! confidence *can* push a group to (or past) its `log_threshold` /
//! `block_threshold` and yield a `Block` **recommendation**. The one guard on the
//! enforce path is `SemanticVerdict::enforce_safe`: a group whose Block is
//! carried **only** by blind/synthetic views has `has_capable == false`, so
//! `enforce_safe` is `false` and the enforce dispatch downgrades that Block to a
//! shadow `Log` (E0 / A2). Net current semantics: `BlindDecoded` **can** raise a
//! `Block` *recommendation* through the weighted threshold but **cannot** cause an
//! *enforced* block unless some directly-observable (`Raw`/`UrlDecoded`/…) view in
//! the same group corroborates it.
//!
//! **Enforce-time decision point (do NOT change here — shadow behaviour frozen).**
//! Before enforcement is switched on, revisit whether `BlindDecoded` should carry
//! its full detector weight in the aggregate. Options on the table: (a) keep
//! today's behaviour — full weight, gated solely by `enforce_safe`; (b) apply a
//! per-provenance down-weight or ceiling so a blind-only view contributes a capped
//! fraction; (c) require ≥2 corroborating views before a blind contribution counts
//! toward `block_threshold`. This module intentionally implements (a) today; the
//! choice is an enforcement-tuning decision, not a scoring bug, and must be made
//! with holdout calibration data — not silently here. Fixed by
//! `blind_decoded_participates_in_weighted_threshold_but_not_enforce_safe`.
//!
//! **Cross-family aggregation is `max`, not `+` (no double counting).** One
//! payload routinely produces evidence in more than one family — `cat /etc/passwd`
//! fires `rce.sensitive_read` (70) and `rce_ast.sensitive_read` (70) in `Rce` *and*
//! `traversal.sensitive_abs` (68) in `Traversal`. Only the first pair combines:
//! the group key is `(scope, field, attack)`, so weighted summation is confined
//! **inside** a family (that is the deliberate two-detector corroboration), and the
//! request roll-up across families is `request_score = max_g group_score` with a
//! **single** winning group supplying the one recommendation and the one
//! `primary_result`. A second family can therefore only *replace* the winner by
//! scoring higher; it can never add to another family's score, and two sub-block
//! families can never sum their way to a Block. Fixed by
//! `cross_family_evidence_rolls_up_by_max_not_by_sum` and
//! `cross_family_pair_cannot_manufacture_a_block`. (Severity is compared before
//! score in [`WinnerKey`], so a family that reached Block always outranks one that
//! only reached Log — a Block is never masked by a higher-scoring Log.)
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
//!
//! **Disposition and attribution are two different questions (T17).** The
//! comparator above answers "which group carries the most corroborated evidence",
//! which is the right question for *whether to act* and the wrong one for *what
//! to call it*: group scores are not comparable across families, because
//! `Σ weight = 1` is imposed **per family**. A single-detector family scores
//! `1.0 · c`; a two-detector family with one detector firing scores `0.5 · c` on
//! evidence of identical strength — and severity is compared before score, so the
//! single-detector family can reach `Block` and outrank a `Log` outright. So
//! `cat /etc/passwd` used to be reported as `DirTraversal`: `rce.sensitive_read`
//! (70 · 0.5 = 35, under `Rce`'s log threshold) lost to `traversal.sensitive_abs`
//! (68 · 1.0 = 68, `Log`).
//!
//! Renormalising the scores would fix the label by moving the thresholds, which
//! are a separately calibrated contract, so the fix is on the evidence instead:
//! some rules match a construct **several families share**
//! ([`SHARED_CONSTRUCT_RULES`]) — matching one proves an attack, not which attack
//! it is. Such a group still wins the disposition on its score exactly as before;
//! it just does not get to *name* the event while a co-located family (same
//! scope, same field) produced family-discriminating evidence. `recommendation`,
//! `request_score` and `enforce_safe` are bit-for-bit unchanged by that step —
//! only `primary_result` moves. Fixed by
//! `shared_construct_cedes_naming_to_a_co_located_specific_family` and
//! `attribution_never_moves_the_disposition`.

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

/// Rule keys whose matched construct is **shared across attack families**:
/// matching one proves an attack is under way, but not *which* attack it is.
///
/// The whole list today is the sensitive-absolute-path rules. The literal
/// `/etc/passwd` is the payload of a path traversal (`../../../../etc/passwd`),
/// of a command execution (`cat /etc/passwd`) and of a local-file include alike;
/// the `Traversal` family owns these rules only because that is where the
/// string-matching detector for absolute paths happens to live, not because a
/// match discriminates the family. Every *other* traversal rule —
/// `traversal.overlong`, `traversal.encoded_dotdot`, `traversal.plain_dotdot` —
/// matches `../` itself, a construct no other family's grammar produces, and is
/// deliberately NOT listed here.
///
/// **This list changes attribution only.** It selects which signal populates
/// `primary_result`, i.e. what an operator sees the event *called*.
/// `recommendation`, `request_score` and `enforce_safe` are all taken from the
/// decision winner and are bit-for-bit unaffected by anything here (see step 3b
/// in [`score`]). A group whose only evidence is a shared construct still wins
/// the disposition on its score exactly as before — it just does not get to name
/// the event while a co-located family produced family-discriminating evidence.
///
/// This is deliberately NOT an attempt to disambiguate genuinely ambiguous
/// grammar. A quote-closed tautology (`' or '1'='1`) fires `ast.tautology` and
/// `xpath.quote_tautology` on the same bytes, and a reverse proxy cannot know
/// whether the backend hands that string to a SQL engine or an `XPath` evaluator.
/// Each rule discriminates its family *within its own grammar*, so neither is
/// listed and the existing deterministic tie-break still decides.
///
/// Kept in sync with the live rule tables by
/// `detectors::tests::shared_construct_rules_all_name_a_live_rule`: a rename that
/// silently turned an entry here into dead weight fails that test.
pub(super) const SHARED_CONSTRUCT_RULES: &[&str] = &[
    "traversal.sensitive_abs",
    "traversal.sensitive_abs_brace",
    "traversal.sensitive_abs_ops",
];

/// Whether `rule_key` names a cross-family shared construct
/// ([`SHARED_CONSTRUCT_RULES`]).
///
/// A linear scan of a three-element `&'static` slice: once per admitted signal
/// (to maintain [`Group::best_specific`]) plus at most one more per scored
/// request. It allocates nothing and compares no more bytes than the roll-up
/// tie-break already does.
fn is_shared_construct(rule_key: &str) -> bool {
    SHARED_CONSTRUCT_RULES.contains(&rule_key)
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
    /// This group's strongest signal whose `rule_key` is **not** a cross-family
    /// shared construct — i.e. the family's best *family-discriminating* evidence
    /// — or `None` when everything it produced is a construct other families
    /// share.
    ///
    /// Attribution-only: it never enters [`Group::score`], so it cannot move a
    /// threshold. Ranked by [`specific_is_better`] — raw confidence, deliberately
    /// **not** the weighted contribution that ranks [`Group::best`]. Weights are a
    /// family-internal aggregation parameter with no cross-family meaning, and
    /// comparing weighted numbers across families is the exact mistake this whole
    /// step exists to undo. Confidence is the detector's own unscaled statement of
    /// strength, on one scale for every family. Ties break structurally, so the
    /// choice is `HashMap`-order-independent.
    best_specific: Option<&'a DetectionSignal>,
}

/// The `(scope, field, attack)` → [`Group`] accumulation map built by [`score`].
type GroupMap<'a> = HashMap<(InspectionScope, &'a str, AttackKind), Group<'a>>;

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
        AttackKind::NoSqlInjection => 5,
        AttackKind::Ssti => 6,
        AttackKind::LdapInjection => 7,
        AttackKind::XpathInjection => 8,
        AttackKind::Deserialization => 9,
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
        DetectorId::NoSqlStruct => 8,
        DetectorId::SstiStruct => 9,
        DetectorId::LdapStruct => 10,
        DetectorId::XpathStruct => 11,
        DetectorId::DeserStruct => 12,
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

/// Ordering key for the attribution-only search in [`reattribute_shared_construct`].
///
/// Same shape as [`WinnerKey`] but with **raw confidence** in place of severity
/// and weighted score, and deliberately so on both counts: a naming candidate is
/// picked for the strength of its family-discriminating evidence, not for whether
/// its own family happened to cross a threshold (a volume question) nor for a
/// weighted number that only means something inside its own family. Greatest key
/// wins; the [`Reverse`]d structural tuple is unique per group, so the order is
/// total and the result never depends on `HashMap` iteration order.
type AttributionKey<'a> = (u8, Reverse<(u8, u8, &'a str, &'a str)>);

/// Whether a candidate should replace a group's current [`Group::best_specific`]
/// under a total, `HashMap`-order-independent order: higher raw confidence wins;
/// on a tie the smaller `(detector_ord, rule_key)` wins.
fn specific_is_better(new: &DetectionSignal, cur: &DetectionSignal) -> bool {
    match new.confidence.get().cmp(&cur.confidence.get()) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => {
            (detector_ord(new.detector), new.rule_key) < (detector_ord(cur.detector), cur.rule_key)
        }
    }
}

/// Pick the signal that should *name* an event whose decision winner is
/// represented by a cross-family shared construct ([`SHARED_CONSTRUCT_RULES`]).
///
/// Returns `None` to keep the decision winner's own signal — nothing better was
/// co-located, so the shared construct is still the most honest label available.
/// Search order:
///
/// 1. **Inside the winning group.** If the family that won the decision also
///    produced family-discriminating evidence on this field, attribution stays
///    in that family and only the rule sharpens — the smallest correction that
///    fixes the label.
/// 2. **A co-located group of another family** — same `scope` *and* same `field`,
///    so it is provably the same bytes being described — that produced
///    family-discriminating evidence, ranked by [`AttributionKey`].
///
/// Restricting step 2 to the same `(scope, field)` is what keeps this from being
/// a global "prefer family X" rule: evidence about a different field describes a
/// different part of the request and says nothing about what *this* construct is.
///
/// The winning group's severity, score, and provenance are untouched — this
/// selects a `primary_result` and nothing else.
fn reattribute_shared_construct<'a>(
    groups: &GroupMap<'a>,
    scope: InspectionScope,
    field: &'a str,
    attack: AttackKind,
) -> Option<&'a DetectionSignal> {
    if let Some(sig) = groups.get(&(scope, field, attack)).and_then(|g| g.best_specific) {
        return Some(sig);
    }
    let mut best: Option<(AttributionKey<'a>, &'a DetectionSignal)> = None;
    for (&(g_scope, g_field, g_attack), g) in groups {
        if g_scope != scope || g_field != field || g_attack == attack {
            continue;
        }
        let Some(sig) = g.best_specific else {
            continue;
        };
        let key: AttributionKey<'a> = (
            sig.confidence.get(),
            Reverse((attack_ord(g_attack), scope_ord(g_scope), g_field, sig.rule_key)),
        );
        if best.as_ref().is_none_or(|(k, _)| key > *k) {
            best = Some((key, sig));
        }
    }
    best.map(|(_, sig)| sig)
}

/// Compute the closed Lane 2 verdict for a set of signals.
///
/// Returns a [`SemanticVerdict`] whose `request_score` is guaranteed to be in
/// `0..=100`. With `signals` empty (the P1a production reality — no detectors)
/// the result is always `recommendation = None`, `request_score = 0`,
/// `primary_result = None`.
///
/// **`degraded` semantics (D1).** `degraded` records that the per-request work
/// budget ran out, i.e. some part of the request was never inspected. It is
/// **scoring-neutral**: the signals that *were* produced are scored, ranked and
/// (if they cross a threshold) recommended exactly as on a non-degraded request,
/// and `enforce_safe` is still derived from the winning group's provenance rather
/// than being forced to `false`. Degradation is an abstention over what was not
/// looked at; it is not evidence against what was. The flag is propagated to
/// [`SemanticVerdict::degraded`] so the miss window remains observable in the
/// persisted observation (`degraded` / `exhausted`).
#[must_use]
pub fn score<'a>(signals: &'a [DetectionSignal], cfg: &RuntimeScoringConfig, degraded: bool) -> SemanticVerdict {
    // Budget degradation is an **abstention over the un-inspected remainder**, not
    // a retraction of what was already observed (D1). It is deliberately NOT a
    // short-circuit here: the signals below are real detector hits on real views
    // that were fully inspected before the budget ran out, and they are scored
    // exactly as on a non-degraded request. `degraded` is carried through to the
    // verdict (and from there to the persisted observation) so the miss window
    // stays visible in telemetry.
    //
    // Why the earlier "degraded ⇒ zero the whole verdict" rule was a bypass
    // primitive, not a safe fail-open: every budget counter is attacker-reachable
    // (a JSON body with `max_fields_per_phase` harmless leaves, an oversized field,
    // a wide decode fan-out), so an attacker could pad any request into the
    // degraded state and have the entire Lane 2 verdict — including a
    // fully-observed, high-confidence hit on an *early* field — reset to
    // `request_score = 0` / `recommendation = None`. Fail-open must mean "we do not
    // claim the request is clean", which is already true: Lane 2 only runs after
    // Lane 1 came back clean and it never suppresses a Lane 1 verdict, so a
    // partial signal set can only ever ADD detection, never remove one. Under-
    // scoring (a group missing a corroborating detector that never got to run) is
    // the only direction partiality can move the score, and that direction is safe.

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
    let mut groups: GroupMap<'a> = HashMap::new();
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
            best_specific: None,
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
        // The attribution track (step 3b), restricted to this family's own
        // discriminating evidence and ranked on raw confidence — it reads no
        // weight and writes no score. Maintained here rather than recomputed later
        // because `canonical` is consumed by this single pass.
        if !is_shared_construct(sig.rule_key) && g.best_specific.is_none_or(|cur| specific_is_better(sig, cur)) {
            g.best_specific = Some(sig);
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
    // The winning group's key, kept for the attribution step below. Never used
    // for the decision itself.
    let mut winner_group: Option<(InspectionScope, &'a str, AttackKind)> = None;

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
            winner_group = Some((scope, field, attack));
        }
    }

    // 3b) Attribution correction (T17). The decision is already final above —
    //     `recommendation`, `request_score` and `winner_has_capable` are fixed and
    //     are NOT read or written here. What is still open is which signal *names*
    //     the event.
    //
    //     Group scores are not comparable across families: `Σ weight = 1` is
    //     imposed per family, so a single-detector family scores `1.0 · c` where a
    //     two-detector family with one detector firing scores `0.5 · c` on
    //     evidence of the same strength — and the roll-up compares severity first,
    //     so the single-detector family can also outrank on severity alone. That
    //     comparison is the right one for "should this be acted on" (it is a
    //     volume question, and every family's thresholds are calibrated on its own
    //     scale) and the wrong one for "what is this" (an identity question).
    //     Renormalising to fix the label would move the thresholds, which are a
    //     separately calibrated contract — so the label is fixed here instead, on
    //     the evidence rather than on the arithmetic.
    //
    //     `/etc/passwd` says "someone is after a secret file"; `cat /etc/passwd`
    //     says "…by executing a command". Only the second belongs in a responder's
    //     runbook, and only the second is family-discriminating evidence.
    //
    //     One downstream consequence, stated rather than hidden: the engine reads
    //     `primary_result.phase` back as the family key for
    //     `enforcement_overrides` (`engine.rs`, `effective_enforcement_mode`). With
    //     the shipped empty override map every family resolves to the global mode,
    //     so a corrected label cannot move an action. With overrides configured it
    //     can — and that is the intended reading: an override for `rce` should
    //     apply to a request that is an RCE, which is precisely the judgement this
    //     step exists to get right.
    if let (Some(sig), Some((w_scope, w_field, w_attack))) = (primary, winner_group)
        && is_shared_construct(sig.rule_key)
        && let Some(better) = reattribute_shared_construct(&groups, w_scope, w_field, w_attack)
    {
        primary = Some(better);
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
    fn epsilon_weight_slack_still_clamps_to_100() {
        // codex P1a ("epsilon vs clamp口径"): the loader tolerates a weight sum of
        // 1 ± WEIGHT_SUM_EPSILON (1e-6). At the positive boundary the raw group
        // score with both detectors at confidence 100 is 100·(1 + 1e-6) =
        // 100.0001 — marginally over 100 — so the convex-combination bound is not
        // literally airtight. The load-bearing invariant is `clamp_score_to_u8`:
        // the emitted `request_score` must still be exactly 100, never 101, never a
        // wrap/panic. This test fixes that口径 reconciliation.
        const EPS: f64 = 1e-6;
        let mut weights = HashMap::new();
        // Sum = 0.6 + (0.4 + 1e-6) = 1 + 1e-6, the max a validated config admits.
        weights.insert(DetectorId::StructRule, 0.6);
        weights.insert(DetectorId::Ast, 0.4 + EPS);
        let mut attacks = HashMap::new();
        attacks.insert(
            AttackKind::SqlInjection,
            RuntimeAttackConfig {
                enabled: true,
                weights,
                log_threshold: 40,
                block_threshold: 80,
                hard_veto_allowlist: HashSet::new(),
            },
        );
        let cfg = RuntimeScoringConfig { attacks };
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
        let v = score(&signals, &cfg, false);
        // Raw score 100.0001 → clamp maps ≥ 100.0 to exactly 100.
        assert_eq!(
            v.request_score, 100,
            "an epsilon-over weight sum must still clamp to 100, never overflow the byte"
        );
        assert_eq!(v.recommendation, SemanticAction::Block);
    }

    #[test]
    fn blind_decoded_participates_in_weighted_threshold_but_not_enforce_safe() {
        // codex P1c (BlindDecoded aggregation semantics — enforce decision point).
        // Documents + fixes today's behaviour: a BlindDecoded signal is NOT a
        // hard-veto candidate, yet it DOES count toward the ordinary weighted
        // threshold. A lone single-detector (weight 1.0) BlindDecoded hit at conf
        // 92 crosses the Block bar → Block *recommendation*, but the Block is
        // carried solely by a blind view → `enforce_safe == false`, so at enforce
        // time it is downgraded to shadow Log.
        let cfg = three_family_cfg(); // rce weight 1.0, block_threshold 80
        let blind_over = [sig(
            AttackKind::Rce,
            DetectorId::Rce,
            "body",
            92,
            "rce.reverse_shell",
            Provenance::BlindDecoded,
        )];
        let v = score(&blind_over, &cfg, false);
        assert_eq!(
            v.request_score, 92,
            "BlindDecoded contributes its full weighted share to the aggregate"
        );
        assert_eq!(
            v.recommendation,
            SemanticAction::Block,
            "a BlindDecoded hit past block_threshold yields a Block RECOMMENDATION"
        );
        assert!(
            !v.enforce_safe,
            "but a blind-only Block is not enforce-safe — enforce path downgrades it"
        );

        // Below the threshold the blind contribution produces no recommendation at
        // all (it is plain weighted scoring, not a veto floor).
        let blind_under = [sig(
            AttackKind::Rce,
            DetectorId::Rce,
            "body",
            30,
            "rce.reverse_shell",
            Provenance::BlindDecoded,
        )];
        let v = score(&blind_under, &cfg, false);
        assert_eq!(v.request_score, 30, "weighted contribution 1.0 × 30 = 30");
        assert_eq!(
            v.recommendation,
            SemanticAction::None,
            "30 < log_threshold 40 → no recommendation; BlindDecoded is not a veto floor"
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

    /// The SHIPPED `rce` (rce 0.5 / `rce_ast` 0.5) + `traversal` (traversal 1.0)
    /// families, both `log_threshold = 40` / `block_threshold = 80`.
    fn shipped_rce_traversal_cfg() -> RuntimeScoringConfig {
        let mut attacks = HashMap::new();
        let mut rce_weights = HashMap::new();
        rce_weights.insert(DetectorId::Rce, 0.5);
        rce_weights.insert(DetectorId::RceAst, 0.5);
        attacks.insert(
            AttackKind::Rce,
            RuntimeAttackConfig {
                enabled: true,
                weights: rce_weights,
                log_threshold: 40,
                block_threshold: 80,
                hard_veto_allowlist: HashSet::new(),
            },
        );
        let mut trav_weights = HashMap::new();
        trav_weights.insert(DetectorId::Traversal, 1.0);
        attacks.insert(
            AttackKind::Traversal,
            RuntimeAttackConfig {
                enabled: true,
                weights: trav_weights,
                log_threshold: 40,
                block_threshold: 80,
                hard_veto_allowlist: HashSet::new(),
            },
        );
        RuntimeScoringConfig { attacks }
    }

    /// **Cross-family roll-up is `max`, never a sum — one payload cannot be
    /// counted twice.**
    ///
    /// `cat /etc/passwd` legitimately fires three rules: `rce.sensitive_read` (70)
    /// and `rce_ast.sensitive_read` (70) inside the `Rce` family — the designed
    /// 0.5/0.5 corroboration — and `traversal.sensitive_abs` (68) inside the
    /// `Traversal` family. The concern that this is "one piece of evidence voting
    /// twice" would only be true if family scores combined additively. They do not:
    /// the group key is `(scope, field, attack)`, weighted summation happens
    /// **inside** a group, and the request roll-up is
    /// `request_score = max_g group_score` with a **single** winning group
    /// supplying the one recommendation and the one `primary_result`.
    ///
    /// So the traversal hit can never lift the RCE score (or vice versa); it can
    /// only *replace* it as the winner if it scores higher. Here it does not:
    /// 70 > 68, so the verdict is one `Log` attributed to `Rce` with
    /// `request_score = 70` — not 138, and not a second independent verdict.
    #[test]
    fn cross_family_evidence_rolls_up_by_max_not_by_sum() {
        let signals = [
            sig(
                AttackKind::Rce,
                DetectorId::Rce,
                "body",
                70,
                "rce.sensitive_read",
                Provenance::Raw,
            ),
            sig(
                AttackKind::Rce,
                DetectorId::RceAst,
                "body",
                70,
                "rce_ast.sensitive_read",
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
        let cfg = shipped_rce_traversal_cfg();
        let v = score(&signals, &cfg, false);
        // Rce group  = 0.5·70 + 0.5·70 = 70 (in-family corroboration, by design).
        // Trav group = 1.0·68        = 68.
        // Request    = max(70, 68)   = 70. NOT 70 + 68 = 138, and NOT 100.
        assert_eq!(v.request_score, 70, "request score is the max group score, never a sum");
        assert_eq!(
            v.recommendation,
            SemanticAction::Log,
            "70 ≥ log(40) but < block(80): one Log, not two votes toward a Block"
        );
        assert_eq!(
            v.primary_result.as_ref().and_then(|r| r.rule_id.as_deref()),
            Some("rce.sensitive_read"),
            "a single winning group supplies the single primary"
        );

        // Removing the traversal signal entirely changes nothing about the RCE
        // verdict — the proof that the second family contributes zero score to the
        // first (i.e. it is not a second vote, only a second attribution).
        let without_traversal = score(&signals[..2], &cfg, false);
        assert_eq!(without_traversal.request_score, v.request_score);
        assert_eq!(without_traversal.recommendation, v.recommendation);

        // And the traversal group on its own is likewise unaffected by the RCE one.
        let traversal_only = score(&signals[2..], &cfg, false);
        assert_eq!(traversal_only.request_score, 68);
        assert_eq!(traversal_only.recommendation, SemanticAction::Log);
    }

    /// A same-field cross-family pair can never manufacture a Block that neither
    /// family reached on its own — the `max` roll-up makes the worst case "the
    /// higher of the two", not "their sum".
    #[test]
    fn cross_family_pair_cannot_manufacture_a_block() {
        // Two sub-block groups: Rce 0.5·78 = 39 (below its own Log bar) and
        // Traversal 1.0·68 = 68 (Log). Sum would be 107 → Block; max is 68 → Log.
        let signals = [
            sig(
                AttackKind::Rce,
                DetectorId::Rce,
                "body",
                78,
                "rce.piped_shell",
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
        let v = score(&signals, &shipped_rce_traversal_cfg(), false);
        assert_eq!(v.request_score, 68);
        assert_eq!(v.recommendation, SemanticAction::Log);
    }

    /// **T17 — the shared construct wins the decision but not the name.**
    ///
    /// The production shape of `cat /etc/passwd` on a field the shell AST layer
    /// does not get to parse: `rce.sensitive_read` fires alone (70 · 0.5 = 35,
    /// under `Rce`'s log threshold of 40) while `traversal.sensitive_abs` fires at
    /// 68 · 1.0 = 68 and reaches `Log`. Before this fix the roll-up handed the
    /// name to the higher-scoring group and the operator saw `DirTraversal` for a
    /// command execution.
    ///
    /// The scores are not comparable — `Σ weight = 1` is per family, so the
    /// two-detector family is halved for firing one detector on evidence of equal
    /// strength. The decision still belongs to the traversal group (its threshold
    /// is calibrated on its own scale); the *name* belongs to the only signal that
    /// says which family this is. `/etc/passwd` is shared with traversal, LFI and
    /// RCE alike; `cat /etc/passwd` is not.
    #[test]
    fn shared_construct_cedes_naming_to_a_co_located_specific_family() {
        let signals = [
            sig(
                AttackKind::Rce,
                DetectorId::Rce,
                "body",
                70,
                "rce.sensitive_read",
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
        let v = score(&signals, &shipped_rce_traversal_cfg(), false);
        // Disposition — identical to the pre-fix behaviour, byte for byte.
        assert_eq!(v.request_score, 68, "the traversal group still sets the score");
        assert_eq!(v.recommendation, SemanticAction::Log, "35 < log(40) ≤ 68");
        // Attribution — the fix.
        let primary = v.primary_result.as_ref().expect("a Log carries a primary");
        assert_eq!(
            primary.rule_id.as_deref(),
            Some("rce.sensitive_read"),
            "the family-discriminating rule names the event"
        );
        assert_eq!(primary.phase, AttackKind::Rce.to_phase(), "…and so does the phase");
    }

    /// **T17 reverse proof — a shared construct alone still names its own event.**
    ///
    /// `../../../../etc/passwd` with nothing else on the field: the traversal group
    /// is the only evidence there is, so `traversal.sensitive_abs` remains the most
    /// honest label available and keeps the name. The correction is conditional on a
    /// co-located discriminating alternative existing, not a blanket demotion of the
    /// `Traversal` family.
    #[test]
    fn shared_construct_keeps_naming_when_nothing_specific_is_co_located() {
        let signals = [sig(
            AttackKind::Traversal,
            DetectorId::Traversal,
            "body",
            68,
            "traversal.sensitive_abs",
            Provenance::Raw,
        )];
        let v = score(&signals, &shipped_rce_traversal_cfg(), false);
        assert_eq!(v.recommendation, SemanticAction::Log);
        assert_eq!(
            v.primary_result.as_ref().and_then(|r| r.rule_id.as_deref()),
            Some("traversal.sensitive_abs"),
        );
    }

    /// **T17 reverse proof — evidence about a *different* field never renames.**
    ///
    /// An RCE hit in a `cmd` parameter says nothing about what a `/etc/passwd` in
    /// the `path` parameter is: they are different bytes. Restricting the handover
    /// to the same `(scope, field)` is what stops this from becoming "RCE always
    /// beats traversal".
    #[test]
    fn attribution_does_not_cross_fields() {
        let signals = [
            sig(
                AttackKind::Rce,
                DetectorId::Rce,
                "cmd",
                70,
                "rce.sensitive_read",
                Provenance::Raw,
            ),
            sig(
                AttackKind::Traversal,
                DetectorId::Traversal,
                "path",
                68,
                "traversal.sensitive_abs",
                Provenance::Raw,
            ),
        ];
        let v = score(&signals, &shipped_rce_traversal_cfg(), false);
        assert_eq!(
            v.primary_result.as_ref().and_then(|r| r.rule_id.as_deref()),
            Some("traversal.sensitive_abs"),
            "a co-located family means the SAME field, not merely the same request"
        );
    }

    /// **T17 — a family that also produced its own discriminating evidence keeps
    /// the name, and only the rule sharpens.**
    ///
    /// Handing the name to another family when the winner can speak for itself
    /// would be a bigger correction than the label needs. Here the traversal group
    /// carries both a shared construct at confidence 90 and a `../`-based rule at
    /// 60 (a two-detector traversal family, so both survive canonicalisation): the
    /// shared construct wins `best` on contribution, and attribution falls back
    /// inside the family rather than to the co-located `Rce` group.
    #[test]
    fn attribution_prefers_the_winning_family_s_own_specific_evidence() {
        let mut cfg = shipped_rce_traversal_cfg();
        let mut trav_weights = HashMap::new();
        trav_weights.insert(DetectorId::Traversal, 0.5);
        trav_weights.insert(DetectorId::StructRule, 0.5);
        if let Some(trav) = cfg.attacks.get_mut(&AttackKind::Traversal) {
            trav.weights = trav_weights;
        }
        let signals = [
            sig(
                AttackKind::Traversal,
                DetectorId::Traversal,
                "body",
                90,
                "traversal.sensitive_abs",
                Provenance::Raw,
            ),
            sig(
                AttackKind::Traversal,
                DetectorId::StructRule,
                "body",
                60,
                "traversal.encoded_dotdot",
                Provenance::Raw,
            ),
            sig(
                AttackKind::Rce,
                DetectorId::Rce,
                "body",
                70,
                "rce.sensitive_read",
                Provenance::Raw,
            ),
        ];
        let v = score(&signals, &cfg, false);
        assert_eq!(v.request_score, 75, "0.5·90 + 0.5·60 — attribution never moves a score");
        assert_eq!(
            v.primary_result.as_ref().and_then(|r| r.rule_id.as_deref()),
            Some("traversal.encoded_dotdot"),
            "the winner's own `../` evidence keeps the name in the family"
        );
    }

    /// **T17 — attribution is inert on the decision.**
    ///
    /// The load-bearing invariant of the whole change: for the payload that moved,
    /// `recommendation`, `request_score` and `enforce_safe` are identical to what
    /// the same signals produce with the shared-construct signal deleted from the
    /// winning group's competition — i.e. the naming step reads the decision and
    /// never writes it. Blocking behaviour cannot move because of a label.
    #[test]
    fn attribution_never_moves_the_disposition() {
        let cfg = shipped_rce_traversal_cfg();
        let shared = sig(
            AttackKind::Traversal,
            DetectorId::Traversal,
            "body",
            68,
            "traversal.sensitive_abs",
            Provenance::Raw,
        );
        let specific = sig(
            AttackKind::Rce,
            DetectorId::Rce,
            "body",
            70,
            "rce.sensitive_read",
            Provenance::Raw,
        );
        let both = score(&[shared.clone(), specific], &cfg, false);
        let shared_alone = score(std::slice::from_ref(&shared), &cfg, false);

        assert_eq!(both.recommendation, shared_alone.recommendation);
        assert_eq!(both.request_score, shared_alone.request_score);
        assert_eq!(both.enforce_safe, shared_alone.enforce_safe);
        assert_ne!(
            both.primary_result.as_ref().and_then(|r| r.rule_id.as_deref()),
            shared_alone.primary_result.as_ref().and_then(|r| r.rule_id.as_deref()),
            "only the name moved"
        );
    }

    /// **T17 — the handover is deterministic across `HashMap` seeds.**
    ///
    /// Two co-located families both carry discriminating evidence at exactly the
    /// same contribution, so the choice of who names the event rests entirely on
    /// the structural tie-break in [`AttributionKey`]. Scoring the same signals in
    /// every permutation must produce one answer; if the tie-break were ever
    /// dropped this would flake rather than fail cleanly, which is why the
    /// permutations are enumerated instead of trusted.
    #[test]
    fn attribution_tie_break_is_order_independent() {
        let mut cfg = shipped_rce_traversal_cfg();
        let mut xss_weights = HashMap::new();
        xss_weights.insert(DetectorId::XssDom, 1.0);
        cfg.attacks.insert(
            AttackKind::Xss,
            RuntimeAttackConfig {
                enabled: true,
                weights: xss_weights,
                log_threshold: 40,
                block_threshold: 80,
                hard_veto_allowlist: HashSet::new(),
            },
        );
        let signals = [
            // Wins the disposition at 1.0 · 90 = 90, on a shared construct.
            sig(
                AttackKind::Traversal,
                DetectorId::Traversal,
                "body",
                90,
                "traversal.sensitive_abs",
                Provenance::Raw,
            ),
            // Both discriminating signals sit at confidence 70 — and note the Rce
            // one is worth half as much *score* (0.5 weight) as the Xss one, which
            // is exactly the incomparable number the attribution key refuses to
            // read. Only `attack_ord` separates them.
            sig(
                AttackKind::Rce,
                DetectorId::Rce,
                "body",
                70,
                "rce.sensitive_read",
                Provenance::Raw,
            ),
            sig(
                AttackKind::Xss,
                DetectorId::XssDom,
                "body",
                70,
                "xss.script_tag",
                Provenance::Raw,
            ),
        ];
        for order in [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
            let permuted: Vec<DetectionSignal> = order.iter().filter_map(|&i| signals.get(i).cloned()).collect();
            assert_eq!(permuted.len(), signals.len(), "permutation must keep every signal");
            let v = score(&permuted, &cfg, false);
            assert_eq!(
                v.primary_result.as_ref().and_then(|r| r.rule_id.as_deref()),
                Some("rce.sensitive_read"),
                "attack_ord(Rce)=1 < attack_ord(Xss)=2 decides, for every input order {order:?}"
            );
        }
    }

    /// The confidence budget the new AST rules were chosen against: in the shipped
    /// `rce` family (two detectors at 0.5) a **single** detector hit at confidence
    /// 80 lands exactly on `log_threshold` and stays strictly below
    /// `block_threshold`. A false positive from a lone AST rule therefore costs one
    /// shadow log line and can never drop a request; reaching Block still requires
    /// the structural detector to corroborate independently.
    #[test]
    fn lone_ast_hit_at_conf_80_logs_but_cannot_block() {
        let lone = [sig(
            AttackKind::Rce,
            DetectorId::RceAst,
            "body",
            80,
            "rce_ast.cmd_chain_injection",
            Provenance::Raw,
        )];
        let v = score(&lone, &shipped_rce_traversal_cfg(), false);
        assert_eq!(v.request_score, 40, "0.5 × 80 = 40");
        assert_eq!(v.recommendation, SemanticAction::Log);

        // conf 60 (`rce_ast.param_indirect`) is below the Log bar by construction:
        // observable in `semantic_observations`, never a verdict on its own.
        let quiet = [sig(
            AttackKind::Rce,
            DetectorId::RceAst,
            "body",
            60,
            "rce_ast.param_indirect",
            Provenance::Raw,
        )];
        let q = score(&quiet, &shipped_rce_traversal_cfg(), false);
        assert_eq!(q.request_score, 30, "0.5 × 60 = 30");
        assert_eq!(q.recommendation, SemanticAction::None);

        // Corroborated by the structural detector, the same chain reaches Block.
        let corroborated = [
            sig(
                AttackKind::Rce,
                DetectorId::RceAst,
                "body",
                80,
                "rce_ast.cmd_chain_injection",
                Provenance::Raw,
            ),
            sig(
                AttackKind::Rce,
                DetectorId::Rce,
                "body",
                80,
                "rce.shell_exec_flag",
                Provenance::Raw,
            ),
        ];
        let c = score(&corroborated, &shipped_rce_traversal_cfg(), false);
        assert_eq!(c.request_score, 80);
        assert_eq!(c.recommendation, SemanticAction::Block);
    }
}
