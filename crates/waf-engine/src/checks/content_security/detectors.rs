//! Lane 2 production semantic detectors (plan v2.2 §8).
//!
//! P1b ships the first real detector: [`StructuralSqlDetector`], an `OpenRASP`
//! `sql_policy`-derived **structural / regex half-semantic** `SQLi` detector. It
//! is deliberately *not* an AST parser — `sqlparser-rs` is P2. It inspects the
//! normalised (`lower_trunc`) form of each preprocessor [`View`] and returns a
//! context-free [`DetectionFinding`]; the pipeline
//! ([`View::to_signal`](super::preprocess::View::to_signal)) attaches
//! provenance / field / scope / detector-id, so a detector can never forge the
//! provenance that gates hard-veto eligibility (codex A-1).
//!
//! **Shadow only in P1b**: the `SQLi` family ships with `enforcement_mode =
//! log_only`, so a match is at most logged + persisted, never a Block.

use regex::Regex;
use tracing::error;

use super::budget::ContentInspectionState;
use super::preprocess::{PreprocessCtx, SemanticDetector, View};
use super::types::{AttackKind, DetectionFinding, DetectorId};

/// How a compiled rule decides whether it fired.
enum RuleKind {
    /// Fires when the pattern matches at least once.
    Presence,
    /// Fires when the pattern matches at least this many times (density / frequency).
    Count(usize),
}

/// One compiled structural `SQLi` rule.
struct CompiledRule {
    /// Stable matching key (hard-veto allowlist matches on this, never `detail`).
    rule_key: &'static str,
    /// Graded confidence `0..=100` (shadow starting values, pre-holdout
    /// calibration — plan §6.6 / §8.2).
    confidence: u8,
    re: Regex,
    kind: RuleKind,
}

/// The rule table (plan §8.2). Patterns run against the **lowercased** normalised
/// view text, so every pattern is authored lowercase. Ordered high→low
/// confidence for readability; `detect` returns the strongest firing rule.
///
/// `(rule_key, confidence, pattern, kind, default_on)`.
///
/// `default_on = false` marks a rule that ships **disabled** by default (plan
/// v2.2: the high-noise stacked / chr / hex / `information_schema` rules require
/// holdout calibration before they may run). [`StructuralSqlDetector::new`]
/// compiles only the `default_on` rules; [`StructuralSqlDetector::with_all_rules`]
/// (test-only) compiles the whole table.
const RULES: &[(&str, u8, &str, RuleKind, bool)] = &[
    // Exfiltration / file write.
    (
        "sql.into_outfile",
        95,
        r"\binto\s+(outfile|dumpfile)\b",
        RuleKind::Presence,
        true,
    ),
    // Stacked query: a statement separator followed by another statement keyword.
    // DEFAULT-OFF (plan v2.2): fires on prose / code `; select …` with no SQL
    // context; needs holdout calibration before it may run.
    (
        "sql.stacked",
        90,
        r";\s*(select|insert|update|delete|drop|create|alter|union|declare|exec|grant)\b",
        RuleKind::Presence,
        false,
    ),
    // Dangerous functions / time-based blind primitives. The call-paren form
    // (`sleep(`, `benchmark(`, …) or `waitfor delay` is required.
    (
        "sql.dangerous_fn",
        85,
        r"\b(load_file|benchmark|sleep|pg_sleep|updatexml|extractvalue|xp_cmdshell)\s*\(|\bwaitfor\s+delay\b",
        RuleKind::Presence,
        true,
    ),
    // UNION-based with NULL / numeric / comma padding (column-count probing).
    // Requires adjacent `union [all|distinct] select` (SQL context), not just
    // `union … select` separated by arbitrary prose.
    (
        "sql.union_null",
        78,
        r"\bunion\b(?:\s+(?:all|distinct))?\s+select\b.{0,80}?(\bnull\b|,\s*null|,\s*,|\b\d+\s*,\s*\d+)",
        RuleKind::Presence,
        true,
    ),
    // General UNION SELECT — requires adjacent `union [all|distinct] select`.
    (
        "sql.union_select",
        72,
        r"\bunion\b(?:\s+(?:all|distinct))?\s+select\b",
        RuleKind::Presence,
        true,
    ),
    // MySQL version-gated comment `/*!12345 …*/` — requires a digit right after
    // `/*!` (a real version gate), so a plain `/*! license */` banner does not fire.
    ("sql.version_comment", 70, r"/\*!\d", RuleKind::Presence, true),
    // information_schema enumeration. DEFAULT-OFF (plan v2.2); also narrowed to
    // the structural `information_schema.tables|columns` form (a bare
    // `information_schema` field name no longer fires).
    (
        "sql.info_schema",
        65,
        r"\binformation_schema\s*\.\s*(tables|columns)\b",
        RuleKind::Presence,
        false,
    ),
    // chr()/char() obfuscation frequency ≥ 5. DEFAULT-OFF (plan v2.2): code /
    // formulas with repeated `char(` calls false-positive.
    ("sql.chr_freq", 45, r"\b(chr|char)\s*\(", RuleKind::Count(5), false),
    // Hex-literal density ≥ 2. DEFAULT-OFF (plan v2.2): log lines / on-chain data
    // with `0x…` constants false-positive. Token-bounded (`\b`).
    ("sql.hex_const", 40, r"\b0x[0-9a-f]+\b", RuleKind::Count(2), false),
];

/// `OpenRASP`-derived structural `SQLi` detector (plan §8). Registered in the
/// `SQLi` attack family; matches on the normalised view text.
pub struct StructuralSqlDetector {
    rules: Vec<CompiledRule>,
}

impl StructuralSqlDetector {
    /// Compile the **default-on** rules. A pattern that fails to compile (a bug —
    /// the patterns are constants) is logged and skipped rather than panicking, so
    /// the detector degrades to a smaller rule set instead of aborting startup
    /// (iron rule: no panic in production).
    ///
    /// The high-noise stacked / chr / hex / `information_schema` rules are
    /// `default_on = false` (plan v2.2) and are **not** compiled here; they await
    /// holdout calibration before they may run in production.
    #[must_use]
    pub fn new() -> Self {
        Self::compile(false)
    }

    /// Test-only constructor that compiles **every** rule in the table, including
    /// the default-off high-noise rules, so unit tests can exercise them.
    #[cfg(test)]
    #[must_use]
    pub fn with_all_rules() -> Self {
        Self::compile(true)
    }

    /// Compile the rule table, keeping either the default-on subset or all rules.
    #[must_use]
    fn compile(all: bool) -> Self {
        let mut rules = Vec::with_capacity(RULES.len());
        for (rule_key, confidence, pattern, kind, default_on) in RULES {
            if !all && !*default_on {
                continue;
            }
            match Regex::new(pattern) {
                Ok(re) => rules.push(CompiledRule {
                    rule_key,
                    confidence: *confidence,
                    re,
                    kind: match kind {
                        RuleKind::Presence => RuleKind::Presence,
                        RuleKind::Count(n) => RuleKind::Count(*n),
                    },
                }),
                Err(e) => error!("StructuralSqlDetector: rule '{rule_key}' failed to compile: {e}"),
            }
        }
        Self { rules }
    }
}

impl Default for StructuralSqlDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticDetector for StructuralSqlDetector {
    fn id(&self) -> DetectorId {
        DetectorId::StructRule
    }

    fn detect(
        &self,
        view: &View<'_>,
        _ctx: &PreprocessCtx<'_>,
        _state: &mut ContentInspectionState,
    ) -> Option<DetectionFinding> {
        let hay = view.lower_trunc.as_str();
        let mut best: Option<&CompiledRule> = None;
        for rule in &self.rules {
            let fired = match rule.kind {
                RuleKind::Presence => rule.re.is_match(hay),
                RuleKind::Count(min) => rule.re.find_iter(hay).take(min).count() >= min,
            };
            if fired && best.is_none_or(|b| rule.confidence > b.confidence) {
                best = Some(rule);
            }
        }
        let rule = best?;
        Some(DetectionFinding {
            attack: AttackKind::SqlInjection,
            confidence: rule.confidence,
            rule_key: rule.rule_key,
            // De-identified: names the rule, never echoes the payload.
            detail: std::borrow::Cow::Owned(format!(
                "structural SQLi rule '{}' matched (confidence {})",
                rule.rule_key, rule.confidence
            )),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::sync::Arc;

    use bytes::Bytes;
    use waf_common::{HostConfig, RequestCtx};

    use super::*;
    use crate::checks::content_security::budget::ContentInspectionState;
    use crate::checks::content_security::types::{InspectionScope, Provenance};

    fn view(text: &str) -> View<'static> {
        // Mirror the preprocessor's normalisation so tests exercise the real
        // matching surface (lowercase, whitespace-collapsed).
        let lower_trunc: String = text
            .to_ascii_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        View {
            location: Cow::Borrowed("query"),
            round: 0,
            text: Cow::Owned(text.to_string()),
            lower_trunc,
            provenance: Provenance::Raw,
        }
    }

    fn throwaway_req() -> RequestCtx {
        RequestCtx {
            req_id: "t".to_string(),
            client_ip: "127.0.0.1".parse().expect("ip"),
            client_port: 0,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: "/".to_string(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config: Arc::new(HostConfig::default()),
            geo: None,
        }
    }

    fn fire(text: &str) -> Option<DetectionFinding> {
        let det = StructuralSqlDetector::new();
        let req = throwaway_req();
        let pctx = PreprocessCtx {
            scope: InspectionScope::Body,
            req: &req,
        };
        let mut st = ContentInspectionState::default();
        det.detect(&view(text), &pctx, &mut st)
    }

    /// Fire against the FULL rule set (including default-off rules).
    fn fire_all(text: &str) -> Option<DetectionFinding> {
        let det = StructuralSqlDetector::with_all_rules();
        let req = throwaway_req();
        let pctx = PreprocessCtx {
            scope: InspectionScope::Body,
            req: &req,
        };
        let mut st = ContentInspectionState::default();
        det.detect(&view(text), &pctx, &mut st)
    }

    #[test]
    fn all_rules_compile() {
        // Every pattern in the table must compile (default-on and default-off).
        let det = StructuralSqlDetector::with_all_rules();
        assert_eq!(det.rules.len(), RULES.len(), "every rule pattern must compile");
    }

    #[test]
    fn default_on_excludes_high_noise_rules() {
        // plan v2.2: stacked / chr / hex / info_schema ship disabled by default.
        let det = StructuralSqlDetector::new();
        let on: std::collections::HashSet<&str> = det.rules.iter().map(|r| r.rule_key).collect();
        for off in ["sql.stacked", "sql.chr_freq", "sql.hex_const", "sql.info_schema"] {
            assert!(!on.contains(off), "{off} must be default-off");
        }
        for onk in [
            "sql.into_outfile",
            "sql.dangerous_fn",
            "sql.union_null",
            "sql.union_select",
            "sql.version_comment",
        ] {
            assert!(on.contains(onk), "{onk} must be default-on");
        }
    }

    #[test]
    fn union_select_fires() {
        let f = fire("1 union select username,password from users").expect("union select must fire");
        assert!(matches!(f.rule_key, "sql.union_null" | "sql.union_select"));
        assert_eq!(f.attack, AttackKind::SqlInjection);
    }

    #[test]
    fn union_all_select_fires() {
        // `union all select` / `union distinct select` are still SQL context.
        assert!(fire("1 union all select 1,2").is_some());
        assert!(fire("1 union distinct select 1,2").is_some());
    }

    #[test]
    fn stacked_query_fires_when_enabled() {
        // Default-off, but must fire when the full rule set is compiled.
        let f = fire_all("1; drop table users").expect("stacked query must fire with all rules");
        assert_eq!(f.rule_key, "sql.stacked");
        // …and must NOT fire on the default-on rule set.
        assert!(fire("1; drop table users").is_none(), "stacked is default-off");
    }

    #[test]
    fn into_outfile_is_strongest() {
        // outfile (95) beats a co-occurring union (≤78) → hard-veto candidate wins.
        let f = fire("1 union select 1 into outfile '/tmp/x'").expect("outfile must fire");
        assert_eq!(f.rule_key, "sql.into_outfile", "strongest rule wins");
        assert_eq!(f.confidence, 95);
    }

    #[test]
    fn dangerous_fn_fires() {
        assert_eq!(
            fire("1 and sleep(5)").expect("sleep must fire").rule_key,
            "sql.dangerous_fn"
        );
        assert_eq!(
            fire("1 and extractvalue(1,concat(0x7e,version()))")
                .expect("extractvalue must fire")
                .rule_key,
            "sql.dangerous_fn"
        );
    }

    #[test]
    fn version_comment_fires() {
        // A bare version comment (no union/select) fires exactly the version rule.
        assert_eq!(
            fire("/*!12345 x */").expect("bare version comment fires").rule_key,
            "sql.version_comment"
        );
    }

    #[test]
    fn clean_traffic_does_not_fire() {
        // Prose, JSON and ordinary queries must not trip any rule.
        assert!(fire("the quick brown fox jumps over the lazy dog").is_none());
        assert!(fire(r#"{"name":"alice","role":"admin","age":30}"#).is_none());
        assert!(fire("q=laptop&sort=price&order=asc&page=2").is_none());
        assert!(
            fire("SELECTED_ITEMS=3&reunion=family").is_none(),
            "word-boundary guards"
        );
        assert!(fire("please sleep well tonight").is_none(), "sleep without call parens");
    }

    /// codex §3.2 false-positive corpus: every one of these benign inputs must
    /// stay below the default log threshold (i.e. produce no finding) on the
    /// DEFAULT-ON rule set. This is the calibration evidence for shadow-on.
    #[test]
    fn clean_traffic_codex_negatives_do_not_fire() {
        // union/select in prose or as unrelated params — no adjacency, no fire.
        assert!(
            fire("the union will select a representative for the committee").is_none(),
            "prose 'union … select' must not fire"
        );
        assert!(
            fire("operation=union&action=select&scope=all").is_none(),
            "unrelated union/select params must not fire"
        );
        // A plain licence banner comment — no version digit → version_comment off.
        assert!(
            fire("/*! license: MIT, see LICENSE for details */").is_none(),
            "non-version /*! banner must not fire"
        );
        // Bare information_schema field name (no `.tables`) — and rule is default-off.
        assert!(
            fire("column=information_schema&sort=asc").is_none(),
            "bare information_schema must not fire"
        );
        // Even with the full rule set, a bare information_schema without the
        // structural `.tables|.columns` form stays clean.
        assert!(
            fire_all("column=information_schema&sort=asc").is_none(),
            "bare information_schema is not structural"
        );
        // Repeated char( in code / a formula — chr_freq is default-off.
        assert!(
            fire("char(65)+char(66)+char(67)+char(68)+char(69)").is_none(),
            "code char( repetition must not fire (chr_freq default-off)"
        );
        // Hex constants in a log line — hex_const is default-off.
        assert!(
            fire("addr=0xdeadbeef nonce=0xcafebabe block=0x1f").is_none(),
            "log 0x constants must not fire (hex_const default-off)"
        );
        // benchmark / sleep mentioned as words (no call parens) — no fire.
        assert!(
            fire("see the benchmark results and sleep schedule").is_none(),
            "benchmark/sleep as words (no parens) must not fire"
        );
    }

    #[test]
    fn info_schema_structural_form_fires_when_enabled() {
        // The narrowed structural `information_schema.tables|columns` form still
        // fires under the full rule set, in isolation from the union rules.
        assert_eq!(
            fire_all("select table_name from information_schema.tables")
                .expect("structural info_schema.tables fires")
                .rule_key,
            "sql.info_schema"
        );
        assert_eq!(
            fire_all("select 1 from information_schema.columns where 1=1")
                .expect("info_schema.columns fires")
                .rule_key,
            "sql.info_schema"
        );
    }
}
