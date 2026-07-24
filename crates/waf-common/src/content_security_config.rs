//! Serializable configuration for the Lane 2 semantic content-security engine
//! (plan v2.2 §6.5 / §12.2 / §14).
//!
//! This module holds **only** serde-friendly primitives (strings / enums as
//! strings / maps). It deliberately does not depend on `waf-engine`'s internal
//! `DetectorId`; the engine compiles this into an immutable runtime config at
//! startup (plan §6.5: "不得让 `waf-common` 反向依赖 engine 的 `DetectorId`").
//!
//! Everything here is **off by default**: a zero-config install never activates
//! Lane 2. `enabled = false`, `enforcement_mode = "log_only"`, HPP off, dialect
//! `generic`, no attack families — proving "零配置不启用" (plan §14.2 / task
//! P1a zero-enforcement constraint).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Top-level Lane 2 semantic content-security configuration.
///
/// `#[serde(default)]` on every field means an empty `[content_security]` TOML
/// table (or a missing one) deserializes to [`ContentSecurityConfig::default`],
/// i.e. the whole semantic lane stays off.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ContentSecurityConfig {
    /// Master switch for the entire Lane 2 semantic lane. Default `false` — the
    /// lane does not run at all unless explicitly enabled.
    pub enabled: bool,
    /// Runtime enforcement mode: `"off"`, `"log_only"` (shadow) or `"enforce"`.
    /// Default `"log_only"`: even when the lane is enabled it can, at most, log.
    pub enforcement_mode: String,
    /// SQL dialect assumption for the (future) AST layer. P1 is global
    /// `"generic"` and does not claim per-host dialects (plan §14.2).
    pub dialect: String,
    /// HTTP-parameter-pollution synthetic-view generation. Global off (plan
    /// §7.4 / §14.2): never claimed per-host.
    pub hpp: bool,
    /// Canary rollout width in basis points (0–10000). `bucket < rollout_bps`
    /// selects a request for `enforce` while the lane is otherwise `log_only`
    /// (plan §13.3). Default 0 → no request is canaried.
    pub rollout_bps: u32,
    /// Stable salt mixed into the deterministic canary hash so bucketing is
    /// reproducible across nodes and restarts (plan §13.3).
    pub rollout_salt: String,
    /// Deterministic `DoS` work-budget caps (plan §12.2).
    pub budget: SemanticBudgetConfig,
    /// Anomaly-rate circuit-breaker parameters (plan §13.3).
    pub breaker: SemanticBreakerConfig,
    /// Per-attack-family scoring configuration, keyed by attack family
    /// (`"sql_injection"` / `"rce"` / `"xss"` / `"traversal"` / `"xxe"`). An absent
    /// or disabled family contributes nothing (plan §6.2).
    pub attacks: BTreeMap<String, SemanticAttackConfig>,
    /// Per-attack-family enforcement-mode overrides (E0). Each key is an attack
    /// family (`"sql_injection"` / `"rce"` / `"xss"` / `"traversal"` / `"xxe"`); each value
    /// is `"off"` / `"log_only"` / `"enforce"` and overrides the global
    /// [`Self::enforcement_mode`] **for that family only**. A family not listed
    /// here inherits the global mode, so the shipped **empty** map is
    /// behaviourally identical to the pure-global posture (zero behaviour
    /// change). This lets an operator switch a single high-confidence family
    /// (e.g. `sql_injection`) to `enforce` while the rest of the lane stays
    /// `log_only`. These are independent of the per-host Lane 1 legacy toggles —
    /// see the A3 contract note in `configs/default.toml`.
    pub enforcement_overrides: BTreeMap<String, String>,
}

/// Per-attack-family scoring configuration (plan §6.2).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SemanticAttackConfig {
    /// Whether this attack family participates in scoring. An **empty** family
    /// must be `enabled = false` (plan §6.2: 空 family 必须显式关闭并免除权重和
    /// 校验).
    pub enabled: bool,
    /// Per-detector weights. When the family is enabled these must sum to 1.0
    /// over the listed detectors; the loader validates but never re-normalises
    /// (plan §6.2 唯一加载规则).
    pub weights: BTreeMap<String, f64>,
    /// Score at/above which a `log_only` recommendation is produced (0–100).
    pub log_threshold: u8,
    /// Score at/above which a `Block` recommendation is produced (0–100). Must
    /// be `>= log_threshold`.
    pub block_threshold: u8,
    /// Stable `rule_key` allowlist that may hard-veto (single-signal Block)
    /// once holdout-calibrated (plan §6.3). Empty by default.
    pub hard_veto_allowlist: Vec<String>,
}

/// Deterministic work-budget caps with conservative factory defaults
/// (plan §12.2). Every value must be non-zero.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SemanticBudgetConfig {
    pub max_fields_per_phase: u32,
    pub max_views_per_field: u32,
    pub max_ast_attempts_per_request: u32,
    pub max_ast_input_bytes_total: usize,
    /// Maximum HTML5 fragment-parse attempts per request for the XSS DOM
    /// detector (P-XSS-1). Independent of the AST budget so a request cannot
    /// double its worst-case work by mixing SQL and HTML payloads.
    pub max_html_parse_attempts_per_request: u32,
    /// Total input bytes handed to the HTML5 parser across all views of a
    /// request. A second, cumulative cap on top of the per-parse byte backstop.
    pub max_html_parse_input_bytes_total: usize,
    pub max_tokens_per_view: u32,
    pub max_list_items: u32,
    pub max_preprocess_output_bytes_total: usize,
    /// Per-field **input** admission cap in bytes (plan §12.2, codex A-2). A
    /// single field longer than this is rejected on a borrowed view **before**
    /// any clone / URL-decode / normalise allocation happens, so an adversarial
    /// oversized field cannot force unbudgeted work. Default 16 KiB.
    pub max_field_input_bytes: usize,
    /// Bounded recursive-decode rounds for the Lane 2 preprocessor. Default 3,
    /// tighter than the legacy `MAX_DECODE_PASSES = 5` (plan §7.1).
    pub max_decode_rounds: u8,
}

impl Default for SemanticBudgetConfig {
    fn default() -> Self {
        Self {
            max_fields_per_phase: 64,
            max_views_per_field: 12,
            max_ast_attempts_per_request: 6,
            max_ast_input_bytes_total: 256 * 1024,
            max_html_parse_attempts_per_request: 6,
            max_html_parse_input_bytes_total: 256 * 1024,
            max_tokens_per_view: 512,
            max_list_items: 1024,
            max_preprocess_output_bytes_total: 512 * 1024,
            max_field_input_bytes: 16 * 1024,
            max_decode_rounds: 3,
        }
    }
}

/// Anomaly-rate circuit-breaker parameters (plan §13.3). Values are calibrated
/// against real traffic later; these are safe starting points.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SemanticBreakerConfig {
    /// Sliding statistics window, seconds.
    pub window_secs: u64,
    /// Minimum samples in the window before the breaker may evaluate.
    pub min_samples: u32,
    /// Anomaly rate (0.0–1.0) at/above which the breaker opens.
    pub anomaly_rate_threshold: f64,
    /// Cooldown before an open breaker transitions to half-open, seconds.
    pub cooldown_secs: u64,
}

impl Default for SemanticBreakerConfig {
    fn default() -> Self {
        Self {
            window_secs: 300,
            min_samples: 200,
            anomaly_rate_threshold: 0.05,
            cooldown_secs: 900,
        }
    }
}

impl Default for ContentSecurityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            enforcement_mode: "log_only".to_string(),
            dialect: "generic".to_string(),
            hpp: false,
            rollout_bps: 0,
            rollout_salt: String::new(),
            budget: SemanticBudgetConfig::default(),
            breaker: SemanticBreakerConfig::default(),
            attacks: BTreeMap::new(),
            enforcement_overrides: BTreeMap::new(),
        }
    }
}

/// Weight sum tolerance (floating-point slack around Σ = 1.0).
const WEIGHT_SUM_EPSILON: f64 = 1e-6;

impl ContentSecurityConfig {
    /// Strictly validate the configuration. Returns a human-readable error
    /// string on the first violation; **never** mutates or re-normalises
    /// (plan §6.2 唯一加载规则: loader 只校验不改写).
    ///
    /// This is the single semantic-validation entry point; the engine's runtime
    /// compilation additionally resolves detector-id strings.
    pub fn validate(&self) -> Result<(), String> {
        match self.enforcement_mode.as_str() {
            "off" | "log_only" | "enforce" => {}
            other => {
                return Err(format!(
                    "content_security.enforcement_mode must be one of off/log_only/enforce, got '{other}'"
                ));
            }
        }

        match self.dialect.as_str() {
            "generic" => {}
            other => {
                return Err(format!(
                    "content_security.dialect only supports 'generic' in P1, got '{other}'"
                ));
            }
        }

        if self.rollout_bps > 10_000 {
            return Err(format!(
                "content_security.rollout_bps must be 0..=10000, got {}",
                self.rollout_bps
            ));
        }

        self.budget.validate()?;
        self.breaker.validate()?;

        for (name, family) in &self.attacks {
            if !is_known_attack_family(name) {
                return Err(format!(
                    "content_security.attacks has unknown family '{name}' \
                     (expected sql_injection/rce/xss/traversal/xxe)"
                ));
            }
            family.validate(name)?;
        }

        // Per-family enforcement overrides (E0): each key must be a known family
        // and each value a valid mode. Strict — a typo must fail startup, never
        // silently fall back to the global mode.
        for (name, mode) in &self.enforcement_overrides {
            if !is_known_attack_family(name) {
                return Err(format!(
                    "content_security.enforcement_overrides has unknown family '{name}' \
                     (expected sql_injection/rce/xss/traversal/xxe)"
                ));
            }
            match mode.as_str() {
                "off" | "log_only" | "enforce" => {}
                other => {
                    return Err(format!(
                        "content_security.enforcement_overrides.{name} must be one of \
                         off/log_only/enforce, got '{other}'"
                    ));
                }
            }
        }

        Ok(())
    }
}

impl SemanticBudgetConfig {
    fn validate(&self) -> Result<(), String> {
        let checks: [(&str, u64); 11] = [
            ("max_fields_per_phase", u64::from(self.max_fields_per_phase)),
            ("max_views_per_field", u64::from(self.max_views_per_field)),
            (
                "max_ast_attempts_per_request",
                u64::from(self.max_ast_attempts_per_request),
            ),
            ("max_ast_input_bytes_total", self.max_ast_input_bytes_total as u64),
            (
                "max_html_parse_attempts_per_request",
                u64::from(self.max_html_parse_attempts_per_request),
            ),
            (
                "max_html_parse_input_bytes_total",
                self.max_html_parse_input_bytes_total as u64,
            ),
            ("max_tokens_per_view", u64::from(self.max_tokens_per_view)),
            ("max_list_items", u64::from(self.max_list_items)),
            (
                "max_preprocess_output_bytes_total",
                self.max_preprocess_output_bytes_total as u64,
            ),
            ("max_field_input_bytes", self.max_field_input_bytes as u64),
            ("max_decode_rounds", u64::from(self.max_decode_rounds)),
        ];
        for (field, value) in checks {
            if value == 0 {
                return Err(format!("content_security.budget.{field} must be > 0"));
            }
        }
        Ok(())
    }
}

impl SemanticBreakerConfig {
    fn validate(&self) -> Result<(), String> {
        if self.window_secs == 0 {
            return Err("content_security.breaker.window_secs must be > 0".to_string());
        }
        if self.min_samples == 0 {
            return Err("content_security.breaker.min_samples must be > 0".to_string());
        }
        if self.cooldown_secs == 0 {
            return Err("content_security.breaker.cooldown_secs must be > 0".to_string());
        }
        if !self.anomaly_rate_threshold.is_finite()
            || self.anomaly_rate_threshold <= 0.0
            || self.anomaly_rate_threshold > 1.0
        {
            return Err(format!(
                "content_security.breaker.anomaly_rate_threshold must be in (0.0, 1.0], got {}",
                self.anomaly_rate_threshold
            ));
        }
        Ok(())
    }
}

impl SemanticAttackConfig {
    fn validate(&self, family: &str) -> Result<(), String> {
        if self.block_threshold > 100 {
            return Err(format!(
                "content_security.attacks.{family}.block_threshold must be 0..=100"
            ));
        }
        if self.log_threshold > 100 {
            return Err(format!(
                "content_security.attacks.{family}.log_threshold must be 0..=100"
            ));
        }
        if self.log_threshold > self.block_threshold {
            return Err(format!(
                "content_security.attacks.{family}: log_threshold ({}) must be <= block_threshold ({})",
                self.log_threshold, self.block_threshold
            ));
        }

        // Weights are always range-checked (finite, non-negative). Blind trust
        // of a NaN/negative weight would corrupt the closed score.
        for (detector, weight) in &self.weights {
            if !weight.is_finite() || *weight < 0.0 {
                return Err(format!(
                    "content_security.attacks.{family}.weights.{detector} must be a finite, non-negative number, got {weight}"
                ));
            }
        }

        if self.enabled {
            // An enabled family must have detectors whose weights sum to exactly
            // 1.0. Empty enabled families are illegal (plan §6.2).
            if self.weights.is_empty() {
                return Err(format!(
                    "content_security.attacks.{family} is enabled but has no weights; \
                     an empty attack family must be enabled = false"
                ));
            }
            let sum: f64 = self.weights.values().copied().sum();
            if (sum - 1.0).abs() > WEIGHT_SUM_EPSILON {
                return Err(format!(
                    "content_security.attacks.{family}: enabled detector weights must sum to 1.0, got {sum}"
                ));
            }
        }
        // A disabled family is exempt from the weight-sum rule (plan §6.2).

        Ok(())
    }
}

/// Recognised attack-family keys (must match `waf_engine`'s `AttackKind`).
fn is_known_attack_family(name: &str) -> bool {
    matches!(name, "sql_injection" | "rce" | "xss" | "traversal" | "xxe")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_off_and_valid() {
        let cfg = ContentSecurityConfig::default();
        assert!(!cfg.enabled, "lane must be off by default");
        assert_eq!(cfg.enforcement_mode, "log_only");
        assert!(!cfg.hpp);
        assert_eq!(cfg.rollout_bps, 0);
        assert!(cfg.attacks.is_empty());
        cfg.validate().expect("default config must validate");
    }

    #[test]
    fn rejects_bad_enforcement_mode() {
        let cfg = ContentSecurityConfig {
            enforcement_mode: "panic".to_string(),
            ..ContentSecurityConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_enabled_family_with_bad_weight_sum() {
        let mut weights = BTreeMap::new();
        weights.insert("struct_rule".to_string(), 0.5);
        weights.insert("ast".to_string(), 0.3); // sums to 0.8
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
            attacks,
            ..ContentSecurityConfig::default()
        };
        let err = cfg.validate().expect_err("weight sum 0.8 must be rejected");
        assert!(err.contains("sum to 1.0"), "unexpected error: {err}");
    }

    #[test]
    fn accepts_enabled_family_with_unit_weight_sum() {
        let mut weights = BTreeMap::new();
        weights.insert("struct_rule".to_string(), 0.6);
        weights.insert("ast".to_string(), 0.4);
        let mut attacks = BTreeMap::new();
        attacks.insert(
            "sql_injection".to_string(),
            SemanticAttackConfig {
                enabled: true,
                weights,
                log_threshold: 40,
                block_threshold: 80,
                hard_veto_allowlist: vec!["sql.into_outfile".to_string()],
            },
        );
        let cfg = ContentSecurityConfig {
            enabled: true,
            attacks,
            ..ContentSecurityConfig::default()
        };
        cfg.validate().expect("unit-sum enabled family must validate");
    }

    #[test]
    fn rejects_empty_enabled_family() {
        let mut attacks = BTreeMap::new();
        attacks.insert(
            "xss".to_string(),
            SemanticAttackConfig {
                enabled: true,
                ..SemanticAttackConfig::default()
            },
        );
        let cfg = ContentSecurityConfig {
            enabled: true,
            attacks,
            ..ContentSecurityConfig::default()
        };
        assert!(cfg.validate().is_err(), "empty enabled family must be rejected");
    }

    #[test]
    fn disabled_empty_family_is_exempt() {
        let mut attacks = BTreeMap::new();
        attacks.insert("xss".to_string(), SemanticAttackConfig::default());
        let cfg = ContentSecurityConfig {
            enabled: true,
            attacks,
            ..ContentSecurityConfig::default()
        };
        cfg.validate()
            .expect("disabled empty family must be exempt from weight-sum");
    }

    #[test]
    fn rejects_negative_weight() {
        let mut weights = BTreeMap::new();
        weights.insert("struct_rule".to_string(), -1.0);
        let mut attacks = BTreeMap::new();
        attacks.insert(
            "sql_injection".to_string(),
            SemanticAttackConfig {
                enabled: false, // even a disabled family range-checks weights
                weights,
                ..SemanticAttackConfig::default()
            },
        );
        let cfg = ContentSecurityConfig {
            attacks,
            ..ContentSecurityConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_threshold_inversion() {
        let mut weights = BTreeMap::new();
        weights.insert("struct_rule".to_string(), 1.0);
        let mut attacks = BTreeMap::new();
        attacks.insert(
            "sql_injection".to_string(),
            SemanticAttackConfig {
                enabled: true,
                weights,
                log_threshold: 90,
                block_threshold: 50,
                hard_veto_allowlist: Vec::new(),
            },
        );
        let cfg = ContentSecurityConfig {
            enabled: true,
            attacks,
            ..ContentSecurityConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_rollout_bps_over_10000() {
        let cfg = ContentSecurityConfig {
            rollout_bps: 10_001,
            ..ContentSecurityConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn accepts_valid_enforcement_override() {
        let mut overrides = BTreeMap::new();
        overrides.insert("sql_injection".to_string(), "enforce".to_string());
        let cfg = ContentSecurityConfig {
            enabled: true,
            enforcement_overrides: overrides,
            ..ContentSecurityConfig::default()
        };
        cfg.validate().expect("a single-family enforce override must validate");
    }

    #[test]
    fn rejects_enforcement_override_unknown_family() {
        let mut overrides = BTreeMap::new();
        overrides.insert("sqli".to_string(), "enforce".to_string()); // typo
        let cfg = ContentSecurityConfig {
            enforcement_overrides: overrides,
            ..ContentSecurityConfig::default()
        };
        assert!(cfg.validate().is_err(), "an unknown override family must be rejected");
    }

    #[test]
    fn rejects_enforcement_override_bad_mode() {
        let mut overrides = BTreeMap::new();
        overrides.insert("rce".to_string(), "panic".to_string());
        let cfg = ContentSecurityConfig {
            enforcement_overrides: overrides,
            ..ContentSecurityConfig::default()
        };
        assert!(cfg.validate().is_err(), "an unknown override mode must be rejected");
    }
}
