//! Immutable runtime content-security config, compiled at engine startup.
//!
//! Compiled from the serializable
//! [`waf_common::content_security_config::ContentSecurityConfig`] (plan v2.2
//! §6.5). This is where detector-id strings are resolved to
//! [`super::types::DetectorId`] — `waf-common` deliberately never depends on the
//! engine's `DetectorId`.

use std::collections::HashMap;

use waf_common::content_security_config::ContentSecurityConfig;

use super::budget::Budget;
use super::canary::BreakerConfig;
use super::scoring::RuntimeScoringConfig;
use super::types::AttackKind;

/// Runtime enforcement mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementMode {
    /// Semantic lane produces no action at all.
    Off,
    /// Shadow mode — at most a `LogOnly` security event (the safe default).
    LogOnly,
    /// May block, subject to canary + breaker + host `log_only_mode`.
    Enforce,
}

/// Parse a serialized enforcement-mode string into [`EnforcementMode`]. Shared by
/// the global mode and the E0 per-family overrides so both accept exactly the
/// same vocabulary. Assumes [`ContentSecurityConfig::validate`] already ran, but
/// re-checks defensively (a programmatic config may bypass `load_config`).
fn parse_enforcement_mode(s: &str) -> Result<EnforcementMode, String> {
    match s {
        "off" => Ok(EnforcementMode::Off),
        "log_only" => Ok(EnforcementMode::LogOnly),
        "enforce" => Ok(EnforcementMode::Enforce),
        other => Err(format!("unknown enforcement_mode '{other}'")),
    }
}

/// SQL dialect assumption. P1 is global `Generic` only (plan §14.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Generic,
}

/// Compiled, immutable Lane 2 configuration held by the subsystem.
#[derive(Debug, Clone)]
pub struct RuntimeContentSecurityConfig {
    pub enabled: bool,
    pub enforcement_mode: EnforcementMode,
    /// Per-family enforcement-mode overrides (E0). A family present here uses its
    /// mode instead of [`Self::enforcement_mode`]; absent families inherit the
    /// global mode. Empty by default → identical to the pure-global posture.
    pub enforcement_overrides: HashMap<AttackKind, EnforcementMode>,
    pub dialect: Dialect,
    pub hpp_enabled: bool,
    pub rollout_bps: u32,
    pub rollout_salt: String,
    pub budget: Budget,
    pub breaker: BreakerConfig,
    pub scoring: RuntimeScoringConfig,
}

impl Default for RuntimeContentSecurityConfig {
    /// The zero-config default: the entire lane is off, shadow mode, global
    /// generic dialect, HPP off, no rollout, empty scoring.
    fn default() -> Self {
        Self {
            enabled: false,
            enforcement_mode: EnforcementMode::LogOnly,
            enforcement_overrides: HashMap::new(),
            dialect: Dialect::Generic,
            hpp_enabled: false,
            rollout_bps: 0,
            rollout_salt: String::new(),
            budget: Budget::default(),
            breaker: BreakerConfig::default(),
            scoring: RuntimeScoringConfig::default(),
        }
    }
}

impl RuntimeContentSecurityConfig {
    /// Compile the serializable config into the immutable runtime form.
    ///
    /// Re-runs [`ContentSecurityConfig::validate`] defensively (so a config
    /// constructed programmatically, bypassing `load_config`, is still checked),
    /// then resolves enforcement mode, dialect and the detector-id strings.
    pub fn compile(cfg: &ContentSecurityConfig) -> Result<Self, String> {
        cfg.validate()?;

        let enforcement_mode = parse_enforcement_mode(&cfg.enforcement_mode)?;

        // Resolve the per-family overrides (E0): family-key string → AttackKind,
        // mode string → EnforcementMode. Rejects an unknown family the same way
        // the scoring compile rejects an unknown `[attacks]` family.
        let mut enforcement_overrides = HashMap::new();
        for (family_key, mode) in &cfg.enforcement_overrides {
            let Some(attack) = AttackKind::from_config_key(family_key) else {
                return Err(format!(
                    "enforcement_overrides references unknown attack family '{family_key}'"
                ));
            };
            enforcement_overrides.insert(attack, parse_enforcement_mode(mode)?);
        }

        let dialect = match cfg.dialect.as_str() {
            "generic" => Dialect::Generic,
            other => return Err(format!("unknown dialect '{other}'")),
        };

        Ok(Self {
            enabled: cfg.enabled,
            enforcement_mode,
            enforcement_overrides,
            dialect,
            hpp_enabled: cfg.hpp,
            rollout_bps: cfg.rollout_bps,
            rollout_salt: cfg.rollout_salt.clone(),
            budget: Budget::from_config(&cfg.budget),
            breaker: BreakerConfig::from_config(&cfg.breaker),
            scoring: RuntimeScoringConfig::compile(cfg)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use waf_common::content_security_config::SemanticAttackConfig;

    use super::*;

    #[test]
    fn default_config_is_off() {
        let rt = RuntimeContentSecurityConfig::default();
        assert!(!rt.enabled);
        assert_eq!(rt.enforcement_mode, EnforcementMode::LogOnly);
        assert_eq!(rt.dialect, Dialect::Generic);
    }

    #[test]
    fn compile_resolves_detector_ids() {
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
            attacks,
            ..ContentSecurityConfig::default()
        };
        let rt = RuntimeContentSecurityConfig::compile(&cfg).expect("valid config compiles");
        assert!(rt.enabled);
        assert_eq!(rt.scoring.attacks.len(), 1);
    }

    #[test]
    fn shipped_default_toml_compiles_all_families() {
        use super::super::types::AttackKind;

        // Regression: the shipped `configs/default.toml` must load, validate and
        // compile through the runtime — proving every family's detector-id
        // (`struct_rule` / `rce` / `traversal`) resolves and the weight sums are
        // accepted. Guards against config drift breaking startup.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../configs/default.toml");
        let app = waf_common::config::load_config(path).expect("shipped default.toml must load + validate");
        let rt = RuntimeContentSecurityConfig::compile(&app.content_security)
            .expect("shipped default.toml content_security must compile");
        assert!(rt.enabled, "shipped lane is enabled (shadow)");
        assert_eq!(
            rt.enforcement_mode,
            EnforcementMode::LogOnly,
            "shipped posture is log_only"
        );
        // All four families present and enabled (SQLi/RCE/Traversal + P-XSS-1 Xss).
        for fam in [
            AttackKind::SqlInjection,
            AttackKind::Rce,
            AttackKind::Traversal,
            AttackKind::Xss,
        ] {
            let ac = rt.scoring.attacks.get(&fam).expect("family present");
            assert!(ac.enabled, "{fam:?} enabled");
            assert!(
                ac.hard_veto_allowlist.is_empty(),
                "{fam:?} hard-veto allowlist must be empty pre-holdout"
            );
        }
    }

    #[test]
    fn compile_resolves_enforcement_overrides() {
        use super::super::types::AttackKind;

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
        let mut overrides = BTreeMap::new();
        overrides.insert("sql_injection".to_string(), "enforce".to_string());
        let cfg = ContentSecurityConfig {
            enabled: true,
            // Global stays log_only; only SQLi is overridden to enforce.
            attacks,
            enforcement_overrides: overrides,
            ..ContentSecurityConfig::default()
        };
        let rt = RuntimeContentSecurityConfig::compile(&cfg).expect("valid override compiles");
        assert_eq!(rt.enforcement_mode, EnforcementMode::LogOnly, "global stays shadow");
        assert_eq!(
            rt.enforcement_overrides.get(&AttackKind::SqlInjection).copied(),
            Some(EnforcementMode::Enforce),
            "the SQLi family override resolves to enforce"
        );
        assert!(
            !rt.enforcement_overrides.contains_key(&AttackKind::Rce),
            "an un-overridden family inherits the global mode (absent from the map)"
        );
    }

    #[test]
    fn compile_rejects_unknown_detector() {
        let mut weights = BTreeMap::new();
        weights.insert("nonexistent".to_string(), 1.0);
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
        assert!(RuntimeContentSecurityConfig::compile(&cfg).is_err());
    }
}
