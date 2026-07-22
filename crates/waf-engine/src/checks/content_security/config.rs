//! Immutable runtime content-security config, compiled at engine startup.
//!
//! Compiled from the serializable
//! [`waf_common::content_security_config::ContentSecurityConfig`] (plan v2.2
//! §6.5). This is where detector-id strings are resolved to
//! [`super::types::DetectorId`] — `waf-common` deliberately never depends on the
//! engine's `DetectorId`.

use waf_common::content_security_config::ContentSecurityConfig;

use super::budget::Budget;
use super::canary::BreakerConfig;
use super::scoring::RuntimeScoringConfig;

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

        let enforcement_mode = match cfg.enforcement_mode.as_str() {
            "off" => EnforcementMode::Off,
            "log_only" => EnforcementMode::LogOnly,
            "enforce" => EnforcementMode::Enforce,
            other => return Err(format!("unknown enforcement_mode '{other}'")),
        };

        let dialect = match cfg.dialect.as_str() {
            "generic" => Dialect::Generic,
            other => return Err(format!("unknown dialect '{other}'")),
        };

        Ok(Self {
            enabled: cfg.enabled,
            enforcement_mode,
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
