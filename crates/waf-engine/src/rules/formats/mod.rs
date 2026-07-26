//! Rule format parsers — YAML, `ModSecurity` (`SecRule`), JSON.

pub mod json;
pub mod modsec;
pub mod yaml;

use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::registry::Rule;
use crate::checks::{RuleDescriptor, RuleState};

/// Supported rule file formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleFormat {
    #[default]
    Yaml,
    ModSec,
    Json,
}

impl RuleFormat {
    /// Infer format from file extension.
    pub fn from_path(path: &Path) -> Option<Self> {
        match path.extension()?.to_str()? {
            "yaml" | "yml" => Some(Self::Yaml),
            "conf" | "modsec" => Some(Self::ModSec),
            "json" => Some(Self::Json),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Yaml => "yaml",
            Self::ModSec => "modsec",
            Self::Json => "json",
        }
    }
}

impl std::fmt::Display for RuleFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parse rule content from a string given a known format.
pub fn parse_rules(content: &str, format: RuleFormat) -> Result<Vec<Rule>> {
    match format {
        RuleFormat::Yaml => yaml::parse(content),
        RuleFormat::ModSec => modsec::parse(content),
        RuleFormat::Json => json::parse(content),
    }
}

/// A validation error found while parsing a rule file.
#[derive(Debug, Clone)]
pub struct ValidationError {
    pub line: Option<usize>,
    pub field: Option<String>,
    pub message: String,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(line) = self.line {
            write!(f, "line {line}: ")?;
        }
        write!(f, "{}", self.message)
    }
}

/// Validate a rule file and return a list of errors (empty = valid).
pub fn validate_rules(content: &str, format: RuleFormat) -> Vec<ValidationError> {
    match parse_rules(content, format) {
        Ok(rules) => {
            let mut errors = Vec::new();
            for (i, rule) in rules.iter().enumerate() {
                if rule.id.is_empty() {
                    errors.push(ValidationError {
                        line: None,
                        field: Some(format!("rules[{i}].id")),
                        message: "Rule id must not be empty".to_string(),
                    });
                }
                if rule.name.is_empty() {
                    errors.push(ValidationError {
                        line: None,
                        field: Some(format!("rules[{i}].name")),
                        message: "Rule name must not be empty".to_string(),
                    });
                }
            }
            errors
        }
        Err(e) => vec![ValidationError {
            line: None,
            field: None,
            message: format!("Parse error: {e}"),
        }],
    }
}

/// Export format for the `rules export` command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Yaml,
    Json,
}

impl ExportFormat {
    /// Parse a `--format` value. `None` for anything else.
    ///
    /// Deliberately fallible: silently falling back to YAML would answer
    /// `--format=xlm` with a YAML document and let the caller believe it asked
    /// for it.
    #[must_use]
    pub fn parse_flag(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "yaml" | "yml" => Some(Self::Yaml),
            "json" => Some(Self::Json),
            _ => None,
        }
    }

    /// Spelling accepted by [`Self::parse_flag`], for help and error text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Yaml => "yaml",
            Self::Json => "json",
        }
    }
}

/// Serialize a list of rules to a string in the given format.
pub fn export_rules(rules: &[Rule], format: ExportFormat) -> Result<String> {
    match format {
        ExportFormat::Yaml => {
            let out = serde_yaml::to_string(rules)?;
            Ok(out)
        }
        ExportFormat::Json => {
            let out = serde_json::to_string_pretty(rules)?;
            Ok(out)
        }
    }
}

/// One enforced CRS rule as `prx-waf rules export` writes it.
///
/// A flat mirror of [`RuleDescriptor`] carrying exactly the field names
/// `GET /api/rules/registry` uses, so a dump taken from the CLI and one taken
/// from the API can be diffed against each other without a translation step.
///
/// Deliberately *not* a [`Rule`]: a descriptor carries no match expression, so
/// emitting one in the importable rule schema would produce a file that parses,
/// loads, and detects nothing.
#[derive(Debug, Serialize)]
struct RegistryEntry<'a> {
    id: &'a str,
    crs_id: Option<u32>,
    name: &'a str,
    category: &'a str,
    source: &'a str,
    severity: &'a str,
    score: u32,
    paranoia: u8,
    phase: &'a str,
    declared_action: &'a str,
    /// What the request path does with a match in the exported scope, after the
    /// operator override — the one field a reviewer actually acts on.
    effective_action: &'a str,
    state: &'a str,
    overridden: bool,
}

impl<'a> From<&'a RuleDescriptor> for RegistryEntry<'a> {
    fn from(rule: &'a RuleDescriptor) -> Self {
        Self {
            id: &rule.id,
            crs_id: rule.crs_id,
            name: &rule.name,
            category: &rule.category,
            source: &rule.source,
            severity: rule.severity,
            score: rule.score,
            paranoia: rule.paranoia,
            phase: rule.phase,
            declared_action: rule.declared_action,
            effective_action: match rule.state {
                RuleState::Active => rule.declared_action,
                RuleState::Disabled => "disabled",
                RuleState::LogOnly => "log",
            },
            state: rule.state.as_str(),
            overridden: rule.state != RuleState::Active,
        }
    }
}

/// Serialize the enforced rule inventory — what [`crate::OWASPCheck::registry`]
/// returns for one scope — as YAML or JSON.
///
/// This is the set the request path walks, not the contents of a rule file, so
/// the dump answers "what is this WAF enforcing" for an audit or a diff between
/// two deployments.
pub fn export_registry(rules: &[RuleDescriptor], format: ExportFormat) -> Result<String> {
    let entries: Vec<RegistryEntry<'_>> = rules.iter().map(RegistryEntry::from).collect();
    match format {
        ExportFormat::Yaml => Ok(serde_yaml::to_string(&entries)?),
        ExportFormat::Json => Ok(serde_json::to_string_pretty(&entries)?),
    }
}

#[cfg(test)]
mod export_registry_tests {
    use super::{ExportFormat, export_registry};
    use crate::checks::{RuleDescriptor, RuleState};

    fn text<'a>(items: &'a [serde_json::Value], idx: usize, key: &str) -> Option<&'a str> {
        items.get(idx)?.get(key)?.as_str()
    }

    fn flag(items: &[serde_json::Value], idx: usize, key: &str) -> Option<bool> {
        items.get(idx)?.get(key)?.as_bool()
    }

    fn descriptor(id: &str, state: RuleState) -> RuleDescriptor {
        RuleDescriptor {
            id: id.to_string(),
            crs_id: Some(942_100),
            name: "SQL Injection Attack Detected".to_string(),
            category: "sqli".to_string(),
            source: "rules/owasp-crs/sqli.yaml".to_string(),
            severity: "critical",
            score: 5,
            paranoia: 1,
            phase: "request",
            declared_action: "score",
            state,
        }
    }

    #[test]
    fn parse_flag_rejects_unknown_formats() {
        assert_eq!(ExportFormat::parse_flag("yaml"), Some(ExportFormat::Yaml));
        assert_eq!(ExportFormat::parse_flag(" YML "), Some(ExportFormat::Yaml));
        assert_eq!(ExportFormat::parse_flag("Json"), Some(ExportFormat::Json));
        assert_eq!(ExportFormat::parse_flag("xml"), None);
        assert_eq!(ExportFormat::parse_flag(""), None);
    }

    #[test]
    fn json_export_carries_the_effective_action() {
        let rules = [
            descriptor("CRS-942100", RuleState::Active),
            descriptor("CRS-942110", RuleState::LogOnly),
            descriptor("CRS-942120", RuleState::Disabled),
        ];
        let out = match export_registry(&rules, ExportFormat::Json) {
            Ok(out) => out,
            Err(e) => panic!("export failed: {e}"),
        };
        let parsed: serde_json::Value = match serde_json::from_str(&out) {
            Ok(v) => v,
            Err(e) => panic!("export is not valid JSON: {e}"),
        };
        let items = parsed.as_array().unwrap_or_else(|| panic!("expected a JSON array"));
        assert_eq!(items.len(), 3);
        assert_eq!(text(items, 0, "effective_action"), Some("score"));
        assert_eq!(flag(items, 0, "overridden"), Some(false));
        assert_eq!(text(items, 1, "effective_action"), Some("log"));
        assert_eq!(text(items, 1, "state"), Some("log_only"));
        assert_eq!(text(items, 2, "effective_action"), Some("disabled"));
        assert_eq!(flag(items, 2, "overridden"), Some(true));
    }

    #[test]
    fn yaml_export_has_no_pattern_field_to_re_import() {
        let rules = [descriptor("CRS-942100", RuleState::Active)];
        let out = match export_registry(&rules, ExportFormat::Yaml) {
            Ok(out) => out,
            Err(e) => panic!("export failed: {e}"),
        };
        assert!(out.contains("id: CRS-942100"), "{out}");
        assert!(out.contains("crs_id: 942100"), "{out}");
        // A descriptor has no match expression: the dump must not look like a
        // loadable rule file.
        assert!(!out.contains("pattern"), "{out}");
    }
}
