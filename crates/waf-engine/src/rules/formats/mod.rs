//! Rule format parsers — YAML, `ModSecurity` (`SecRule`), JSON.

pub mod json;
pub mod modsec;
pub mod yaml;

use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::registry::Rule;

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
    pub fn parse_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => Self::Json,
            _ => Self::Yaml,
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
