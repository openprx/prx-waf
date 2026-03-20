//! YAML rule format parser.

use std::collections::HashMap;

use anyhow::Result;
use serde::Deserialize;

use super::super::registry::Rule;

/// Raw YAML rule with all fields optional / defaulted.
#[derive(Debug, Deserialize)]
struct YamlRule {
    id: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default = "default_category")]
    category: String,
    #[serde(default = "default_source")]
    source: String,
    #[serde(default = "default_enabled")]
    enabled: bool,
    #[serde(default = "default_action")]
    action: String,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    pattern: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    metadata: HashMap<String, String>,
}

fn default_category() -> String {
    "custom".to_string()
}
fn default_source() -> String {
    "file".to_string()
}
fn default_enabled() -> bool {
    true
}
fn default_action() -> String {
    "block".to_string()
}

/// Parse YAML content into a list of `Rule`s.
pub fn parse(content: &str) -> Result<Vec<Rule>> {
    let raw: Vec<YamlRule> = serde_yaml::from_str(content)?;
    Ok(raw
        .into_iter()
        .map(|r| Rule {
            id: r.id,
            name: r.name,
            description: r.description,
            category: r.category,
            source: r.source,
            enabled: r.enabled,
            action: r.action,
            severity: r.severity,
            pattern: r.pattern,
            tags: r.tags,
            metadata: r.metadata,
        })
        .collect())
}

/// Serialize a list of rules to YAML.
pub fn export(rules: &[Rule]) -> Result<String> {
    Ok(serde_yaml::to_string(rules)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_rule() {
        let yaml = r#"
- id: "TEST-001"
  name: "Test rule"
"#;
        let rules = parse(yaml).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "TEST-001");
        assert_eq!(rules[0].action, "block");
        assert!(rules[0].enabled);
    }

    #[test]
    fn parse_full_rule() {
        let yaml = r#"
- id: "TEST-002"
  name: "Full rule"
  description: "A complete rule"
  category: "sqli"
  source: "owasp"
  enabled: false
  action: "log"
  severity: "high"
  pattern: "(?i)union.*select"
  tags:
    - "sqli"
    - "owasp"
  metadata:
    cve: "CVE-2021-0001"
"#;
        let rules = parse(yaml).unwrap();
        assert_eq!(rules.len(), 1);
        assert!(!rules[0].enabled);
        assert_eq!(rules[0].category, "sqli");
        assert_eq!(rules[0].severity.as_deref(), Some("high"));
    }
}
