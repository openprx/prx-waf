//! JSON rule format parser.

use std::collections::HashMap;

use anyhow::Result;
use serde::Deserialize;

use super::super::registry::Rule;

/// Raw JSON rule — same shape as the YAML format.
#[derive(Debug, Deserialize)]
struct JsonRule {
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
const fn default_enabled() -> bool {
    true
}
fn default_action() -> String {
    "block".to_string()
}

/// Parse JSON content (array of rules) into `Rule`s.
pub fn parse(content: &str) -> Result<Vec<Rule>> {
    let raw: Vec<JsonRule> = serde_json::from_str(content)?;
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

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn parse_json_rules() {
        let json = r#"[{"id":"J-001","name":"Test JSON rule"}]"#;
        let rules = parse(json).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "J-001");
        assert_eq!(rules[0].action, "block");
    }

    #[test]
    fn empty_array() {
        let rules = parse("[]").unwrap();
        assert!(rules.is_empty());
    }
}
