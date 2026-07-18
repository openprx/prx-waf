//! Custom WAF Rules Engine
//!
//! Evaluates user-defined rules stored in `PostgreSQL` against incoming requests.
//! Each rule has:
//!   - Conditions (AND/OR) matching fields of the request
//!   - An action (Block / Allow / Log / Challenge)
//!   - An optional Rhai script for complex evaluation logic

use std::sync::Arc;

use anyhow::Context;
use dashmap::DashMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::warn;

use waf_common::{DetectionResult, Phase, RequestCtx};

// ── Condition field ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionField {
    Ip,
    Path,
    Query,
    Method,
    Body,
    Cookie,
    UserAgent,
    ContentType,
    ContentLength,
    Host,
    /// Arbitrary header — value is the header name (lowercased)
    Header(String),
    // ── GeoIP fields (populated when GeoIP is enabled) ──────────────────────
    /// Full country name (e.g. "China", "United States")
    GeoCountry,
    /// ISO 3166-1 alpha-2 country code (e.g. "CN", "US")
    GeoIso,
    /// Province / state
    GeoProvince,
    /// City
    GeoCity,
    /// ISP / organization
    GeoIsp,
}

// ── Comparison operator ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    Eq,
    Ne,
    Contains,
    NotContains,
    StartsWith,
    EndsWith,
    Regex,
    InList,
    NotInList,
    CidrMatch,
    Gt,
    Lt,
    Gte,
    Lte,
}

// ── Condition value ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConditionValue {
    Str(String),
    List(Vec<String>),
    Number(i64),
}

// ── Single condition ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub field: ConditionField,
    pub operator: Operator,
    pub value: ConditionValue,
}

// ── Condition combinator ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ConditionOp {
    #[default]
    And,
    Or,
}

impl ConditionOp {
    pub const fn parse_str(s: &str) -> Self {
        if s.eq_ignore_ascii_case("or") {
            Self::Or
        } else {
            Self::And
        }
    }
}

// ── Rule action ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Block,
    Allow,
    Log,
    Challenge,
}

impl RuleAction {
    pub fn parse_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "allow" => Self::Allow,
            "log" => Self::Log,
            "challenge" => Self::Challenge,
            _ => Self::Block,
        }
    }
}

// ── A single custom WAF rule ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CustomRule {
    pub id: String,
    pub host_code: String,
    pub name: String,
    pub priority: i32,
    pub enabled: bool,
    pub condition_op: ConditionOp,
    pub conditions: Vec<Condition>,
    pub action: RuleAction,
    pub action_status: u16,
    pub action_msg: Option<String>,
    /// Optional Rhai expression that overrides `conditions` when present.
    pub script: Option<String>,
    /// Regexes precompiled at load time (M-8), one slot per condition index
    /// (`None` unless that condition uses [`Operator::Regex`]).  Empty when the
    /// rule was built without precompilation (e.g. in unit tests).
    pub regex_cache: Vec<Option<Arc<Regex>>>,
}

/// Outcome of a custom-rule match, carrying the rule's configured action so the
/// engine can dispatch on it (M-7) rather than always blocking with 403.
#[derive(Debug, Clone)]
pub struct CustomRuleMatch {
    pub result: DetectionResult,
    pub action: RuleAction,
    pub action_status: u16,
    pub action_msg: Option<String>,
}

// ── Custom rules engine ───────────────────────────────────────────────────────

/// Thread-safe custom rules engine.
///
/// Rules are cached in a `DashMap<host_code, Vec<CustomRule>>` sorted by
/// priority (ascending — lower number wins).  A special key `"*"` holds
/// global rules that apply to every host.
pub struct CustomRulesEngine {
    rules: DashMap<String, Vec<CustomRule>>,
    rhai: Arc<rhai::Engine>,
}

impl CustomRulesEngine {
    pub fn new() -> Self {
        let mut engine = rhai::Engine::new();
        // Restrict the scripting sandbox
        engine.set_max_operations(100_000);
        engine.set_max_call_levels(16);
        engine.set_max_expr_depths(64, 32);

        Self {
            rules: DashMap::new(),
            rhai: Arc::new(engine),
        }
    }

    /// Replace all rules for a host (sorted by priority).
    pub fn load_host(&self, host_code: &str, mut rules: Vec<CustomRule>) {
        rules.retain(|r| r.enabled);
        rules.sort_by_key(|r| r.priority);
        self.rules.insert(host_code.to_string(), rules);
    }

    /// Append a single rule (hot-add).
    pub fn add_rule(&self, rule: CustomRule) {
        let host_code = rule.host_code.clone();
        let mut entry = self.rules.entry(host_code).or_default();
        entry.push(rule);
        entry.sort_by_key(|r| r.priority);
    }

    /// Remove a rule by ID.
    pub fn remove_rule(&self, host_code: &str, rule_id: &str) {
        if let Some(mut rules) = self.rules.get_mut(host_code) {
            rules.retain(|r| r.id != rule_id);
        }
    }

    /// Total number of cached rules.
    pub fn len(&self) -> usize {
        self.rules.iter().map(|e| e.value().len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Evaluate all rules against the request context.
    ///
    /// Returns the first matching rule as a [`CustomRuleMatch`] (carrying its
    /// action), or `None`.
    pub fn check(&self, ctx: &RequestCtx) -> Option<CustomRuleMatch> {
        let host_code = &ctx.host_config.code;

        // Host-specific rules first
        if let Some(rules) = self.rules.get(host_code)
            && let Some(r) = self.eval_list(ctx, &rules)
        {
            return Some(r);
        }

        // Global rules
        if let Some(rules) = self.rules.get("*")
            && let Some(r) = self.eval_list(ctx, &rules)
        {
            return Some(r);
        }

        None
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn eval_list(&self, ctx: &RequestCtx, rules: &[CustomRule]) -> Option<CustomRuleMatch> {
        for rule in rules {
            if !rule.enabled {
                continue;
            }

            let matched = rule.script.as_ref().map_or_else(
                || self.eval_conditions(ctx, rule),
                |script| self.eval_script(ctx, script),
            );

            if matched {
                return Some(CustomRuleMatch {
                    result: DetectionResult {
                        rule_id: Some(rule.id.clone()),
                        rule_name: rule.name.clone(),
                        phase: Phase::CustomRule,
                        detail: format!("Custom rule '{}' matched", rule.name),
                    },
                    action: rule.action.clone(),
                    action_status: rule.action_status,
                    action_msg: rule.action_msg.clone(),
                });
            }
        }
        None
    }

    fn eval_script(&self, ctx: &RequestCtx, script: &str) -> bool {
        let mut scope = rhai::Scope::new();
        scope.push("ip", ctx.client_ip.to_string());
        scope.push("path", ctx.path.clone());
        scope.push("method", ctx.method.clone());
        scope.push("query", ctx.query.clone());
        scope.push("host", ctx.host.clone());
        scope.push("user_agent", ctx.headers.get("user-agent").cloned().unwrap_or_default());
        scope.push("referer", ctx.headers.get("referer").cloned().unwrap_or_default());
        scope.push(
            "content_type",
            ctx.headers.get("content-type").cloned().unwrap_or_default(),
        );
        #[allow(clippy::cast_possible_wrap)]
        scope.push("content_length", ctx.content_length as i64);

        self.rhai
            .eval_expression_with_scope::<bool>(&mut scope, script)
            .unwrap_or_else(|e| {
                warn!("Rhai script error: {e}");
                false
            })
    }

    fn eval_conditions(&self, ctx: &RequestCtx, rule: &CustomRule) -> bool {
        if rule.conditions.is_empty() {
            return false;
        }
        let eval_at = |i: usize, c: &Condition| {
            let compiled = rule.regex_cache.get(i).and_then(Option::as_ref);
            self.eval_one(ctx, c, compiled)
        };
        match rule.condition_op {
            ConditionOp::And => rule.conditions.iter().enumerate().all(|(i, c)| eval_at(i, c)),
            ConditionOp::Or => rule.conditions.iter().enumerate().any(|(i, c)| eval_at(i, c)),
        }
    }

    fn eval_one(&self, ctx: &RequestCtx, cond: &Condition, compiled_regex: Option<&Arc<Regex>>) -> bool {
        let fval = self.field_value(ctx, &cond.field);
        let fstr = fval.as_deref().unwrap_or("");

        match (&cond.operator, &cond.value) {
            (Operator::Eq, ConditionValue::Str(v)) => fstr.eq_ignore_ascii_case(v),
            (Operator::Ne, ConditionValue::Str(v)) => !fstr.eq_ignore_ascii_case(v),
            (Operator::Contains, ConditionValue::Str(v)) => fstr.contains(v.as_str()),
            (Operator::NotContains, ConditionValue::Str(v)) => !fstr.contains(v.as_str()),
            (Operator::StartsWith, ConditionValue::Str(v)) => fstr.starts_with(v.as_str()),
            (Operator::EndsWith, ConditionValue::Str(v)) => fstr.ends_with(v.as_str()),
            // M-8: use the precompiled regex; when absent (rule not built via
            // `from_db_rule`) the condition simply does not match.
            (Operator::Regex, ConditionValue::Str(_)) => compiled_regex.is_some_and(|r| r.is_match(fstr)),
            (Operator::InList, ConditionValue::List(l)) => l.iter().any(|v| v == fstr),
            (Operator::NotInList, ConditionValue::List(l)) => !l.iter().any(|v| v == fstr),
            (Operator::CidrMatch, ConditionValue::Str(cidr)) => cidr
                .parse::<ipnet::IpNet>()
                .ok()
                .is_some_and(|net| net.contains(&ctx.client_ip)),
            (Operator::Gt, ConditionValue::Number(n)) => fstr.parse::<i64>().ok().is_some_and(|v| v > *n),
            (Operator::Lt, ConditionValue::Number(n)) => fstr.parse::<i64>().ok().is_some_and(|v| v < *n),
            (Operator::Gte, ConditionValue::Number(n)) => fstr.parse::<i64>().ok().is_some_and(|v| v >= *n),
            (Operator::Lte, ConditionValue::Number(n)) => fstr.parse::<i64>().ok().is_some_and(|v| v <= *n),
            _ => false,
        }
    }

    #[allow(clippy::unused_self)]
    fn field_value(&self, ctx: &RequestCtx, field: &ConditionField) -> Option<String> {
        match field {
            ConditionField::Ip => Some(ctx.client_ip.to_string()),
            // M-6: match against the decoded path so encoded evasions such as
            // `/%61dmin` are normalised to `/admin` before comparison.
            ConditionField::Path => Some(crate::checks::url_decode(&ctx.path)),
            ConditionField::Query => Some(ctx.query.clone()),
            ConditionField::Method => Some(ctx.method.clone()),
            ConditionField::Host => Some(ctx.host.clone()),
            ConditionField::ContentLength => Some(ctx.content_length.to_string()),
            ConditionField::Body => Some(String::from_utf8_lossy(&ctx.body_preview).into_owned()),
            ConditionField::Cookie => ctx.headers.get("cookie").cloned(),
            ConditionField::UserAgent => ctx.headers.get("user-agent").cloned(),
            ConditionField::ContentType => ctx.headers.get("content-type").cloned(),
            ConditionField::Header(name) => ctx.headers.get(&name.to_lowercase()).cloned(),
            // ── GeoIP fields ────────────────────────────────────────────────
            ConditionField::GeoCountry => ctx.geo.as_ref().map(|g| g.country.clone()),
            ConditionField::GeoIso => ctx.geo.as_ref().map(|g| g.iso_code.clone()),
            ConditionField::GeoProvince => ctx.geo.as_ref().map(|g| g.province.clone()),
            ConditionField::GeoCity => ctx.geo.as_ref().map(|g| g.city.clone()),
            ConditionField::GeoIsp => ctx.geo.as_ref().map(|g| g.isp.clone()),
        }
    }
}

impl Default for CustomRulesEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper: deserialize a DB CustomRule row into an engine CustomRule ─────────

use waf_storage::models::CustomRule as DbCustomRule;

pub fn from_db_rule(row: &DbCustomRule) -> anyhow::Result<CustomRule> {
    // M-8: parse conditions strictly. Malformed JSON is a load-time error (the
    // caller warns and skips the rule) rather than a silent fail-open to an
    // empty, never-matching condition list.  A null value is a legitimately
    // empty condition list (e.g. a script-only rule).
    let conditions: Vec<Condition> = if row.conditions.is_null() {
        Vec::new()
    } else {
        serde_json::from_value(row.conditions.clone())
            .with_context(|| format!("custom rule {} has invalid conditions JSON", row.id))?
    };

    // Precompile any regex conditions once, at load time. An invalid pattern is
    // a load-time error (skip + warn) instead of a per-request silent no-match.
    let mut regex_cache: Vec<Option<Arc<Regex>>> = Vec::with_capacity(conditions.len());
    for cond in &conditions {
        if let (Operator::Regex, ConditionValue::Str(pattern)) = (&cond.operator, &cond.value) {
            let re = Regex::new(pattern)
                .with_context(|| format!("custom rule {} has an invalid regex '{pattern}'", row.id))?;
            regex_cache.push(Some(Arc::new(re)));
        } else {
            regex_cache.push(None);
        }
    }

    Ok(CustomRule {
        id: row.id.to_string(),
        host_code: row.host_code.clone(),
        name: row.name.clone(),
        priority: row.priority,
        enabled: row.enabled,
        condition_op: ConditionOp::parse_str(&row.condition_op),
        conditions,
        action: RuleAction::parse_str(&row.action),
        action_status: u16::try_from(row.action_status).unwrap_or(403),
        action_msg: row.action_msg.clone(),
        script: row.script.clone(),
        regex_cache,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::sync::Arc;
    use waf_common::HostConfig;

    fn make_ctx(path: &str, method: &str, ip: &str) -> RequestCtx {
        let host_config = Arc::new(HostConfig {
            code: "test".into(),
            host: "example.com".into(),
            ..HostConfig::default()
        });
        RequestCtx {
            req_id: "test".into(),
            client_ip: ip.parse().unwrap(),
            client_port: 12345,
            method: method.into(),
            host: "example.com".into(),
            port: 80,
            path: path.into(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config,
            geo: None,
        }
    }

    #[test]
    fn test_ip_cidr_match() {
        let engine = CustomRulesEngine::new();
        let rule = CustomRule {
            id: "r1".into(),
            host_code: "test".into(),
            name: "Block 10.0.0.0/8".into(),
            priority: 1,
            enabled: true,
            condition_op: ConditionOp::And,
            conditions: vec![Condition {
                field: ConditionField::Ip,
                operator: Operator::CidrMatch,
                value: ConditionValue::Str("10.0.0.0/8".into()),
            }],
            action: RuleAction::Block,
            action_status: 403,
            action_msg: None,
            script: None,
            regex_cache: Vec::new(),
        };
        engine.add_rule(rule);

        let ctx = make_ctx("/", "GET", "10.0.1.5");
        assert!(engine.check(&ctx).is_some());

        let ctx2 = make_ctx("/", "GET", "192.168.1.1");
        assert!(engine.check(&ctx2).is_none());
    }

    #[test]
    fn test_path_starts_with() {
        let engine = CustomRulesEngine::new();
        let rule = CustomRule {
            id: "r2".into(),
            host_code: "test".into(),
            name: "Block admin".into(),
            priority: 1,
            enabled: true,
            condition_op: ConditionOp::And,
            conditions: vec![Condition {
                field: ConditionField::Path,
                operator: Operator::StartsWith,
                value: ConditionValue::Str("/admin".into()),
            }],
            action: RuleAction::Block,
            action_status: 403,
            action_msg: None,
            script: None,
            regex_cache: Vec::new(),
        };
        engine.add_rule(rule);

        let ctx = make_ctx("/admin/users", "GET", "1.2.3.4");
        assert!(engine.check(&ctx).is_some());

        let ctx2 = make_ctx("/public", "GET", "1.2.3.4");
        assert!(engine.check(&ctx2).is_none());
    }

    #[test]
    fn test_path_match_uses_decoded_path() {
        // M-6: `/%61dmin` decodes to `/admin` and must match a `/admin` rule.
        let engine = CustomRulesEngine::new();
        let rule = CustomRule {
            id: "r_dec".into(),
            host_code: "test".into(),
            name: "Block admin (decoded)".into(),
            priority: 1,
            enabled: true,
            condition_op: ConditionOp::And,
            conditions: vec![Condition {
                field: ConditionField::Path,
                operator: Operator::StartsWith,
                value: ConditionValue::Str("/admin".into()),
            }],
            action: RuleAction::Block,
            action_status: 403,
            action_msg: None,
            script: None,
            regex_cache: Vec::new(),
        };
        engine.add_rule(rule);

        let ctx = make_ctx("/%61dmin/users", "GET", "1.2.3.4");
        assert!(engine.check(&ctx).is_some());
    }

    #[test]
    fn test_rhai_script() {
        let engine = CustomRulesEngine::new();
        let rule = CustomRule {
            id: "r3".into(),
            host_code: "test".into(),
            name: "Rhai block DELETE on /api".into(),
            priority: 1,
            enabled: true,
            condition_op: ConditionOp::And,
            conditions: vec![],
            action: RuleAction::Block,
            action_status: 403,
            action_msg: None,
            script: Some(r#"method == "DELETE" && path.starts_with("/api")"#.into()),
            regex_cache: Vec::new(),
        };
        engine.add_rule(rule);

        let ctx = make_ctx("/api/users/1", "DELETE", "1.2.3.4");
        assert!(engine.check(&ctx).is_some());

        let ctx2 = make_ctx("/api/users/1", "GET", "1.2.3.4");
        assert!(engine.check(&ctx2).is_none());
    }

    #[test]
    fn test_match_carries_action_and_status() {
        // M-7: the match must surface the rule's action + status for dispatch.
        let engine = CustomRulesEngine::new();
        engine.add_rule(CustomRule {
            id: "r_allow".into(),
            host_code: "test".into(),
            name: "Allow exception".into(),
            priority: 1,
            enabled: true,
            condition_op: ConditionOp::And,
            conditions: vec![Condition {
                field: ConditionField::Path,
                operator: Operator::StartsWith,
                value: ConditionValue::Str("/public".into()),
            }],
            action: RuleAction::Allow,
            action_status: 200,
            action_msg: None,
            script: None,
            regex_cache: Vec::new(),
        });

        let m = engine.check(&make_ctx("/public/x", "GET", "1.2.3.4")).expect("match");
        assert!(matches!(m.action, RuleAction::Allow));
        assert_eq!(m.action_status, 200);
    }

    fn db_rule(conditions: serde_json::Value) -> DbCustomRule {
        DbCustomRule {
            id: uuid::Uuid::nil(),
            host_code: "test".into(),
            name: "r".into(),
            description: None,
            priority: 1,
            enabled: true,
            condition_op: "and".into(),
            conditions,
            action: "block".into(),
            action_status: 403,
            action_msg: None,
            script: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn from_db_rule_precompiles_regex_and_matches() {
        // M-8: a valid regex condition compiles at load and matches at runtime.
        let row = db_rule(serde_json::json!([
            {"field": "path", "operator": "regex", "value": "^/adm[a-z]+$"}
        ]));
        let rule = from_db_rule(&row).expect("valid rule");
        assert_eq!(rule.regex_cache.len(), 1);
        assert!(rule.regex_cache.first().is_some_and(Option::is_some));

        let engine = CustomRulesEngine::new();
        engine.add_rule(rule);
        assert!(engine.check(&make_ctx("/admin", "GET", "1.2.3.4")).is_some());
        assert!(engine.check(&make_ctx("/other", "GET", "1.2.3.4")).is_none());
    }

    #[test]
    fn from_db_rule_rejects_invalid_regex() {
        // M-8: an invalid regex is a load-time error (rule skipped + warned),
        // not a silent fail-open.
        let row = db_rule(serde_json::json!([
            {"field": "path", "operator": "regex", "value": "([unclosed"}
        ]));
        assert!(from_db_rule(&row).is_err());
    }

    #[test]
    fn from_db_rule_rejects_malformed_conditions() {
        // M-8: malformed conditions JSON must error rather than default to an
        // empty (never-matching) list.
        let row = db_rule(serde_json::json!({"not": "an array"}));
        assert!(from_db_rule(&row).is_err());
    }
}
