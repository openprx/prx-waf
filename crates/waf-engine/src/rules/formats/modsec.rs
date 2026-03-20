//! ModSecurity SecRule parser — basic subset.
//!
//! Supported directives: `SecRule`
//! Supported variables: ARGS, REQUEST_HEADERS, REQUEST_URI, REQUEST_BODY, REQUEST_METHOD
//! Supported operators: @rx (regex), @contains, @beginsWith, @endsWith, @ipMatch
//! Supported actions: deny, pass, log, block, redirect, allow
//! Continuation lines via `\` are supported.

use std::collections::HashMap;

use anyhow::{Result, bail};
use regex::Regex;

use super::super::registry::Rule;

/// Parse a ModSecurity rule file into the internal `Rule` format.
pub fn parse(content: &str) -> Result<Vec<Rule>> {
    // Join continuation lines
    let joined = join_lines(content);
    let mut rules = Vec::new();

    for (line_no, line) in joined.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.to_uppercase().starts_with("SECRULE ") {
            match parse_secrule(line, line_no + 1) {
                Ok(rule) => rules.push(rule),
                Err(e) => {
                    tracing::warn!("modsec parse error at line {}: {e}", line_no + 1);
                }
            }
        }
        // Ignore other directives (SecDefaultAction, SecComponentSignature, etc.)
    }

    Ok(rules)
}

/// Join continuation lines (lines ending with `\`).
fn join_lines(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut pending: Option<String> = None;

    for line in content.lines() {
        if let Some(stripped) = line.strip_suffix('\\') {
            let base = pending.take().unwrap_or_default();
            pending = Some(format!("{}{} ", base, stripped.trim_end()));
        } else {
            if let Some(base) = pending.take() {
                out.push_str(&base);
            }
            out.push_str(line);
            out.push('\n');
        }
    }
    if let Some(base) = pending {
        out.push_str(&base);
        out.push('\n');
    }
    out
}

/// Parse a single `SecRule VARIABLES OPERATOR "ACTIONS"` line.
fn parse_secrule(line: &str, line_no: usize) -> Result<Rule> {
    // Strip "SecRule " prefix (case-insensitive)
    let rest = &line["SecRule ".len()..];

    // Split into: VARIABLES  OPERATOR  "ACTIONS"
    // Variables: everything up to first whitespace
    // Operator: next token (could be @rx, @contains, etc.) wrapped in quotes or bare
    // Actions: last quoted string

    let parts = split_secrule_parts(rest)?;
    if parts.len() < 3 {
        bail!(
            "line {line_no}: expected VARIABLES OPERATOR ACTIONS, got {}",
            line
        );
    }

    let variables = &parts[0];
    let operator_str = &parts[1];
    let actions_str = &parts[2];

    // Parse operator and value
    let (op_name, op_value) = parse_operator(operator_str);

    // Parse actions into a map
    let actions = parse_actions(actions_str);

    let id = actions
        .get("id")
        .map(|s| format!("MODSEC-{}", s))
        .unwrap_or_else(|| format!("MODSEC-LINE-{}", line_no));

    let name = actions
        .get("msg")
        .cloned()
        .unwrap_or_else(|| format!("ModSecurity rule {}", id));

    let action = if actions.contains_key("deny") || actions.contains_key("block") {
        "block"
    } else if actions.contains_key("allow") || actions.contains_key("pass") {
        "allow"
    } else {
        "log"
    }
    .to_string();

    let category = infer_category(variables, &op_value);

    let mut metadata = HashMap::new();
    metadata.insert("variables".to_string(), variables.clone());
    metadata.insert("operator".to_string(), op_name.to_string());
    if let Some(phase) = actions.get("phase") {
        metadata.insert("phase".to_string(), phase.clone());
    }
    if let Some(status) = actions.get("status") {
        metadata.insert("status".to_string(), status.clone());
    }

    Ok(Rule {
        id,
        name,
        description: actions.get("msg").cloned(),
        category,
        source: "modsec".to_string(),
        enabled: true,
        action,
        severity: actions.get("severity").cloned(),
        pattern: Some(op_value),
        tags: vec!["modsec".to_string()],
        metadata,
    })
}

/// Split "VARIABLES OPERATOR ACTIONS_STRING" respecting quotes.
fn split_secrule_parts(s: &str) -> Result<Vec<String>> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let chars = s.chars().peekable();

    for c in chars {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                if !in_quotes && !current.is_empty() {
                    parts.push(current.clone());
                    current.clear();
                }
            }
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    parts.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    Ok(parts)
}

/// Parse an operator string like `@rx pattern` or `"@contains foo"`.
fn parse_operator(op: &str) -> (&'static str, String) {
    let op = op.trim_matches('"');
    if let Some(rest) = op.strip_prefix("@rx ") {
        return ("regex", rest.to_string());
    }
    if let Some(rest) = op.strip_prefix("@contains ") {
        return ("contains", rest.to_string());
    }
    if let Some(rest) = op.strip_prefix("@beginsWith ") {
        return ("beginsWith", rest.to_string());
    }
    if let Some(rest) = op.strip_prefix("@endsWith ") {
        return ("endsWith", rest.to_string());
    }
    if let Some(rest) = op.strip_prefix("@ipMatch ") {
        return ("ipMatch", rest.to_string());
    }
    // bare regex without @rx
    ("regex", op.to_string())
}

/// Parse comma-separated actions like `id:1001,phase:1,deny,status:403,msg:'XSS'`.
fn parse_actions(actions: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for part in actions.split(',') {
        let part = part.trim().trim_matches('"').trim_matches('\'');
        if let Some((k, v)) = part.split_once(':') {
            map.insert(
                k.trim().to_lowercase(),
                v.trim().trim_matches('\'').to_string(),
            );
        } else if !part.is_empty() {
            map.insert(part.to_lowercase(), String::new());
        }
    }
    map
}

/// Infer a rule category from variable names and operator value.
fn infer_category(variables: &str, value: &str) -> String {
    let v = variables.to_lowercase();
    let val = value.to_lowercase();

    if val.contains("union") && val.contains("select") {
        return "sqli".to_string();
    }
    if val.contains("<script") || val.contains("javascript:") {
        return "xss".to_string();
    }
    if val.contains("../") || val.contains("..\\") {
        return "traversal".to_string();
    }
    if v.contains("request_uri") {
        return "path".to_string();
    }
    if v.contains("args") {
        return "input".to_string();
    }
    "custom".to_string()
}

// Satisfy the unused import from Regex
#[allow(unused_imports)]
use Regex as _Regex;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_secrule() {
        let content = r#"SecRule REQUEST_URI "@rx /admin" "id:1001,phase:1,deny,status:403,msg:'Admin blocked'"
"#;
        let rules = parse(content).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "MODSEC-1001");
        assert_eq!(rules[0].action, "block");
    }

    #[test]
    fn parse_continuation_line() {
        let content =
            "SecRule ARGS \"@contains <script>\" \\\n    \"id:1002,phase:2,deny,msg:'XSS'\"\n";
        let rules = parse(content).unwrap();
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn skip_comments() {
        let content = "# This is a comment\nSecRule REQUEST_URI \"@rx /test\" \"id:1003,deny\"\n";
        let rules = parse(content).unwrap();
        assert_eq!(rules.len(), 1);
    }
}
