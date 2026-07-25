use std::sync::LazyLock;

use regex::RegexSet;
use waf_common::{DetectionResult, Phase, RequestCtx};

use super::{Check, request_targets};

/// Pattern descriptions aligned by index with `SQLI_SET` patterns.
static SQLI_DESCS: &[&str] = &[
    "UNION SELECT injection",
    "comment-based injection (-- / #)",
    "stacked query injection (;DROP/DELETE/...)",
    "time-based blind injection (SLEEP/BENCHMARK/WAITFOR)",
    "xp_cmdshell execution",
    "INFORMATION_SCHEMA enumeration",
    "OR/AND always-true tautology",
    "LOAD_FILE() read",
    "INTO OUTFILE/DUMPFILE write",
    "hex-encoded string injection (0x...)",
    "quoted string escape (')",
    "MySQL/MSSQL system table enumeration",
];

/// Fail-closed compile result (Low-1): `Some(set)` on success, `None` if the
/// literal pattern set failed to compile. All patterns above are compile-time
/// string literals, so `None` should never happen in practice — but if it
/// ever did, silently falling back to `RegexSet::empty()` would make this
/// checker match nothing and fail *open* (block none, allow everything). The
/// constructor for this checker is infallible (`Check::new() -> Self`, wired
/// into `engine.rs` as `Box<dyn Check>`), so a compile failure cannot be
/// propagated as a startup error without threading `Result` through the
/// engine's checker construction — out of scope here. Instead `check()`
/// below treats a `None` set as an unconditional match, i.e. fail-closed
/// (block/alert on every request) rather than fail-open.
static SQLI_SET: LazyLock<Option<RegexSet>> = LazyLock::new(|| {
    match RegexSet::new([
        // UNION … SELECT
        r"(?i)\bunion\b[\s/\*]+select\b",
        // ── SQLI-002 — comment-based injection ───────────────────────────────
        //
        // The original `(--|#|/*…*/)\s*?(select|union|drop|…)` blocked every
        // markdown heading that happens to start with a DML verb — `# Update
        // the billing schema`, `## Delete stale rows` — i.e. a 403 on any
        // docs / issue / comment API. That branch also had close to zero
        // detection value: text *after* a `--` or `#` comment marker is inert,
        // so `-- select` is not an injection at all. What is worth matching is
        // the comment used as a *query terminator* right behind an injected
        // quote (`admin'--`, `admin'#`), and inline `/*…*/` comments used to
        // split a keyword (`/*!50000union*/select`). The `'#` form additionally
        // requires the value to end there, because `'#…'` is also how every
        // jQuery/CSS id selector is written (`$('#app')`).
        concat!(
            r"(?i)(?:'\s{0,4}--",
            r#"|'\s{0,4}#[ \t]{0,4}(?:$|[&"'\]}])"#,
            r"|/\*[\s\S]{0,64}?\*/\s*(?:select|union|drop|insert|update|delete|exec|xp_)",
            r"|(?:select|union|drop|insert|update|delete)\s*/\*[\s\S]{0,64}?\*/)",
        ),
        // ── SQLI-003 — stacked query ─────────────────────────────────────────
        // The quoted form (`'; DROP …`) plus the unquoted structural forms: a
        // numeric injection point (`?id=1; DROP TABLE users--`) never carries a
        // quote and was previously missed entirely. Each unquoted alternative
        // requires the full statement shape (`DROP TABLE`, `DELETE FROM`,
        // `INSERT INTO`, `UPDATE … SET`), so ordinary prose with a semicolon
        // ("update shipped; delete request pending") does not match.
        concat!(
            r"(?i)(?:'[\s]*;[\s]*(?:drop|delete|insert|update|exec|select|truncate)\b",
            r"|;\s*(?:drop|truncate)\s+(?:table|database)\b",
            r"|;\s*delete\s+from\b",
            r"|;\s*insert\s+into\b",
            r"|;\s*update\s+\w{1,64}\s+set\b",
            r"|;\s*exec(?:ute)?\s)",
        ),
        // Time-based blind
        r"(?i)\b(sleep|benchmark|waitfor[\s]+delay|pg_sleep)\s*\(",
        // xp_cmdshell
        r"(?i)\bxp_cmdshell\b",
        // INFORMATION_SCHEMA / sys.tables / sysobjects. `information_schema`
        // requires the structural `.<identifier>` form so a bare field named
        // `information_schema` (e.g. `?column=information_schema`) no longer
        // fires, while ANY catalog view/table selected off it (`.triggers`,
        // `.views`, `.statistics`, `.key_column_usage`, … not just the original
        // five) is caught — mirrors the narrowed content-security detector.
        r"(?i)\b(information_schema\s*\.\s*\w+|sys\.(tables|columns|databases)|sysobjects|sysusers)\b",
        // OR/AND tautologies
        r"(?i)\b(or|and)\b[\s]+'[^']*'[\s]*=[\s]*'[^']*'",
        // LOAD_FILE()
        r"(?i)\bload_file\s*\(",
        // INTO OUTFILE / DUMPFILE
        r"(?i)\binto[\s]+(outfile|dumpfile)\b",
        // Hex literals 0x41… in an SQL syntactic position (right of an operator
        // / delimiter). A bare long hex run in free text (colour codes, hashes)
        // no longer fires — only hex used as an SQL operand does.
        r"(?i)[=(,<>]\s*0x[0-9a-f]{4,}\b",
        // ── SQLI-011 — quote followed by an SQL keyword ──────────────────────
        // `'\s*(or|and|union|…)` fires on any language that writes an elided
        // article: `l'union fait la force`, `l'and…`, `d'insert…`. The keyword
        // alone is not the signal — the *statement shape* behind it is, so each
        // alternative now demands the syntax that actually makes it SQL.
        concat!(
            r"(?i)(?:'\s*(?:or|and)\s+[^']{0,32}[=<>]",
            r"|'\s*union\s+(?:all\s+)?select\b",
            r"|'\s*(?:drop|truncate)\s+(?:table|database)\b",
            r"|'\s*insert\s+into\b",
            r"|'\s*update\s+\w{1,64}\s+set\b",
            r"|'\s*delete\s+from\b",
            r"|'\s*exec(?:ute)?\b",
            r"|'\s*select\s+[\w*])",
        ),
        // MySQL/MSSQL catalog tables
        r"(?i)\b(mysql\.(user|db)|master\.\.(sysdatabases|sysobjects))\b",
    ]) {
        Ok(set) => Some(set),
        Err(e) => {
            tracing::error!(
                "BUG: SQL injection regex set failed to compile: {e} — failing closed \
                 (this checker will now flag every request until the code is fixed)"
            );
            None
        }
    }
});

/// SQL injection detection checker.
pub struct SqlInjectionCheck;

impl SqlInjectionCheck {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for SqlInjectionCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for SqlInjectionCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        if !ctx.host_config.defense_config.sqli {
            return None;
        }

        let Some(set) = SQLI_SET.as_ref() else {
            // Fail-closed: the pattern set failed to compile at startup.
            return Some(DetectionResult {
                rule_id: Some("SQLI-000".to_string()),
                rule_name: "SQL Injection".to_string(),
                phase: Phase::SqlInjection,
                detail: "fail-closed: SQL injection pattern set failed to compile at startup".to_string(),
            });
        };

        for (location, value) in request_targets(ctx) {
            let matches = set.matches(&value);
            if matches.matched_any() {
                let idx = matches.iter().next().unwrap_or(0);
                let desc = SQLI_DESCS.get(idx).copied().unwrap_or("SQL Injection pattern");
                return Some(DetectionResult {
                    rule_id: Some(format!("SQLI-{:03}", idx + 1)),
                    rule_name: "SQL Injection".to_string(),
                    phase: Phase::SqlInjection,
                    detail: format!("{desc} detected in {location}"),
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Arc;
    use waf_common::{DefenseConfig, HostConfig};

    fn make_ctx(query: &str, body: &str) -> RequestCtx {
        RequestCtx {
            req_id: "test".to_string(),
            client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
            client_port: 12345,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: "/".to_string(),
            query: query.to_string(),
            headers: HashMap::new(),
            body_preview: Bytes::from(body.to_string()),
            content_length: body.len() as u64,
            is_tls: false,
            host_config: Arc::new(HostConfig {
                defense_config: DefenseConfig {
                    sqli: true,
                    ..DefenseConfig::default()
                },
                ..HostConfig::default()
            }),
            geo: None,
        }
    }

    #[test]
    fn detects_union_select() {
        let checker = SqlInjectionCheck::new();
        let ctx = make_ctx("id=1 UNION SELECT 1,2,3--", "");
        assert!(checker.check(&ctx).is_some(), "Should detect UNION SELECT");
    }

    #[test]
    fn detects_sleep() {
        let checker = SqlInjectionCheck::new();
        let ctx = make_ctx("id=1 AND SLEEP(5)--", "");
        assert!(checker.check(&ctx).is_some(), "Should detect SLEEP()");
    }

    #[test]
    fn detects_tautology() {
        let checker = SqlInjectionCheck::new();
        // Both sides properly quoted: ' OR '1'='1' (trailing quote required by pattern)
        let ctx = make_ctx("", "username=admin' OR '1'='1' --");
        assert!(checker.check(&ctx).is_some(), "Should detect OR tautology");
    }

    #[test]
    fn allows_clean_request() {
        let checker = SqlInjectionCheck::new();
        let ctx = make_ctx("name=alice&page=2", "");
        assert!(checker.check(&ctx).is_none(), "Should allow clean request");
    }

    #[test]
    fn information_schema_bare_field_name_is_allowed() {
        // A plain field named `information_schema` (no `.tables`/`.columns`) must
        // not fire after the structural-context narrowing.
        let checker = SqlInjectionCheck::new();
        let ctx = make_ctx("column=information_schema&sort=asc", "");
        assert!(
            checker.check(&ctx).is_none(),
            "bare information_schema field must not fire"
        );
    }

    #[test]
    fn information_schema_structural_still_detected() {
        let checker = SqlInjectionCheck::new();
        let ctx = make_ctx("id=1 UNION SELECT table_name FROM information_schema.tables", "");
        assert!(
            checker.check(&ctx).is_some(),
            "information_schema.tables enumeration must still fire"
        );
    }

    #[test]
    fn information_schema_non_listed_views_now_detected() {
        // F-B: the original narrowing only accepted five catalog tables
        // (tables/columns/schemata/routines/databases), silently missing every
        // other injectable catalog view. `information_schema\.\w+` now catches
        // the blind-injection favourites `.triggers`, `.views`, `.statistics`,
        // `.key_column_usage` with no `union`/comment needed.
        let checker = SqlInjectionCheck::new();
        for view in ["triggers", "views", "statistics", "key_column_usage"] {
            let payload = format!("id=1 and (select count(*) from information_schema.{view})>0");
            let ctx = make_ctx(&payload, "");
            assert!(
                checker.check(&ctx).is_some(),
                "information_schema.{view} enumeration must fire"
            );
        }
    }

    #[test]
    fn bare_long_hex_in_free_text_is_allowed() {
        // A long hex run that is not operator-adjacent (e.g. a commit hash / hash
        // fragment sitting in free text) must not trip the hex-literal rule; the
        // original bare `0x[0-9a-f]{4,}` matched it anywhere.
        let checker = SqlInjectionCheck::new();
        let ctx = make_ctx("note=commit 0xdeadbeefcafe1234 reverted", "");
        assert!(checker.check(&ctx).is_none(), "free-text hex must not fire");
    }

    #[test]
    fn hex_literal_as_sql_operand_still_detected() {
        // Hex directly adjacent to an SQL operator / delimiter (function arg here)
        // is a genuine operand and must still fire.
        let checker = SqlInjectionCheck::new();
        let ctx = make_ctx("q=cast(0x41414141 as char)", "");
        assert!(
            checker.check(&ctx).is_some(),
            "hex literal used as an SQL operand must still fire"
        );
    }

    /// Markdown headings, elided articles and jQuery selectors are ordinary
    /// content, not SQL.
    #[test]
    fn benign_text_with_sql_shaped_tokens_is_allowed() {
        let checker = SqlInjectionCheck::new();
        for body in [
            "# Update the billing schema\n\n## Delete stale rows before insert\n",
            r##"{"md":"# Update\n## Delete rows"}"##,
            r#"{"fr":"l'union fait la force"}"#,
            r#"{"note":"user's order and admin's report"}"#,
            r#"{"jq":"$(document).ready(function(){ $('#a').val(1); });"}"#,
            r#"{"desc":"Order #1234 update shipped; delete request pending"}"#,
            r#"{"body":"Please run the migration; then verify the report"}"#,
            r#"{"query":"SELECT name FROM users WHERE id = $1"}"#,
        ] {
            let ctx = make_ctx("", body);
            assert!(checker.check(&ctx).is_none(), "benign text must not fire: {body}");
        }
    }

    /// The injection shapes those narrowings must keep — plus the unquoted
    /// stacked query that Lane1 used to miss entirely.
    #[test]
    fn narrowed_rules_still_detect_injection() {
        let checker = SqlInjectionCheck::new();
        for (query, body) in [
            // unquoted stacked query — previously undetected
            ("id=1; DROP TABLE users--", ""),
            ("id=1; DELETE FROM users", ""),
            // quoted stacked query
            ("", r#"{"x":"';drop table users--"}"#),
            // comment used as a query terminator
            ("u=admin'--", ""),
            ("", r#"{"u":"admin'#"}"#),
            // inline comment keyword splitting
            ("", r#"{"x":"1/*!50000union*/select 1"}"#),
            // quote + statement shape
            ("", r#"{"x":"' union all select password from users"}"#),
            ("", r#"{"x":"' or 1=1"}"#),
            ("", r#"{"x":"admin';exec xp_cmdshell 'dir'"}"#),
        ] {
            let ctx = make_ctx(query, body);
            assert!(
                checker.check(&ctx).is_some(),
                "sql injection must still fire: {query:?} {body:?}"
            );
        }
    }

    #[test]
    fn skips_when_disabled() {
        let checker = SqlInjectionCheck::new();
        let mut ctx = make_ctx("id=1 UNION SELECT 1,2,3--", "");
        Arc::make_mut(&mut ctx.host_config).defense_config.sqli = false;
        assert!(checker.check(&ctx).is_none(), "Should skip when disabled");
    }
}
