//! Built-in OWASP CRS rules (subset compiled into the binary).

use super::super::registry::Rule;
use std::collections::HashMap;

fn rule(id: &str, name: &str, category: &str, pattern: &str, severity: &str) -> Rule {
    Rule {
        id: id.to_string(),
        name: name.to_string(),
        description: Some(format!("OWASP CRS: {name}")),
        category: category.to_string(),
        source: "builtin-owasp".to_string(),
        enabled: true,
        action: "block".to_string(),
        severity: Some(severity.to_string()),
        pattern: Some(pattern.to_string()),
        tags: vec!["owasp".to_string(), "builtin".to_string()],
        metadata: HashMap::new(),
    }
}

/// Return the built-in OWASP CRS rules.
pub fn rules() -> Vec<Rule> {
    vec![
        // SQL Injection
        rule(
            "OWASP-942100",
            "SQL Injection Attack Detected via libinjection",
            "sqli",
            r"(?i)(\bunion\b.{0,100}\bselect\b|\bselect\b.{0,100}\bfrom\b|\binsert\b.{0,100}\binto\b|\bupdate\b.{0,100}\bset\b|\bdelete\b.{0,100}\bfrom\b)",
            "critical",
        ),
        rule(
            "OWASP-942200",
            "Detects MySQL comment-/space-obfuscated injections",
            "sqli",
            r"(?i)(\/\*[^*]*\*\/|--|#)[[:space:]]*[\w\s]*",
            "high",
        ),
        rule(
            "OWASP-942300",
            "Detects MySQL charset switch and MSSQL DoS attempts",
            "sqli",
            r"(?i)(char\s*\(\s*\d+|convert\s*\(|cast\s*\(|exec\s*\(|execute\s*\()",
            "high",
        ),
        rule(
            "OWASP-942400",
            "SQL Hex Encoding",
            "sqli",
            r"(?i)(0x[0-9a-f]{4,}|\\x[0-9a-f]{2})",
            "medium",
        ),
        // XSS
        rule(
            "OWASP-941100",
            "XSS Attack Detected via libinjection",
            "xss",
            r"(?i)(<script[^>]*>|javascript\s*:|on\w+\s*=|<img[^>]+\bon\w+\s*=)",
            "critical",
        ),
        rule(
            "OWASP-941200",
            "XSS Filter Evasion Techniques",
            "xss",
            r"(?i)(&#\d+;|&#x[0-9a-f]+;|\\u[0-9a-f]{4})",
            "high",
        ),
        rule(
            "OWASP-941300",
            "IE XSS Filters - Attack Detected",
            "xss",
            r"(?i)(<[^>]*\bvbscript\s*:|expression\s*\(|url\s*\()",
            "high",
        ),
        // Remote Code Execution
        rule(
            "OWASP-932100",
            "Remote Command Execution: Unix Command Injection",
            "rce",
            r"(?i)(;\s*(ls|cat|id|whoami|uname|pwd|wget|curl|bash|sh|python|perl|ruby|nc|ncat)\b|`[^`]*`|\$\([^)]*\))",
            "critical",
        ),
        rule(
            "OWASP-932110",
            "Remote Command Execution: Windows Command Injection",
            "rce",
            r"(?i)(cmd\.exe|powershell|wscript|cscript|certutil|bitsadmin|regsvr32)",
            "critical",
        ),
        // Path Traversal
        rule(
            "OWASP-930100",
            "Path Traversal Attack",
            "traversal",
            r"(?:\.\.[\\/]){2,}|(?:%2e%2e[\\/]){1,}|(?:\.\.%2f){1,}|(?:\.\.%5c){1,}",
            "high",
        ),
        rule(
            "OWASP-930110",
            "Path Traversal Attack (Windows Specific)",
            "traversal",
            r"(?i)\.\.\\|\.\.\\/|%5c%2e%2e|%2e%2e%5c",
            "high",
        ),
        // Server-Side Request Forgery
        rule(
            "OWASP-934100",
            "SSRF Attempt - IP Address in Parameter",
            "ssrf",
            r"(?i)(https?://(?:127\.0\.0\.1|0\.0\.0\.0|localhost|169\.254\.\d+\.\d+|::1|[fF][cCdD][0-9a-fA-F]{2}::))",
            "high",
        ),
        // Remote File Inclusion
        rule(
            "OWASP-931100",
            "Possible Remote File Inclusion (RFI) Attack",
            "rfi",
            r"(?i)(https?://[^/\s]+/[^?\s]*\.php|file://|phar://|zip://|data://)",
            "high",
        ),
        // Protocol Violations
        rule(
            "OWASP-920100",
            "Invalid HTTP Request Line",
            "protocol",
            r"(?i)^(?:get|post|put|delete|patch|head|options|trace|connect)\s+[^\s]+\s+http/[0-9]\.[0-9]",
            "medium",
        ),
    ]
}
