//! Built-in scanner / vulnerability tool detection rules.

use super::super::registry::Rule;
use std::collections::HashMap;

fn rule(id: &str, name: &str, pattern: &str, severity: &str) -> Rule {
    let mut meta = HashMap::new();
    meta.insert("detection_type".to_string(), "ua_pattern".to_string());
    Rule {
        id: id.to_string(),
        name: name.to_string(),
        description: Some(format!("Scanner/tool detection: {name}")),
        category: "scanner".to_string(),
        source: "builtin-scanner".to_string(),
        enabled: true,
        action: "block".to_string(),
        severity: Some(severity.to_string()),
        pattern: Some(pattern.to_string()),
        tags: vec!["scanner".to_string(), "builtin".to_string()],
        metadata: meta,
    }
}

/// Return the built-in scanner detection rules.
pub fn rules() -> Vec<Rule> {
    vec![
        // Security scanners
        rule("SCAN-001", "Nikto web scanner", r"(?i)\bnikto\b", "high"),
        rule("SCAN-002", "Nmap web scanner", r"(?i)\bnmap\b", "high"),
        rule(
            "SCAN-003",
            "sqlmap SQL injection tool",
            r"(?i)\bsqlmap\b",
            "critical",
        ),
        rule(
            "SCAN-004",
            "Acunetix Web Vulnerability Scanner",
            r"(?i)(acunetix|acubw)",
            "high",
        ),
        rule(
            "SCAN-005",
            "Nessus vulnerability scanner",
            r"(?i)\bnessus\b",
            "high",
        ),
        rule(
            "SCAN-006",
            "OpenVAS vulnerability scanner",
            r"(?i)\bopenvas\b",
            "high",
        ),
        rule(
            "SCAN-007",
            "Burp Suite proxy/scanner",
            r"(?i)\bburpsuite\b|\bburp[- ]suite\b",
            "high",
        ),
        rule(
            "SCAN-008",
            "OWASP ZAP scanner",
            r"(?i)\bzap\b.*\bhttp\b|\bowasp.*scanner\b",
            "high",
        ),
        rule(
            "SCAN-009",
            "w3af web application scanner",
            r"(?i)\bw3af\b",
            "high",
        ),
        rule(
            "SCAN-010",
            "Skipfish web scanner",
            r"(?i)\bskipfish\b",
            "high",
        ),
        rule("SCAN-011", "Wfuzz fuzzing tool", r"(?i)\bwfuzz\b", "high"),
        rule(
            "SCAN-012",
            "DirBuster directory bruteforce",
            r"(?i)\bdirbuster\b",
            "high",
        ),
        rule(
            "SCAN-013",
            "Gobuster directory bruteforce",
            r"(?i)\bgobuster\b",
            "high",
        ),
        rule(
            "SCAN-014",
            "Hydra password bruteforce",
            r"(?i)\bhydra\b",
            "critical",
        ),
        rule(
            "SCAN-015",
            "Metasploit Framework",
            r"(?i)(metasploit|msf)",
            "critical",
        ),
        // Network recon tools
        rule("SCAN-016", "Shodan scanner", r"(?i)\bshodan\b", "medium"),
        rule("SCAN-017", "Censys scanner", r"(?i)\bcensys\b", "medium"),
        rule(
            "SCAN-018",
            "zgrab2 banner grabber",
            r"(?i)\bzgrab\b",
            "high",
        ),
        rule("SCAN-019", "Masscan", r"(?i)\bmasscan\b", "high"),
        // Fuzzing path patterns (not UA-based; applied to path)
        rule(
            "SCAN-100",
            "Common vulnerability probe paths",
            r"(?i)(/\.git/|/\.env$|/wp-login\.php|/phpmyadmin|/admin\.php|/shell\.php|/cmd\.php|/eval\.php)",
            "high",
        ),
        rule(
            "SCAN-101",
            "Common backup file probe",
            r"(?i)\.(bak|backup|old|orig|save|swp|~)$",
            "medium",
        ),
        rule(
            "SCAN-102",
            "PHP info disclosure probe",
            r"(?i)(phpinfo\s*\(\s*\)|php\.ini|php-fpm\.conf)",
            "high",
        ),
    ]
}
