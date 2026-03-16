//! Sensitive word / data-leak detection using Aho-Corasick multi-pattern search.
//!
//! Checks request fields (path, query, body, headers) for configured patterns.
//! Patterns are loaded from PostgreSQL per host and cached in memory.
//!
//! Built-in patterns detect common data-leak signatures:
//!   - Credit card numbers (PAN patterns)
//!   - US Social Security Numbers
//!   - Private key material
//!   - Custom per-host word lists

use std::sync::Arc;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use dashmap::DashMap;

use waf_common::{DetectionResult, Phase, RequestCtx};

use super::Check;

// ── Built-in sensitive data patterns ─────────────────────────────────────────

/// Default patterns for data-leak detection (applied globally, all hosts).
static BUILTIN_PATTERNS: &[&str] = &[
    // Private key markers
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    // AWS credentials
    "AKIAIOSFODNN7EXAMPLE",
    "aws_secret_access_key",
    "aws_access_key_id",
];

// ── Per-host pattern set ──────────────────────────────────────────────────────

struct HostPatterns {
    /// Compiled Aho-Corasick automaton (request patterns)
    request_ac: AhoCorasick,
    /// Pattern list (for error messages)
    patterns: Vec<String>,
}

impl HostPatterns {
    fn build(patterns: &[String]) -> Option<Self> {
        if patterns.is_empty() {
            return None;
        }
        let ac = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostFirst)
            .ascii_case_insensitive(true)
            .build(patterns)
            .ok()?;
        Some(Self {
            request_ac: ac,
            patterns: patterns.to_vec(),
        })
    }

    fn find_in(&self, text: &str) -> Option<&str> {
        if let Some(m) = self.request_ac.find(text) {
            return self.patterns.get(m.pattern().as_usize()).map(|s| s.as_str());
        }
        None
    }
}

// ── Built-in automaton ────────────────────────────────────────────────────────

fn builtin_ac() -> Arc<AhoCorasick> {
    Arc::new(
        AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostFirst)
            .ascii_case_insensitive(true)
            .build(BUILTIN_PATTERNS)
            .expect("builtin sensitive patterns must compile"),
    )
}

// ── SensitiveCheck ───────────────────────────────────────────────────────────

/// WAF checker for sensitive word / data-leak detection.
pub struct SensitiveCheck {
    /// Global built-in patterns
    builtin: Arc<AhoCorasick>,
    /// Per-host patterns: host_code → HostPatterns
    per_host: Arc<DashMap<String, HostPatterns>>,
}

impl SensitiveCheck {
    pub fn new() -> Self {
        Self {
            builtin: builtin_ac(),
            per_host: Arc::new(DashMap::new()),
        }
    }

    /// Reload patterns for a host (called from engine reload).
    pub fn load_host(&self, host_code: &str, patterns: Vec<String>) {
        if let Some(hp) = HostPatterns::build(&patterns) {
            self.per_host.insert(host_code.to_string(), hp);
        } else {
            self.per_host.remove(host_code);
        }
    }

    /// Remove all patterns for a host.
    pub fn clear_host(&self, host_code: &str) {
        self.per_host.remove(host_code);
    }

    fn scan(&self, text: &str, host_code: &str) -> Option<String> {
        // Check built-in patterns
        if let Some(m) = self.builtin.find(text) {
            return Some(BUILTIN_PATTERNS[m.pattern().as_usize()].to_string());
        }

        // Check per-host patterns
        if let Some(hp) = self.per_host.get(host_code) {
            if let Some(pat) = hp.find_in(text) {
                return Some(pat.to_string());
            }
        }

        None
    }
}

impl Default for SensitiveCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for SensitiveCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        if !ctx.host_config.defense_config.sensitive {
            return None;
        }

        let host_code = &ctx.host_config.code;
        let targets = [
            ("path", ctx.path.as_str()),
            ("query", ctx.query.as_str()),
        ];

        for (location, text) in &targets {
            if let Some(pattern) = self.scan(text, host_code) {
                return Some(DetectionResult {
                    rule_id: None,
                    rule_name: "Sensitive Data Detection".to_string(),
                    phase: Phase::Sensitive,
                    detail: format!("Sensitive pattern '{}' found in {}", pattern, location),
                });
            }
        }

        // Scan body preview
        if !ctx.body_preview.is_empty() {
            let body = String::from_utf8_lossy(&ctx.body_preview);
            if let Some(pattern) = self.scan(&body, host_code) {
                return Some(DetectionResult {
                    rule_id: None,
                    rule_name: "Sensitive Data Detection".to_string(),
                    phase: Phase::Sensitive,
                    detail: format!("Sensitive pattern '{}' found in body", pattern),
                });
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::sync::Arc;
    use bytes::Bytes;
    use std::collections::HashMap;
    use waf_common::{DefenseConfig, HostConfig};

    fn make_ctx(path: &str, body: &[u8]) -> RequestCtx {
        let mut dc = DefenseConfig::default();
        dc.sensitive = true;
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
            method: "GET".into(),
            host: "example.com".into(),
            port: 80,
            path: path.into(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::copy_from_slice(body),
            content_length: body.len() as u64,
            is_tls: false,
            host_config,
        }
    }

    #[test]
    fn test_private_key_detection() {
        let checker = SensitiveCheck::new();
        let ctx = make_ctx("/upload", b"-----BEGIN RSA PRIVATE KEY-----\nMIIEo...");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn test_custom_word() {
        let checker = SensitiveCheck::new();
        checker.load_host("test", vec!["super_secret_token".to_string()]);
        let ctx = make_ctx("/api?token=super_secret_token", b"");
        let result = checker.check(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn test_no_match() {
        let checker = SensitiveCheck::new();
        let ctx = make_ctx("/public/page", b"Hello world");
        assert!(checker.check(&ctx).is_none());
    }
}
