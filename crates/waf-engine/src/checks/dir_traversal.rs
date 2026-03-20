use std::sync::LazyLock;

use regex::RegexSet;
use waf_common::{DetectionResult, Phase, RequestCtx};

use super::{Check, url_decode};

static TRAVERSAL_DESCS: &[&str] = &[
    "directory traversal (../)",
    "URL-encoded traversal (%2e%2e)",
    "double URL-encoded traversal (%252e%252e)",
    "Unicode-encoded traversal",
    "Windows backslash traversal (..\\)",
    "null byte injection (%00)",
    "absolute path to sensitive directory",
    "Windows drive-letter path (C:\\)",
];

static TRAVERSAL_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        // Classic ../
        r"(\.\./|\.\.\\)",
        // URL single-encoded: %2e%2e or %2E%2E (with / or %2f after)
        r"(?i)%2e%2e(%2f|%5c|/|\\)",
        // Double URL-encoded: %252e%252e
        r"(?i)%252e%252e",
        // Unicode / overlong encoding
        r"(?i)\.\.((%c0%af)|(%c1%9c)|(%e0%80%af)|(%c0%9v))",
        // Windows backslash traversal
        r"\.\.\\",
        // Null byte
        r"%00",
        // Absolute path to known sensitive Unix directories
        r"(?i)/(etc|proc|var/log|usr/local|root|home|tmp|dev|sys)(/|$)",
        // Windows drive-letter path
        r"(?i)[A-Za-z]:\\",
    ])
    .expect("Directory traversal regex set compilation failed")
});

/// Directory traversal / path injection detection checker.
pub struct DirTraversalCheck;

impl DirTraversalCheck {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DirTraversalCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for DirTraversalCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        if !ctx.host_config.defense_config.dir_traversal {
            return None;
        }

        // Check both the raw path/query and their decoded forms.
        let candidates = [
            ("path", ctx.path.clone()),
            ("path(decoded)", url_decode(&ctx.path)),
            ("query", ctx.query.clone()),
            ("query(decoded)", url_decode(&ctx.query)),
        ];

        for (location, value) in &candidates {
            if value.is_empty() {
                continue;
            }
            let matches = TRAVERSAL_SET.matches(value);
            if matches.matched_any() {
                let idx = matches.iter().next().unwrap_or(0);
                let desc = TRAVERSAL_DESCS
                    .get(idx)
                    .copied()
                    .unwrap_or("path traversal");
                return Some(DetectionResult {
                    rule_id: Some(format!("TRAV-{:03}", idx + 1)),
                    rule_name: "Directory Traversal".to_string(),
                    phase: Phase::DirTraversal,
                    detail: format!("{} detected in {}", desc, location),
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

    fn make_ctx(path: &str, query: &str) -> RequestCtx {
        RequestCtx {
            req_id: "test".to_string(),
            client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
            client_port: 0,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: path.to_string(),
            query: query.to_string(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config: Arc::new(HostConfig {
                defense_config: DefenseConfig {
                    dir_traversal: true,
                    ..DefenseConfig::default()
                },
                ..HostConfig::default()
            }),
            geo: None,
        }
    }

    #[test]
    fn detects_dot_dot_slash() {
        let checker = DirTraversalCheck::new();
        let ctx = make_ctx("/images/../../../etc/passwd", "");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detects_encoded_traversal() {
        let checker = DirTraversalCheck::new();
        let ctx = make_ctx("/", "file=%2e%2e%2fetc%2fpasswd");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detects_double_encoded() {
        let checker = DirTraversalCheck::new();
        let ctx = make_ctx("/%252e%252e/etc/passwd", "");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn allows_clean_path() {
        let checker = DirTraversalCheck::new();
        let ctx = make_ctx("/api/v1/users", "page=2");
        assert!(checker.check(&ctx).is_none());
    }
}
