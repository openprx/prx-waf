//! Anti-hotlinking protection.
//!
//! Validates the `Referer` request header against a per-host allow-list.
//! Supports wildcard sub-domain matching (`*.example.com`).

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use waf_common::{DetectionResult, Phase, RequestCtx};

use super::Check;

// ── Per-host configuration ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotlinkConfig {
    pub enabled: bool,
    /// If true, requests with no Referer header are allowed (direct navigation).
    pub allow_empty_referer: bool,
    /// Allowed referer domains. Supports `*.example.com` wildcard prefix.
    pub allowed_domains: Vec<String>,
    /// Optional URL to redirect blocked requests to.
    pub redirect_url: Option<String>,
}

impl Default for HotlinkConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_empty_referer: true,
            allowed_domains: Vec::new(),
            redirect_url: None,
        }
    }
}

impl HotlinkConfig {
    /// Returns `true` if the given referer URL is allowed.
    pub fn is_allowed(&self, referer: &str) -> bool {
        let domain = extract_domain(referer);
        self.allowed_domains.iter().any(|pat| domain_matches(pat, &domain))
    }
}

// ── Domain helpers ────────────────────────────────────────────────────────────

/// Extract the host part from a URL string.
fn extract_domain(url: &str) -> String {
    let s = url.trim();
    // Strip scheme
    let s = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    // Strip path/query/fragment
    let s = s.split('/').next().unwrap_or(s);
    // Strip port
    let s = s.split(':').next().unwrap_or(s);
    s.to_lowercase()
}

/// Match a domain against a pattern (exact or `*.example.com` wildcard).
fn domain_matches(pattern: &str, domain: &str) -> bool {
    let pat = pattern.trim().to_lowercase();
    if pat.starts_with("*.") {
        let suffix = &pat[1..]; // ".example.com"
        domain == &pat[2..] || domain.ends_with(suffix)
    } else {
        domain == pat
    }
}

// ── AntiHotlinkCheck ─────────────────────────────────────────────────────────

/// WAF checker for anti-hotlinking (Referer validation).
pub struct AntiHotlinkCheck {
    /// `host_code` → `HotlinkConfig`
    configs: DashMap<String, HotlinkConfig>,
}

impl AntiHotlinkCheck {
    pub fn new() -> Self {
        Self {
            configs: DashMap::new(),
        }
    }

    /// Load or update a host's hotlink config.
    pub fn set_config(&self, host_code: &str, config: HotlinkConfig) {
        self.configs.insert(host_code.to_string(), config);
    }

    /// Remove a host's config.
    pub fn clear_host(&self, host_code: &str) {
        self.configs.remove(host_code);
    }

    pub fn len(&self) -> usize {
        self.configs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.configs.is_empty()
    }
}

impl Default for AntiHotlinkCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for AntiHotlinkCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        let host_code = &ctx.host_config.code;

        let config = self.configs.get(host_code)?.clone();

        if !config.enabled {
            return None;
        }

        let referer = ctx.headers.get("referer").map_or("", String::as_str);

        // Empty referer handling
        if referer.is_empty() {
            if config.allow_empty_referer {
                return None;
            }
            return Some(DetectionResult {
                rule_id: None,
                rule_name: "Anti-Hotlink".to_string(),
                phase: Phase::AntiHotlink,
                detail: "Request blocked: missing Referer header".to_string(),
            });
        }

        // Check allow-list
        if config.is_allowed(referer) {
            return None;
        }

        Some(DetectionResult {
            rule_id: None,
            rule_name: "Anti-Hotlink".to_string(),
            phase: Phase::AntiHotlink,
            detail: format!("Referer '{referer}' not in allow-list"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::sync::Arc;
    use waf_common::HostConfig;

    fn make_ctx(referer: Option<&str>) -> RequestCtx {
        let host_config = Arc::new(HostConfig {
            code: "test".into(),
            host: "example.com".into(),
            ..HostConfig::default()
        });
        let mut headers = HashMap::new();
        if let Some(r) = referer {
            headers.insert("referer".to_string(), r.to_string());
        }
        RequestCtx {
            req_id: "test".into(),
            client_ip: "1.2.3.4".parse().unwrap(),
            client_port: 0,
            method: "GET".into(),
            host: "example.com".into(),
            port: 80,
            path: "/image.jpg".into(),
            query: String::new(),
            headers,
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config,
            geo: None,
        }
    }

    #[test]
    fn test_allowed_domain() {
        let checker = AntiHotlinkCheck::new();
        checker.set_config(
            "test",
            HotlinkConfig {
                enabled: true,
                allow_empty_referer: true,
                allowed_domains: vec!["example.com".into(), "*.mysite.com".into()],
                redirect_url: None,
            },
        );

        // Exact match
        assert!(checker.check(&make_ctx(Some("https://example.com/page"))).is_none());
        // Wildcard match
        assert!(checker.check(&make_ctx(Some("https://sub.mysite.com/page"))).is_none());
        // Not allowed
        assert!(checker.check(&make_ctx(Some("https://evil.com/page"))).is_some());
        // Empty allowed (allow_empty_referer = true)
        assert!(checker.check(&make_ctx(None)).is_none());
    }

    #[test]
    fn test_block_empty_referer() {
        let checker = AntiHotlinkCheck::new();
        checker.set_config(
            "test",
            HotlinkConfig {
                enabled: true,
                allow_empty_referer: false,
                allowed_domains: vec!["example.com".into()],
                redirect_url: None,
            },
        );

        assert!(checker.check(&make_ctx(None)).is_some());
        assert!(checker.check(&make_ctx(Some("https://example.com/"))).is_none());
    }

    #[test]
    fn test_disabled() {
        let checker = AntiHotlinkCheck::new();
        checker.set_config(
            "test",
            HotlinkConfig {
                enabled: false,
                allow_empty_referer: false,
                allowed_domains: vec![],
                redirect_url: None,
            },
        );

        // Disabled — always passes
        assert!(checker.check(&make_ctx(Some("https://evil.com/"))).is_none());
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(extract_domain("https://example.com/path"), "example.com");
        assert_eq!(extract_domain("http://sub.example.com:8080/"), "sub.example.com");
        assert_eq!(extract_domain("example.com"), "example.com");
    }

    #[test]
    fn test_domain_matches() {
        assert!(domain_matches("example.com", "example.com"));
        assert!(!domain_matches("example.com", "evil.com"));
        assert!(domain_matches("*.example.com", "sub.example.com"));
        assert!(domain_matches("*.example.com", "example.com"));
        assert!(!domain_matches("*.example.com", "example.org"));
    }
}
