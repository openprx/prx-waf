//! GeoIP-based access control check.
//!
//! Evaluates country/region rules against the geo information that was
//! already populated by `GeoIpService` before the checker pipeline runs.
//!
//! Rules support two modes:
//! - **blocklist** – block requests from specific countries / ISO codes
//! - **allowlist** – only allow requests from specific countries / ISO codes
//!   (all others are blocked)
//!
//! Rules are loaded per-host via [`GeoCheck::load_rules`].

use std::collections::HashSet;
use std::sync::Arc;

use dashmap::DashMap;
use waf_common::{DetectionResult, Phase, RequestCtx};

use super::Check;

/// A single geo-based rule.
#[derive(Debug, Clone)]
pub struct GeoRule {
    pub id: String,
    pub name: String,
    pub mode: GeoRuleMode,
    /// ISO country codes to match (uppercase, e.g. "CN", "US").
    pub iso_codes: HashSet<String>,
    /// Country names to match (case-insensitive).
    pub countries: HashSet<String>,
}

/// Whether the rule blocks the listed countries or allows only them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeoRuleMode {
    /// Block requests from these countries.
    Block,
    /// Allow requests only from these countries; block everything else.
    AllowOnly,
}

/// Host-level geo rule set.
#[derive(Debug, Default)]
struct HostGeoRules {
    rules: Vec<GeoRule>,
}

/// GeoIP-based access control check.
///
/// Thread-safe: rules are stored in a `DashMap` keyed by host code.
pub struct GeoCheck {
    /// Rules per host code. Key `"*"` holds global rules.
    rules: Arc<DashMap<String, HostGeoRules>>,
}

impl GeoCheck {
    pub fn new() -> Self {
        Self {
            rules: Arc::new(DashMap::new()),
        }
    }

    /// Replace all geo rules for the given host (or `"*"` for global rules).
    pub fn load_rules(&self, host_code: &str, rules: Vec<GeoRule>) {
        self.rules.insert(host_code.to_string(), HostGeoRules { rules });
    }

    /// Remove all rules for a host.
    pub fn clear_rules(&self, host_code: &str) {
        self.rules.remove(host_code);
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn eval_rules(&self, host_code: &str, geo: &waf_common::GeoIpInfo) -> Option<DetectionResult> {
        // Host-specific rules first
        if let Some(entry) = self.rules.get(host_code)
            && let Some(r) = Self::match_rules(geo, &entry.rules)
        {
            return Some(r);
        }
        // Global rules
        if let Some(entry) = self.rules.get("*")
            && let Some(r) = Self::match_rules(geo, &entry.rules)
        {
            return Some(r);
        }
        None
    }

    fn match_rules(geo: &waf_common::GeoIpInfo, rules: &[GeoRule]) -> Option<DetectionResult> {
        for rule in rules {
            let matched = Self::geo_matches(geo, rule);
            match rule.mode {
                GeoRuleMode::Block => {
                    if matched {
                        return Some(DetectionResult {
                            rule_id: Some(rule.id.clone()),
                            rule_name: rule.name.clone(),
                            phase: Phase::GeoIp,
                            detail: format!(
                                "Blocked by geo rule '{}': country='{}' iso='{}'",
                                rule.name, geo.country, geo.iso_code
                            ),
                        });
                    }
                }
                GeoRuleMode::AllowOnly => {
                    if !matched && (!geo.country.is_empty() || !geo.iso_code.is_empty()) {
                        return Some(DetectionResult {
                            rule_id: Some(rule.id.clone()),
                            rule_name: rule.name.clone(),
                            phase: Phase::GeoIp,
                            detail: format!(
                                "Blocked by geo allowlist '{}': country='{}' iso='{}' not in allowed list",
                                rule.name, geo.country, geo.iso_code
                            ),
                        });
                    }
                }
            }
        }
        None
    }

    /// Returns `true` if the geo info matches any of the rule's criteria.
    fn geo_matches(geo: &waf_common::GeoIpInfo, rule: &GeoRule) -> bool {
        // Match ISO code (uppercase compare)
        if !geo.iso_code.is_empty() && rule.iso_codes.contains(&geo.iso_code.to_uppercase()) {
            return true;
        }
        // Match country name (case-insensitive)
        if !geo.country.is_empty() && rule.countries.iter().any(|c| c.eq_ignore_ascii_case(&geo.country)) {
            return true;
        }
        false
    }
}

impl Default for GeoCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for GeoCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        // If geo info was not populated (GeoIP disabled or xdb missing) skip.
        let Some(geo) = &ctx.geo else {
            return None;
        };
        // No useful info yet (e.g. private IP not in xdb)
        if geo.country.is_empty() && geo.iso_code.is_empty() {
            return None;
        }
        self.eval_rules(&ctx.host_config.code, geo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Arc;
    use waf_common::{GeoIpInfo, HostConfig, RequestCtx};

    fn make_ctx(iso: &str, country: &str) -> RequestCtx {
        let host_config = Arc::new(HostConfig {
            code: "test".into(),
            host: "example.com".into(),
            ..HostConfig::default()
        });
        RequestCtx {
            req_id: "test".into(),
            client_ip: "1.2.3.4".parse::<IpAddr>().unwrap(),
            client_port: 12345,
            method: "GET".into(),
            host: "example.com".into(),
            port: 80,
            path: "/".into(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config,
            geo: Some(GeoIpInfo {
                country: country.to_string(),
                iso_code: iso.to_string(),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn block_by_iso() {
        let check = GeoCheck::new();
        check.load_rules(
            "*",
            vec![GeoRule {
                id: "GEO-001".into(),
                name: "Block KP".into(),
                mode: GeoRuleMode::Block,
                iso_codes: ["KP".to_string()].into(),
                countries: HashSet::new(),
            }],
        );

        let ctx = make_ctx("KP", "North Korea");
        assert!(check.check(&ctx).is_some());

        let ctx2 = make_ctx("US", "United States");
        assert!(check.check(&ctx2).is_none());
    }

    #[test]
    fn no_geo_info_passes() {
        let check = GeoCheck::new();
        check.load_rules(
            "*",
            vec![GeoRule {
                id: "GEO-002".into(),
                name: "Block All".into(),
                mode: GeoRuleMode::Block,
                iso_codes: ["XX".to_string()].into(),
                countries: HashSet::new(),
            }],
        );
        let host_config = Arc::new(HostConfig::default());
        let ctx = RequestCtx {
            req_id: "t".into(),
            client_ip: "127.0.0.1".parse().unwrap(),
            client_port: 80,
            method: "GET".into(),
            host: "localhost".into(),
            port: 80,
            path: "/".into(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config,
            geo: None,
        };
        assert!(check.check(&ctx).is_none());
    }
}
