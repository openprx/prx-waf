pub mod engine;

use std::net::IpAddr;
use dashmap::DashMap;
use ipnet::IpNet;
use tracing::debug;

/// In-memory IP rule store with CIDR support
#[derive(Default)]
pub struct IpRuleSet {
    /// Exact IP entries and CIDR ranges per host_code
    /// key: host_code ("*" for global), value: list of IpNet
    entries: DashMap<String, Vec<IpNet>>,
}

impl IpRuleSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load rules from storage entries
    pub fn load(&self, host_code: &str, cidrs: &[String]) {
        let nets: Vec<IpNet> = cidrs
            .iter()
            .filter_map(|s| {
                // Try parsing as CIDR first, then as plain IP
                s.parse::<IpNet>()
                    .or_else(|_| {
                        s.parse::<IpAddr>().map(|ip| IpNet::from(ip))
                    })
                    .ok()
                    .inspect(|_| debug!("Loaded IP rule: {}", s))
                    .or_else(|| {
                        tracing::warn!("Invalid IP/CIDR: {}", s);
                        None
                    })
            })
            .collect();
        self.entries.insert(host_code.to_string(), nets);
    }

    /// Check if an IP matches any rule for a given host_code
    pub fn matches(&self, host_code: &str, ip: IpAddr) -> bool {
        // Check host-specific rules
        if let Some(nets) = self.entries.get(host_code) {
            if nets.iter().any(|net| net.contains(&ip)) {
                return true;
            }
        }
        // Check global rules (host_code = "*")
        if let Some(nets) = self.entries.get("*") {
            if nets.iter().any(|net| net.contains(&ip)) {
                return true;
            }
        }
        false
    }

    /// Insert a single rule
    pub fn insert(&self, host_code: &str, cidr: &str) {
        let net = cidr.parse::<IpNet>()
            .or_else(|_| cidr.parse::<IpAddr>().map(IpNet::from));

        if let Ok(net) = net {
            self.entries
                .entry(host_code.to_string())
                .or_default()
                .push(net);
        } else {
            tracing::warn!("Failed to parse IP/CIDR for insert: {}", cidr);
        }
    }

    /// Remove all rules for a host_code
    pub fn clear_host(&self, host_code: &str) {
        self.entries.remove(host_code);
    }

    /// Total number of rules
    pub fn len(&self) -> usize {
        self.entries.iter().map(|e| e.value().len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// URL match type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlMatchType {
    Exact,
    Prefix,
    Contains,
    Suffix,
}

impl UrlMatchType {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "prefix" => Self::Prefix,
            "contains" => Self::Contains,
            "suffix" => Self::Suffix,
            _ => Self::Exact,
        }
    }
}

/// URL rule entry
#[derive(Debug, Clone)]
pub struct UrlRule {
    pub id: String,
    pub pattern: String,
    pub match_type: UrlMatchType,
}

impl UrlRule {
    pub fn matches(&self, path: &str) -> bool {
        match self.match_type {
            UrlMatchType::Exact => self.pattern == path,
            UrlMatchType::Prefix => path.starts_with(&self.pattern),
            UrlMatchType::Contains => path.contains(&self.pattern),
            UrlMatchType::Suffix => path.ends_with(&self.pattern),
        }
    }
}

/// In-memory URL rule store
#[derive(Default)]
pub struct UrlRuleSet {
    /// key: host_code, value: list of UrlRule
    entries: DashMap<String, Vec<UrlRule>>,
}

impl UrlRuleSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(&self, host_code: &str, rules: Vec<UrlRule>) {
        self.entries.insert(host_code.to_string(), rules);
    }

    pub fn matches(&self, host_code: &str, path: &str) -> Option<String> {
        // Check host-specific rules
        if let Some(rules) = self.entries.get(host_code) {
            if let Some(rule) = rules.iter().find(|r| r.matches(path)) {
                return Some(rule.id.clone());
            }
        }
        // Check global rules
        if let Some(rules) = self.entries.get("*") {
            if let Some(rule) = rules.iter().find(|r| r.matches(path)) {
                return Some(rule.id.clone());
            }
        }
        None
    }

    pub fn insert(&self, host_code: &str, rule: UrlRule) {
        self.entries
            .entry(host_code.to_string())
            .or_default()
            .push(rule);
    }

    pub fn clear_host(&self, host_code: &str) {
        self.entries.remove(host_code);
    }

    pub fn len(&self) -> usize {
        self.entries.iter().map(|e| e.value().len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
