pub mod builtin;
pub mod engine;
pub mod formats;
pub mod hot_reload;
pub mod manager;
pub mod registry;
pub mod sources;

use dashmap::DashMap;
use ipnet::IpNet;
use std::net::IpAddr;
use tracing::debug;

/// In-memory IP rule store with CIDR support
#[derive(Default)]
pub struct IpRuleSet {
    /// Exact IP entries and CIDR ranges per `host_code`
    /// key: `host_code` ("*" for global), value: list of `IpNet`
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
                    .or_else(|_| s.parse::<IpAddr>().map(IpNet::from))
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

    /// Check if an IP matches any rule for a given `host_code`
    pub fn matches(&self, host_code: &str, ip: IpAddr) -> bool {
        // Check host-specific rules
        if let Some(nets) = self.entries.get(host_code)
            && nets.iter().any(|net| net.contains(&ip))
        {
            return true;
        }
        // Check global rules (host_code = "*")
        if let Some(nets) = self.entries.get("*")
            && nets.iter().any(|net| net.contains(&ip))
        {
            return true;
        }
        false
    }

    /// Insert a single rule
    pub fn insert(&self, host_code: &str, cidr: &str) {
        let net = cidr
            .parse::<IpNet>()
            .or_else(|_| cidr.parse::<IpAddr>().map(IpNet::from));

        if let Ok(net) = net {
            self.entries.entry(host_code.to_string()).or_default().push(net);
        } else {
            tracing::warn!("Failed to parse IP/CIDR for insert: {}", cidr);
        }
    }

    /// Remove all rules for a `host_code`
    pub fn clear_host(&self, host_code: &str) {
        self.entries.remove(host_code);
    }

    /// Remove all rules across all hosts
    pub fn clear_all(&self) {
        self.entries.clear();
    }

    /// Total number of rules
    pub fn len(&self) -> usize {
        self.entries.iter().map(|e| e.value().len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Atomically replace all entries with those from `other`.
    ///
    /// Uses an overwrite-then-prune strategy to minimize the window
    /// where rules might be missing:
    /// 1. Copy all entries from `other` (existing keys are overwritten in place)
    /// 2. Remove any stale keys not present in `other`
    ///
    /// During step 1, readers see either old or new rules for each key — never empty.
    /// The only brief gap is during step 2 for keys being removed.
    pub fn swap_from(&self, other: &Self) {
        // Phase 1: Overwrite / insert all keys from the new set
        for entry in &other.entries {
            self.entries.insert(entry.key().clone(), entry.value().clone());
        }

        // Phase 2: Collect stale keys, then remove them
        let new_keys: std::collections::HashSet<String> = other.entries.iter().map(|e| e.key().clone()).collect();
        let stale_keys: Vec<String> = self
            .entries
            .iter()
            .map(|e| e.key().clone())
            .filter(|k| !new_keys.contains(k))
            .collect();
        for key in stale_keys {
            self.entries.remove(&key);
        }
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
    pub fn parse_str(s: &str) -> Self {
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
    /// key: `host_code`, value: list of `UrlRule`
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
        if let Some(rules) = self.entries.get(host_code)
            && let Some(rule) = rules.iter().find(|r| r.matches(path))
        {
            return Some(rule.id.clone());
        }
        // Check global rules
        if let Some(rules) = self.entries.get("*")
            && let Some(rule) = rules.iter().find(|r| r.matches(path))
        {
            return Some(rule.id.clone());
        }
        None
    }

    pub fn insert(&self, host_code: &str, rule: UrlRule) {
        self.entries.entry(host_code.to_string()).or_default().push(rule);
    }

    pub fn clear_host(&self, host_code: &str) {
        self.entries.remove(host_code);
    }

    /// Remove all rules across all hosts
    pub fn clear_all(&self) {
        self.entries.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.iter().map(|e| e.value().len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Atomically replace all entries with those from `other`.
    ///
    /// Uses an overwrite-then-prune strategy to minimize the window
    /// where rules might be missing:
    /// 1. Copy all entries from `other` (existing keys are overwritten in place)
    /// 2. Remove any stale keys not present in `other`
    pub fn swap_from(&self, other: &Self) {
        // Phase 1: Overwrite / insert all keys from the new set
        for entry in &other.entries {
            self.entries.insert(entry.key().clone(), entry.value().clone());
        }

        // Phase 2: Collect stale keys, then remove them
        let new_keys: std::collections::HashSet<String> = other.entries.iter().map(|e| e.key().clone()).collect();
        let stale_keys: Vec<String> = self
            .entries
            .iter()
            .map(|e| e.key().clone())
            .filter(|k| !new_keys.contains(k))
            .collect();
        for key in stale_keys {
            self.entries.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::sync::Arc;

    // -------------------------------------------------------------------------
    // IpRuleSet basic (5)
    // -------------------------------------------------------------------------

    #[test]
    fn ip_rule_set_insert_and_lookup() {
        let set = IpRuleSet::new();
        set.insert("h1", "192.168.1.1");
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(set.matches("h1", ip));
    }

    #[test]
    fn ip_rule_set_remove() {
        let set = IpRuleSet::new();
        set.insert("h1", "10.0.0.1");
        set.clear_host("h1");
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!set.matches("h1", ip));
    }

    #[test]
    fn ip_rule_set_remove_nonexistent() {
        let set = IpRuleSet::new();
        // Must not panic
        set.clear_host("nonexistent");
    }

    #[test]
    fn ip_rule_set_clear_all() {
        let set = IpRuleSet::new();
        set.insert("h1", "10.0.0.1");
        set.insert("h2", "10.0.0.2");
        set.insert("h3", "10.0.0.3");
        set.clear_all();
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn ip_rule_set_clear_host() {
        let set = IpRuleSet::new();
        set.insert("h1", "10.1.0.1");
        set.insert("h2", "10.2.0.1");
        set.clear_host("h1");
        let ip1: IpAddr = "10.1.0.1".parse().unwrap();
        let ip2: IpAddr = "10.2.0.1".parse().unwrap();
        assert!(!set.matches("h1", ip1));
        assert!(set.matches("h2", ip2));
    }

    // -------------------------------------------------------------------------
    // IpRuleSet swap_from (7)
    // -------------------------------------------------------------------------

    #[test]
    fn ip_rule_set_swap_from_add_new() {
        let target = IpRuleSet::new();
        let source = IpRuleSet::new();
        source.insert("h_new", "172.16.0.1");
        target.swap_from(&source);
        let ip: IpAddr = "172.16.0.1".parse().unwrap();
        assert!(target.matches("h_new", ip));
    }

    #[test]
    fn ip_rule_set_swap_from_update() {
        let target = IpRuleSet::new();
        target.insert("h1", "10.0.0.1");

        let source = IpRuleSet::new();
        source.insert("h1", "10.0.0.2");
        target.swap_from(&source);

        let old_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let new_ip: IpAddr = "10.0.0.2".parse().unwrap();
        // After swap, h1 should only have the new IP
        assert!(!target.matches("h1", old_ip));
        assert!(target.matches("h1", new_ip));
    }

    #[test]
    fn ip_rule_set_swap_from_prune_stale() {
        let target = IpRuleSet::new();
        target.insert("stale", "1.1.1.1");
        target.insert("keep", "2.2.2.2");

        let source = IpRuleSet::new();
        source.insert("keep", "2.2.2.2");
        target.swap_from(&source);

        let stale_ip: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(!target.matches("stale", stale_ip));
        let keep_ip: IpAddr = "2.2.2.2".parse().unwrap();
        assert!(target.matches("keep", keep_ip));
    }

    #[test]
    fn ip_rule_set_swap_from_empty_source() {
        let target = IpRuleSet::new();
        target.insert("h1", "10.0.0.1");
        target.insert("h2", "10.0.0.2");

        let source = IpRuleSet::new();
        target.swap_from(&source);

        assert_eq!(target.len(), 0);
    }

    #[test]
    fn ip_rule_set_swap_from_empty_target() {
        let target = IpRuleSet::new();
        let source = IpRuleSet::new();
        source.insert("h1", "192.168.0.1");
        source.insert("h2", "192.168.0.2");

        target.swap_from(&source);

        let ip1: IpAddr = "192.168.0.1".parse().unwrap();
        let ip2: IpAddr = "192.168.0.2".parse().unwrap();
        assert!(target.matches("h1", ip1));
        assert!(target.matches("h2", ip2));
    }

    #[test]
    fn ip_rule_set_swap_no_gap() {
        let target = IpRuleSet::new();
        target.insert("h1", "10.0.0.1");

        let source = IpRuleSet::new();
        source.insert("h1", "10.0.0.1");

        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(target.matches("h1", ip));
        target.swap_from(&source);
        assert!(target.matches("h1", ip));
    }

    #[test]
    fn ip_rule_set_swap_idempotent() {
        let target = IpRuleSet::new();
        let source = IpRuleSet::new();
        source.insert("h1", "10.0.0.1");
        source.insert("h2", "10.0.0.2");

        target.swap_from(&source);
        let len_after_first = target.len();

        target.swap_from(&source);
        let len_after_second = target.len();

        assert_eq!(len_after_first, len_after_second);

        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(target.matches("h1", ip1));
        assert!(target.matches("h2", ip2));
    }

    // -------------------------------------------------------------------------
    // IpRuleSet concurrent (2)
    // -------------------------------------------------------------------------

    #[test]
    fn ip_rule_set_concurrent_read_during_swap() {
        let target = Arc::new(IpRuleSet::new());
        target.insert("h1", "10.0.0.1");

        let readers: Vec<_> = (0..10)
            .map(|_| {
                let t = Arc::clone(&target);
                std::thread::spawn(move || {
                    for _ in 0..100 {
                        let ip: IpAddr = "10.0.0.1".parse().unwrap();
                        let _ = t.matches("h1", ip);
                    }
                })
            })
            .collect();

        let source = IpRuleSet::new();
        source.insert("h1", "10.0.0.2");
        for _ in 0..5 {
            target.swap_from(&source);
        }

        for handle in readers {
            handle.join().unwrap();
        }
    }

    #[test]
    fn ip_rule_set_concurrent_insert_remove() {
        let set = Arc::new(IpRuleSet::new());

        let inserters: Vec<_> = (0..5)
            .map(|i| {
                let s = Arc::clone(&set);
                std::thread::spawn(move || {
                    for j in 0..20u8 {
                        s.insert(&format!("h{i}"), &format!("10.{i}.{j}.1"));
                    }
                })
            })
            .collect();

        let removers: Vec<_> = (0..5)
            .map(|i| {
                let s = Arc::clone(&set);
                std::thread::spawn(move || {
                    for _ in 0..10 {
                        s.clear_host(&format!("h{i}"));
                    }
                })
            })
            .collect();

        for h in inserters {
            h.join().unwrap();
        }
        for h in removers {
            h.join().unwrap();
        }
        // Just verifying no panic occurred; length state is non-deterministic
    }

    // -------------------------------------------------------------------------
    // UrlRuleSet basic (4)
    // -------------------------------------------------------------------------

    #[test]
    fn url_rule_set_insert_and_lookup() {
        let set = UrlRuleSet::new();
        set.insert(
            "h1",
            UrlRule {
                id: "rule1".to_string(),
                pattern: "/admin".to_string(),
                match_type: UrlMatchType::Exact,
            },
        );
        assert_eq!(set.matches("h1", "/admin"), Some("rule1".to_string()));
        assert_eq!(set.matches("h1", "/other"), None);
    }

    #[test]
    fn url_rule_set_remove() {
        let set = UrlRuleSet::new();
        set.insert(
            "h1",
            UrlRule {
                id: "rule1".to_string(),
                pattern: "/admin".to_string(),
                match_type: UrlMatchType::Exact,
            },
        );
        set.clear_host("h1");
        assert_eq!(set.matches("h1", "/admin"), None);
    }

    #[test]
    fn url_rule_set_clear_all() {
        let set = UrlRuleSet::new();
        set.insert(
            "h1",
            UrlRule {
                id: "r1".to_string(),
                pattern: "/a".to_string(),
                match_type: UrlMatchType::Exact,
            },
        );
        set.insert(
            "h2",
            UrlRule {
                id: "r2".to_string(),
                pattern: "/b".to_string(),
                match_type: UrlMatchType::Exact,
            },
        );
        set.clear_all();
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn url_rule_set_clear_host() {
        let set = UrlRuleSet::new();
        set.insert(
            "h1",
            UrlRule {
                id: "r1".to_string(),
                pattern: "/admin".to_string(),
                match_type: UrlMatchType::Exact,
            },
        );
        set.insert(
            "h2",
            UrlRule {
                id: "r2".to_string(),
                pattern: "/secret".to_string(),
                match_type: UrlMatchType::Exact,
            },
        );
        set.clear_host("h1");
        assert_eq!(set.matches("h1", "/admin"), None);
        assert_eq!(set.matches("h2", "/secret"), Some("r2".to_string()));
    }

    // -------------------------------------------------------------------------
    // UrlRuleSet swap_from (3)
    // -------------------------------------------------------------------------

    #[test]
    fn url_rule_set_swap_from_add_new() {
        let target = UrlRuleSet::new();
        let source = UrlRuleSet::new();
        source.insert(
            "h_new",
            UrlRule {
                id: "r_new".to_string(),
                pattern: "/new".to_string(),
                match_type: UrlMatchType::Prefix,
            },
        );
        target.swap_from(&source);
        assert_eq!(target.matches("h_new", "/new/path"), Some("r_new".to_string()));
    }

    #[test]
    fn url_rule_set_swap_from_prune_stale() {
        let target = UrlRuleSet::new();
        target.insert(
            "stale",
            UrlRule {
                id: "rs".to_string(),
                pattern: "/stale".to_string(),
                match_type: UrlMatchType::Exact,
            },
        );
        target.insert(
            "keep",
            UrlRule {
                id: "rk".to_string(),
                pattern: "/keep".to_string(),
                match_type: UrlMatchType::Exact,
            },
        );

        let source = UrlRuleSet::new();
        source.insert(
            "keep",
            UrlRule {
                id: "rk".to_string(),
                pattern: "/keep".to_string(),
                match_type: UrlMatchType::Exact,
            },
        );
        target.swap_from(&source);

        assert_eq!(target.matches("stale", "/stale"), None);
        assert_eq!(target.matches("keep", "/keep"), Some("rk".to_string()));
    }

    #[test]
    fn url_rule_set_swap_from_empty() {
        let target = UrlRuleSet::new();
        target.insert(
            "h1",
            UrlRule {
                id: "r1".to_string(),
                pattern: "/x".to_string(),
                match_type: UrlMatchType::Exact,
            },
        );
        let source = UrlRuleSet::new();
        target.swap_from(&source);
        assert_eq!(target.len(), 0);
    }

    // -------------------------------------------------------------------------
    // Len/utility (4)
    // -------------------------------------------------------------------------

    #[test]
    fn ip_rule_set_len_accuracy() {
        let set = IpRuleSet::new();
        set.insert("h1", "10.0.0.1");
        set.insert("h1", "10.0.0.2");
        set.insert("h2", "192.168.0.1");
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn url_rule_set_len_accuracy() {
        let set = UrlRuleSet::new();
        set.insert(
            "h1",
            UrlRule {
                id: "r1".to_string(),
                pattern: "/a".to_string(),
                match_type: UrlMatchType::Exact,
            },
        );
        set.insert(
            "h1",
            UrlRule {
                id: "r2".to_string(),
                pattern: "/b".to_string(),
                match_type: UrlMatchType::Exact,
            },
        );
        set.insert(
            "h2",
            UrlRule {
                id: "r3".to_string(),
                pattern: "/c".to_string(),
                match_type: UrlMatchType::Exact,
            },
        );
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn ip_rule_set_host_entries_only_host() {
        let set = IpRuleSet::new();
        set.insert("h1", "10.1.0.1");
        set.insert("h2", "10.2.0.1");
        set.clear_host("h1");

        let ip1: IpAddr = "10.1.0.1".parse().unwrap();
        let ip2: IpAddr = "10.2.0.1".parse().unwrap();
        assert!(!set.matches("h1", ip1));
        assert!(set.matches("h2", ip2));
    }

    #[test]
    fn url_rule_set_host_entries_only_host() {
        let set = UrlRuleSet::new();
        set.insert(
            "h1",
            UrlRule {
                id: "r1".to_string(),
                pattern: "/h1".to_string(),
                match_type: UrlMatchType::Exact,
            },
        );
        set.insert(
            "h2",
            UrlRule {
                id: "r2".to_string(),
                pattern: "/h2".to_string(),
                match_type: UrlMatchType::Exact,
            },
        );
        set.clear_host("h1");

        assert_eq!(set.matches("h1", "/h1"), None);
        assert_eq!(set.matches("h2", "/h2"), Some("r2".to_string()));
    }

    // -------------------------------------------------------------------------
    // IpRuleSet CIDR / IPv6 / wildcard (5)
    // -------------------------------------------------------------------------

    #[test]
    #[allow(clippy::unwrap_used)]
    fn ip_rule_set_cidr_range_match() {
        let set = IpRuleSet::new();
        set.load("h1", &["192.168.0.0/24".to_string()]);
        let in_range: IpAddr = "192.168.0.50".parse().unwrap();
        let out_of_range: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(set.matches("h1", in_range));
        assert!(!set.matches("h1", out_of_range));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn ip_rule_set_ipv6_cidr_match() {
        let set = IpRuleSet::new();
        set.insert("h1", "2001:db8::/32");
        let in_range: IpAddr = "2001:db8::1".parse().unwrap();
        let out_of_range: IpAddr = "2001:db9::1".parse().unwrap();
        assert!(set.matches("h1", in_range));
        assert!(!set.matches("h1", out_of_range));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn ip_rule_set_global_wildcard_fallback() {
        let set = IpRuleSet::new();
        set.insert("*", "203.0.113.0/24");
        let ip: IpAddr = "203.0.113.42".parse().unwrap();
        // The "*" bucket should match any host_code lookup
        assert!(set.matches("any_host", ip));
        assert!(set.matches("another_host", ip));
    }

    #[test]
    fn ip_rule_set_invalid_cidr_ignored() {
        let set = IpRuleSet::new();
        set.insert("h1", "not-a-cidr");
        assert_eq!(set.len(), 0);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn ip_rule_set_host_specific_before_global() {
        let set = IpRuleSet::new();
        // Host-specific rule: 10.0.0.0/8 on "h1"
        set.insert("h1", "10.0.0.0/8");
        // Global rule: 192.168.0.0/24 on "*"
        set.insert("*", "192.168.0.0/24");

        let host_ip: IpAddr = "10.5.5.5".parse().unwrap();
        let global_ip: IpAddr = "192.168.0.100".parse().unwrap();
        let unmatched_ip: IpAddr = "172.16.0.1".parse().unwrap();

        // Host-specific rule matches for h1
        assert!(set.matches("h1", host_ip));
        // Global rule matches for h1 (fallback also checked)
        assert!(set.matches("h1", global_ip));
        // Global rule matches for a different host
        assert!(set.matches("h2", global_ip));
        // Neither rule matches this IP for h2
        assert!(!set.matches("h2", unmatched_ip));
    }

    // -------------------------------------------------------------------------
    // UrlRuleSet match types (3)
    // -------------------------------------------------------------------------

    #[test]
    fn url_rule_set_prefix_match() {
        let set = UrlRuleSet::new();
        set.insert(
            "h1",
            UrlRule {
                id: "prefix_rule".to_string(),
                pattern: "/api".to_string(),
                match_type: UrlMatchType::Prefix,
            },
        );
        assert_eq!(set.matches("h1", "/api/users"), Some("prefix_rule".to_string()));
        assert_eq!(set.matches("h1", "/home"), None);
    }

    #[test]
    fn url_rule_set_contains_match() {
        let set = UrlRuleSet::new();
        set.insert(
            "h1",
            UrlRule {
                id: "contains_rule".to_string(),
                pattern: "admin".to_string(),
                match_type: UrlMatchType::Contains,
            },
        );
        assert_eq!(set.matches("h1", "/foo/admin/bar"), Some("contains_rule".to_string()));
        assert_eq!(set.matches("h1", "/home"), None);
    }

    #[test]
    fn url_rule_set_suffix_match() {
        let set = UrlRuleSet::new();
        set.insert(
            "h1",
            UrlRule {
                id: "suffix_rule".to_string(),
                pattern: ".php".to_string(),
                match_type: UrlMatchType::Suffix,
            },
        );
        assert_eq!(set.matches("h1", "/index.php"), Some("suffix_rule".to_string()));
        assert_eq!(set.matches("h1", "/index.html"), None);
    }

    // -------------------------------------------------------------------------
    // UrlRuleSet wildcard fallback (1)
    // -------------------------------------------------------------------------

    #[test]
    fn url_rule_set_global_wildcard_fallback() {
        let set = UrlRuleSet::new();
        set.insert(
            "*",
            UrlRule {
                id: "global_rule".to_string(),
                pattern: "/blocked".to_string(),
                match_type: UrlMatchType::Exact,
            },
        );
        // The "*" bucket should match any host_code lookup
        assert_eq!(set.matches("any_host", "/blocked"), Some("global_rule".to_string()));
        assert_eq!(set.matches("another_host", "/blocked"), Some("global_rule".to_string()));
        // A non-matching path should return None
        assert_eq!(set.matches("any_host", "/allowed"), None);
    }

    // -------------------------------------------------------------------------
    // Concurrent swap correctness (1)
    // -------------------------------------------------------------------------

    #[test]
    #[allow(clippy::unwrap_used)]
    fn ip_rule_set_concurrent_swap_correctness() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let set = Arc::new(IpRuleSet::new());

        // Populate initial source with 100 known entries (10.0.0.0/24 block)
        let initial_source = IpRuleSet::new();
        for i in 0u8..100 {
            initial_source.insert("h1", &format!("10.0.0.{i}"));
        }
        set.swap_from(&initial_source);

        let done = Arc::new(AtomicBool::new(false));

        // Spawn 5 reader threads that continuously call matches()
        let readers: Vec<_> = (0..5)
            .map(|_| {
                let s = Arc::clone(&set);
                let d = Arc::clone(&done);
                std::thread::spawn(move || {
                    let mut saw_match = false;
                    while !d.load(Ordering::Relaxed) {
                        let ip: IpAddr = "10.0.0.50".parse().unwrap();
                        if s.matches("h1", ip) {
                            saw_match = true;
                        }
                        std::thread::yield_now();
                    }
                    // After done is set, do a final check
                    let ip: IpAddr = "10.0.0.50".parse().unwrap();
                    saw_match || s.matches("h1", ip)
                })
            })
            .collect();

        // Main thread performs a swap with a new source that also contains the probe IP
        let new_source = IpRuleSet::new();
        for i in 0u8..100 {
            new_source.insert("h1", &format!("10.0.0.{i}"));
        }
        // Also add extra entries to verify swap completeness
        new_source.insert("h1", "10.1.1.1");
        set.swap_from(&new_source);

        // Signal readers to stop
        done.store(true, Ordering::Relaxed);

        // All readers should have seen at least one match (or the final check passes)
        for handle in readers {
            let saw = handle.join().unwrap();
            assert!(saw, "reader thread should have seen a match for 10.0.0.50");
        }

        // After swap, the new entry must be visible
        let new_ip: IpAddr = "10.1.1.1".parse().unwrap();
        assert!(set.matches("h1", new_ip));
    }

    // -------------------------------------------------------------------------
    // Edge cases (2)
    // -------------------------------------------------------------------------

    #[test]
    fn url_rule_set_concurrent_swap() {
        let target = Arc::new(UrlRuleSet::new());

        let handles: Vec<_> = (0..8)
            .map(|i| {
                let t = Arc::clone(&target);
                std::thread::spawn(move || {
                    let source = UrlRuleSet::new();
                    source.insert(
                        &format!("h{i}"),
                        UrlRule {
                            id: format!("r{i}"),
                            pattern: format!("/path{i}"),
                            match_type: UrlMatchType::Prefix,
                        },
                    );
                    t.swap_from(&source);
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn ip_rule_set_large_dataset_swap() {
        let source = IpRuleSet::new();
        for i in 0u32..10_000 {
            let a = u8::try_from(i >> 8).unwrap_or(0);
            let b = (i & 0xff) as u8;
            source.insert("bulk", &format!("10.{a}.{b}.1"));
        }

        let target = IpRuleSet::new();
        target.swap_from(&source);

        assert_eq!(target.len(), 10_000);
    }
}
