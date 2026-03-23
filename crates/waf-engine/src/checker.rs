use std::sync::Arc;
use tracing::{debug, info};

use waf_common::{DetectionResult, Phase, RequestCtx, WafAction, WafDecision};
use waf_storage::Database;

use crate::rules::{IpRuleSet, UrlMatchType, UrlRule, UrlRuleSet};

/// In-memory rule store backed by `PostgreSQL`
pub struct RuleStore {
    pub allow_ips: Arc<IpRuleSet>,
    pub block_ips: Arc<IpRuleSet>,
    pub allow_urls: Arc<UrlRuleSet>,
    pub block_urls: Arc<UrlRuleSet>,
    db: Arc<Database>,
}

impl RuleStore {
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            allow_ips: Arc::new(IpRuleSet::new()),
            block_ips: Arc::new(IpRuleSet::new()),
            allow_urls: Arc::new(UrlRuleSet::new()),
            block_urls: Arc::new(UrlRuleSet::new()),
            db,
        }
    }

    /// Load all rules from database into memory using atomic swap.
    ///
    /// Instead of clearing rules first (which creates a window where all rules
    /// are empty), this method:
    /// 1. Loads all data from DB into temporary rule sets (no live mutation)
    /// 2. Swaps each live rule set from the temporary one (overwrite + prune)
    ///
    /// This eliminates the "rule gap" where blacklist/whitelist rules are empty
    /// during the reload window.
    pub async fn reload_all(&self) -> anyhow::Result<()> {
        info!("Reloading WAF rules from database");

        // Phase 1: Load all rules from DB (no memory modification yet)
        let allow_ip_rows = self.db.list_allow_ips(None).await?;
        let block_ip_rows = self.db.list_block_ips(None).await?;
        let allow_url_rows = self.db.list_allow_urls(None).await?;
        let block_url_rows = self.db.list_block_urls(None).await?;

        // Phase 2: Build temporary rule sets (in-memory only, very fast)
        let new_allow_ips = IpRuleSet::new();
        Self::populate_ip_rules(&new_allow_ips, &allow_ip_rows, |row| (&row.host_code, &row.ip_cidr));

        let new_block_ips = IpRuleSet::new();
        Self::populate_ip_rules(&new_block_ips, &block_ip_rows, |row| (&row.host_code, &row.ip_cidr));

        let new_allow_urls = UrlRuleSet::new();
        Self::populate_url_rules(&new_allow_urls, &allow_url_rows, |row| {
            (
                &row.host_code,
                UrlRule {
                    id: row.id.to_string(),
                    pattern: row.url_pattern.clone(),
                    match_type: UrlMatchType::parse_str(&row.match_type),
                },
            )
        });

        let new_block_urls = UrlRuleSet::new();
        Self::populate_url_rules(&new_block_urls, &block_url_rows, |row| {
            (
                &row.host_code,
                UrlRule {
                    id: row.id.to_string(),
                    pattern: row.url_pattern.clone(),
                    match_type: UrlMatchType::parse_str(&row.match_type),
                },
            )
        });

        // Phase 3: Atomic swap — overwrite live sets from temporaries, then prune
        // No IO involved; only fast in-memory DashMap operations
        self.allow_ips.swap_from(&new_allow_ips);
        self.block_ips.swap_from(&new_block_ips);
        self.allow_urls.swap_from(&new_allow_urls);
        self.block_urls.swap_from(&new_block_urls);

        info!(
            "Rules loaded: allow_ips={}, block_ips={}, allow_urls={}, block_urls={}",
            self.allow_ips.len(),
            self.block_ips.len(),
            self.allow_urls.len(),
            self.block_urls.len(),
        );

        Ok(())
    }

    /// Populate an `IpRuleSet` from database rows.
    ///
    /// The `extract` closure maps each row to `(host_code, ip_cidr)`.
    fn populate_ip_rules<T, F>(target: &IpRuleSet, rows: &[T], extract: F)
    where
        F: Fn(&T) -> (&str, &str),
    {
        use std::collections::HashMap;
        let mut map: HashMap<&str, Vec<String>> = HashMap::new();
        for row in rows {
            let (host_code, ip_cidr) = extract(row);
            map.entry(host_code).or_default().push(ip_cidr.to_string());
        }
        for (code, cidrs) in map {
            target.load(code, &cidrs);
        }
    }

    /// Populate a `UrlRuleSet` from database rows.
    ///
    /// The `extract` closure maps each row to `(host_code, UrlRule)`.
    fn populate_url_rules<T, F>(target: &UrlRuleSet, rows: &[T], extract: F)
    where
        F: Fn(&T) -> (&str, UrlRule),
    {
        use std::collections::HashMap;
        let mut map: HashMap<&str, Vec<UrlRule>> = HashMap::new();
        for row in rows {
            let (host_code, rule) = extract(row);
            map.entry(host_code).or_default().push(rule);
        }
        for (code, rules) in map {
            target.load(code, rules);
        }
    }

    /// Reload rules for a specific host using load-then-swap pattern.
    ///
    /// All DB queries complete before any live mutation. Then each rule set
    /// is updated with a single `load()` call (which overwrites the host key
    /// in the underlying `DashMap`), so the window is minimal.
    pub async fn reload_host(&self, host_code: &str) -> anyhow::Result<()> {
        debug!("Reloading rules for host: {}", host_code);

        // Phase 1: Load all data from DB (no live mutation yet)
        let allow_ip_rows = self.db.list_allow_ips(Some(host_code)).await?;
        let block_ip_rows = self.db.list_block_ips(Some(host_code)).await?;
        let allow_url_rows = self.db.list_allow_urls(Some(host_code)).await?;
        let block_url_rows = self.db.list_block_urls(Some(host_code)).await?;

        // Phase 2: Build rule data in memory
        let allow_cidrs: Vec<String> = allow_ip_rows.iter().map(|r| r.ip_cidr.clone()).collect();
        let block_cidrs: Vec<String> = block_ip_rows.iter().map(|r| r.ip_cidr.clone()).collect();
        let allow_rules: Vec<UrlRule> = allow_url_rows
            .iter()
            .map(|r| UrlRule {
                id: r.id.to_string(),
                pattern: r.url_pattern.clone(),
                match_type: UrlMatchType::parse_str(&r.match_type),
            })
            .collect();
        let block_rules: Vec<UrlRule> = block_url_rows
            .iter()
            .map(|r| UrlRule {
                id: r.id.to_string(),
                pattern: r.url_pattern.clone(),
                match_type: UrlMatchType::parse_str(&r.match_type),
            })
            .collect();

        // Phase 3: Swap — load() overwrites the host key atomically in DashMap
        // For empty result sets, clear the host key instead
        if allow_cidrs.is_empty() {
            self.allow_ips.clear_host(host_code);
        } else {
            self.allow_ips.load(host_code, &allow_cidrs);
        }

        if block_cidrs.is_empty() {
            self.block_ips.clear_host(host_code);
        } else {
            self.block_ips.load(host_code, &block_cidrs);
        }

        if allow_rules.is_empty() {
            self.allow_urls.clear_host(host_code);
        } else {
            self.allow_urls.load(host_code, allow_rules);
        }

        if block_rules.is_empty() {
            self.block_urls.clear_host(host_code);
        } else {
            self.block_urls.load(host_code, block_rules);
        }

        Ok(())
    }
}

/// Run Phase 1 WAF check: IP whitelist
/// If the IP is whitelisted, allow immediately (skip further checks)
pub fn check_ip_whitelist(ctx: &RequestCtx, store: &RuleStore) -> WafDecision {
    let host_code = &ctx.host_config.code;

    if store.allow_ips.matches(host_code, ctx.client_ip) {
        debug!("IP {} whitelisted for host {}", ctx.client_ip, host_code);
        return WafDecision {
            action: WafAction::Allow,
            result: Some(DetectionResult {
                rule_id: None,
                rule_name: "IP Whitelist".to_string(),
                phase: Phase::IpWhitelist,
                detail: format!("IP {} matched whitelist", ctx.client_ip),
            }),
        };
    }

    WafDecision::allow()
}

/// Run Phase 2 WAF check: IP blacklist
pub fn check_ip_blacklist(ctx: &RequestCtx, store: &RuleStore) -> WafDecision {
    let host_code = &ctx.host_config.code;

    if store.block_ips.matches(host_code, ctx.client_ip) {
        debug!("IP {} blocked for host {}", ctx.client_ip, host_code);
        return WafDecision::block(
            403,
            Some("Access denied.".to_string()),
            DetectionResult {
                rule_id: None,
                rule_name: "IP Blacklist".to_string(),
                phase: Phase::IpBlacklist,
                detail: format!("IP {} matched blacklist", ctx.client_ip),
            },
        );
    }

    WafDecision::allow()
}

/// Run Phase 3 WAF check: URL whitelist
/// If the URL is whitelisted, allow immediately
pub fn check_url_whitelist(ctx: &RequestCtx, store: &RuleStore) -> Option<WafDecision> {
    let host_code = &ctx.host_config.code;

    if let Some(rule_id) = store.allow_urls.matches(host_code, &ctx.path) {
        debug!("URL {} whitelisted for host {}", ctx.path, host_code);
        return Some(WafDecision {
            action: WafAction::Allow,
            result: Some(DetectionResult {
                rule_id: Some(rule_id),
                rule_name: "URL Whitelist".to_string(),
                phase: Phase::UrlWhitelist,
                detail: format!("Path {} matched URL whitelist", ctx.path),
            }),
        });
    }

    None
}

/// Run Phase 4 WAF check: URL blacklist
pub fn check_url_blacklist(ctx: &RequestCtx, store: &RuleStore) -> WafDecision {
    let host_code = &ctx.host_config.code;

    if let Some(rule_id) = store.block_urls.matches(host_code, &ctx.path) {
        debug!("URL {} blocked for host {}", ctx.path, host_code);
        return WafDecision::block(
            403,
            Some("Access denied.".to_string()),
            DetectionResult {
                rule_id: Some(rule_id),
                rule_name: "URL Blacklist".to_string(),
                phase: Phase::UrlBlacklist,
                detail: format!("Path {} matched URL blacklist", ctx.path),
            },
        );
    }

    WafDecision::allow()
}
