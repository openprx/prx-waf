use std::sync::Arc;
use tracing::{debug, info};

use waf_common::{DetectionResult, Phase, RequestCtx, WafAction, WafDecision};
use waf_storage::{
    Database,
    models::{AllowIp, AllowUrl, BlockIp, BlockUrl},
};

use crate::rules::{IpRuleSet, UrlMatchType, UrlRule, UrlRuleSet};

/// In-memory rule store backed by PostgreSQL
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

    /// Load all rules from database into memory
    pub async fn reload_all(&self) -> anyhow::Result<()> {
        info!("Reloading WAF rules from database");

        // Load allow IPs
        let allow_ips = self.db.list_allow_ips(None).await?;
        self.load_allow_ips(&allow_ips);

        // Load block IPs
        let block_ips = self.db.list_block_ips(None).await?;
        self.load_block_ips(&block_ips);

        // Load allow URLs
        let allow_urls = self.db.list_allow_urls(None).await?;
        self.load_allow_urls(&allow_urls);

        // Load block URLs
        let block_urls = self.db.list_block_urls(None).await?;
        self.load_block_urls(&block_urls);

        info!(
            "Rules loaded: allow_ips={}, block_ips={}, allow_urls={}, block_urls={}",
            self.allow_ips.len(),
            self.block_ips.len(),
            self.allow_urls.len(),
            self.block_urls.len(),
        );

        Ok(())
    }

    fn load_allow_ips(&self, rows: &[AllowIp]) {
        // Group by host_code
        use std::collections::HashMap;
        let mut map: HashMap<&str, Vec<String>> = HashMap::new();
        for row in rows {
            map.entry(&row.host_code)
                .or_default()
                .push(row.ip_cidr.clone());
        }
        for (code, cidrs) in map {
            self.allow_ips.load(code, &cidrs);
        }
    }

    fn load_block_ips(&self, rows: &[BlockIp]) {
        use std::collections::HashMap;
        let mut map: HashMap<&str, Vec<String>> = HashMap::new();
        for row in rows {
            map.entry(&row.host_code)
                .or_default()
                .push(row.ip_cidr.clone());
        }
        for (code, cidrs) in map {
            self.block_ips.load(code, &cidrs);
        }
    }

    fn load_allow_urls(&self, rows: &[AllowUrl]) {
        use std::collections::HashMap;
        let mut map: HashMap<&str, Vec<UrlRule>> = HashMap::new();
        for row in rows {
            map.entry(&row.host_code).or_default().push(UrlRule {
                id: row.id.to_string(),
                pattern: row.url_pattern.clone(),
                match_type: UrlMatchType::parse_str(&row.match_type),
            });
        }
        for (code, rules) in map {
            self.allow_urls.load(code, rules);
        }
    }

    fn load_block_urls(&self, rows: &[BlockUrl]) {
        use std::collections::HashMap;
        let mut map: HashMap<&str, Vec<UrlRule>> = HashMap::new();
        for row in rows {
            map.entry(&row.host_code).or_default().push(UrlRule {
                id: row.id.to_string(),
                pattern: row.url_pattern.clone(),
                match_type: UrlMatchType::parse_str(&row.match_type),
            });
        }
        for (code, rules) in map {
            self.block_urls.load(code, rules);
        }
    }

    /// Reload rules for a specific host
    pub async fn reload_host(&self, host_code: &str) -> anyhow::Result<()> {
        debug!("Reloading rules for host: {}", host_code);

        let allow_ips = self.db.list_allow_ips(Some(host_code)).await?;
        let cidrs: Vec<String> = allow_ips.iter().map(|r| r.ip_cidr.clone()).collect();
        self.allow_ips.clear_host(host_code);
        self.allow_ips.load(host_code, &cidrs);

        let block_ips = self.db.list_block_ips(Some(host_code)).await?;
        let cidrs: Vec<String> = block_ips.iter().map(|r| r.ip_cidr.clone()).collect();
        self.block_ips.clear_host(host_code);
        self.block_ips.load(host_code, &cidrs);

        let allow_urls = self.db.list_allow_urls(Some(host_code)).await?;
        let rules: Vec<UrlRule> = allow_urls
            .iter()
            .map(|r| UrlRule {
                id: r.id.to_string(),
                pattern: r.url_pattern.clone(),
                match_type: UrlMatchType::parse_str(&r.match_type),
            })
            .collect();
        self.allow_urls.clear_host(host_code);
        self.allow_urls.load(host_code, rules);

        let block_urls = self.db.list_block_urls(Some(host_code)).await?;
        let rules: Vec<UrlRule> = block_urls
            .iter()
            .map(|r| UrlRule {
                id: r.id.to_string(),
                pattern: r.url_pattern.clone(),
                match_type: UrlMatchType::parse_str(&r.match_type),
            })
            .collect();
        self.block_urls.clear_host(host_code);
        self.block_urls.load(host_code, rules);

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
