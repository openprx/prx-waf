use std::sync::{Arc, OnceLock};
use tracing::{debug, warn};
use uuid::Uuid;

use waf_common::{RequestCtx, WafAction, WafDecision};
use waf_storage::{
    models::{AttackLog, CreateSecurityEvent},
    Database,
};

use crate::block_page::render_block_page;
use crate::checker::{
    check_ip_blacklist, check_ip_whitelist, check_url_blacklist, check_url_whitelist, RuleStore,
};
use crate::checks::{
    AntiHotlinkCheck, BotCheck, CcCheck, Check, DirTraversalCheck, OWASPCheck, RceCheck,
    ScannerCheck, SensitiveCheck, SqlInjectionCheck, XssCheck,
};
use crate::crowdsec::{appsec_to_detection, AppSecClient, AppSecResult, CrowdSecChecker};
use crate::rules::engine::{from_db_rule, CustomRulesEngine};

/// WAF engine configuration
#[derive(Debug, Clone, Default)]
pub struct WafEngineConfig {
    /// Whether to log allowed requests that matched whitelist rules
    pub log_whitelist_hits: bool,
}

/// Main WAF engine — runs all detection phases.
///
/// Phase 1-4  : IP / URL whitelist + blacklist (fast-path)
/// Phase 16   : CrowdSec bouncer (cache lookup — runs early for efficiency)
/// Phase 5-11 : Attack detection (CC, scanner, bot, SQLi, XSS, RCE, traversal)
/// Phase 16b  : CrowdSec AppSec (async HTTP check — runs after local detectors)
/// Phase 12   : Custom rules engine (Rhai scripting)
/// Phase 13   : OWASP CRS subset
/// Phase 14   : Sensitive data detection
/// Phase 15   : Anti-hotlinking
pub struct WafEngine {
    pub store: Arc<RuleStore>,
    pub custom_rules: Arc<CustomRulesEngine>,
    pub sensitive: Arc<SensitiveCheck>,
    pub hotlink: Arc<AntiHotlinkCheck>,
    db: Arc<Database>,
    #[allow(dead_code)]
    config: WafEngineConfig,
    /// Dynamic checker pipeline (Phase 5-11 detectors).
    checkers: Vec<Box<dyn Check>>,
    owasp: Arc<OWASPCheck>,
    // ── Phase 6: CrowdSec ────────────────────────────────────────────────────
    /// Bouncer checker (set once after engine construction via set_crowdsec)
    crowdsec_checker: OnceLock<Arc<CrowdSecChecker>>,
    /// AppSec client (set once after engine construction via set_crowdsec)
    appsec_client: OnceLock<Arc<AppSecClient>>,
}

impl WafEngine {
    pub fn new(db: Arc<Database>, config: WafEngineConfig) -> Self {
        let store = Arc::new(RuleStore::new(Arc::clone(&db)));
        let custom_rules = Arc::new(CustomRulesEngine::new());
        let sensitive = Arc::new(SensitiveCheck::new());
        let hotlink = Arc::new(AntiHotlinkCheck::new());
        let owasp = Arc::new(OWASPCheck::new());

        // Build the Phase 5-11 checker pipeline.
        // CC runs first to shed flood traffic before expensive pattern checks.
        let checkers: Vec<Box<dyn Check>> = vec![
            Box::new(CcCheck::new()),
            Box::new(ScannerCheck::new()),
            Box::new(BotCheck::new()),
            Box::new(SqlInjectionCheck::new()),
            Box::new(XssCheck::new()),
            Box::new(RceCheck::new()),
            Box::new(DirTraversalCheck::new()),
        ];

        Self {
            store,
            custom_rules,
            sensitive,
            hotlink,
            db,
            config,
            checkers,
            owasp,
            crowdsec_checker: OnceLock::new(),
            appsec_client: OnceLock::new(),
        }
    }

    /// Plug CrowdSec components into the engine (called once after init).
    pub fn set_crowdsec(
        &self,
        checker: Arc<CrowdSecChecker>,
        appsec: Option<Arc<AppSecClient>>,
    ) {
        let _ = self.crowdsec_checker.set(checker);
        if let Some(ac) = appsec {
            let _ = self.appsec_client.set(ac);
        }
    }

    /// Reload all rules from the database
    pub async fn reload_rules(&self) -> anyhow::Result<()> {
        // Reload IP/URL rules
        self.store.reload_all().await?;

        // Reload custom rules
        let custom_rules = self.db.list_custom_rules(None).await?;
        {
            let mut by_host: std::collections::HashMap<String, Vec<_>> =
                std::collections::HashMap::new();
            for row in &custom_rules {
                match from_db_rule(row) {
                    Ok(rule) => {
                        by_host
                            .entry(row.host_code.clone())
                            .or_default()
                            .push(rule);
                    }
                    Err(e) => warn!("Failed to parse custom rule {}: {}", row.id, e),
                }
            }
            for (host_code, rules) in by_host {
                self.custom_rules.load_host(&host_code, rules);
            }
        }

        // Reload sensitive patterns
        let patterns = self.db.list_sensitive_patterns(None).await?;
        {
            let mut by_host: std::collections::HashMap<String, Vec<String>> =
                std::collections::HashMap::new();
            for row in &patterns {
                if row.check_request {
                    by_host
                        .entry(row.host_code.clone())
                        .or_default()
                        .push(row.pattern.clone());
                }
            }
            for (host_code, pats) in by_host {
                self.sensitive.load_host(&host_code, pats);
            }
        }

        // Reload hotlink configs
        let hotlink_configs = self.db.list_hotlink_configs().await?;
        for row in &hotlink_configs {
            let domains: Vec<String> = row
                .allowed_domains
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let config = crate::checks::anti_hotlink::HotlinkConfig {
                enabled: row.enabled,
                allow_empty_referer: row.allow_empty_referer,
                allowed_domains: domains,
                redirect_url: row.redirect_url.clone(),
            };
            self.hotlink.set_config(&row.host_code, config);
        }

        Ok(())
    }

    /// Run the full WAF inspection pipeline.
    ///
    /// Returns the WAF decision. Callers should check `decision.is_allowed()`.
    pub async fn inspect(&self, ctx: &RequestCtx) -> WafDecision {
        // Skip WAF if guard is disabled for this host
        if !ctx.host_config.guard_status {
            return WafDecision::allow();
        }

        // ── Phase 1: IP Whitelist — allow immediately if matched ──────────────
        let ip_wl = check_ip_whitelist(ctx, &self.store);
        if let Some(ref result) = ip_wl.result {
            if matches!(ip_wl.action, WafAction::Allow)
                && result.phase == waf_common::Phase::IpWhitelist
            {
                debug!("Request allowed by IP whitelist: {}", ctx.client_ip);
                return ip_wl;
            }
        }

        // ── Phase 2: IP Blacklist — block if matched ───────────────────────────
        let ip_bl = check_ip_blacklist(ctx, &self.store);
        if !ip_bl.is_allowed() {
            self.log_attack(ctx, &ip_bl).await;
            return ip_bl;
        }

        // ── Phase 3: URL Whitelist — allow immediately if matched ──────────────
        if let Some(url_wl) = check_url_whitelist(ctx, &self.store) {
            debug!("Request allowed by URL whitelist: {}", ctx.path);
            return url_wl;
        }

        // ── Phase 4: URL Blacklist — block if matched ──────────────────────────
        let url_bl = check_url_blacklist(ctx, &self.store);
        if !url_bl.is_allowed() {
            self.log_attack(ctx, &url_bl).await;
            return url_bl;
        }

        // ── Phase 16a: CrowdSec Bouncer — fast cache lookup ───────────────────
        if let Some(cs) = self.crowdsec_checker.get() {
            if let Some(result) = cs.check(ctx) {
                let rule_name = result.rule_name.clone();
                let decision = if ctx.host_config.log_only_mode {
                    WafDecision {
                        action: WafAction::LogOnly,
                        result: Some(result),
                    }
                } else {
                    let body = render_block_page(ctx, &rule_name);
                    WafDecision::block(403, Some(body), result)
                };
                self.log_security_event(ctx, &decision).await;
                return decision;
            }
        }

        // ── Phase 5-11: Attack detection pipeline ─────────────────────────────
        for checker in &self.checkers {
            if let Some(result) = checker.check(ctx) {
                let rule_name = result.rule_name.clone();

                let decision = if ctx.host_config.log_only_mode {
                    WafDecision {
                        action: WafAction::LogOnly,
                        result: Some(result),
                    }
                } else {
                    let body = render_block_page(ctx, &rule_name);
                    WafDecision::block(403, Some(body), result)
                };

                self.log_security_event(ctx, &decision).await;
                return decision;
            }
        }

        // ── Phase 16b: CrowdSec AppSec — async per-request check ──────────────
        if let Some(appsec) = self.appsec_client.get() {
            match appsec.check_request(ctx).await {
                AppSecResult::Block { message } => {
                    let result = appsec_to_detection(message);
                    let rule_name = result.rule_name.clone();
                    let decision = if ctx.host_config.log_only_mode {
                        WafDecision {
                            action: WafAction::LogOnly,
                            result: Some(result),
                        }
                    } else {
                        let body = render_block_page(ctx, &rule_name);
                        WafDecision::block(403, Some(body), result)
                    };
                    self.log_security_event(ctx, &decision).await;
                    return decision;
                }
                AppSecResult::Allow | AppSecResult::Unavailable => {}
            }
        }

        // ── Phase 12: Custom rules engine ─────────────────────────────────────
        if let Some(result) = self.custom_rules.check(ctx) {
            let rule_name = result.rule_name.clone();
            let decision = if ctx.host_config.log_only_mode {
                WafDecision {
                    action: WafAction::LogOnly,
                    result: Some(result),
                }
            } else {
                let body = render_block_page(ctx, &rule_name);
                WafDecision::block(403, Some(body), result)
            };
            self.log_security_event(ctx, &decision).await;
            return decision;
        }

        // ── Phase 13: OWASP CRS ────────────────────────────────────────────────
        if let Some(result) = self.owasp.check(ctx) {
            let rule_name = result.rule_name.clone();
            let decision = if ctx.host_config.log_only_mode {
                WafDecision {
                    action: WafAction::LogOnly,
                    result: Some(result),
                }
            } else {
                let body = render_block_page(ctx, &rule_name);
                WafDecision::block(403, Some(body), result)
            };
            self.log_security_event(ctx, &decision).await;
            return decision;
        }

        // ── Phase 14: Sensitive data ───────────────────────────────────────────
        if let Some(result) = self.sensitive.check(ctx) {
            let rule_name = result.rule_name.clone();
            let decision = if ctx.host_config.log_only_mode {
                WafDecision {
                    action: WafAction::LogOnly,
                    result: Some(result),
                }
            } else {
                let body = render_block_page(ctx, &rule_name);
                WafDecision::block(403, Some(body), result)
            };
            self.log_security_event(ctx, &decision).await;
            return decision;
        }

        // ── Phase 15: Anti-hotlinking ──────────────────────────────────────────
        if let Some(result) = self.hotlink.check(ctx) {
            let rule_name = result.rule_name.clone();
            let decision = if ctx.host_config.log_only_mode {
                WafDecision {
                    action: WafAction::LogOnly,
                    result: Some(result),
                }
            } else {
                let body = render_block_page(ctx, &rule_name);
                WafDecision::block(403, Some(body), result)
            };
            self.log_security_event(ctx, &decision).await;
            return decision;
        }

        WafDecision::allow()
    }

    // ── Logging helpers ───────────────────────────────────────────────────────

    /// Log a Phase 1/2 event to the `attack_logs` table (fire-and-forget).
    async fn log_attack(&self, ctx: &RequestCtx, decision: &WafDecision) {
        let result = match &decision.result {
            Some(r) => r,
            None => return,
        };

        let action_str = match &decision.action {
            WafAction::Block { .. } => "block",
            WafAction::Allow => "allow",
            WafAction::LogOnly => "log_only",
            WafAction::Redirect { .. } => "redirect",
        };

        let log = AttackLog {
            id: Uuid::new_v4(),
            host_code: ctx.host_config.code.clone(),
            host: ctx.host.clone(),
            client_ip: ctx.client_ip.to_string(),
            method: ctx.method.clone(),
            path: ctx.path.clone(),
            query: if ctx.query.is_empty() {
                None
            } else {
                Some(ctx.query.clone())
            },
            rule_id: result.rule_id.clone(),
            rule_name: result.rule_name.clone(),
            action: action_str.to_string(),
            phase: result.phase.to_string(),
            detail: Some(result.detail.clone()),
            request_headers: None,
            created_at: chrono::Utc::now(),
        };

        let db = Arc::clone(&self.db);
        tokio::spawn(async move {
            if let Err(e) = db.create_attack_log(log).await {
                warn!("Failed to log attack event: {}", e);
            }
        });
    }

    /// Log a Phase 2+ security event to the `security_events` table (fire-and-forget).
    async fn log_security_event(&self, ctx: &RequestCtx, decision: &WafDecision) {
        let result = match &decision.result {
            Some(r) => r,
            None => return,
        };

        let action_str = match &decision.action {
            WafAction::Block { .. } => "block",
            WafAction::Allow => "allow",
            WafAction::LogOnly => "log_only",
            WafAction::Redirect { .. } => "redirect",
        };

        let event = CreateSecurityEvent {
            host_code: ctx.host_config.code.clone(),
            client_ip: ctx.client_ip.to_string(),
            method: ctx.method.clone(),
            path: ctx.path.clone(),
            rule_id: result.rule_id.clone(),
            rule_name: result.rule_name.clone(),
            action: action_str.to_string(),
            detail: Some(result.detail.clone()),
            geo_info: None,
        };

        let db = Arc::clone(&self.db);
        tokio::spawn(async move {
            if let Err(e) = db.create_security_event(event).await {
                warn!("Failed to log security event: {}", e);
            }
        });
    }
}
