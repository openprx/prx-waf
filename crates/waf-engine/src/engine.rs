use std::sync::{Arc, OnceLock};
use tracing::{debug, warn};
use uuid::Uuid;

use waf_common::{DetectionResult, RequestCtx, WafAction, WafDecision};
use waf_storage::{
    Database,
    models::{AttackLog, CreateSecurityEvent},
};

use crate::block_page::render_block_page;
use crate::checker::{RuleStore, check_ip_blacklist, check_ip_whitelist, check_url_blacklist, check_url_whitelist};
use crate::checks::{
    AntiHotlinkCheck, BotCheck, CcCheck, Check, DirTraversalCheck, GeoCheck, OWASPCheck, RceCheck, ScannerCheck,
    SensitiveCheck, SqlInjectionCheck, XssCheck,
};
use crate::community::{CommunityChecker, CommunityReporter, RequestInfo};
use crate::crowdsec::{AppSecClient, AppSecResult, CrowdSecChecker, FallbackAction, appsec_to_detection};
use crate::geoip::GeoIpService;
use crate::rules::engine::{CustomRulesEngine, from_db_rule};

/// WAF engine configuration
#[derive(Debug, Clone, Default)]
pub struct WafEngineConfig {
    /// Whether to log allowed requests that matched whitelist rules
    pub log_whitelist_hits: bool,
}

/// Main WAF engine — runs all detection phases.
///
/// Phase 1-4  : IP / URL whitelist + blacklist (fast-path)
/// Phase 16   : `CrowdSec` bouncer (cache lookup — runs early for efficiency)
/// Phase 5-11 : Attack detection (CC, scanner, bot, `SQLi`, XSS, RCE, traversal)
/// Phase 16b  : `CrowdSec` `AppSec` (async HTTP check — runs after local detectors)
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
    /// CC / rate-limit checker.
    ///
    /// Kept as a dedicated field (not inside a checker vector) so it is invoked
    /// **exactly once per request** — in the header phase ([`inspect`]) only —
    /// preventing the double-counting that would otherwise occur when a request
    /// with a body is inspected again in [`inspect_body`].
    cc_check: CcCheck,
    /// Header-phase-only detectors (scanner / bot). Not re-run for body content.
    header_checkers: Vec<Box<dyn Check>>,
    /// Content-type detectors (`SQLi` / XSS / RCE / traversal) run in both the
    /// header phase and the body phase (once `body_preview` is populated).
    content_checkers: Vec<Box<dyn Check>>,
    owasp: Arc<OWASPCheck>,
    /// GeoIP-based access control check (Phase 17).
    geo_check: Arc<GeoCheck>,
    // ── Phase 6: `CrowdSec` ───────────────────────────────────────────────────
    /// Bouncer checker (set once after engine construction via `set_crowdsec`)
    crowdsec_checker: OnceLock<Arc<CrowdSecChecker>>,
    /// `AppSec` client (set once after engine construction via `set_crowdsec`)
    appsec_client: OnceLock<Arc<AppSecClient>>,
    // ── Community ──────────────────────────────────────────────────────────
    /// Community blocklist checker (set once after engine construction via `set_community`)
    community_checker: OnceLock<Arc<CommunityChecker>>,
    /// Community signal reporter for pushing detections (set once via `set_community_reporter`)
    community_reporter: OnceLock<Arc<CommunityReporter>>,
    // ── `GeoIP` ────────────────────────────────────────────────────────────────
    /// `GeoIP` lookup service (set once after engine construction via `set_geoip`)
    geoip: OnceLock<Arc<GeoIpService>>,
}

impl WafEngine {
    pub fn new(db: Arc<Database>, config: WafEngineConfig) -> Self {
        let store = Arc::new(RuleStore::new(Arc::clone(&db)));
        let custom_rules = Arc::new(CustomRulesEngine::new());
        let sensitive = Arc::new(SensitiveCheck::new());
        let hotlink = Arc::new(AntiHotlinkCheck::new());
        let owasp = Arc::new(OWASPCheck::new());
        let geo_check = Arc::new(GeoCheck::new());

        // CC is a dedicated field (single counting point — see field docs).
        let cc_check = CcCheck::new();

        // Header-phase-only detectors.
        let header_checkers: Vec<Box<dyn Check>> = vec![Box::new(ScannerCheck::new()), Box::new(BotCheck::new())];

        // Content-type detectors — re-used by both the header and body phases.
        let content_checkers: Vec<Box<dyn Check>> = vec![
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
            cc_check,
            header_checkers,
            content_checkers,
            owasp,
            geo_check,
            crowdsec_checker: OnceLock::new(),
            appsec_client: OnceLock::new(),
            community_checker: OnceLock::new(),
            community_reporter: OnceLock::new(),
            geoip: OnceLock::new(),
        }
    }

    /// Plug `CrowdSec` components into the engine (called once after init).
    pub fn set_crowdsec(&self, checker: Arc<CrowdSecChecker>, appsec: Option<Arc<AppSecClient>>) {
        let _ = self.crowdsec_checker.set(checker);
        if let Some(ac) = appsec {
            let _ = self.appsec_client.set(ac);
        }
    }

    /// Plug the community checker into the engine (called once after init).
    pub fn set_community(&self, checker: Arc<CommunityChecker>) {
        let _ = self.community_checker.set(checker);
    }

    /// Plug the community signal reporter into the engine (called once after init).
    ///
    /// When set, every WAF detection (block or `log_only`) is pushed to the
    /// community reporter buffer for eventual batch upload.
    pub fn set_community_reporter(&self, reporter: Arc<CommunityReporter>) {
        let _ = self.community_reporter.set(reporter);
    }

    /// Plug the `GeoIP` lookup service into the engine (called once after init).
    ///
    /// After this call every request will have its `ctx.geo` populated before
    /// the checker pipeline runs, enabling `GeoIP`-based rules.
    pub fn set_geoip(&self, service: Arc<GeoIpService>) {
        let _ = self.geoip.set(service);
    }

    /// Return a reference to the `GeoCheck` so callers can load rules.
    pub const fn geo_check(&self) -> &Arc<GeoCheck> {
        &self.geo_check
    }

    /// Reload all rules from the database
    pub async fn reload_rules(&self) -> anyhow::Result<()> {
        // Reload IP/URL rules
        self.store.reload_all().await?;

        // Reload custom rules
        let custom_rules = self.db.list_custom_rules(None).await?;
        {
            let mut by_host: std::collections::HashMap<String, Vec<_>> = std::collections::HashMap::new();
            for row in &custom_rules {
                match from_db_rule(row) {
                    Ok(rule) => {
                        by_host.entry(row.host_code.clone()).or_default().push(rule);
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
            let mut by_host: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
            for row in &patterns {
                if row.check_request {
                    by_host
                        .entry(row.host_code.clone())
                        .or_default()
                        .push(row.pattern.clone());
                }
            }
            for (host_code, pats) in by_host {
                self.sensitive.load_host(&host_code, &pats);
            }
        }

        // Reload hotlink configs
        let hotlink_configs = self.db.list_hotlink_configs().await?;
        for row in &hotlink_configs {
            let domains: Vec<String> = row
                .allowed_domains
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
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

    /// Build a block (or log-only) decision from a detection result and record
    /// it to the security-event log (and optionally the community reporter).
    ///
    /// Centralises the previously-duplicated `render_block_page` / `log_only`
    /// branching that every detector phase used.
    fn record_block(&self, ctx: &RequestCtx, result: DetectionResult, report_community: bool) -> WafDecision {
        let decision = if ctx.host_config.log_only_mode {
            WafDecision {
                action: WafAction::LogOnly,
                result: Some(result),
            }
        } else {
            let body = render_block_page(ctx, &result.rule_name);
            WafDecision::block(403, Some(body), result)
        };
        self.log_security_event(ctx, &decision);
        if report_community {
            self.report_community_signal(ctx, &decision);
        }
        decision
    }

    /// Content-type detection sub-pipeline shared by the header and body phases.
    ///
    /// Runs `SQLi` / XSS / RCE / traversal, `CrowdSec` `AppSec`, custom rules,
    /// OWASP CRS and sensitive-data detection.  It deliberately does **not** run
    /// CC / IP / URL / geo / bouncer / community — those are header-phase-only
    /// and must be evaluated exactly once per request (see [`inspect`]).
    async fn inspect_content(&self, ctx: &RequestCtx) -> Option<WafDecision> {
        // ── Phase 5-9: SQLi / XSS / RCE / traversal ───────────────────────────
        for checker in &self.content_checkers {
            if let Some(result) = checker.check(ctx) {
                return Some(self.record_block(ctx, result, true));
            }
        }

        // ── Phase 16b: CrowdSec AppSec — async per-request check ──────────────
        if let Some(appsec) = self.appsec_client.get() {
            match appsec.check_request(ctx).await {
                AppSecResult::Block { message } => {
                    let result = appsec_to_detection(message);
                    return Some(self.record_block(ctx, result, true));
                }
                AppSecResult::Allow => {}
                // H-4: apply the configured failure_action instead of always
                // failing open.
                AppSecResult::Unavailable => match appsec.failure_action() {
                    FallbackAction::Block => {
                        let result = crate::crowdsec::appsec::appsec_unavailable_detection();
                        return Some(self.record_block(ctx, result, false));
                    }
                    FallbackAction::Log => {
                        // Record the outage but let the request continue.
                        let result = crate::crowdsec::appsec::appsec_unavailable_detection();
                        let decision = WafDecision {
                            action: WafAction::LogOnly,
                            result: Some(result),
                        };
                        self.log_security_event(ctx, &decision);
                    }
                    FallbackAction::Allow => {}
                },
            }
        }

        // ── Phase 12: Custom rules engine ─────────────────────────────────────
        if let Some(result) = self.custom_rules.check(ctx) {
            return Some(self.record_block(ctx, result, true));
        }

        // ── Phase 13: OWASP CRS ────────────────────────────────────────────────
        if let Some(result) = self.owasp.check(ctx) {
            return Some(self.record_block(ctx, result, true));
        }

        // ── Phase 14: Sensitive data ───────────────────────────────────────────
        if let Some(result) = self.sensitive.check(ctx) {
            return Some(self.record_block(ctx, result, true));
        }

        None
    }

    /// Run the header-phase WAF inspection pipeline (the full pipeline).
    ///
    /// `ctx` is taken as `&mut` so the engine can enrich it with `GeoIP` data
    /// before the checker pipeline runs.  This is the **only** place CC / IP /
    /// URL / geo / bouncer / community checks run, so rate-limit counting and
    /// community reporting happen exactly once per request.  Callers should
    /// check `decision.is_allowed()`.
    pub async fn inspect(&self, ctx: &mut RequestCtx) -> WafDecision {
        // Skip WAF if guard is disabled for this host
        if !ctx.host_config.guard_status {
            return WafDecision::allow();
        }

        // ── GeoIP enrichment — populate ctx.geo before any checks ────────────
        if let Some(geoip) = self.geoip.get() {
            ctx.geo = Some(geoip.lookup(ctx.client_ip));
        }

        // ── Phase 1: IP Whitelist — allow immediately if matched ──────────────
        let ip_whitelist = check_ip_whitelist(ctx, &self.store);
        if let Some(ref result) = ip_whitelist.result
            && matches!(ip_whitelist.action, WafAction::Allow)
            && result.phase == waf_common::Phase::IpWhitelist
        {
            debug!("Request allowed by IP whitelist: {}", ctx.client_ip);
            return ip_whitelist;
        }

        // ── Phase 2: IP Blacklist — block if matched ───────────────────────────
        let ip_blacklist = check_ip_blacklist(ctx, &self.store);
        if !ip_blacklist.is_allowed() {
            self.log_attack(ctx, &ip_blacklist);
            self.report_community_signal(ctx, &ip_blacklist);
            return ip_blacklist;
        }

        // ── Phase 3: URL Whitelist — allow immediately if matched ──────────────
        if let Some(url_wl) = check_url_whitelist(ctx, &self.store) {
            debug!("Request allowed by URL whitelist: {}", ctx.path);
            return url_wl;
        }

        // ── Phase 4: URL Blacklist — block if matched ──────────────────────────
        let url_bl = check_url_blacklist(ctx, &self.store);
        if !url_bl.is_allowed() {
            self.log_attack(ctx, &url_bl);
            self.report_community_signal(ctx, &url_bl);
            return url_bl;
        }

        // ── Phase 16a: CrowdSec Bouncer — fast cache lookup ───────────────────
        if let Some(cs) = self.crowdsec_checker.get()
            && let Some(result) = cs.check(ctx)
        {
            return self.record_block(ctx, result, true);
        }

        // ── Phase 18: Community blocklist ─────────────────────────────────────
        if let Some(cc) = self.community_checker.get()
            && let Some(result) = cc.check(ctx)
        {
            // Community detections are not reported back to the community feed.
            return self.record_block(ctx, result, false);
        }

        // ── Phase 17: GeoIP access control ────────────────────────────────────
        if let Some(result) = self.geo_check.check(ctx) {
            return self.record_block(ctx, result, true);
        }

        // ── Phase 11: CC / rate limit — single counting point ─────────────────
        if let Some(result) = self.cc_check.check(ctx) {
            return self.record_block(ctx, result, true);
        }

        // ── Phase 8 / 10: scanner + bot (header-only) ─────────────────────────
        for checker in &self.header_checkers {
            if let Some(result) = checker.check(ctx) {
                return self.record_block(ctx, result, true);
            }
        }

        // ── Phase 5-14: content-type detectors + custom + owasp + sensitive ───
        if let Some(decision) = self.inspect_content(ctx).await {
            return decision;
        }

        // ── Phase 15: Anti-hotlinking ──────────────────────────────────────────
        if let Some(result) = self.hotlink.check(ctx) {
            return self.record_block(ctx, result, true);
        }

        WafDecision::allow()
    }

    /// Run the body-phase WAF inspection.
    ///
    /// Only content-type detection runs here (`SQLi` / XSS / RCE / traversal /
    /// sensitive / custom / OWASP / `AppSec`) against the now-populated
    /// `body_preview`.  CC / IP / URL / geo / bouncer / community are **not**
    /// re-run — they were already evaluated (and counted) in [`inspect`] during
    /// the header phase.
    pub async fn inspect_body(&self, ctx: &mut RequestCtx) -> WafDecision {
        // Skip WAF if guard is disabled for this host
        if !ctx.host_config.guard_status {
            return WafDecision::allow();
        }

        // Enrich GeoIP for custom rules that reference geo fields on the body
        // phase (the header-phase enrichment ran on a separate ctx clone).
        if let Some(geoip) = self.geoip.get()
            && ctx.geo.is_none()
        {
            ctx.geo = Some(geoip.lookup(ctx.client_ip));
        }

        if let Some(decision) = self.inspect_content(ctx).await {
            return decision;
        }

        WafDecision::allow()
    }

    // ── Logging helpers ───────────────────────────────────────────────────────

    /// Log a Phase 1/2 event to the `attack_logs` table (fire-and-forget).
    fn log_attack(&self, ctx: &RequestCtx, decision: &WafDecision) {
        let Some(result) = &decision.result else {
            return;
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
            geo_info: ctx.geo.as_ref().map(|g| {
                serde_json::json!({
                    "country": g.country,
                    "province": g.province,
                    "city": g.city,
                    "isp": g.isp,
                    "iso_code": g.iso_code,
                })
            }),
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
    fn log_security_event(&self, ctx: &RequestCtx, decision: &WafDecision) {
        let Some(result) = &decision.result else {
            return;
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
            geo_info: ctx.geo.as_ref().map(|g| {
                serde_json::json!({
                    "country": g.country,
                    "province": g.province,
                    "city": g.city,
                    "isp": g.isp,
                    "iso_code": g.iso_code,
                })
            }),
        };

        let db = Arc::clone(&self.db);
        tokio::spawn(async move {
            if let Err(e) = db.create_security_event(event).await {
                warn!("Failed to log security event: {}", e);
            }
        });
    }

    /// Push a detection signal to the community reporter via bounded channel.
    ///
    /// This is a **synchronous** call on the hot path — no `tokio::spawn`,
    /// no async mutex, just a single `try_send` into an MPSC channel.
    /// When the channel is full (back-pressure from flood traffic), the signal is silently
    /// dropped and the reporter logs the drop count periodically.
    fn report_community_signal(&self, ctx: &RequestCtx, decision: &WafDecision) {
        let Some(reporter) = self.community_reporter.get() else {
            return;
        };
        let Some(result) = &decision.result else {
            return;
        };

        let req_info = RequestInfo {
            http_method: ctx.method.clone(),
            request_path: ctx.path.clone(),
            request_host: ctx.host.clone(),
            geo_country: ctx.geo.as_ref().map(|g| g.iso_code.clone()),
        };

        reporter.try_push_detection(ctx.client_ip, result, Some(&req_info));
    }
}
