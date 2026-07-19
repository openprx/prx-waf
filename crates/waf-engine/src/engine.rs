use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwapOption;
use parking_lot::RwLock as ParkingRwLock;
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
use crate::rules::cluster_sync::SyncedRuleStore;
use crate::rules::engine::{CustomRuleMatch, CustomRulesEngine, RuleAction, from_db_rule};
use crate::rules::registry::RuleRegistry;

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
    // ── Cluster data-plane sync ─────────────────────────────────────────────────
    /// Shared cluster rule registry (`NodeState.rule_registry`). Attached once
    /// via [`Self::attach_synced_registry`] when this node is part of a cluster.
    /// Its presence is what makes [`crate::RuleReloader::on_rules_updated`] consume
    /// synced rules instead of reloading from the local database (worker path).
    synced_registry: OnceLock<Arc<ParkingRwLock<RuleRegistry>>>,
    /// Request-path snapshot rebuilt from the synced registry on every sync.
    ///
    /// Kept **separate** from the database-backed stores so a DB reload never
    /// prunes synced rules and vice-versa. `None` until the first sync arrives;
    /// on a standalone (non-cluster) node it stays `None`, so the request path is
    /// byte-for-byte unchanged.
    synced: ArcSwapOption<SyncedRuleStore>,
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
            synced_registry: OnceLock::new(),
            synced: ArcSwapOption::empty(),
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

    // ── Cluster data-plane sync (worker consume side) ───────────────────────────

    /// Attach the shared cluster rule registry (`NodeState.rule_registry`).
    ///
    /// Called by the cluster↔engine wiring in `main.rs` when this node joins a
    /// cluster. Once attached, [`crate::RuleReloader::on_rules_updated`] rebuilds
    /// the request-path [`SyncedRuleStore`] from this registry instead of
    /// reloading from the local database — the DB-less worker path. Idempotent:
    /// a second call is ignored.
    pub fn attach_synced_registry(&self, registry: Arc<ParkingRwLock<RuleRegistry>>) {
        if self.synced_registry.set(registry).is_err() {
            warn!("synced registry already attached; ignoring duplicate attach");
        }
    }

    /// Returns `true` when a cluster synced registry has been attached.
    pub fn has_synced_registry(&self) -> bool {
        self.synced_registry.get().is_some()
    }

    /// Rebuild the request-path [`SyncedRuleStore`] from the attached registry
    /// and atomically publish it. No-op when no registry is attached.
    ///
    /// The rebuild happens off the request path; readers see either the previous
    /// snapshot or the new one, never a partially-populated store.
    pub fn refresh_synced_rules(&self) {
        let Some(registry) = self.synced_registry.get() else {
            return;
        };
        let store = {
            let guard = registry.read();
            SyncedRuleStore::from_registry(&guard)
        };
        self.synced.store(Some(Arc::new(store)));
    }

    /// Clear the request-path [`SyncedRuleStore`] (Worker→Main promotion).
    ///
    /// When a worker is elected Main it becomes the DB-authoritative source of
    /// rules, so the rules it previously consumed from the *old* Main must stop
    /// matching — otherwise the same rules are evaluated twice (once from the DB
    /// stores, once from the leftover synced store). Atomically publishes `None`
    /// so the request path falls back to the DB-backed stores on the next
    /// request.
    ///
    /// Idempotent and safe on a standalone node: storing `None` when the store is
    /// already `None` (never synced) is a no-op. The DB-backed stores are
    /// bucket-isolated and untouched. The attached registry itself is left in
    /// place; the worker pull loop stops once this node is Main, so the store is
    /// not re-populated.
    pub fn clear_synced_rules(&self) {
        self.synced.store(None);
    }

    /// Current synced-rule snapshot, if any. Cheap (an `Arc` clone) so it is safe
    /// to call once per request phase.
    fn synced_snapshot(&self) -> Option<Arc<SyncedRuleStore>> {
        self.synced.load_full()
    }

    /// Build a block (or log-only) decision from a detection result and record
    /// it to the security-event log (and optionally the community reporter).
    ///
    /// Centralises the previously-duplicated `render_block_page` / `log_only`
    /// branching that every detector phase used.
    fn record_block(&self, ctx: &RequestCtx, result: DetectionResult, report_community: bool) -> WafDecision {
        self.record_block_status(ctx, result, 403, None, report_community)
    }

    /// Like [`record_block`] but with a caller-supplied status code and optional
    /// override body (used by custom rules that set `action_status` /
    /// `action_msg`, M-7).
    fn record_block_status(
        &self,
        ctx: &RequestCtx,
        result: DetectionResult,
        status: u16,
        body_override: Option<String>,
        report_community: bool,
    ) -> WafDecision {
        let decision = if ctx.host_config.log_only_mode {
            WafDecision {
                action: WafAction::LogOnly,
                result: Some(result),
            }
        } else {
            let body = body_override.unwrap_or_else(|| render_block_page(ctx, &result.rule_name));
            WafDecision::block(status, Some(body), result)
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

        // Cluster-synced rules live in a separate, DB-isolated store. Snapshot
        // it once for this phase; `None` on a standalone node (zero overhead).
        let synced = self.synced_snapshot();

        // ── Phase 12: Custom rules engine (dispatch on the rule action, M-7) ──
        // Database-backed custom rules first, then cluster-synced ones. Both go
        // through the same dispatch so a synced rule behaves identically.
        if let Some(m) = self.custom_rules.check(ctx)
            && let Some(decision) = self.dispatch_custom_match(ctx, m)
        {
            return Some(decision);
        }
        if let Some(synced) = &synced
            && let Some(m) = synced.custom_rules.check(ctx)
            && let Some(decision) = self.dispatch_custom_match(ctx, m)
        {
            return Some(decision);
        }

        // ── Phase 13: OWASP CRS ────────────────────────────────────────────────
        if let Some(result) = self.owasp.check(ctx) {
            return Some(self.record_block(ctx, result, true));
        }

        // ── Phase 14: Sensitive data ───────────────────────────────────────────
        if let Some(result) = self.sensitive.check(ctx) {
            return Some(self.record_block(ctx, result, true));
        }
        if let Some(synced) = &synced
            && let Some(result) = synced.sensitive.check(ctx)
        {
            return Some(self.record_block(ctx, result, true));
        }

        None
    }

    /// Dispatch a custom-rule match on its configured action (M-7).
    ///
    /// Returns `Some(decision)` when the request must short-circuit (allow /
    /// block / challenge) and `None` when the rule only logged and the pipeline
    /// should continue. Shared by the database-backed and cluster-synced custom
    /// rule engines so both behave identically.
    fn dispatch_custom_match(&self, ctx: &RequestCtx, m: CustomRuleMatch) -> Option<WafDecision> {
        match m.action {
            // Allow acts as an explicit exception: short-circuit and allow.
            RuleAction::Allow => Some(WafDecision::allow()),
            // Log records the hit but lets the request continue the pipeline.
            RuleAction::Log => {
                let decision = WafDecision {
                    action: WafAction::LogOnly,
                    result: Some(m.result),
                };
                self.log_security_event(ctx, &decision);
                self.report_community_signal(ctx, &decision);
                None
            }
            // Block / Challenge deny using the rule's configured status code
            // (Challenge has no interactive backend yet, so it denies too).
            RuleAction::Block | RuleAction::Challenge => {
                Some(self.record_block_status(ctx, m.result, m.action_status, m.action_msg, true))
            }
        }
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

        // Cluster-synced IP/URL rules live in a separate, DB-isolated store.
        // Snapshot once for this pipeline; `None` on a standalone node.
        let synced = self.synced_snapshot();
        let host_code = ctx.host_config.code.clone();

        // ── Phase 1: IP Whitelist — allow immediately if matched ──────────────
        let ip_whitelist = check_ip_whitelist(ctx, &self.store);
        if let Some(ref result) = ip_whitelist.result
            && matches!(ip_whitelist.action, WafAction::Allow)
            && result.phase == waf_common::Phase::IpWhitelist
        {
            debug!("Request allowed by IP whitelist: {}", ctx.client_ip);
            return ip_whitelist;
        }
        if let Some(s) = &synced
            && s.allow_ips.matches(&host_code, ctx.client_ip)
        {
            debug!("Request allowed by synced IP whitelist: {}", ctx.client_ip);
            return WafDecision {
                action: WafAction::Allow,
                result: Some(DetectionResult {
                    rule_id: None,
                    rule_name: "IP Whitelist (Cluster Sync)".to_string(),
                    phase: waf_common::Phase::IpWhitelist,
                    detail: format!("IP {} matched synced whitelist", ctx.client_ip),
                }),
            };
        }

        // ── Phase 2: IP Blacklist — block if matched ───────────────────────────
        let ip_blacklist = check_ip_blacklist(ctx, &self.store);
        if !ip_blacklist.is_allowed() {
            self.log_attack(ctx, &ip_blacklist);
            self.report_community_signal(ctx, &ip_blacklist);
            return ip_blacklist;
        }
        if let Some(s) = &synced
            && s.block_ips.matches(&host_code, ctx.client_ip)
        {
            let decision = WafDecision::block(
                403,
                Some("Access denied.".to_string()),
                DetectionResult {
                    rule_id: None,
                    rule_name: "IP Blacklist (Cluster Sync)".to_string(),
                    phase: waf_common::Phase::IpBlacklist,
                    detail: format!("IP {} matched synced blacklist", ctx.client_ip),
                },
            );
            self.log_attack(ctx, &decision);
            self.report_community_signal(ctx, &decision);
            return decision;
        }

        // ── Phase 3: URL Whitelist — allow immediately if matched ──────────────
        if let Some(url_wl) = check_url_whitelist(ctx, &self.store) {
            debug!("Request allowed by URL whitelist: {}", ctx.path);
            return url_wl;
        }
        if let Some(s) = &synced {
            let decoded = crate::checks::url_decode(&ctx.path);
            if let Some(rule_id) = s.allow_urls.matches(&host_code, &decoded) {
                debug!("Request allowed by synced URL whitelist: {}", ctx.path);
                return WafDecision {
                    action: WafAction::Allow,
                    result: Some(DetectionResult {
                        rule_id: Some(rule_id),
                        rule_name: "URL Whitelist (Cluster Sync)".to_string(),
                        phase: waf_common::Phase::UrlWhitelist,
                        detail: format!("Path {} matched synced URL whitelist", ctx.path),
                    }),
                };
            }
        }

        // ── Phase 4: URL Blacklist — block if matched ──────────────────────────
        let url_bl = check_url_blacklist(ctx, &self.store);
        if !url_bl.is_allowed() {
            self.log_attack(ctx, &url_bl);
            self.report_community_signal(ctx, &url_bl);
            return url_bl;
        }
        if let Some(s) = &synced {
            // Match both the raw and decoded path (M-6 evasion parity).
            let decoded = crate::checks::url_decode(&ctx.path);
            let matched = s.block_urls.matches(&host_code, &ctx.path).or_else(|| {
                if decoded == ctx.path {
                    None
                } else {
                    s.block_urls.matches(&host_code, &decoded)
                }
            });
            if let Some(rule_id) = matched {
                let decision = WafDecision::block(
                    403,
                    Some("Access denied.".to_string()),
                    DetectionResult {
                        rule_id: Some(rule_id),
                        rule_name: "URL Blacklist (Cluster Sync)".to_string(),
                        phase: waf_common::Phase::UrlBlacklist,
                        detail: format!("Path {} matched synced URL blacklist", ctx.path),
                    },
                );
                self.log_attack(ctx, &decision);
                self.report_community_signal(ctx, &decision);
                return decision;
            }
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
