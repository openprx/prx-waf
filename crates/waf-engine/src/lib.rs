pub mod block_page;
pub mod checker;
pub mod checks;
pub mod community;
pub mod crowdsec;
pub mod engine;
pub mod geoip;
pub mod geoip_updater;
pub mod plugins;
pub mod rules;

pub use checker::RuleStore;
pub use checks::{
    AntiHotlinkCheck, ContentInspectionState, ContentSecuritySubsystem, ContentVerdict, GeoCheck, GeoRule, GeoRuleMode,
    InspectionScope, OWASPCheck, RuntimeContentSecurityConfig, SemanticAction, SemanticVerdict, SensitiveCheck,
};
pub use community::{
    CommunityChecker, CommunityClient, CommunityComponents, CommunityConfig, CommunityReporter, RequestInfo,
    init_community,
};
pub use crowdsec::{
    CacheStats, CrowdSecChecker, CrowdSecClient, CrowdSecComponents, CrowdSecConfig, Decision, DecisionCache,
    init_crowdsec,
};
pub use engine::{WafEngine, WafEngineConfig};
pub use geoip::{GeoIpService, cache_policy_from_str};
pub use geoip_updater::{UpdateResult, XdbUpdater, spawn_auto_updater};
pub use plugins::{PluginAction, PluginInfo, PluginManager, WasmPlugin};
pub use rules::cluster_sync::{self, SyncedRuleStore};
pub use rules::engine::{CustomRule, CustomRulesEngine};
pub use rules::formats::{ExportFormat, RuleFormat, ValidationError};
pub use rules::ip_feed::{IpFeedFormat, IpFeedSource, spawn_ip_feed_sync};
pub use rules::manager::RuleManager;
pub use rules::registry::{Rule, RuleRegistry, RuleStats};
pub use rules::sources::{RuleLoadReport, RuleReloadReport, RuleSource};

/// Callback trait invoked by the cluster sync layer after rules are updated.
///
/// `WafEngine` provides the canonical implementation, which delegates to its
/// existing `reload_rules()` method.  Test code (and workers without a live
/// engine) can supply a no-op implementation.
#[async_trait::async_trait]
pub trait RuleReloader: Send + Sync {
    /// Called after the local `RuleRegistry` has been mutated by a cluster
    /// sync operation.  `version` is the authoritative version received from
    /// the main node.
    async fn on_rules_updated(&self, version: u64) -> anyhow::Result<()>;

    /// Called exactly once when this node is promoted Worker→Main.
    ///
    /// A freshly-promoted Main is the DB-authoritative rule source, so any rules
    /// it previously consumed from the old Main (the cluster-synced store) must
    /// stop matching to avoid double evaluation. The default implementation is a
    /// no-op; `WafEngine` overrides it to drop its synced store. Idempotent, so a
    /// spurious call on a node that is already Main (or never synced) is
    /// harmless.
    async fn on_promoted_to_main(&self) {}
}

#[async_trait::async_trait]
impl RuleReloader for WafEngine {
    /// Called by the cluster sync layer after `NodeState.rule_registry` has been
    /// mutated by a pull from the authenticated Main.
    ///
    /// When a cluster registry is attached (worker / DB-less path), rebuild the
    /// request-path [`SyncedRuleStore`] from the freshly-synced registry so the
    /// **next request** evaluates the new rules without touching the local
    /// database. The synced store is bucket-isolated from the DB stores, so this
    /// never prunes DB-loaded rules and a DB reload never prunes synced rules.
    ///
    /// Without an attached registry (standalone node), fall back to the historic
    /// database reload so single-node behaviour is unchanged.
    async fn on_rules_updated(&self, _version: u64) -> anyhow::Result<()> {
        if self.has_synced_registry() {
            self.refresh_synced_rules();
            Ok(())
        } else {
            self.reload_rules().await
        }
    }

    /// Drop the request-path synced store on Worker→Main promotion so this node
    /// stops matching rules it consumed from the old Main and relies solely on
    /// its DB-authoritative stores. No-op on a standalone node that never synced.
    async fn on_promoted_to_main(&self) {
        self.clear_synced_rules();
    }
}
