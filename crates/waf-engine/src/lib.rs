pub mod block_page;
pub mod checker;
pub mod checks;
pub mod crowdsec;
pub mod engine;
pub mod geoip;
pub mod geoip_updater;
pub mod plugins;
pub mod rules;

pub use checker::RuleStore;
pub use checks::{AntiHotlinkCheck, GeoCheck, GeoRule, GeoRuleMode, OWASPCheck, SensitiveCheck};
pub use crowdsec::{
    init_crowdsec, CacheStats, CrowdSecChecker, CrowdSecClient, CrowdSecComponents,
    CrowdSecConfig, Decision, DecisionCache,
};
pub use engine::{WafEngine, WafEngineConfig};
pub use geoip::{cache_policy_from_str, GeoIpService};
pub use geoip_updater::{spawn_auto_updater, UpdateResult, XdbUpdater};
pub use plugins::{PluginAction, PluginInfo, PluginManager, WasmPlugin};
pub use rules::engine::{CustomRule, CustomRulesEngine};
pub use rules::formats::{ExportFormat, RuleFormat, ValidationError};
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
}

#[async_trait::async_trait]
impl RuleReloader for WafEngine {
    async fn on_rules_updated(&self, _version: u64) -> anyhow::Result<()> {
        self.reload_rules().await
    }
}
