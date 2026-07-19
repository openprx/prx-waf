pub mod config;
pub mod events;
pub mod rules;
pub mod scheduler;

use async_trait::async_trait;
use tracing::warn;
use waf_engine::RuleReloader;

use crate::node::NodeState;
use crate::protocol::{ApiForward, ApiForwardResponse, ConfigSync, RuleSyncResponse};

pub use scheduler::{SYNC_INTERVAL_MS, run_config_broadcast_loop, run_rule_pull_loop};

/// Executes an API write request forwarded from a worker on the main node.
///
/// A `ForwardOnly` worker has no local database, so mutating API calls are
/// tunnelled to the main over the cluster QUIC link. The main node attaches an
/// implementation of this trait so the transport dispatch can run the write
/// against the real API/storage layer and return the HTTP result.
#[async_trait]
pub trait ApiForwardHandler: Send + Sync {
    /// Handle a forwarded write and produce the response to relay back to the
    /// originating worker's HTTP client.
    async fn handle(&self, request: ApiForward) -> ApiForwardResponse;
}

/// No-op rule reloader used when no data-plane engine is attached (unit tests,
/// or a node whose engine wiring is deferred).
///
/// Synced rules are still applied to the shared registry; only the post-apply
/// engine notification is skipped.
pub struct NoopRuleReloader;

#[async_trait]
impl RuleReloader for NoopRuleReloader {
    async fn on_rules_updated(&self, _version: u64) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Apply a rule-sync push (`RuleSyncResponse`) received from a peer.
///
/// # Security (H-9)
///
/// The push is applied **only** when `auth_id` — the identity proven by the
/// peer's mTLS certificate — is the current cluster Main, as recorded from an
/// accepted `JoinResponse` or an authenticated `ElectionResult`. A worker never
/// accepts rule state from a non-Main source; doing so would be an
/// unauthenticated cluster-wide rule write (`apply_full_snapshot` clears and
/// replaces the registry), which is exactly the risk H-9 exists to prevent.
/// Pushes from any other identity are dropped with a warning.
pub async fn apply_incoming_rule_sync(node_state: &NodeState, auth_id: &str, response: RuleSyncResponse) {
    if !node_state.is_current_main(auth_id).await {
        warn!(
            sender = %auth_id,
            version = response.version,
            "Dropping RuleSyncResponse: sender is not the authenticated cluster Main"
        );
        return;
    }
    // Capture the authoritative version before `response` is moved into the
    // applier so we can advance the telemetry counter after a successful apply.
    let version = response.version;
    let reloader = node_state.rule_reloader();
    if let Err(e) = rules::apply_sync_response_shared(response, &node_state.rule_registry, reloader.as_ref()).await {
        warn!("Failed to apply rule sync from main: {e}");
        return;
    }
    // Only now that the rules are live in the data-plane registry do we reflect
    // the applied version in the `cluster/status` telemetry. Monotonic, so an
    // out-of-order or stale push never regresses the reported version. This
    // mirrors how `apply_incoming_config_sync` advances `config_version`.
    node_state.advance_rules_version(version).await;
}

/// Apply a config-sync push received from a peer.
///
/// Auth-gated to the current Main for the same reason as [`apply_incoming_rule_sync`].
pub async fn apply_incoming_config_sync(node_state: &NodeState, auth_id: &str, sync: &ConfigSync) {
    if !node_state.is_current_main(auth_id).await {
        warn!(sender = %auth_id, "Dropping ConfigSync: sender is not the authenticated cluster Main");
        return;
    }
    let applied = node_state.config_syncer.lock().await.apply_sync(sync);
    match applied {
        Ok(()) => {
            node_state.set_config_version(sync.version).await;
        }
        Err(e) => warn!("Failed to apply config sync: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use waf_common::config::ClusterConfig;
    use waf_engine::Rule;

    use super::rules::snapshot_rules;
    use super::*;
    use crate::node::{NodeState, StorageMode};
    use crate::protocol::{ChangeOp, RuleChange, RuleSyncResponse, SyncType};

    fn worker(id: &str) -> Arc<NodeState> {
        let cfg = ClusterConfig {
            node_id: id.to_string(),
            ..ClusterConfig::default()
        };
        Arc::new(NodeState::new(cfg, StorageMode::ForwardOnly).expect("NodeState::new"))
    }

    fn rule(id: &str) -> Rule {
        Rule {
            id: id.to_string(),
            name: format!("rule {id}"),
            description: None,
            category: "custom".to_string(),
            source: "cluster".to_string(),
            enabled: true,
            action: "block".to_string(),
            severity: Some("high".to_string()),
            pattern: Some("evil".to_string()),
            tags: Vec::new(),
            metadata: std::collections::HashMap::new(),
        }
    }

    fn full_snapshot_response(version: u64, rules: &[Rule]) -> RuleSyncResponse {
        RuleSyncResponse {
            version,
            sync_type: SyncType::Full,
            changes: Vec::new(),
            snapshot_lz4: snapshot_rules(rules).expect("snapshot"),
        }
    }

    fn incremental_upsert(version: u64, r: &Rule) -> RuleSyncResponse {
        RuleSyncResponse {
            version,
            sync_type: SyncType::Incremental,
            changes: vec![RuleChange {
                op: ChangeOp::Upsert,
                rule_id: r.id.clone(),
                rule_json: Some(serde_json::to_value(r).expect("serialize rule")),
            }],
            snapshot_lz4: Vec::new(),
        }
    }

    /// Clone the registry contents + version out from under the read lock so
    /// assertions never hold the guard (keeps clippy's drop-tightening lint happy).
    fn snapshot(node: &NodeState) -> (std::collections::HashMap<String, Rule>, u64) {
        let reg = node.rule_registry.read();
        (reg.rules.clone(), reg.version)
    }

    #[tokio::test]
    async fn rule_sync_from_non_main_is_rejected() {
        let node = worker("worker-1");
        node.set_main_node_id("main-A".to_string()).await;

        // A peer authenticated as "attacker-B" (not the Main) pushes rules.
        apply_incoming_rule_sync(&node, "attacker-B", full_snapshot_response(7, &[rule("r1")])).await;

        let (rules, version) = snapshot(&node);
        assert!(
            !rules.contains_key("r1"),
            "a non-Main peer must not be able to push rules into the data plane"
        );
        assert_eq!(version, 0, "registry version must be untouched by a rejected push");
        assert_eq!(
            *node.rules_version.read().await,
            0,
            "cluster/status telemetry must not advance for a rejected push"
        );
    }

    #[tokio::test]
    async fn rule_sync_with_no_known_main_is_rejected() {
        // main_node_id is None until the worker has joined / seen an election.
        let node = worker("worker-1");
        apply_incoming_rule_sync(&node, "anyone", full_snapshot_response(3, &[rule("r1")])).await;
        assert!(!snapshot(&node).0.contains_key("r1"));
    }

    #[tokio::test]
    async fn rule_sync_from_authenticated_main_is_applied_and_takes_effect() {
        let node = worker("worker-1");
        node.set_main_node_id("main-A".to_string()).await;

        // Full snapshot from the authenticated Main.
        apply_incoming_rule_sync(&node, "main-A", full_snapshot_response(9, &[rule("r1")])).await;
        let (rules, version) = snapshot(&node);
        let applied = rules
            .get("r1")
            .expect("synced rule must be present in the data-plane registry");
        assert!(applied.enabled, "synced rule must be live (enabled)");
        assert_eq!(applied.pattern.as_deref(), Some("evil"));
        assert_eq!(version, 9, "registry version follows the Main's authoritative version");
        assert_eq!(
            *node.rules_version.read().await,
            9,
            "cluster/status telemetry must report the applied version after a full snapshot"
        );

        // A follow-up incremental upsert from the Main also takes effect.
        let mut r2 = rule("r2");
        r2.action = "log".to_string();
        apply_incoming_rule_sync(&node, "main-A", incremental_upsert(10, &r2)).await;
        let (rules, version) = snapshot(&node);
        assert!(rules.contains_key("r1"), "existing rule survives an incremental update");
        assert_eq!(rules.get("r2").map(|r| r.action.as_str()), Some("log"));
        assert_eq!(version, 10);
        assert_eq!(
            *node.rules_version.read().await,
            10,
            "cluster/status telemetry advances with each applied incremental push"
        );

        // A stale/out-of-order push carrying an older version is still applied to
        // the registry, but must not regress the monotonic telemetry counter.
        apply_incoming_rule_sync(&node, "main-A", incremental_upsert(4, &r2)).await;
        assert_eq!(
            *node.rules_version.read().await,
            10,
            "cluster/status telemetry is monotonic and never regresses"
        );
    }

    #[tokio::test]
    async fn full_snapshot_replaces_removed_rules() {
        let node = worker("worker-1");
        node.set_main_node_id("main-A".to_string()).await;

        apply_incoming_rule_sync(&node, "main-A", full_snapshot_response(1, &[rule("r1"), rule("r2")])).await;
        assert_eq!(snapshot(&node).0.len(), 2);

        // A later full snapshot without r2 must drop it (clear + replace).
        apply_incoming_rule_sync(&node, "main-A", full_snapshot_response(2, &[rule("r1")])).await;
        let (rules, _) = snapshot(&node);
        assert!(rules.contains_key("r1"));
        assert!(
            !rules.contains_key("r2"),
            "rules deleted on the Main are removed on the worker"
        );
    }

    #[tokio::test]
    async fn config_sync_is_gated_to_the_authenticated_main() {
        let node = worker("worker-1");
        node.set_main_node_id("main-A".to_string()).await;

        let sync = ConfigSync {
            version: 5,
            config_toml: "x = 1".to_string(),
        };

        // Rejected from a non-Main peer.
        apply_incoming_config_sync(&node, "attacker-B", &sync).await;
        assert_eq!(*node.config_version.read().await, 0);

        // Accepted from the authenticated Main.
        apply_incoming_config_sync(&node, "main-A", &sync).await;
        assert_eq!(*node.config_version.read().await, 5);
        assert_eq!(node.config_syncer.lock().await.current_version(), 5);
    }

    #[tokio::test]
    async fn main_records_change_and_answers_worker_pull() {
        // Main records an authoritative change; a worker pull is then answered
        // with a response that carries the rule.
        let main = Arc::new(
            NodeState::new(
                ClusterConfig {
                    node_id: "main-A".to_string(),
                    role: "main".to_string(),
                    ..ClusterConfig::default()
                },
                StorageMode::Full,
            )
            .expect("NodeState::new"),
        );

        main.record_rule_change(ChangeOp::Upsert, "r1".to_string(), Some(rule("r1")))
            .await;
        assert_eq!(*main.rules_version.read().await, 1);
        assert!(snapshot(&main).0.contains_key("r1"));

        // Build a sync response for a brand-new worker (version 0).
        let rules: Vec<Rule> = snapshot(&main).0.into_values().collect();
        let response = {
            let changelog = main.rule_changelog.lock().await;
            rules::handle_sync_request(
                &changelog,
                &crate::protocol::RuleSyncRequest { current_version: 0 },
                &rules,
            )
            .expect("handle_sync_request")
        };
        // A brand-new worker (version 0) precedes the first recorded change
        // (version 1) → it receives a full snapshot carrying the current rules.
        assert_eq!(response.version, 1);
        assert!(matches!(response.sync_type, SyncType::Full));
        let restored = rules::restore_snapshot(&response.snapshot_lz4).expect("restore snapshot");
        assert_eq!(restored.len(), 1);
        assert_eq!(restored.first().map(|r| r.id.as_str()), Some("r1"));

        // A worker already at version 1 asking after a version-2 change gets an
        // incremental delta instead.
        main.record_rule_change(ChangeOp::Delete, "r1".to_string(), None).await;
        let rules2: Vec<Rule> = snapshot(&main).0.into_values().collect();
        let inc = {
            let changelog2 = main.rule_changelog.lock().await;
            rules::handle_sync_request(
                &changelog2,
                &crate::protocol::RuleSyncRequest { current_version: 1 },
                &rules2,
            )
            .expect("handle_sync_request")
        };
        assert!(matches!(inc.sync_type, SyncType::Incremental));
        assert_eq!(inc.version, 2);
        assert_eq!(inc.changes.len(), 1);
        assert!(matches!(inc.changes.first().map(|c| c.op), Some(ChangeOp::Delete)));
    }
}
