//! Hook that broadcasts admin rule changes to the cluster.
//!
//! When an administrator creates or deletes a detection-affecting rule through
//! the management API, the change must reach every worker's request path. This
//! module bridges the API handlers to the cluster's authoritative changelog via
//! `NodeState::record_rule_change`, which appends the change and broadcasts an
//! incremental push to dialed peers.
//!
//! # Main-only
//!
//! Recording a change is only meaningful on the **Main** node — it owns the
//! authoritative changelog that workers pull from. A worker that recorded its
//! own change would bump its local registry version and push to its Main peer,
//! corrupting the sync direction. Admin writes on a worker should instead be
//! write-forwarded to the Main (the `cluster_forward` machinery); until that is
//! wired into the API layer, this hook simply **skips** the broadcast on a
//! worker so a local edit never triggers an erroneous push. The local database
//! write itself is unaffected.
//!
//! On a standalone (non-cluster) node `cluster_state` is `None` and every call
//! is a no-op, so single-node behaviour is unchanged.

use std::sync::Arc;

use waf_cluster::NodeState;
use waf_cluster::protocol::ChangeOp;
use waf_common::config::NodeRole;
use waf_engine::Rule;

/// Record a rule change on the cluster **only when this node is the Main**.
///
/// * `cluster_state` — `None` on a standalone node → no-op.
/// * `rule` — `Some` for an upsert, `None` for a delete.
pub async fn record_if_main(cluster_state: Option<&Arc<NodeState>>, op: ChangeOp, rule_id: String, rule: Option<Rule>) {
    let Some(node) = cluster_state else {
        return;
    };
    if node.current_role().await != NodeRole::Main {
        // Worker edit: the local DB write already happened; skip the broadcast
        // so we never push in the wrong direction.
        return;
    }
    node.record_rule_change(op, rule_id, rule).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use waf_cluster::StorageMode;
    use waf_common::config::ClusterConfig;
    use waf_engine::cluster_sync::{SyncedKind, registry_id};

    fn node(node_id: &str, role: &str) -> Arc<NodeState> {
        let cfg = ClusterConfig {
            node_id: node_id.to_string(),
            role: role.to_string(),
            ..ClusterConfig::default()
        };
        Arc::new(NodeState::new(cfg, StorageMode::Full).expect("NodeState::new"))
    }

    fn sample_rule(id: &str) -> Rule {
        Rule {
            id: id.to_string(),
            name: "n".to_string(),
            description: None,
            category: "cluster-custom".to_string(),
            source: "cluster".to_string(),
            enabled: true,
            action: "block".to_string(),
            severity: None,
            pattern: None,
            tags: Vec::new(),
            metadata: std::collections::HashMap::new(),
        }
    }

    #[tokio::test]
    async fn main_records_and_bumps_version() {
        let main = node("main-a", "main");
        let id = uuid::Uuid::new_v4();
        let rid = registry_id(SyncedKind::Custom, id);
        record_if_main(Some(&main), ChangeOp::Upsert, rid.clone(), Some(sample_rule(&rid))).await;

        assert_eq!(*main.rules_version.read().await, 1, "main must record the change");
        assert!(main.rule_registry.read().rules.contains_key(&rid));
    }

    #[tokio::test]
    async fn worker_does_not_broadcast() {
        let worker = node("worker-a", "worker");
        let rid = registry_id(SyncedKind::Custom, uuid::Uuid::new_v4());
        record_if_main(Some(&worker), ChangeOp::Upsert, rid.clone(), Some(sample_rule(&rid))).await;

        assert_eq!(
            *worker.rules_version.read().await,
            0,
            "a worker edit must not touch the authoritative changelog"
        );
        assert!(worker.rule_registry.read().rules.is_empty());
    }

    #[tokio::test]
    async fn standalone_is_noop() {
        // No panic, nothing to observe — just exercise the None branch.
        record_if_main(None, ChangeOp::Delete, "x".to_string(), None).await;
    }
}
