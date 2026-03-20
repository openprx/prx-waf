//! Integration tests: two-node QUIC mTLS cluster — connect and exchange heartbeats.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

/// Install the ring crypto provider once per process.
///
/// rustls 0.23 requires an explicit provider when multiple feature flags are
/// enabled (e.g., both `ring` and `aws-lc-rs` pulled in via transitive deps).
fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

use waf_cluster::{
    ClusterMessage, NodeState, RuleReloader, StorageMode,
    crypto::{ca::CertificateAuthority, node_cert::NodeCertificate},
    node::PeerInfo,
    protocol::{ChangeOp, RuleSyncRequest, SyncType},
    sync::rules::{RuleChangelog, apply_sync_response, handle_sync_request},
    transport::{client::ClusterClient, server::ClusterServer},
};
use waf_common::config::{ClusterConfig, NodeRole};
use waf_engine::{Rule, RuleRegistry};

// ─── Shared test helpers ───────────────────────────────────────────────────────

/// No-op [`RuleReloader`] used in rule-sync tests — accepts updates silently.
struct NoopReloader;

#[async_trait::async_trait]
impl RuleReloader for NoopReloader {
    async fn on_rules_updated(&self, _version: u64) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Build a minimal [`Rule`] with the given id for use in tests.
fn make_test_rule(id: &str) -> Rule {
    Rule {
        id: id.to_string(),
        name: format!("Test Rule {id}"),
        description: None,
        category: "sqli".to_string(),
        source: "test".to_string(),
        enabled: true,
        action: "block".to_string(),
        severity: Some("high".to_string()),
        pattern: Some(r"SELECT\s+.+\s+FROM".to_string()),
        tags: vec![],
        metadata: HashMap::new(),
    }
}

/// Bind to a random available port on loopback and return its `SocketAddr`.
fn random_loopback_addr() -> SocketAddr {
    let listener = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind UDP");
    listener.local_addr().expect("local_addr")
}

/// Build a minimal `ClusterConfig` pointing to the given listen address.
fn minimal_config(listen_addr: SocketAddr) -> ClusterConfig {
    ClusterConfig {
        enabled: true,
        listen_addr: listen_addr.to_string(),
        ..ClusterConfig::default()
    }
}

/// Helper: build a `NodeState` with the given id and addr.
fn make_node_state(node_id: &str, config: ClusterConfig) -> Arc<NodeState> {
    let mut cfg = config;
    cfg.node_id = node_id.to_string();
    Arc::new(NodeState::new(cfg, StorageMode::Full).expect("NodeState::new failed"))
}

// ─── QUIC transport tests ──────────────────────────────────────────────────────

#[tokio::test]
async fn two_nodes_connect_and_exchange_heartbeat() {
    install_crypto_provider();

    // ── Addresses ──────────────────────────────────────────────────────────
    let server_addr = random_loopback_addr();
    let client_addr = random_loopback_addr();

    // ── Shared cluster CA ──────────────────────────────────────────────────
    let ca = CertificateAuthority::generate(365).expect("CA generate");
    let ca_cert_der = ca.cert_der().expect("CA DER");

    // ── Server node cert ───────────────────────────────────────────────────
    let server_cert = NodeCertificate::generate("integration-server", &ca, 1).expect("server cert");

    // ── Client node cert ───────────────────────────────────────────────────
    let client_cert = NodeCertificate::generate("integration-client", &ca, 1).expect("client cert");

    // ── Server state — pre-register client as known peer ──────────────────
    let server_state = make_node_state("integration-server", minimal_config(server_addr));
    {
        let mut peers = server_state.peers.write().await;
        peers.push(PeerInfo {
            node_id: "integration-client".to_string(),
            addr: client_addr,
            role: NodeRole::Worker,
            last_seen_ms: 0,
        });
    }

    // ── Start server ───────────────────────────────────────────────────────
    let server = ClusterServer::new(
        server_addr,
        ca_cert_der.clone(),
        server_cert.cert_pem.clone(),
        server_cert.key_pem.clone(),
    );

    let server_state_srv = Arc::clone(&server_state);
    tokio::spawn(async move {
        if let Err(e) = server.serve(server_state_srv).await {
            eprintln!("Server error: {e}");
        }
    });

    // Give the server a moment to start listening.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // ── Client state ───────────────────────────────────────────────────────
    let client_state = make_node_state("integration-client", minimal_config(client_addr));

    // ── Client channel: send a heartbeat ──────────────────────────────────
    let (tx, rx) = mpsc::channel::<ClusterMessage>(16);

    let client = ClusterClient::new(
        server_addr,
        "integration-client".to_string(),
        ca_cert_der,
        client_cert.cert_pem,
        client_cert.key_pem,
    );

    let client_state_for_task = Arc::clone(&client_state);
    tokio::spawn(async move {
        if let Err(e) = client.run_with_reconnect(client_state_for_task, rx).await {
            eprintln!("Client error: {e}");
        }
    });

    // ── Send a heartbeat from client ───────────────────────────────────────
    tokio::time::sleep(Duration::from_millis(80)).await;

    let hb = waf_cluster::protocol::Heartbeat {
        sequence: 1,
        timestamp_ms: 0,
        node_id: "integration-client".to_string(),
        role: NodeRole::Worker,
        uptime_secs: 0,
        cpu_percent: 0.0,
        memory_used_bytes: 0,
        total_requests: 0,
        blocked_requests: 0,
        rules_version: 0,
        config_version: 0,
    };

    tx.send(ClusterMessage::Heartbeat(hb))
        .await
        .expect("send heartbeat");

    // ── Verify server updated peer last_seen_ms ────────────────────────────
    tokio::time::sleep(Duration::from_millis(200)).await;

    let peers = server_state.peers.read().await;
    let client_peer = peers
        .iter()
        .find(|p| p.node_id == "integration-client")
        .expect("client peer not found in server state");

    assert!(
        client_peer.last_seen_ms > 0,
        "server should have recorded a heartbeat from the client (last_seen_ms={})",
        client_peer.last_seen_ms
    );
}

#[tokio::test]
async fn cert_generation_and_roundtrip() {
    let ca = CertificateAuthority::generate(365).expect("CA generate");
    assert!(!ca.cert_pem().is_empty());
    assert!(ca.cert_pem().starts_with("-----BEGIN CERTIFICATE-----"));
    let _der = ca.cert_der().expect("CA DER");

    let node_cert = NodeCertificate::generate("test-node", &ca, 1).expect("node cert");
    assert!(!node_cert.cert_pem.is_empty());
    assert!(!node_cert.key_pem.is_empty());

    let chain = node_cert.cert_chain_der().expect("cert chain DER");
    assert!(!chain.is_empty());
    node_cert.private_key_der().expect("private key DER");
}

// ─── Rule sync tests ───────────────────────────────────────────────────────────

/// A rule created on the main node is correctly delivered to the worker.
///
/// This test exercises the full sync pipeline in-process:
/// 1. Main: record a rule change in the `RuleChangelog`.
/// 2. Worker: issue a `RuleSyncRequest` at version 0 (brand-new node).
/// 3. Main: respond with `handle_sync_request` — expects a **Full** snapshot
///    because the worker has never synced before.
/// 4. Worker: apply via `apply_sync_response` + `NoopReloader`.
/// 5. Assert the worker registry contains the rule at the correct version.
///
/// A second pass then exercises the **Incremental** path:
/// 6. Main: add a second rule to the changelog.
/// 7. Worker: re-request from its current version.
/// 8. Main: responds with one incremental change.
/// 9. Worker: applies and both rules are now present.
#[tokio::test]
async fn rule_created_on_main_synced_to_worker() {
    // ── Main: build a rule and record it in the changelog ─────────────────
    let rule_a = make_test_rule("sqli-001");
    let mut changelog = RuleChangelog::new(500);
    changelog.record_change(ChangeOp::Upsert, rule_a.id.clone(), Some(&rule_a));

    // ── Worker: brand-new — current_version = 0 ───────────────────────────
    let request_v0 = RuleSyncRequest { current_version: 0 };

    // ── Main: respond to the request ──────────────────────────────────────
    let resp_full = handle_sync_request(&changelog, &request_v0, std::slice::from_ref(&rule_a))
        .expect("handle_sync_request (full) failed");

    // A worker at version 0 is behind the first changelog entry (version 1),
    // so the main must send a full snapshot.
    assert!(
        matches!(resp_full.sync_type, SyncType::Full),
        "brand-new worker should receive a full snapshot"
    );
    assert!(
        !resp_full.snapshot_lz4.is_empty(),
        "full snapshot payload must not be empty"
    );
    let full_version = resp_full.version;

    // ── Worker: apply the full snapshot ───────────────────────────────────
    let mut worker_registry = RuleRegistry::new();
    let reloader = NoopReloader;
    apply_sync_response(resp_full, &mut worker_registry, &reloader)
        .await
        .expect("apply_sync_response (full) failed");

    assert!(
        worker_registry.rules.contains_key("sqli-001"),
        "worker registry must contain the synced rule after full snapshot"
    );
    assert_eq!(
        worker_registry.version, full_version,
        "worker version must match main's authoritative version after full sync"
    );

    // ── Main: add a second rule ────────────────────────────────────────────
    let rule_b = make_test_rule("xss-001");
    changelog.record_change(ChangeOp::Upsert, rule_b.id.clone(), Some(&rule_b));

    // ── Worker: request from its current version ───────────────────────────
    let request_v1 = RuleSyncRequest {
        current_version: worker_registry.version,
    };

    let all_rules = [rule_a.clone(), rule_b.clone()];
    let resp_incr = handle_sync_request(&changelog, &request_v1, &all_rules)
        .expect("handle_sync_request (incremental) failed");

    assert!(
        matches!(resp_incr.sync_type, SyncType::Incremental),
        "existing worker should receive incremental diff, not full snapshot"
    );
    assert_eq!(
        resp_incr.changes.len(),
        1,
        "exactly one rule change since last sync"
    );
    assert_eq!(resp_incr.changes[0].rule_id, "xss-001");
    let incr_version = resp_incr.version;

    // ── Worker: apply the incremental diff ────────────────────────────────
    apply_sync_response(resp_incr, &mut worker_registry, &reloader)
        .await
        .expect("apply_sync_response (incremental) failed");

    assert!(
        worker_registry.rules.contains_key("xss-001"),
        "worker registry must contain the new rule after incremental sync"
    );
    assert!(
        worker_registry.rules.contains_key("sqli-001"),
        "worker registry must retain previously synced rules"
    );
    assert_eq!(
        worker_registry.version, incr_version,
        "worker version must match main's authoritative version after incremental sync"
    );

    // ── Verify rule deletion is propagated ────────────────────────────────
    changelog.record_change(ChangeOp::Delete, "sqli-001".to_string(), None);

    let request_v2 = RuleSyncRequest {
        current_version: worker_registry.version,
    };
    let remaining_rules = [rule_b.clone()];
    let resp_delete = handle_sync_request(&changelog, &request_v2, &remaining_rules)
        .expect("handle_sync_request (delete) failed");

    assert!(
        matches!(resp_delete.sync_type, SyncType::Incremental),
        "delete should be delivered as incremental change"
    );
    assert_eq!(resp_delete.changes.len(), 1, "one deletion change");

    apply_sync_response(resp_delete, &mut worker_registry, &reloader)
        .await
        .expect("apply_sync_response (delete) failed");

    assert!(
        !worker_registry.rules.contains_key("sqli-001"),
        "deleted rule must be removed from worker registry"
    );
    assert!(
        worker_registry.rules.contains_key("xss-001"),
        "non-deleted rule must still be present"
    );
}

/// When a worker is too far behind the changelog ring buffer it receives a full
/// snapshot rather than stale incremental changes.
#[tokio::test]
async fn rule_sync_falls_back_to_full_when_worker_too_far_behind() {
    // Fill the changelog to capacity (3 entries max), then request from 0.
    let mut changelog = RuleChangelog::new(3);
    for i in 0..3u32 {
        let rule = make_test_rule(&format!("rule-{i:03}"));
        changelog.record_change(ChangeOp::Upsert, rule.id.clone(), Some(&rule));
    }

    // Worker at version 0 is behind the oldest retained entry (version 1) once
    // the ring buffer has been populated past its capacity.  With max_retained=3
    // and 3 insertions, the oldest entry is version 1, so version 0 < 1 → Full.
    let request = RuleSyncRequest { current_version: 0 };
    let rules: Vec<Rule> = (0..3u32)
        .map(|i| make_test_rule(&format!("rule-{i:03}")))
        .collect();
    let resp =
        handle_sync_request(&changelog, &request, &rules).expect("handle_sync_request failed");

    assert!(
        matches!(resp.sync_type, SyncType::Full),
        "worker too far behind should receive full snapshot"
    );

    let mut registry = RuleRegistry::new();
    let reloader = NoopReloader;
    apply_sync_response(resp, &mut registry, &reloader)
        .await
        .expect("apply full snapshot after fallback failed");

    assert_eq!(
        registry.rules.len(),
        3,
        "all 3 rules should be in worker registry"
    );
    assert_eq!(registry.version, changelog.current_version());
}
