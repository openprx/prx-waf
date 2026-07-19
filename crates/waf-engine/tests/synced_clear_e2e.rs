//! Worker→Main promotion clears the cluster-synced rule store.
//!
//! Proves the data-plane half of the fix end-to-end: a worker that consumed a
//! cluster-synced IP blocklist blocks the listed IP, and once the synced store
//! is cleared (as happens on a Worker→Main promotion) the very same request
//! falls back to the DB-authoritative stores and is no longer matched by the
//! leftover synced rule.
//!
//! Ignored by default because `WafEngine::new` needs a live Postgres (the DB
//! stores are DB-backed even though this test only exercises the synced path).
//! Run explicitly with:
//!
//! ```bash
//! DATABASE_URL=postgresql://prx_waf:prx_waf@127.0.0.1:15432/prx_waf \
//!   cargo test -p waf-engine --test synced_clear_e2e -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use chrono::Utc;
use parking_lot::RwLock as ParkingRwLock;
use uuid::Uuid;
use waf_common::{HostConfig, RequestCtx, WafAction};
use waf_engine::WafEngineConfig;
use waf_engine::rules::registry::RuleRegistry;
use waf_engine::{WafEngine, cluster_sync};
use waf_storage::Database;
use waf_storage::models::BlockIp;

fn database_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgresql://prx_waf:prx_waf@127.0.0.1:15432/prx_waf".to_string())
}

fn make_ctx(host_code: &str, client_ip: &str) -> RequestCtx {
    let host_config = Arc::new(HostConfig {
        code: host_code.to_string(),
        host: "example.com".to_string(),
        guard_status: true,
        ..HostConfig::default()
    });
    // A benign User-Agent keeps the unrelated Bot detector from blocking, so the
    // test isolates the synced-store behaviour.
    let mut headers = HashMap::new();
    headers.insert("user-agent".to_string(), "Mozilla/5.0 (synced-clear-test)".to_string());
    RequestCtx {
        req_id: "synced-clear".to_string(),
        client_ip: client_ip.parse().expect("ip"),
        client_port: 12345,
        method: "GET".to_string(),
        host: "example.com".to_string(),
        port: 80,
        path: "/".to_string(),
        query: String::new(),
        headers,
        body_preview: Bytes::new(),
        content_length: 0,
        is_tls: false,
        host_config,
        geo: None,
    }
}

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn promotion_clear_drops_synced_matches_and_falls_back_to_db() {
    let db = Arc::new(Database::connect(&database_url(), 5).await.expect("connect Postgres"));
    db.migrate().await.expect("migrate");
    let engine = WafEngine::new(Arc::clone(&db), WafEngineConfig::default());

    // Worker path: attach a synced registry carrying a single block-IP rule and
    // publish it to the request-path store.
    let mut registry = RuleRegistry::new();
    registry.insert(cluster_sync::block_ip_to_rule(&BlockIp {
        id: Uuid::new_v4(),
        host_code: "h1".to_string(),
        ip_cidr: "203.0.113.0/24".to_string(),
        remarks: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }));
    engine.attach_synced_registry(Arc::new(ParkingRwLock::new(registry)));
    engine.refresh_synced_rules();

    // Before promotion: the listed IP is blocked by the synced rule.
    let mut ctx = make_ctx("h1", "203.0.113.7");
    let decision = engine.inspect(&mut ctx).await;
    match decision.action {
        WafAction::Block { status, .. } => {
            assert_eq!(status, 403);
            let name = decision.result.expect("block result").rule_name;
            assert_eq!(
                name, "IP Blacklist (Cluster Sync)",
                "must be matched by the synced store"
            );
        }
        other => panic!("expected the synced blacklist to block, got {other:?}"),
    }

    // Promotion: drop the synced store (what on_promoted_to_main triggers).
    engine.clear_synced_rules();

    // After promotion: the same request falls back to the (empty) DB stores and
    // is no longer matched by the leftover synced rule.
    let mut ctx = make_ctx("h1", "203.0.113.7");
    let decision = engine.inspect(&mut ctx).await;
    assert!(
        decision.is_allowed(),
        "after clearing the synced store the request must not match any synced rule"
    );

    // Idempotent: clearing again is harmless and the request stays clean.
    engine.clear_synced_rules();
    let mut ctx = make_ctx("h1", "203.0.113.7");
    assert!(engine.inspect(&mut ctx).await.is_allowed());
}

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn clear_on_standalone_engine_is_a_noop() {
    let db = Arc::new(Database::connect(&database_url(), 5).await.expect("connect Postgres"));
    db.migrate().await.expect("migrate");
    let engine = WafEngine::new(Arc::clone(&db), WafEngineConfig::default());

    // No synced registry was ever attached (standalone node): clearing must be a
    // no-op and a normal request is unaffected.
    engine.clear_synced_rules();
    let mut ctx = make_ctx("h1", "203.0.113.7");
    assert!(engine.inspect(&mut ctx).await.is_allowed());
}
