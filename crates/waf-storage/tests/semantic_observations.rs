//! DB-gated test for the Lane 2 `semantic_observations` schema + repo (P1a).
//!
//! Exercises migration `0011_semantic_observations.sql` on a clean database and
//! the `insert_semantic_observation` / `list_semantic_observations` repo methods.
//! `#[ignore]`d and gated on a live Postgres, like the engine parity suite:
//!
//! ```bash
//! DATABASE_URL=postgresql://prx_waf:prx_waf@127.0.0.1:15432/prx_waf \
//!   cargo test -p waf-storage --test semantic_observations -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use waf_storage::Database;
use waf_storage::models::{CreateSemanticObservation, SemanticObservationQuery};

fn database_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgresql://prx_waf:prx_waf@127.0.0.1:15432/prx_waf".to_string())
}

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn migration_applies_and_roundtrips_an_observation() {
    let db = Database::connect(&database_url(), 5).await.expect("connect Postgres");
    db.migrate().await.expect("migrate (incl. 0011_semantic_observations)");

    // Unique host so the list assertion is isolated from any prior rows.
    let host = format!("p1a-{}", uuid::Uuid::new_v4());
    let signals = serde_json::json!([
        {
            "detector": "struct_rule",
            "attack": "sql_injection",
            "field": "body",
            "scope": "body",
            "confidence": 60,
            "rule_key": "sql.union_null",
            "provenance": "raw"
        }
    ]);

    db.insert_semantic_observation(CreateSemanticObservation {
        host_code: host.clone(),
        client_ip: "203.0.113.50".to_string(),
        req_id: "req-p1a-1".to_string(),
        scope: "body".to_string(),
        request_score: 60,
        recommendation: "log".to_string(),
        degraded: false,
        exhausted: false,
        pipeline: "semantic".to_string(),
        schema_version: 1,
        observations: signals.clone(),
    })
    .await
    .expect("insert semantic observation");

    let rows = db
        .list_semantic_observations(SemanticObservationQuery {
            host_code: Some(host.clone()),
            page: Some(1),
            page_size: Some(10),
        })
        .await
        .expect("list semantic observations");

    assert_eq!(rows.len(), 1, "exactly the one row we inserted for this unique host");
    let row = rows.first().expect("one row");
    assert_eq!(row.host_code, host);
    assert_eq!(row.request_score, 60);
    assert_eq!(row.recommendation, "log");
    assert_eq!(row.scope, "body");
    assert!(!row.degraded);
    assert_eq!(row.schema_version, 1);
    assert_eq!(row.observations, signals);
}

/// codex A-5: the migration's domain CHECK constraints reject out-of-range /
/// malformed telemetry at the database, even though the insert is parameterised.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn check_constraints_reject_illegal_rows() {
    let db = Database::connect(&database_url(), 5).await.expect("connect Postgres");
    db.migrate().await.expect("migrate (incl. 0011_semantic_observations)");

    let host = format!("p1a-neg-{}", uuid::Uuid::new_v4());
    let valid_signals = serde_json::json!([{ "detector": "struct_rule" }]);

    // A helper producing an otherwise-valid create-request we can perturb.
    let base = |score: i16, scope: &str, rec: &str, ver: i32, obs: serde_json::Value| CreateSemanticObservation {
        host_code: host.clone(),
        client_ip: "203.0.113.51".to_string(),
        req_id: "req-neg".to_string(),
        scope: scope.to_string(),
        request_score: score,
        recommendation: rec.to_string(),
        degraded: false,
        exhausted: false,
        pipeline: "semantic".to_string(),
        schema_version: ver,
        observations: obs,
    };

    // 1) request_score out of 0..=100 (would overflow the documented domain).
    assert!(
        db.insert_semantic_observation(base(32767, "body", "log", 1, valid_signals.clone()))
            .await
            .is_err(),
        "request_score 32767 must be rejected by the range CHECK"
    );
    // 2) unknown scope.
    assert!(
        db.insert_semantic_observation(base(50, "trailer", "log", 1, valid_signals.clone()))
            .await
            .is_err(),
        "unknown scope must be rejected by the scope CHECK"
    );
    // 3) unknown recommendation.
    assert!(
        db.insert_semantic_observation(base(50, "body", "quarantine", 1, valid_signals.clone()))
            .await
            .is_err(),
        "unknown recommendation must be rejected by the recommendation CHECK"
    );
    // 4) non-positive schema_version.
    assert!(
        db.insert_semantic_observation(base(50, "body", "log", 0, valid_signals.clone()))
            .await
            .is_err(),
        "schema_version 0 must be rejected by the positivity CHECK"
    );
    // 5) non-array observations JSON.
    assert!(
        db.insert_semantic_observation(base(50, "body", "log", 1, serde_json::json!({"not": "an array"})))
            .await
            .is_err(),
        "non-array observations must be rejected by the jsonb_typeof CHECK"
    );

    // Sanity: a fully valid row still inserts, so the negatives are not vacuous.
    db.insert_semantic_observation(base(50, "body", "log", 1, valid_signals))
        .await
        .expect("a valid row must still insert");
}

/// Retention/TTL (migration `0012`): `prune_semantic_observations` deletes rows
/// older than the window and keeps recent ones, and rejects a non-positive
/// window instead of wiping the table.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn prune_removes_old_rows_and_keeps_recent() {
    let db = Database::connect(&database_url(), 5).await.expect("connect Postgres");
    db.migrate().await.expect("migrate (incl. 0012 retention)");

    // A non-positive window must never delete anything — it is rejected up front.
    assert!(
        db.prune_semantic_observations(0).await.is_err(),
        "retention_days 0 must be rejected"
    );
    assert!(
        db.prune_semantic_observations(-5).await.is_err(),
        "negative retention_days must be rejected"
    );

    let host = format!("p1a-ttl-{}", uuid::Uuid::new_v4());
    let signals = serde_json::json!([{ "detector": "struct_rule" }]);
    let mk = |req_id: &str| CreateSemanticObservation {
        host_code: host.clone(),
        client_ip: "203.0.113.60".to_string(),
        req_id: req_id.to_string(),
        scope: "body".to_string(),
        request_score: 40,
        recommendation: "log".to_string(),
        degraded: false,
        exhausted: false,
        pipeline: "semantic".to_string(),
        schema_version: 1,
        observations: signals.clone(),
    };

    // A recent row (created_at defaults to now()) and an old row backdated 30
    // days directly on the pool so the prune boundary can be observed.
    db.insert_semantic_observation(mk("recent"))
        .await
        .expect("insert recent");
    db.insert_semantic_observation(mk("old")).await.expect("insert old");
    sqlx::query(
        "UPDATE semantic_observations SET created_at = now() - INTERVAL '30 days' WHERE host_code = $1 AND req_id = $2",
    )
    .bind(&host)
    .bind("old")
    .execute(db.pool())
    .await
    .expect("backdate the old row");

    // Prune everything older than 7 days: the 30-day row goes, the recent stays.
    let deleted = db
        .prune_semantic_observations(7)
        .await
        .expect("prune older than 7 days");
    assert!(deleted >= 1, "at least our backdated row must be pruned");

    let rows = db
        .list_semantic_observations(SemanticObservationQuery {
            host_code: Some(host.clone()),
            page: Some(1),
            page_size: Some(10),
        })
        .await
        .expect("list after prune");
    assert_eq!(rows.len(), 1, "only the recent row survives");
    let survivor = rows.first().expect("one surviving row");
    assert_eq!(survivor.req_id, "recent", "the surviving row is the recent one");
}
