//! DB-gated tests for the `CrowdSec` decision mirror (`crowdsec_decisions`).
//!
//! The mirror is what keeps the bouncer from starting fail-open: on restart the
//! in-memory decision cache is repopulated from this table *before* the proxy
//! serves traffic, so a LAPI that is unreachable at boot no longer means "every
//! previously banned IP is allowed through".
//!
//! Everything below is SQL behaviour that only a real server proves — the
//! `ON CONFLICT (id)` upsert, the `(scope, value)` deletion, the transactional
//! full replace, and the "unexpired only" load predicate. `#[ignore]`d and gated
//! on a live Postgres, like the rest of the storage suite:
//!
//! ```bash
//! DATABASE_URL=postgresql://prx_waf:prx_waf@127.0.0.1:15432/prx_waf \
//!   cargo test -p waf-storage --test crowdsec_decisions -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::{TimeDelta, Utc};
use sqlx::Row;
use waf_storage::Database;
use waf_storage::models::CrowdSecDecisionRow;

fn database_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgresql://prx_waf:prx_waf@127.0.0.1:15432/prx_waf".to_string())
}

async fn connect() -> Database {
    let db = Database::connect(&database_url(), 5).await.expect("connect Postgres");
    db.migrate().await.expect("migrate");
    db
}

/// A positive, effectively-unique `BIGINT`, so tests never collide on the
/// primary key even when run against a shared database. Masked to 63 bits so
/// `i64::try_from` always succeeds.
fn unique_id() -> i64 {
    let masked = uuid::Uuid::new_v4().as_u128() & 0x7FFF_FFFF_FFFF_FFFF;
    i64::try_from(masked).unwrap_or(1)
}

/// A unique address in the IPv6 documentation range, so concurrent runs never
/// share a `(scope, value)` key (the IPv4 documentation ranges are far too small
/// for that).
fn unique_value() -> String {
    let n = uuid::Uuid::new_v4().as_u128() & 0xFFFF_FFFF;
    format!("2001:db8::{n:x}")
}

fn row(id: i64, value: &str, scenario: &str, expires_in: TimeDelta) -> CrowdSecDecisionRow {
    CrowdSecDecisionRow {
        id,
        origin: "crowdsec".to_string(),
        scope: "Ip".to_string(),
        value: value.to_string(),
        type_: "ban".to_string(),
        scenario: scenario.to_string(),
        duration_secs: Some(expires_in.num_seconds()),
        expires_at: Utc::now() + expires_in,
    }
}

/// Rows this test wrote, found by its own unique scenario tag — assertions stay
/// scoped even on a shared database that other suites are also using.
async fn tagged(db: &Database, tag: &str) -> Vec<(i64, String)> {
    sqlx::query("SELECT id, value FROM crowdsec_decisions WHERE scenario = $1 ORDER BY id")
        .bind(tag)
        .fetch_all(db.pool())
        .await
        .unwrap_or_else(|e| panic!("select tagged rows: {e}"))
        .into_iter()
        .map(|r| {
            (
                r.try_get::<i64, _>("id").expect("id is a bigint"),
                r.try_get::<String, _>("value").expect("value is text"),
            )
        })
        .collect()
}

async fn purge(db: &Database, tag: &str) {
    sqlx::query("DELETE FROM crowdsec_decisions WHERE scenario = $1")
        .bind(tag)
        .execute(db.pool())
        .await
        .unwrap_or_else(|e| panic!("purge: {e}"));
}

/// The core recovery guarantee: what the sync task mirrored comes back on the
/// next process start, and only while the decision is still enforceable.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn only_unexpired_decisions_are_restored() {
    let db = connect().await;
    let tag = format!("prxtest/restore-{}", uuid::Uuid::new_v4());
    let live = unique_value();
    let dead = unique_value();

    db.upsert_crowdsec_decisions(&[
        row(unique_id(), &live, &tag, TimeDelta::try_hours(1).unwrap()),
        row(unique_id(), &dead, &tag, TimeDelta::try_hours(-1).unwrap()),
    ])
    .await
    .expect("upsert");

    let restored = db.load_active_crowdsec_decisions().await.expect("load");
    let restored_tagged: Vec<&CrowdSecDecisionRow> = restored.iter().filter(|r| r.scenario == tag).collect();

    assert_eq!(restored_tagged.len(), 1, "only the unexpired decision may be restored");
    assert_eq!(restored_tagged.first().map(|r| r.value.as_str()), Some(live.as_str()));
    assert_eq!(restored_tagged.first().map(|r| r.type_.as_str()), Some("ban"));

    purge(&db, &tag).await;
}

/// `CrowdSec` reuses decision ids after a LAPI database reset. Keying the upsert
/// on `id` must make the reused id *replace* the stale row rather than fail on
/// the primary key or leave two rows claiming the same decision.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn a_reused_decision_id_replaces_the_stale_row() {
    let db = connect().await;
    let tag = format!("prxtest/reuse-{}", uuid::Uuid::new_v4());
    let id = unique_id();
    let old = unique_value();
    let new = unique_value();

    db.upsert_crowdsec_decisions(&[row(id, &old, &tag, TimeDelta::try_hours(1).unwrap())])
        .await
        .expect("first upsert");
    db.upsert_crowdsec_decisions(&[row(id, &new, &tag, TimeDelta::try_hours(2).unwrap())])
        .await
        .expect("second upsert with the same id must not violate the primary key");

    assert_eq!(
        tagged(&db, &tag).await,
        vec![(id, new)],
        "the reused id must replace, not duplicate"
    );

    purge(&db, &tag).await;
}

/// The same batch may legitimately repeat an id. Postgres rejects an
/// `ON CONFLICT DO UPDATE` that touches a row twice in one statement, so the
/// writer de-duplicates first; this pins that the storage layer survives the
/// batch a de-duplicated caller produces, and that a genuinely duplicated batch
/// is the caller's job to collapse (see `crowdsec::store::rows_for`).
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn a_batch_of_distinct_ids_upserts_in_one_statement() {
    let db = connect().await;
    let tag = format!("prxtest/batch-{}", uuid::Uuid::new_v4());
    let rows: Vec<CrowdSecDecisionRow> = (0..25)
        .map(|_| row(unique_id(), &unique_value(), &tag, TimeDelta::try_hours(1).unwrap()))
        .collect();

    db.upsert_crowdsec_decisions(&rows).await.expect("batch upsert");
    assert_eq!(tagged(&db, &tag).await.len(), 25);

    // Re-upserting the identical batch is idempotent.
    db.upsert_crowdsec_decisions(&rows).await.expect("idempotent re-upsert");
    assert_eq!(tagged(&db, &tag).await.len(), 25);

    purge(&db, &tag).await;
}

/// Deletion is keyed on `(scope, value)` — the same key the in-memory cache
/// removes on — so a ban lifted upstream cannot linger in the mirror under a
/// second decision id and be resurrected at the next restart.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn deleting_by_scope_and_value_removes_every_decision_for_that_target() {
    let db = connect().await;
    let tag = format!("prxtest/delete-{}", uuid::Uuid::new_v4());
    let banned = unique_value();
    let other = unique_value();

    // Two live decisions for the same IP (different scenarios upstream), plus
    // an unrelated one that must survive.
    db.upsert_crowdsec_decisions(&[
        row(unique_id(), &banned, &tag, TimeDelta::try_hours(1).unwrap()),
        row(unique_id(), &banned, &tag, TimeDelta::try_hours(4).unwrap()),
        row(unique_id(), &other, &tag, TimeDelta::try_hours(1).unwrap()),
    ])
    .await
    .expect("upsert");

    let removed = db
        .delete_crowdsec_decisions(&[("Ip".to_string(), banned.clone())])
        .await
        .expect("delete");

    assert_eq!(removed, 2, "every row for the lifted target must go");
    let left = tagged(&db, &tag).await;
    assert_eq!(left.len(), 1);
    assert_eq!(left.first().map(|(_, v)| v.as_str()), Some(other.as_str()));

    purge(&db, &tag).await;
}

/// A full LAPI pull is the complete active set, so the mirror is replaced by it
/// wholesale: rows absent from the pull were revoked while the process was down
/// and must not survive to be restored later.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn a_full_replace_drops_rows_absent_from_the_pull() {
    let db = connect().await;
    let tag = format!("prxtest/replace-{}", uuid::Uuid::new_v4());
    let kept_id = unique_id();
    let kept = unique_value();
    let revoked = unique_value();

    // Start from a clean table so `replace_all`'s global semantics are testable.
    sqlx::query("DELETE FROM crowdsec_decisions")
        .execute(db.pool())
        .await
        .expect("clear table");

    db.upsert_crowdsec_decisions(&[
        row(kept_id, &kept, &tag, TimeDelta::try_hours(1).unwrap()),
        row(unique_id(), &revoked, &tag, TimeDelta::try_hours(1).unwrap()),
    ])
    .await
    .expect("seed");

    let removed = db
        .replace_crowdsec_decisions(&[row(kept_id, &kept, &tag, TimeDelta::try_hours(3).unwrap())])
        .await
        .expect("replace");

    assert_eq!(removed, 1, "the row absent from the full pull must be deleted");
    assert_eq!(tagged(&db, &tag).await, vec![(kept_id, kept)]);

    purge(&db, &tag).await;
}

/// "LAPI has no active decisions" is a real answer, not a missing one: an empty
/// full pull must empty the mirror rather than leave stale bans behind.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn an_empty_full_pull_empties_the_mirror() {
    let db = connect().await;
    let tag = format!("prxtest/empty-{}", uuid::Uuid::new_v4());

    sqlx::query("DELETE FROM crowdsec_decisions")
        .execute(db.pool())
        .await
        .expect("clear table");
    db.upsert_crowdsec_decisions(&[row(
        unique_id(),
        &unique_value(),
        &tag,
        TimeDelta::try_hours(1).unwrap(),
    )])
    .await
    .expect("seed");

    db.replace_crowdsec_decisions(&[]).await.expect("empty replace");

    assert!(tagged(&db, &tag).await.is_empty());
    assert!(db.load_active_crowdsec_decisions().await.expect("load").is_empty());
}

/// Every mirror call must tolerate an empty input without a round-trip or an
/// error — the sync task hits this on every quiet poll.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn empty_inputs_are_no_ops() {
    let db = connect().await;
    assert_eq!(db.upsert_crowdsec_decisions(&[]).await.expect("empty upsert"), 0);
    assert_eq!(db.delete_crowdsec_decisions(&[]).await.expect("empty delete"), 0);
}

/// A database that is down must surface as an `Err`, never a panic: the mirror
/// is a fallback, and a failing fallback must not take the WAF with it.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn a_dead_database_returns_an_error_instead_of_panicking() {
    // A pool pointed at a closed port: `connect` itself fails, which is the
    // same branch `init_crowdsec` must survive.
    let result = Database::connect("postgresql://prx_waf:prx_waf@127.0.0.1:1/prx_waf", 1).await;
    assert!(
        result.is_err(),
        "connecting to a dead database must be an Err, not a panic"
    );
}

/// The columns the mirror writes must actually exist with the widths the writer
/// assumes; a schema drift here would turn every mirror write into a runtime
/// error and silently restore the fail-open window.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn the_mirror_columns_match_the_writer_assumptions() {
    let db = connect().await;
    let rows = sqlx::query(
        "SELECT column_name, character_maximum_length
           FROM information_schema.columns
          WHERE table_name = 'crowdsec_decisions'",
    )
    .fetch_all(db.pool())
    .await
    .expect("introspect crowdsec_decisions");

    let widths: std::collections::HashMap<String, Option<i32>> = rows
        .into_iter()
        .map(|r| {
            (
                r.try_get::<String, _>("column_name").expect("column_name"),
                r.try_get::<Option<i32>, _>("character_maximum_length")
                    .expect("character_maximum_length"),
            )
        })
        .collect();

    for (column, expected) in [
        ("origin", CrowdSecDecisionRow::MAX_ORIGIN_LEN),
        ("scope", CrowdSecDecisionRow::MAX_SCOPE_LEN),
        ("value", CrowdSecDecisionRow::MAX_VALUE_LEN),
        ("type", CrowdSecDecisionRow::MAX_TYPE_LEN),
        ("scenario", CrowdSecDecisionRow::MAX_SCENARIO_LEN),
    ] {
        let actual = widths
            .get(column)
            .unwrap_or_else(|| panic!("crowdsec_decisions.{column} is missing"));
        assert_eq!(
            *actual,
            Some(i32::try_from(expected).expect("width fits an i32")),
            "crowdsec_decisions.{column} width drifted from the writer's guard"
        );
    }
    assert!(widths.contains_key("duration_secs"), "duration_secs is missing");
    assert!(widths.contains_key("expires_at"), "expires_at is missing");
}
