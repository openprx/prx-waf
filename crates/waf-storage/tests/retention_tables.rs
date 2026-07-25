//! DB-gated tests for retention across every observability / PII table.
//!
//! Exercises [`Database::prune_retention_table`] against a real Postgres: the
//! per-table `DELETE` statements are literals selected by
//! `RetentionTable::delete_batch_sql`, so only a live database proves they name
//! real columns, respect the retention window, and drain a backlog that spans
//! more than one batch. `#[ignore]`d and gated on a live Postgres, like the rest
//! of the storage suite:
//!
//! ```bash
//! DATABASE_URL=postgresql://prx_waf:prx_waf@127.0.0.1:15432/prx_waf \
//!   cargo test -p waf-storage --test retention_tables -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sqlx::{PgPool, Row};
use waf_storage::{Database, RetentionTable};

fn database_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgresql://prx_waf:prx_waf@127.0.0.1:15432/prx_waf".to_string())
}

async fn connect() -> Database {
    let db = Database::connect(&database_url(), 5).await.expect("connect Postgres");
    db.migrate().await.expect("migrate (incl. 0013 PII retention)");
    db
}

/// A short unique tag. `attack_logs.host_code` is `VARCHAR(32)`, so a full UUID
/// plus a prefix does not fit — 12 hex digits is unique enough for a test row
/// and fits every tag column.
fn unique_tag(prefix: &str) -> String {
    let id = uuid::Uuid::new_v4().simple().to_string();
    format!("{prefix}-{}", id.get(..12).unwrap_or(id.as_str()))
}

/// A tag column per table that a test can filter on, so assertions stay scoped
/// to the rows this test inserted even on a shared database.
const fn tag_column(table: RetentionTable) -> &'static str {
    match table {
        RetentionTable::SemanticObservations | RetentionTable::SecurityEvents | RetentionTable::AttackLogs => {
            "host_code"
        }
        RetentionTable::AuditLog => "admin_username",
        RetentionTable::CrowdsecEvents => "scenario",
    }
}

/// Insert one row into `table` tagged with `tag`, aged `age_days` days.
///
/// Every statement is a literal keyed to the enum variant (no dynamic SQL), and
/// `created_at` is set explicitly so the retention boundary can be placed
/// exactly instead of waiting for wall-clock time.
async fn insert_aged_row(pool: &PgPool, table: RetentionTable, tag: &str, age_days: i32) {
    let sql = match table {
        RetentionTable::SemanticObservations => {
            "INSERT INTO semantic_observations
                 (host_code, client_ip, req_id, scope, request_score, recommendation, observations, created_at)
             VALUES ($1, '203.0.113.10', 'req-ttl', 'body', 40, 'log', '[]'::jsonb, now() - make_interval(days => $2))"
        }
        RetentionTable::SecurityEvents => {
            "INSERT INTO security_events (host_code, client_ip, method, path, rule_name, action, created_at)
             VALUES ($1, '203.0.113.11', 'GET', '/ttl', 'ttl-rule', 'block', now() - make_interval(days => $2))"
        }
        RetentionTable::AttackLogs => {
            "INSERT INTO attack_logs (host_code, host, client_ip, method, path, rule_name, action, phase, created_at)
             VALUES ($1, 'ttl.example', '203.0.113.12'::inet, 'GET', '/ttl', 'ttl-rule', 'block', 'request',
                     now() - make_interval(days => $2))"
        }
        RetentionTable::AuditLog => {
            "INSERT INTO audit_log (admin_username, action, ip_addr, created_at)
             VALUES ($1, 'ttl.update', '203.0.113.13', now() - make_interval(days => $2))"
        }
        RetentionTable::CrowdsecEvents => {
            "INSERT INTO crowdsec_events (scenario, client_ip, decision_type, action_taken, created_at)
             VALUES ($1, '203.0.113.14', 'ban', 'block', now() - make_interval(days => $2))"
        }
    };
    sqlx::query(sql)
        .bind(tag)
        .bind(age_days)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("insert into {}: {e}", table.name()));
}

/// Count the rows in `table` carrying `tag`.
async fn count_tagged(pool: &PgPool, table: RetentionTable, tag: &str) -> i64 {
    // The identifiers come from the closed `RetentionTable` enum / `tag_column`,
    // never from input; the value is still a bind parameter.
    let sql = format!(
        "SELECT COUNT(*) AS n FROM {} WHERE {} = $1",
        table.name(),
        tag_column(table)
    );
    let row = sqlx::query(&sql)
        .bind(tag)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("count {}: {e}", table.name()));
    row.try_get::<i64, _>("n").expect("count is a bigint")
}

/// Every table's prune must delete rows past the window and keep newer ones.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn each_table_prunes_by_its_retention_window() {
    let db = connect().await;
    let pool = db.pool();

    for table in RetentionTable::ALL {
        let tag = unique_tag("ttl");

        // One row inside a 7-day window, one well outside it, and one right on
        // the far side of the boundary (8 days) to prove the comparison is not
        // off by a whole day.
        insert_aged_row(pool, table, &tag, 1).await;
        insert_aged_row(pool, table, &tag, 8).await;
        insert_aged_row(pool, table, &tag, 400).await;
        assert_eq!(count_tagged(pool, table, &tag).await, 3, "{} setup", table.name());

        let deleted = db
            .prune_retention_table(table, 7, 5_000)
            .await
            .unwrap_or_else(|e| panic!("prune {}: {e}", table.name()));

        assert!(
            deleted >= 2,
            "{} must delete at least the two expired rows, deleted {deleted}",
            table.name()
        );
        assert_eq!(
            count_tagged(pool, table, &tag).await,
            1,
            "{}: only the 1-day-old row may survive a 7-day window",
            table.name()
        );
    }
}

/// A backlog larger than one batch must be fully drained by a single sweep,
/// across as many statements as it takes.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn a_multi_batch_backlog_is_fully_drained() {
    let db = connect().await;
    let pool = db.pool();
    let table = RetentionTable::SecurityEvents;
    let tag = unique_tag("ttlb");

    // 250 expired rows at 100 rows per batch: three statements, the last short.
    for _ in 0..250 {
        insert_aged_row(pool, table, &tag, 30).await;
    }
    // Plus one row that must survive, so a "delete everything" bug is caught.
    insert_aged_row(pool, table, &tag, 1).await;
    assert_eq!(count_tagged(pool, table, &tag).await, 251, "setup");

    let deleted = db
        .prune_retention_table(table, 7, 100)
        .await
        .expect("batched prune must succeed");

    assert!(
        deleted >= 250,
        "the whole backlog must go in one sweep, deleted {deleted}"
    );
    assert_eq!(
        count_tagged(pool, table, &tag).await,
        1,
        "a multi-batch sweep must leave exactly the in-window row"
    );
}

/// A non-positive window is rejected up front — it must never be read as
/// "delete everything".
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn a_non_positive_window_is_rejected_for_every_table() {
    let db = connect().await;
    for table in RetentionTable::ALL {
        for bad in [0_i64, -5] {
            assert!(
                db.prune_retention_table(table, bad, 5_000).await.is_err(),
                "{}: retention_days {bad} must be rejected, not wipe the table",
                table.name()
            );
        }
        // A non-positive batch size must not spin either.
        assert!(
            db.prune_retention_table(table, 30, 0).await.is_err(),
            "{}: batch_size 0 must be rejected",
            table.name()
        );
    }
}

/// The `created_at` predicate must be served by an index on every table —
/// otherwise the delete degrades into a full scan and holds locks far too long.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn every_pruned_table_has_a_created_at_index() {
    let db = connect().await;
    for table in RetentionTable::ALL {
        let indexed: bool = sqlx::query(
            "SELECT EXISTS (
                 SELECT 1
                 FROM pg_index i
                 JOIN pg_class t ON t.oid = i.indrelid
                 JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY (i.indkey)
                 WHERE t.relname = $1 AND a.attname = 'created_at'
             ) AS ok",
        )
        .bind(table.name())
        .fetch_one(db.pool())
        .await
        .unwrap_or_else(|e| panic!("index lookup for {}: {e}", table.name()))
        .try_get("ok")
        .expect("exists() is a bool");

        assert!(
            indexed,
            "{} has no index on created_at; the retention DELETE would full-scan it",
            table.name()
        );
    }
}
