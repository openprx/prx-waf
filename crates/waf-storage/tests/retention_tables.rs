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
        RetentionTable::SemanticObservations
        | RetentionTable::SecurityEvents
        | RetentionTable::AttackLogs
        | RetentionTable::RequestStats => "host_code",
        RetentionTable::AuditLog => "admin_username",
        RetentionTable::CrowdsecEvents | RetentionTable::CrowdsecDecisions => "scenario",
        RetentionTable::RefreshTokens => "token_hash",
        RetentionTable::NotificationLog => "event_type",
    }
}

/// A positive, effectively-unique `BIGINT` id for `crowdsec_decisions.id`,
/// which has no default (it mirrors the upstream `CrowdSec` decision id and is
/// normally supplied by the sync job). Masked to 63 bits so `i64::try_from`
/// always succeeds, sidestepping a lossy cast.
fn random_bigint_id() -> i64 {
    let masked = uuid::Uuid::new_v4().as_u128() & 0x7FFF_FFFF_FFFF_FFFF;
    i64::try_from(masked).unwrap_or(1)
}

/// Insert (or reuse) a fixture admin user, for the one table with a `NOT NULL`
/// foreign key (`refresh_tokens.user_id`). Idempotent via `ON CONFLICT` on the
/// unique `username`, so every caller within a test run gets the same row.
async fn ensure_fixture_admin_user(pool: &PgPool) -> uuid::Uuid {
    let row = sqlx::query(
        "INSERT INTO admin_users (username, password_hash)
             VALUES ('retention-test-fixture', 'not-a-real-hash')
         ON CONFLICT (username) DO UPDATE SET username = EXCLUDED.username
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("fixture admin user: {e}"));
    row.try_get("id").expect("id is a uuid")
}

/// Insert one row into `table` tagged with `tag`, aged `age_days` days *on that
/// table's own retention key* — `created_at` for most tables, but
/// `expires_at` for `crowdsec_decisions` / `refresh_tokens` and `period_start`
/// for `request_stats` (see [`RetentionTable::time_column`]). `revoked` is
/// always left `FALSE` here; the revoked-overrides-the-window case has its own
/// dedicated test below.
///
/// Every statement is a literal keyed to the enum variant (no dynamic SQL).
async fn insert_aged_row(pool: &PgPool, table: RetentionTable, tag: &str, age_days: i32) {
    match table {
        RetentionTable::SemanticObservations => {
            sqlx::query(
                "INSERT INTO semantic_observations
                     (host_code, client_ip, req_id, scope, request_score, recommendation, observations, created_at)
                 VALUES ($1, '203.0.113.10', 'req-ttl', 'body', 40, 'log', '[]'::jsonb, now() - make_interval(days => $2))",
            )
            .bind(tag)
            .bind(age_days)
            .execute(pool)
            .await
        }
        RetentionTable::SecurityEvents => {
            sqlx::query(
                "INSERT INTO security_events (host_code, client_ip, method, path, rule_name, action, created_at)
                 VALUES ($1, '203.0.113.11', 'GET', '/ttl', 'ttl-rule', 'block', now() - make_interval(days => $2))",
            )
            .bind(tag)
            .bind(age_days)
            .execute(pool)
            .await
        }
        RetentionTable::AttackLogs => {
            sqlx::query(
                "INSERT INTO attack_logs (host_code, host, client_ip, method, path, rule_name, action, phase, created_at)
                 VALUES ($1, 'ttl.example', '203.0.113.12'::inet, 'GET', '/ttl', 'ttl-rule', 'block', 'request',
                         now() - make_interval(days => $2))",
            )
            .bind(tag)
            .bind(age_days)
            .execute(pool)
            .await
        }
        RetentionTable::AuditLog => {
            sqlx::query(
                "INSERT INTO audit_log (admin_username, action, ip_addr, created_at)
                 VALUES ($1, 'ttl.update', '203.0.113.13', now() - make_interval(days => $2))",
            )
            .bind(tag)
            .bind(age_days)
            .execute(pool)
            .await
        }
        RetentionTable::CrowdsecEvents => {
            sqlx::query(
                "INSERT INTO crowdsec_events (scenario, client_ip, decision_type, action_taken, created_at)
                 VALUES ($1, '203.0.113.14', 'ban', 'block', now() - make_interval(days => $2))",
            )
            .bind(tag)
            .bind(age_days)
            .execute(pool)
            .await
        }
        RetentionTable::CrowdsecDecisions => {
            // Aged on `expires_at`, not `created_at` — the row is inserted "now"
            // (as a real sync would) but the decision itself expired `age_days`
            // ago.
            let id: i64 = random_bigint_id();
            sqlx::query(
                "INSERT INTO crowdsec_decisions (id, origin, scope, value, type, scenario, expires_at, created_at)
                 VALUES ($1, 'crowdsec', 'Ip', '203.0.113.15', 'ban', $2, now() - make_interval(days => $3), now())",
            )
            .bind(id)
            .bind(tag)
            .bind(age_days)
            .execute(pool)
            .await
        }
        RetentionTable::RefreshTokens => {
            let user_id = ensure_fixture_admin_user(pool).await;
            // token_hash is UNIQUE, so fold the age into the tag to keep every
            // row in a 3-row batch distinct.
            let token_hash = format!("{tag}-{age_days}");
            sqlx::query(
                "INSERT INTO refresh_tokens (user_id, token_hash, expires_at, revoked, created_at)
                 VALUES ($1, $2, now() - make_interval(days => $3), FALSE, now())",
            )
            .bind(user_id)
            .bind(&token_hash)
            .bind(age_days)
            .execute(pool)
            .await
        }
        RetentionTable::NotificationLog => {
            sqlx::query(
                "INSERT INTO notification_log (event_type, channel_type, status, message, created_at)
                 VALUES ($1, 'webhook', 'sent', 'ttl fixture row', now() - make_interval(days => $2))",
            )
            .bind(tag)
            .bind(age_days)
            .execute(pool)
            .await
        }
        RetentionTable::RequestStats => {
            sqlx::query(
                "INSERT INTO request_stats (host_code, period_start, period_type, created_at)
                 VALUES ($1, now() - make_interval(days => $2), 'hour', now())",
            )
            .bind(tag)
            .bind(age_days)
            .execute(pool)
            .await
        }
    }
    .map_or_else(|e| panic!("insert into {}: {e}", table.name()), |_| ());
}

/// Count the rows in `table` carrying `tag`.
///
/// `refresh_tokens.token_hash` is `UNIQUE`, so [`insert_aged_row`] folds
/// `age_days` into it to keep a 3-row batch distinct; counting that table
/// therefore matches on the `tag` prefix (`LIKE 'tag%'`) instead of exact
/// equality.
async fn count_tagged(pool: &PgPool, table: RetentionTable, tag: &str) -> i64 {
    // The identifiers come from the closed `RetentionTable` enum / `tag_column`,
    // never from input; the value is still a bind parameter.
    let (op, bound) = if table == RetentionTable::RefreshTokens {
        ("LIKE", format!("{tag}%"))
    } else {
        ("=", tag.to_owned())
    };
    let sql = format!(
        "SELECT COUNT(*) AS n FROM {} WHERE {} {op} $1",
        table.name(),
        tag_column(table)
    );
    let row = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(bound)
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

/// A revoked refresh token must be deleted on the next sweep even when its
/// `expires_at` is far in the future — revocation, not expiry, is what makes
/// the row dead. A non-revoked token with the same far-future expiry is the
/// control: it must survive the same sweep untouched.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn a_revoked_refresh_token_is_deleted_regardless_of_its_still_future_expiry() {
    let db = connect().await;
    let pool = db.pool();
    let user_id = ensure_fixture_admin_user(pool).await;
    let tag = unique_tag("ttlrevoked");

    for (suffix, revoked) in [("revoked", true), ("live", false)] {
        sqlx::query(
            "INSERT INTO refresh_tokens (user_id, token_hash, expires_at, revoked, created_at)
             VALUES ($1, $2, now() + make_interval(days => 3650), $3, now())",
        )
        .bind(user_id)
        .bind(format!("{tag}-{suffix}"))
        .bind(revoked)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("insert refresh_tokens fixture: {e}"));
    }

    let deleted = db
        .prune_retention_table(RetentionTable::RefreshTokens, 7, 5_000)
        .await
        .expect("prune refresh_tokens");
    assert!(deleted >= 1, "the revoked token must be deleted, deleted {deleted}");

    let remaining: i64 = sqlx::query("SELECT COUNT(*) AS n FROM refresh_tokens WHERE token_hash = $1")
        .bind(format!("{tag}-live"))
        .fetch_one(pool)
        .await
        .expect("count live token")
        .try_get("n")
        .expect("count is a bigint");
    assert_eq!(remaining, 1, "the non-revoked, far-future token must survive");

    let revoked_remaining: i64 = sqlx::query("SELECT COUNT(*) AS n FROM refresh_tokens WHERE token_hash = $1")
        .bind(format!("{tag}-revoked"))
        .fetch_one(pool)
        .await
        .expect("count revoked token")
        .try_get("n")
        .expect("count is a bigint");
    assert_eq!(revoked_remaining, 0, "the revoked token must not survive the sweep");
}

/// A `crowdsec_decisions` row with no known expiry (`expires_at IS NULL`) must
/// never be pruned: `expires_at < $cutoff` is `NULL`, not `TRUE`, for such a
/// row, so it is left alone by design rather than guessed at.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn a_crowdsec_decision_with_no_known_expiry_is_never_pruned() {
    let db = connect().await;
    let pool = db.pool();
    let id: i64 = random_bigint_id();
    let tag = unique_tag("ttlnullexp");

    sqlx::query(
        "INSERT INTO crowdsec_decisions (id, origin, scope, value, type, scenario, expires_at, created_at)
         VALUES ($1, 'crowdsec', 'Ip', '203.0.113.16', 'ban', $2, NULL, now() - make_interval(days => 400))",
    )
    .bind(id)
    .bind(&tag)
    .execute(pool)
    .await
    .unwrap_or_else(|e| panic!("insert crowdsec_decisions fixture: {e}"));

    db.prune_retention_table(RetentionTable::CrowdsecDecisions, 1, 5_000)
        .await
        .expect("prune crowdsec_decisions");

    assert_eq!(
        count_tagged(pool, RetentionTable::CrowdsecDecisions, &tag).await,
        1,
        "a decision with no known expiry must survive regardless of its row age"
    );
}

/// Every table's retention predicate must be served by an index on its own
/// [`RetentionTable::time_column`] — otherwise the delete degrades into a full
/// scan and holds locks far too long.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn every_pruned_table_has_an_index_on_its_time_column() {
    let db = connect().await;
    for table in RetentionTable::ALL {
        let indexed: bool = sqlx::query(
            "SELECT EXISTS (
                 SELECT 1
                 FROM pg_index i
                 JOIN pg_class t ON t.oid = i.indrelid
                 JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY (i.indkey)
                 WHERE t.relname = $1 AND a.attname = $2
             ) AS ok",
        )
        .bind(table.name())
        .bind(table.time_column())
        .fetch_one(db.pool())
        .await
        .unwrap_or_else(|e| panic!("index lookup for {}: {e}", table.name()))
        .try_get("ok")
        .expect("exists() is a bool");

        assert!(
            indexed,
            "{} has no index on {}; the retention DELETE would full-scan it",
            table.name(),
            table.time_column()
        );
    }
}

/// `refresh_tokens` additionally deletes on `revoked = TRUE`, independent of
/// `expires_at`. Almost every row has `revoked = FALSE`, so that half of the
/// predicate needs its own (partial) index — otherwise it falls back to a
/// sequential scan every sweep regardless of how the `expires_at` half is
/// served.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn refresh_tokens_has_an_index_on_revoked() {
    let db = connect().await;
    let indexed: bool = sqlx::query(
        "SELECT EXISTS (
             SELECT 1
             FROM pg_index i
             JOIN pg_class t ON t.oid = i.indrelid
             JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY (i.indkey)
             WHERE t.relname = 'refresh_tokens' AND a.attname = 'revoked'
         ) AS ok",
    )
    .fetch_one(db.pool())
    .await
    .expect("index lookup for refresh_tokens.revoked")
    .try_get("ok")
    .expect("exists() is a bool");

    assert!(
        indexed,
        "refresh_tokens has no index on revoked; the revoked = TRUE branch of the retention DELETE would full-scan it"
    );
}
