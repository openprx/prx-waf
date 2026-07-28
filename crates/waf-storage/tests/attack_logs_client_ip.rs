//! DB-gated regression suite for the `attack_logs.client_ip` INET binding bug.
//!
//! `attack_logs.client_ip` is a Postgres `INET NOT NULL` column
//! (`migrations/0001_initial.sql:86`) while [`AttackLog`] carries it as a
//! `String`. Before the fix:
//!
//! * `create_attack_log` bound the `String` straight at the `INET` parameter,
//!   which Postgres rejects with `42804` (*column is of type inet but
//!   expression is of type text*). Every insert failed. The only caller
//!   (`waf_engine::engine::log_attack`) runs detached and swallows the error
//!   into a `warn!`, so the table stayed empty forever and nothing surfaced.
//! * `list_attack_logs` did `SELECT *`, and sqlx is built without the
//!   `ipnetwork` feature, so decoding the raw `INET` column into `String`
//!   failed too — `GET /api/attack-logs` could never render a row.
//! * The `WHERE client_ip = $2` filter compared `inet = text`, an operator
//!   that does not exist.
//!
//! This mirrors the already-fixed `hosts.remote_ip` case (see
//! `tests/hosts_remote_ip.rs` and the `HOST_COLUMNS` comment in `repo.rs`):
//! explicit `::inet` on write, `host(...)` render on read, no new sqlx codec.
//!
//! `#[ignore]`d and gated on a live Postgres, like the other storage suites:
//!
//! ```bash
//! DATABASE_URL=postgresql://prx_waf:prx_waf@127.0.0.1:15432/prx_waf \
//!   cargo test -p waf-storage --test attack_logs_client_ip -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use uuid::Uuid;
use waf_storage::models::{AttackLog, AttackLogQuery, CreateSecurityEvent, SecurityEventQuery};
use waf_storage::{Database, StorageError};

fn database_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgresql://prx_waf:prx_waf@127.0.0.1:15432/prx_waf".to_string())
}

async fn connect() -> Database {
    let db = Database::connect(&database_url(), 5).await.expect("connect Postgres");
    db.migrate().await.expect("migrate");
    db
}

/// Every test tags its rows with a unique `host_code` so the suite never reads
/// or deletes another test's data, even though CI runs it `--test-threads=1`.
fn tag() -> String {
    format!("al-{}", &Uuid::new_v4().simple().to_string()[..12])
}

fn log_row(host_code: &str, client_ip: &str, action: &str) -> AttackLog {
    AttackLog {
        id: Uuid::new_v4(),
        host_code: host_code.to_string(),
        host: "example.test".to_string(),
        client_ip: client_ip.to_string(),
        method: "GET".to_string(),
        path: "/admin".to_string(),
        query: Some("id=1' OR '1'='1".to_string()),
        rule_id: Some("rule-42".to_string()),
        rule_name: "SQL Injection".to_string(),
        action: action.to_string(),
        phase: "url_blacklist".to_string(),
        detail: Some("matched blacklist".to_string()),
        request_headers: Some(serde_json::json!({ "user-agent": "curl/8" })),
        geo_info: Some(serde_json::json!({ "country": "Testland", "iso_code": "TL" })),
        created_at: chrono::Utc::now(),
    }
}

fn query_for(host_code: &str) -> AttackLogQuery {
    AttackLogQuery {
        host_code: Some(host_code.to_string()),
        client_ip: None,
        action: None,
        country: None,
        iso_code: None,
        page: None,
        page_size: None,
    }
}

async fn cleanup(db: &Database, host_code: &str) {
    sqlx::query("DELETE FROM attack_logs WHERE host_code = $1")
        .bind(host_code)
        .execute(db.pool())
        .await
        .expect("cleanup");
}

async fn cleanup_security_events(db: &Database, host_code: &str) {
    sqlx::query("DELETE FROM security_events WHERE host_code = $1")
        .bind(host_code)
        .execute(db.pool())
        .await
        .expect("cleanup security_events");
}

/// The core regression: an IPv4 insert must succeed (was `42804`) and every
/// column must survive the round-trip, with `client_ip` rendered as a bare
/// address — no `/32` netmask leaking out of the `INET` column.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn insert_and_read_back_ipv4() {
    let db = connect().await;
    let host_code = tag();

    let written = log_row(&host_code, "203.0.113.45", "block");
    db.create_attack_log(written.clone())
        .await
        .expect("create_attack_log must succeed (regression: 42804 inet vs text)");

    let (rows, total) = db
        .list_attack_logs(&query_for(&host_code))
        .await
        .expect("list_attack_logs must decode the INET column (regression: decode error)");

    assert_eq!(total, 1, "count query must see the inserted row");
    assert_eq!(rows.len(), 1);
    let got = &rows[0];
    assert_eq!(got.client_ip, "203.0.113.45", "client_ip must round-trip without /32");
    assert_eq!(got.id, written.id);
    assert_eq!(got.host_code, written.host_code);
    assert_eq!(got.host, written.host);
    assert_eq!(got.method, written.method);
    assert_eq!(got.path, written.path);
    assert_eq!(got.query, written.query);
    assert_eq!(got.rule_id, written.rule_id);
    assert_eq!(got.rule_name, written.rule_name);
    assert_eq!(got.action, written.action);
    assert_eq!(got.phase, written.phase);
    assert_eq!(got.detail, written.detail);
    assert_eq!(got.request_headers, written.request_headers);
    assert_eq!(got.geo_info, written.geo_info);

    cleanup(&db, &host_code).await;
}

/// IPv6 is what an `INET` column is *for*, and the WAF sees it on any
/// dual-stack listener. It must store and read back in full, without a `/128`
/// suffix and without Postgres' own re-canonicalisation surprising the caller.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn insert_and_read_back_ipv6() {
    let db = connect().await;
    let host_code = tag();

    db.create_attack_log(log_row(&host_code, "2001:db8::dead:beef", "block"))
        .await
        .expect("IPv6 create_attack_log must succeed");

    let (rows, total) = db.list_attack_logs(&query_for(&host_code)).await.expect("list");
    assert_eq!(total, 1);
    assert_eq!(
        rows[0].client_ip, "2001:db8::dead:beef",
        "IPv6 must round-trip without a /128 suffix"
    );

    cleanup(&db, &host_code).await;
}

/// `?client_ip=<addr>` must select exactly the matching rows — the filter used
/// to be `inet = text`, an operator Postgres does not have.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn filter_by_exact_ip() {
    let db = connect().await;
    let host_code = tag();

    db.create_attack_log(log_row(&host_code, "198.51.100.7", "block"))
        .await
        .expect("insert v4");
    db.create_attack_log(log_row(&host_code, "198.51.100.8", "block"))
        .await
        .expect("insert other v4");
    db.create_attack_log(log_row(&host_code, "2001:db8::1", "block"))
        .await
        .expect("insert v6");

    let mut q = query_for(&host_code);
    q.client_ip = Some("198.51.100.7".to_string());
    let (rows, total) = db.list_attack_logs(&q).await.expect("filter by v4");
    assert_eq!(total, 1, "exact IPv4 filter must match exactly one row");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].client_ip, "198.51.100.7");

    q.client_ip = Some("2001:db8::1".to_string());
    let (rows, total) = db.list_attack_logs(&q).await.expect("filter by v6");
    assert_eq!(total, 1, "exact IPv6 filter must match exactly one row");
    assert_eq!(rows[0].client_ip, "2001:db8::1");

    q.client_ip = Some("203.0.113.99".to_string());
    let (rows, total) = db.list_attack_logs(&q).await.expect("filter by absent IP");
    assert_eq!(total, 0, "an IP with no rows must return nothing, not everything");
    assert!(rows.is_empty());

    cleanup(&db, &host_code).await;
}

/// A CIDR in `?client_ip=` must select the whole subnet. This is the reason the
/// column is `INET` rather than `TEXT`: "show me everything from 10.0.0.0/8" is
/// the query an operator actually runs during an incident.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn filter_by_cidr_subnet() {
    let db = connect().await;
    let host_code = tag();

    db.create_attack_log(log_row(&host_code, "10.1.2.3", "block"))
        .await
        .expect("insert in-subnet");
    db.create_attack_log(log_row(&host_code, "10.4.5.6", "block"))
        .await
        .expect("insert in-subnet 2");
    db.create_attack_log(log_row(&host_code, "192.0.2.7", "block"))
        .await
        .expect("insert out-of-subnet");
    db.create_attack_log(log_row(&host_code, "2001:db8:abcd::5", "block"))
        .await
        .expect("insert v6 in-subnet");

    let mut q = query_for(&host_code);
    q.client_ip = Some("10.0.0.0/8".to_string());
    let (rows, total) = db.list_attack_logs(&q).await.expect("filter by v4 CIDR");
    assert_eq!(total, 2, "10.0.0.0/8 must match both 10.x rows and neither other");
    let mut ips: Vec<&str> = rows.iter().map(|r| r.client_ip.as_str()).collect();
    ips.sort_unstable();
    assert_eq!(ips, vec!["10.1.2.3", "10.4.5.6"]);

    q.client_ip = Some("2001:db8:abcd::/48".to_string());
    let (rows, total) = db.list_attack_logs(&q).await.expect("filter by v6 CIDR");
    assert_eq!(total, 1, "an IPv6 CIDR must not match IPv4 rows");
    assert_eq!(rows[0].client_ip, "2001:db8:abcd::5");

    // A /32 written explicitly is still just one host.
    q.client_ip = Some("10.1.2.3/32".to_string());
    let (_, total) = db.list_attack_logs(&q).await.expect("filter by /32");
    assert_eq!(total, 1);

    cleanup(&db, &host_code).await;
}

/// A malformed address must be rejected in the repo layer as a clean
/// [`StorageError::InvalidInput`] — never a panic, and never a raw Postgres
/// `22P02` surfacing as a 500 from `GET /api/attack-logs?client_ip=...`.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn invalid_client_ip_is_clean_error() {
    let db = connect().await;
    let host_code = tag();

    let err = db
        .create_attack_log(log_row(&host_code, "not-an-ip", "block"))
        .await
        .expect_err("a malformed client_ip must be rejected on write");
    assert!(
        matches!(err, StorageError::InvalidInput(_)),
        "expected InvalidInput, got: {err:?}"
    );

    for bad in ["not-an-ip", "10.0.0.0/99", "10.0.0.0/", "'; DROP TABLE attack_logs; --"] {
        let mut q = query_for(&host_code);
        q.client_ip = Some(bad.to_string());
        match db.list_attack_logs(&q).await {
            Err(StorageError::InvalidInput(_)) => {}
            Err(other) => panic!("filter {bad:?} must fail as InvalidInput, got: {other:?}"),
            Ok(_) => panic!("filter {bad:?} must be rejected, not silently accepted"),
        }
    }

    // The table survived the injection-shaped filter above.
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM attack_logs")
        .fetch_one(db.pool())
        .await
        .expect("attack_logs must still exist");
    let _ = total;

    cleanup(&db, &host_code).await;
}

/// The `attack_logs` half of `get_stats_overview` (`repo.rs` `total_blocked` /
/// `total_allowed`) never touched `client_ip`, so the SQL was always valid —
/// but with every insert failing it could only ever report 0. Prove the numbers
/// move once rows land.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn stats_overview_counts_attack_logs() {
    let db = connect().await;
    let host_code = tag();

    let before = db.get_stats_overview().await.expect("stats before");

    db.create_attack_log(log_row(&host_code, "203.0.113.10", "block"))
        .await
        .expect("insert block");
    db.create_attack_log(log_row(&host_code, "203.0.113.11", "allow"))
        .await
        .expect("insert allow");

    let after = db.get_stats_overview().await.expect("stats after");
    assert_eq!(
        after.total_blocked,
        before.total_blocked + 1,
        "a blocked attack_log must raise total_blocked (was pinned at 0 by the insert failure)"
    );
    assert_eq!(
        after.total_allowed,
        before.total_allowed + 1,
        "an allowed attack_log must raise total_allowed"
    );

    cleanup(&db, &host_code).await;
}

/// The batched insert behind `waf_engine::detection_sink`, against a real
/// Postgres.
///
/// This is not redundant with the single-row tests above. `create_attack_logs`
/// builds its statement text at runtime — one `VALUES` tuple per row, with the
/// `$n` numbering and the `::inet` casts generated rather than written out — and
/// none of that is exercised by a mock writer or by a single-row insert. The
/// only production caller is a background worker that downgrades an error to a
/// `warn!`, which is exactly the shape of failure that stayed invisible for the
/// `INET` bug this file was created for: a malformed multi-row statement would
/// fail the same silent way, and the table would simply never fill.
///
/// So: insert a batch, read every row back, and assert the values did not get
/// shuffled between placeholder positions — the failure mode a hand-generated
/// parameter list actually has, and one that produces perfectly valid rows
/// carrying each other's data.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn a_batch_insert_writes_every_row_with_its_own_values() {
    let db = connect().await;
    let host_code = tag();

    let ips = ["203.0.113.20", "198.51.100.7", "2001:db8::42", "203.0.113.21"];
    let batch: Vec<AttackLog> = ips
        .iter()
        .enumerate()
        .map(|(i, ip)| {
            let mut row = log_row(&host_code, ip, if i % 2 == 0 { "block" } else { "allow" });
            row.path = format!("/row-{i}");
            row.rule_name = format!("rule-name-{i}");
            row
        })
        .collect();

    db.create_attack_logs(batch.clone()).await.expect("batch insert");

    let (rows, total) = db.list_attack_logs(&query_for(&host_code)).await.expect("read back");
    assert_eq!(total, 4, "all four rows must land in one statement");
    assert_eq!(rows.len(), 4);

    for expected in &batch {
        let got = rows
            .iter()
            .find(|r| r.id == expected.id)
            .unwrap_or_else(|| panic!("row {} missing from the batch read-back", expected.id));
        assert_eq!(got.path, expected.path, "path bound to the wrong row");
        assert_eq!(got.rule_name, expected.rule_name, "rule_name bound to the wrong row");
        assert_eq!(got.action, expected.action, "action bound to the wrong row");
        assert_eq!(got.client_ip, expected.client_ip, "client_ip bound to the wrong row");
        assert_eq!(got.method, expected.method);
        assert_eq!(got.host, expected.host);
        assert_eq!(got.query, expected.query);
        assert_eq!(got.detail, expected.detail);
    }

    cleanup(&db, &host_code).await;
}

/// A batch is validated before any SQL is built, so one bad address fails the
/// whole batch as a named error rather than as a raw Postgres `22P02` after some
/// rows have already been composed into the statement.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn one_bad_address_fails_the_batch_as_a_clean_error() {
    let db = connect().await;
    let host_code = tag();

    let batch = vec![
        log_row(&host_code, "203.0.113.30", "block"),
        log_row(&host_code, "not-an-ip", "block"),
    ];
    let err = db
        .create_attack_logs(batch)
        .await
        .expect_err("must reject the bad address");
    assert!(
        matches!(err, StorageError::InvalidInput(_)),
        "expected a validation error naming the field, got {err:?}"
    );

    let (_, total) = db.list_attack_logs(&query_for(&host_code)).await.expect("read back");
    assert_eq!(total, 0, "a rejected batch must not have written its good rows either");

    cleanup(&db, &host_code).await;
}

/// The drain loop can legitimately produce an empty batch; it must not become an
/// `INSERT ... VALUES` with nothing after it.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn an_empty_batch_is_a_no_op() {
    let db = connect().await;
    db.create_attack_logs(Vec::new()).await.expect("empty attack log batch");
    db.create_security_events(Vec::new())
        .await
        .expect("empty security event batch");
}

/// The `security_events` batch, likewise against a real database — same
/// generated-placeholder risk, and it is the queue the flood actually fills.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn a_security_event_batch_writes_every_row_with_its_own_values() {
    let db = connect().await;
    let host_code = tag();

    let batch: Vec<CreateSecurityEvent> = (0..4)
        .map(|i| CreateSecurityEvent {
            host_code: host_code.clone(),
            client_ip: format!("203.0.113.{}", 40 + i),
            method: "GET".to_string(),
            path: format!("/sec-{i}"),
            rule_id: Some(format!("rule-{i}")),
            rule_name: format!("sql_injection_{i}"),
            action: if i % 2 == 0 { "block" } else { "log_only" }.to_string(),
            detail: Some(format!("detail-{i}")),
            geo_info: None,
        })
        .collect();

    db.create_security_events(batch.clone()).await.expect("batch insert");

    let query = SecurityEventQuery {
        host_code: Some(host_code.clone()),
        client_ip: None,
        rule_name: None,
        action: None,
        country: None,
        iso_code: None,
        page: None,
        page_size: None,
    };
    let (rows, total) = db.list_security_events(&query).await.expect("read back");
    assert_eq!(total, 4, "all four rows must land in one statement");

    for expected in &batch {
        let got = rows
            .iter()
            .find(|r| r.path == expected.path)
            .unwrap_or_else(|| panic!("row {} missing from the batch read-back", expected.path));
        assert_eq!(got.rule_name, expected.rule_name, "rule_name bound to the wrong row");
        assert_eq!(got.action, expected.action, "action bound to the wrong row");
        assert_eq!(got.client_ip, expected.client_ip, "client_ip bound to the wrong row");
        assert_eq!(got.detail, expected.detail);
    }

    cleanup_security_events(&db, &host_code).await;
}
