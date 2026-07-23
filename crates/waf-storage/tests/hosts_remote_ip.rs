//! DB-gated regression test for the `hosts.remote_ip` INET binding bug.
//!
//! `remote_ip` is a Postgres `INET` column while the `Host` model carries it as
//! `Option<String>`. Before the fix, `create_host`/`update_host` bound the
//! `Option<String>` as a text parameter straight into the `INET` column, which
//! Postgres rejects with `42804` (column is of type inet but expression is of
//! type text) — so host creation through the admin API always failed. This
//! suite proves the full create → select round-trip now works for a real IP,
//! for `NULL`, across an update, and that an invalid IP is rejected cleanly.
//!
//! `#[ignore]`d and gated on a live Postgres, like the other storage suites:
//!
//! ```bash
//! DATABASE_URL=postgresql://prx_waf:prx_waf@127.0.0.1:15432/prx_waf \
//!   cargo test -p waf-storage --test hosts_remote_ip -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use waf_storage::Database;
use waf_storage::StorageError;
use waf_storage::models::{CreateHost, UpdateHost};

fn database_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgresql://prx_waf:prx_waf@127.0.0.1:15432/prx_waf".to_string())
}

fn create_req(remote_ip: Option<&str>) -> CreateHost {
    CreateHost {
        host: format!("remote-ip-{}.test", uuid::Uuid::new_v4()),
        port: 80,
        ssl: false,
        guard_status: true,
        remote_host: "127.0.0.1".to_string(),
        remote_port: 8080,
        remote_ip: remote_ip.map(str::to_string),
        cert_file: None,
        key_file: None,
        remarks: None,
        start_status: true,
        log_only_mode: false,
    }
}

/// `remote_ip = Some(ipv4)` must persist and round-trip through `get_host`
/// byte-for-byte (no `/32` netmask suffix leaking from the `INET` render).
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn create_and_read_back_ipv4() {
    let db = Database::connect(&database_url(), 5).await.expect("connect Postgres");
    db.migrate().await.expect("migrate");

    let created = db
        .create_host(create_req(Some("192.168.1.10")))
        .await
        .expect("create_host with a valid IP must succeed (regression: 42804)");
    assert_eq!(created.remote_ip.as_deref(), Some("192.168.1.10"));

    let fetched = db
        .get_host(created.id)
        .await
        .expect("get_host")
        .expect("host must exist");
    assert_eq!(
        fetched.remote_ip.as_deref(),
        Some("192.168.1.10"),
        "remote_ip must round-trip without a netmask suffix"
    );

    db.delete_host(created.id).await.expect("cleanup");
}

/// `remote_ip = None` must persist as SQL `NULL` and read back as `None`.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn create_and_read_back_none() {
    let db = Database::connect(&database_url(), 5).await.expect("connect Postgres");
    db.migrate().await.expect("migrate");

    let created = db
        .create_host(create_req(None))
        .await
        .expect("create_host with remote_ip=None must succeed (regression: 42804)");
    assert_eq!(created.remote_ip, None);

    let fetched = db
        .get_host(created.id)
        .await
        .expect("get_host")
        .expect("host must exist");
    assert_eq!(fetched.remote_ip, None);

    db.delete_host(created.id).await.expect("cleanup");
}

/// `update_host` must set, then clear-and-replace `remote_ip` and have the new
/// value survive the `RETURNING` projection and a follow-up `get_host`.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn update_changes_remote_ip() {
    let db = Database::connect(&database_url(), 5).await.expect("connect Postgres");
    db.migrate().await.expect("migrate");

    let created = db.create_host(create_req(Some("10.0.0.1"))).await.expect("create_host");

    let update = UpdateHost {
        host: None,
        port: None,
        ssl: None,
        guard_status: None,
        remote_host: None,
        remote_port: None,
        remote_ip: Some("10.0.0.2".to_string()),
        cert_file: None,
        key_file: None,
        remarks: None,
        start_status: None,
        log_only_mode: None,
    };
    let updated = db
        .update_host(created.id, update)
        .await
        .expect("update_host must succeed (regression: 42804)")
        .expect("host must exist");
    assert_eq!(updated.remote_ip.as_deref(), Some("10.0.0.2"));

    let fetched = db
        .get_host(created.id)
        .await
        .expect("get_host")
        .expect("host must exist");
    assert_eq!(fetched.remote_ip.as_deref(), Some("10.0.0.2"));

    db.delete_host(created.id).await.expect("cleanup");
}

/// An invalid IP must be rejected in the repo layer as a clean
/// `StorageError::InvalidInput` — never a panic and never a raw Postgres cast
/// error bubbling up.
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn invalid_ip_is_clean_error() {
    let db = Database::connect(&database_url(), 5).await.expect("connect Postgres");
    db.migrate().await.expect("migrate");

    let err = db
        .create_host(create_req(Some("not-an-ip")))
        .await
        .expect_err("invalid remote_ip must be rejected");
    match err {
        StorageError::InvalidInput(_) => {}
        other => panic!("expected StorageError::InvalidInput, got: {other:?}"),
    }
}
