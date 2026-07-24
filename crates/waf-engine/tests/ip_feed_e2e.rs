//! End-to-end IP-feed adapter test.
//!
//! Exercises the full path: **fetch a real public feed over the network →
//! parse → load into the WAF block set → a request from a listed IP is blocked
//! (403), while a clean IP is allowed.**
//!
//! Ignored by default because it needs both outbound internet access and a live
//! Postgres (the `RuleStore` is DB-backed). Run explicitly with:
//!
//! ```bash
//! DATABASE_URL=postgresql://prx_waf:prx_waf@127.0.0.1:15432/prx_waf \
//!   cargo test -p waf-engine --test ip_feed_e2e -- --ignored --nocapture
//! ```
//!
//! Note on SSRF: the adapter intentionally rejects loopback/private feed URLs,
//! so a local `python3 -m http.server` cannot serve as a feed — that is by
//! design. This test therefore fetches a genuinely public feed (the Tor exit
//! list, CC0) to prove the fetch leg passes SSRF validation for a public host.

// Diagnostic test binary: `println!` reporting and direct indexing of the
// parsed feed are intentional and safe here (guarded by asserts).
#![allow(clippy::print_stdout, clippy::indexing_slicing, clippy::duration_suboptimal_units)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use bytes::Bytes;
use waf_common::{HostConfig, RequestCtx, WafAction};
use waf_engine::checker::{RuleStore, check_ip_blacklist};
use waf_engine::rules::ip_feed::{IpFeedFormat, IpFeedSource, fetch_ip_feed, parse_ip_feed, refresh_feed};
use waf_storage::Database;

const TOR_FEED_URL: &str = "https://check.torproject.org/torbulkexitlist";

fn database_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgresql://prx_waf:prx_waf@127.0.0.1:15432/prx_waf".to_string())
}

fn make_ctx(client_ip: IpAddr) -> RequestCtx {
    RequestCtx {
        req_id: "e2e".to_string(),
        client_ip,
        client_port: 12345,
        method: "GET".to_string(),
        host: "example.com".to_string(),
        port: 80,
        path: "/".to_string(),
        query: String::new(),
        headers: HashMap::new(),
        body_preview: Bytes::new(),
        content_length: 0,
        is_tls: false,
        host_config: Arc::new(HostConfig::default()),
        geo: None,
    }
}

#[tokio::test]
#[ignore = "requires internet + live Postgres; run with --ignored"]
async fn tor_feed_end_to_end_blocks_listed_ip() {
    // Install the process-level rustls `ring` CryptoProvider before the
    // reqwest-backed fetch builds its TLS client (reqwest is built with
    // `rustls-no-provider`; production does this in `prx-waf` main.rs). Without
    // it, the HTTPS fetch below panics with "no process-level CryptoProvider".
    // `install_default` returns Err only if already installed — idempotent here.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // 1. Fetch the real public feed (proves SSRF passes for a public host).
    let body = fetch_ip_feed(TOR_FEED_URL).await.expect("Tor exit list should fetch");

    // 2. Parse it (proves real-world fault-tolerant parsing).
    let parsed = parse_ip_feed(&body, IpFeedFormat::Plain);
    assert!(
        !parsed.nets.is_empty(),
        "the Tor exit list should contain at least one entry"
    );
    println!(
        "[e2e] fetched {} bytes, parsed {} nets ({} skipped)",
        body.len(),
        parsed.nets.len(),
        parsed.skipped
    );

    // Pick a concrete address that is guaranteed to be in the feed.
    let probe_ip = parsed.nets[0].addr();

    // 3. Build a DB-backed RuleStore and load the feed via the real refresh path.
    let db = Arc::new(
        Database::connect(&database_url(), 5)
            .await
            .expect("connect to e2e Postgres"),
    );
    db.migrate().await.expect("migrate");

    let store = RuleStore::new(Arc::clone(&db));
    let feed = IpFeedSource {
        name: "tor-exit".to_string(),
        url: TOR_FEED_URL.to_string(),
        format: IpFeedFormat::Plain,
        update_interval: std::time::Duration::from_secs(3600),
    };
    let loaded = refresh_feed(&store, &feed).await.expect("refresh feed");
    assert_eq!(loaded, parsed.nets.len(), "refresh should load every parsed net");

    // 4. A request from a listed IP must be blocked with 403.
    let decision = check_ip_blacklist(&make_ctx(probe_ip), &store);
    match decision.action {
        WafAction::Block { status, .. } => {
            assert_eq!(status, 403, "listed IP must be blocked with 403");
            let detail = decision.result.expect("block carries a detection result").detail;
            println!("[e2e] {probe_ip} blocked: {detail}");
            assert!(detail.contains("tor-exit"), "block detail should name the source feed");
        }
        other => panic!("expected 403 Block for listed IP {probe_ip}, got {other:?}"),
    }

    // 5. A clean public IP (Google DNS) that is not on the list must be allowed.
    let clean_ip: IpAddr = "8.8.8.8".parse().expect("valid ip");
    if store.feed_block_ips.match_source(clean_ip).is_none() {
        let decision = check_ip_blacklist(&make_ctx(clean_ip), &store);
        assert!(
            matches!(decision.action, WafAction::Allow),
            "a clean IP must be allowed"
        );
        println!("[e2e] {clean_ip} allowed (not on feed)");
    }
}
