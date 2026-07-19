// G0 — Content-security parity / characterization baseline (engine level).
//
// Companion to `content_security_parity.rs`. Pins the engine-only content
// contracts that require a live [`WafEngine`] (and therefore a database):
//   • the REAL `content_checkers` short-circuit order through
//     [`WafEngine::inspect`] (SQLi wins over a co-matching XSS payload);
//   • host `log_only_mode` downgrades a would-be Block to LogOnly;
//   • the body phase ([`WafEngine::inspect_body`]) re-scans the header/path/
//     query corpus (a clean body with a malicious query still blocks);
//   • HTTP/1.1 ↔ HTTP/3 entry-point parity — both gateways build a `RequestCtx`
//     and call the identical `inspect` / `inspect_body` methods
//     (proxy.rs:341/451, http3.rs:325/374), so an identical ctx yields an
//     identical decision. Driving real H1/H3 servers is out of scope for G0;
//     the shared engine path is the parity surface and is pinned here.
//
// `#[ignore]`d and gated on a live Postgres exactly like `synced_clear_e2e.rs`,
// because `WafEngine::new` needs a DB (the security-event log path is DB-backed
// even though these tests only exercise the in-memory detectors). Run with:
//
// ```bash
// DATABASE_URL=postgresql://prx_waf:prx_waf@127.0.0.1:15432/prx_waf \
//   cargo test -p waf-engine --test content_security_engine_parity -- --ignored --nocapture
// ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use waf_common::{HostConfig, Phase, RequestCtx, WafAction};
use waf_engine::{WafEngine, WafEngineConfig};
use waf_storage::Database;

fn database_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgresql://prx_waf:prx_waf@127.0.0.1:15432/prx_waf".to_string())
}

/// A ctx with a benign User-Agent so the header-phase Scanner/Bot detectors do
/// not fire ahead of the content detectors under test. `guard_status` and all
/// `DefenseConfig` flags default to on (the historical per-host default).
fn make_ctx(query: &str, body: &str, log_only: bool) -> RequestCtx {
    let host_config = Arc::new(HostConfig {
        code: "h1".to_string(),
        host: "example.com".to_string(),
        guard_status: true,
        log_only_mode: log_only,
        ..HostConfig::default()
    });
    let mut headers = HashMap::new();
    headers.insert("user-agent".to_string(), "Mozilla/5.0 (g0-parity)".to_string());
    RequestCtx {
        req_id: "g0-engine".to_string(),
        client_ip: "198.51.100.7".parse().expect("ip"),
        client_port: 12345,
        method: "GET".to_string(),
        host: "example.com".to_string(),
        port: 80,
        path: "/".to_string(),
        query: query.to_string(),
        headers,
        body_preview: Bytes::from(body.to_string()),
        content_length: body.len() as u64,
        is_tls: false,
        host_config,
        geo: None,
    }
}

async fn engine() -> WafEngine {
    let db = Arc::new(Database::connect(&database_url(), 5).await.expect("connect Postgres"));
    db.migrate().await.expect("migrate");
    WafEngine::new(db, WafEngineConfig::default())
}

// ── Real short-circuit order through inspect ─────────────────────────────────

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn inspect_content_short_circuits_sqli_before_xss() {
    let eng = engine().await;
    // Payload trips both SQLi (union select) and XSS (<script>). The real
    // content_checkers vector puts SQLi first → the decision is SQL Injection.
    let mut ctx = make_ctx("q=<script>union select 1</script>", "", false);
    let decision = eng.inspect(&mut ctx).await;
    assert!(matches!(decision.action, WafAction::Block { status: 403, .. }));
    let r = decision.result.expect("block result");
    assert_eq!(r.phase, Phase::SqlInjection);
    assert_eq!(r.rule_name, "SQL Injection");
}

// ── Host log-only downgrade ──────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn host_block_when_log_only_disabled() {
    let eng = engine().await;
    let mut ctx = make_ctx("id=1 union select 1,2,3", "", false);
    let decision = eng.inspect(&mut ctx).await;
    assert!(
        matches!(decision.action, WafAction::Block { status: 403, .. }),
        "log_only_mode=false must Block, got {:?}",
        decision.action
    );
    assert!(!decision.is_allowed());
}

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn host_log_only_downgrades_block_to_logonly() {
    let eng = engine().await;
    let mut ctx = make_ctx("id=1 union select 1,2,3", "", true);
    let decision = eng.inspect(&mut ctx).await;
    // Same malicious request, but log_only_mode=true → LogOnly, not Block.
    assert!(
        matches!(decision.action, WafAction::LogOnly),
        "log_only_mode=true must downgrade to LogOnly, got {:?}",
        decision.action
    );
    // The detection is still populated (the hit is recorded, just not blocked)
    // and LogOnly counts as "allowed" for forwarding purposes.
    assert!(decision.is_allowed());
    let r = decision.result.expect("log-only still carries the detection");
    assert_eq!(r.phase, Phase::SqlInjection);
}

// ── Body phase re-scans the header/path/query corpus ─────────────────────────

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn inspect_body_rescans_query_even_with_clean_body() {
    let eng = engine().await;
    // Clean body, malicious query. The body phase feeds the same request_targets
    // corpus, so the query is (re-)scanned and the request is blocked.
    let mut ctx = make_ctx("id=1 union select 1,2,3", "clean=payload", false);
    let decision = eng.inspect_body(&mut ctx).await;
    assert!(matches!(decision.action, WafAction::Block { status: 403, .. }));
    let r = decision.result.expect("block result");
    assert_eq!(r.phase, Phase::SqlInjection);
    assert_eq!(r.detail, "UNION SELECT injection detected in query");
}

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn inspect_body_flags_malicious_body() {
    let eng = engine().await;
    let mut ctx = make_ctx("", "cmd=$(id)", false);
    let decision = eng.inspect_body(&mut ctx).await;
    assert!(matches!(decision.action, WafAction::Block { status: 403, .. }));
    let r = decision.result.expect("block result");
    assert_eq!(r.phase, Phase::Rce);
    assert_eq!(r.detail, "$() command substitution detected in body");
}

// ── HTTP/1.1 ↔ HTTP/3 entry-point parity ─────────────────────────────────────
//
// Both the HTTP/1.1 proxy (proxy.rs:341 `inspect`, :451 `inspect_body`) and the
// HTTP/3 forwarder (http3.rs:325 `inspect`, :374 `inspect_body`) construct a
// `RequestCtx` and call the SAME two engine methods. There is no per-protocol
// detection branch, so parity reduces to: identical ctx → identical decision.
// Pinned here by running the same malicious/clean requests twice and asserting
// the engine is deterministic across the shared entry point.

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn entrypoint_parity_same_ctx_same_decision() {
    let eng = engine().await;

    // Malicious: both "entry points" (identical ctx) block identically.
    let mut a = make_ctx("q=<script>alert(1)</script>", "", false);
    let mut b = make_ctx("q=<script>alert(1)</script>", "", false);
    let da = eng.inspect(&mut a).await;
    let db = eng.inspect(&mut b).await;
    match (&da.action, &db.action) {
        (WafAction::Block { status: sa, .. }, WafAction::Block { status: sb, .. }) => assert_eq!(sa, sb),
        other => panic!("expected both to Block, got {other:?}"),
    }
    assert_eq!(
        da.result.expect("a").rule_id,
        db.result.expect("b").rule_id,
        "identical ctx must yield identical rule_id across entry points"
    );

    // Clean: both allow identically.
    let mut c = make_ctx("q=hello", "", false);
    let mut d = make_ctx("q=hello", "", false);
    assert!(eng.inspect(&mut c).await.is_allowed());
    assert!(eng.inspect(&mut d).await.is_allowed());
}
