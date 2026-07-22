// G0 — Content-security parity / characterization baseline (checker level).
//
// Purpose: pin the *currently observable* behaviour of the four content
// detectors (`SQLi` / XSS / RCE) plus `DirTraversal` as a zero-regression
// parity baseline for the planned G1 refactor (moving these checkers into a
// `ContentSecuritySubsystem`). Every assertion documents one cell of the
// contract matrix. **These tests deliberately assert the status quo** — where
// today's behaviour is surprising, the surprise is recorded in a comment and
// pinned as-is (G0 changes no production logic).
//
// This file needs **no database** and runs in the default `cargo test`
// gate. The engine-level contracts that require a live `WafEngine` (real
// `content_checkers` short-circuit ordering through `inspect`, host
// `log_only_mode` downgrade, HTTP/1.1↔HTTP/3 entry-point parity) live in the
// sibling `content_security_engine_parity.rs`, gated on a live Postgres and
// `#[ignore]`d — mirroring `synced_clear_e2e.rs`.
//
// ── Contract matrix (checker level) ──────────────────────────────────────
//   For each of {SQLi, XSS, RCE, Traversal}:
//     • representative malicious hit → Some, exact rule_id prefix + id,
//       exact `detail` string, exact `phase`.
//     • representative clean input   → None.
//     • per-host `DefenseConfig` toggle off → None (checker self-disables).
//   Cross-cutting:
//     • URL single- and double-encoded evasion vectors → hit.
//     • location coverage: path / query / cookie / body / curated header —
//       observable via the `detected in <location>` suffix of `detail`.
//     • "body-phase re-scans header/path/query" status quo — a ctx carrying a
//       body still has its path/query/headers inspected (the same
//       `request_targets` set feeds both phases).
//     • intended precedence chain SQLi → XSS → RCE → Traversal (first match
//       wins), pinned here over the same-ordered checker vector that
//       `engine.rs` constructs (engine.rs:111-116). The *real* engine
//       short-circuit is additionally pinned DB-gated in the sibling file.
//     • fail-closed: NOTE only — see comment near the end. The pattern sets
//       are compile-time string literals, so the `*_SET == None` fail-closed
//       branch cannot be triggered from outside the crate; not force-tested.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use waf_common::{HostConfig, Phase, RequestCtx};
use waf_engine::checks::{Check, DirTraversalCheck, RceCheck, SqlInjectionCheck, XssCheck};
use waf_engine::{ContentSecuritySubsystem, ContentVerdict};

// ── Fixtures ────────────────────────────────────────────────────────────────

/// Build a `RequestCtx` with all defenses enabled (matches `DefenseConfig`'s
/// `Default`, which is the historical per-host default: every content detector
/// on). Individual tests flip a single flag to pin the per-host toggle.
fn ctx() -> RequestCtx {
    RequestCtx {
        req_id: "g0".to_string(),
        client_ip: "127.0.0.1".parse().expect("valid ip literal"),
        client_port: 0,
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

fn with_query(mut c: RequestCtx, q: &str) -> RequestCtx {
    c.query = q.to_string();
    c
}

fn with_path(mut c: RequestCtx, p: &str) -> RequestCtx {
    c.path = p.to_string();
    c
}

fn with_body(mut c: RequestCtx, b: &str) -> RequestCtx {
    c.body_preview = Bytes::from(b.to_string());
    c.content_length = b.len() as u64;
    c
}

fn with_header(mut c: RequestCtx, name: &str, value: &str) -> RequestCtx {
    c.headers.insert(name.to_string(), value.to_string());
    c
}

// ═════════════════════════════════════════════════════════════════════════════
// SQL Injection — hit / detail / phase / rule_id, clean, toggle
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn sqli_union_select_hit_pins_rule_id_detail_phase() {
    let r = SqlInjectionCheck::new()
        .check(&with_query(ctx(), "id=1 union select 1,2,3"))
        .expect("UNION SELECT must be detected");
    assert_eq!(r.rule_id.as_deref(), Some("SQLI-001"));
    assert_eq!(r.rule_name, "SQL Injection");
    assert_eq!(r.phase, Phase::SqlInjection);
    assert_eq!(r.detail, "UNION SELECT injection detected in query");
}

#[test]
fn sqli_clean_query_is_allowed() {
    assert!(
        SqlInjectionCheck::new()
            .check(&with_query(ctx(), "name=alice&page=2"))
            .is_none()
    );
}

#[test]
fn sqli_disabled_by_host_toggle_never_hits() {
    let mut c = with_query(ctx(), "id=1 union select 1,2,3");
    Arc::make_mut(&mut c.host_config).defense_config.sqli = false;
    assert!(SqlInjectionCheck::new().check(&c).is_none());
}

// ═════════════════════════════════════════════════════════════════════════════
// XSS — hit / detail / phase / rule_id, clean, toggle
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn xss_script_tag_hit_pins_rule_id_detail_phase() {
    let r = XssCheck::new()
        .check(&with_query(ctx(), "q=<script>alert(1)</script>"))
        .expect("<script> must be detected");
    assert_eq!(r.rule_id.as_deref(), Some("XSS-001"));
    assert_eq!(r.rule_name, "XSS");
    assert_eq!(r.phase, Phase::Xss);
    assert_eq!(r.detail, "<script> tag detected in query");
}

#[test]
fn xss_clean_query_is_allowed() {
    assert!(
        XssCheck::new()
            .check(&with_query(ctx(), "q=hello+world&page=1"))
            .is_none()
    );
}

#[test]
fn xss_disabled_by_host_toggle_never_hits() {
    let mut c = with_query(ctx(), "q=<script>alert(1)</script>");
    Arc::make_mut(&mut c.host_config).defense_config.xss = false;
    assert!(XssCheck::new().check(&c).is_none());
}

// ═════════════════════════════════════════════════════════════════════════════
// RCE — hit / detail / phase / rule_id, clean, toggle
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn rce_subshell_hit_pins_rule_id_detail_phase() {
    // `$(id)` matches only the command-substitution pattern (index 1 → RCE-002);
    // it does not carry a pipe/semicolon so it never trips index 0.
    let r = RceCheck::new()
        .check(&with_body(ctx(), "cmd=$(id)"))
        .expect("$() substitution must be detected");
    assert_eq!(r.rule_id.as_deref(), Some("RCE-002"));
    assert_eq!(r.rule_name, "RCE");
    assert_eq!(r.phase, Phase::Rce);
    assert_eq!(r.detail, "$() command substitution detected in body");
}

#[test]
fn rce_clean_body_is_allowed() {
    assert!(
        RceCheck::new()
            .check(&with_body(ctx(), "action=save&name=hello"))
            .is_none()
    );
}

#[test]
fn rce_disabled_by_host_toggle_never_hits() {
    let mut c = with_body(ctx(), "cmd=$(id)");
    Arc::make_mut(&mut c.host_config).defense_config.rce = false;
    assert!(RceCheck::new().check(&c).is_none());
}

// ═════════════════════════════════════════════════════════════════════════════
// Directory Traversal — hit / detail / phase / rule_id, clean, toggle, encodings
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn traversal_dotdot_slash_hit_pins_rule_id_detail_phase() {
    // "/images/../../../etc/passwd" matches both the literal "../" (index 0) and
    // the absolute-sensitive-dir "/etc" (index 6); `RegexSet::matches().next()`
    // returns the lowest index → TRAV-001.
    let r = DirTraversalCheck::new()
        .check(&with_path(ctx(), "/images/../../../etc/passwd"))
        .expect("../ must be detected");
    assert_eq!(r.rule_id.as_deref(), Some("TRAV-001"));
    assert_eq!(r.rule_name, "Directory Traversal");
    assert_eq!(r.phase, Phase::DirTraversal);
    assert_eq!(r.detail, "directory traversal (../) detected in path");
}

#[test]
fn traversal_clean_path_is_allowed() {
    let c = with_query(with_path(ctx(), "/api/v1/users"), "page=2");
    assert!(DirTraversalCheck::new().check(&c).is_none());
}

#[test]
fn traversal_disabled_by_host_toggle_never_hits() {
    let mut c = with_path(ctx(), "/images/../../../etc/passwd");
    Arc::make_mut(&mut c.host_config).defense_config.dir_traversal = false;
    assert!(DirTraversalCheck::new().check(&c).is_none());
}

#[test]
fn traversal_url_single_encoded_hit_in_raw_query() {
    // Raw query already carries "%2e%2e%2f" (index 1 → TRAV-002); `request_targets`
    // scans the raw form first, so the hit is reported against "query" (not the
    // decoded variant).
    let r = DirTraversalCheck::new()
        .check(&with_query(ctx(), "file=%2e%2e%2fetc%2fpasswd"))
        .expect("single-encoded traversal must be detected");
    assert_eq!(r.rule_id.as_deref(), Some("TRAV-002"));
    assert_eq!(r.detail, "URL-encoded traversal (%2e%2e) detected in query");
}

#[test]
fn traversal_url_double_encoded_hit() {
    // "%252e%252e" (index 2 → TRAV-003) wins over the "/etc" substring (index 6).
    let r = DirTraversalCheck::new()
        .check(&with_path(ctx(), "/%252e%252e/etc/passwd"))
        .expect("double-encoded traversal must be detected");
    assert_eq!(r.rule_id.as_deref(), Some("TRAV-003"));
    assert_eq!(r.detail, "double URL-encoded traversal (%252e%252e) detected in path");
}

// ═════════════════════════════════════════════════════════════════════════════
// Location coverage — the `detected in <location>` suffix pins which request
// target matched. Confirms path / query / cookie / body / curated header are
// all inspected by the same `request_targets` corpus.
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn location_body_is_scanned() {
    let r = DirTraversalCheck::new()
        .check(&with_body(ctx(), "file=../../../etc/passwd"))
        .expect("body must be scanned");
    assert_eq!(r.detail, "directory traversal (../) detected in body");
}

#[test]
fn location_cookie_is_scanned() {
    let c = with_header(ctx(), "cookie", "sid=..%2f..%2fetc%2fpasswd");
    let r = DirTraversalCheck::new().check(&c).expect("cookie must be scanned");
    // The raw cookie carries literal ".." + "%2f", which matches neither the
    // literal "../" (index 0, needs a real slash) nor the "%2e%2e" encoded
    // pattern (index 1, needs encoded dots). Only the *decoded* cookie
    // ("../../etc/passwd") trips index 0 → TRAV-001, reported against the
    // "cookie(decoded)" location. Pins that cookies are decoded before scanning.
    assert_eq!(r.rule_id.as_deref(), Some("TRAV-001"));
    assert_eq!(r.detail, "directory traversal (../) detected in cookie(decoded)");
}

#[test]
fn location_curated_header_user_agent_is_scanned() {
    // `user-agent` is on the curated SCANNED_HEADERS allowlist (H-5).
    let c = with_header(ctx(), "user-agent", "x'; drop table users--");
    let r = SqlInjectionCheck::new()
        .check(&c)
        .expect("curated header must be scanned");
    assert_eq!(r.phase, Phase::SqlInjection);
    assert!(
        r.detail.ends_with("detected in user-agent"),
        "expected header location, got: {}",
        r.detail
    );
}

#[test]
fn location_non_curated_header_is_ignored() {
    // A header NOT on the curated allowlist must not be inspected — pins the
    // bounded-header status quo (H-5). `x-custom` carries a blatant payload yet
    // is ignored.
    let c = with_header(ctx(), "x-custom", "<script>alert(1)</script>");
    assert!(
        XssCheck::new().check(&c).is_none(),
        "non-curated header must not be scanned"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// "Body-phase re-scans header/path/query" status quo.
//
// The engine's body phase (`inspect_body` → `inspect_content`) feeds the very
// same `request_targets(ctx)` corpus as the header phase, so a ctx that carries
// a body still has its path / query / cookie / curated-headers inspected. Pinned
// observably here: a request with a *clean* body but a malicious query is still
// flagged against the query — i.e. the body phase does not restrict scanning to
// the body alone. This is a KNOWN redundancy (header content is scanned twice
// for body-bearing requests); G0 pins it so G1 can reason about parity.
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn body_bearing_request_still_scans_query() {
    let c = with_body(with_query(ctx(), "id=1 union select 1,2"), "clean=payload");
    let r = SqlInjectionCheck::new()
        .check(&c)
        .expect("query must still be scanned even when a body is present");
    assert_eq!(r.detail, "UNION SELECT injection detected in query");
}

#[test]
fn body_bearing_request_still_scans_path() {
    let c = with_body(with_path(ctx(), "/images/../../../etc/passwd"), "clean=payload");
    let r = DirTraversalCheck::new()
        .check(&c)
        .expect("path must still be scanned even when a body is present");
    assert_eq!(r.detail, "directory traversal (../) detected in path");
}

// ═════════════════════════════════════════════════════════════════════════════
// Intended precedence chain (SQLi → XSS → RCE → Traversal), first match wins.
//
// Pinned over the SAME-ORDERED checker vector that `engine.rs` builds at
// construction (engine.rs:111-116). The real engine short-circuit through
// `inspect_content` is additionally pinned DB-gated in
// `content_security_engine_parity.rs`.
// ═════════════════════════════════════════════════════════════════════════════

/// Mirror of `WafEngine::content_checkers` construction order (engine.rs:111-116).
fn content_checkers() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(SqlInjectionCheck::new()),
        Box::new(XssCheck::new()),
        Box::new(RceCheck::new()),
        Box::new(DirTraversalCheck::new()),
    ]
}

/// Run the ordered checker vector, returning the first hit (engine semantics).
fn first_hit(c: &RequestCtx) -> Option<waf_common::DetectionResult> {
    content_checkers().into_iter().find_map(|chk| chk.check(c))
}

#[test]
fn precedence_sqli_wins_over_xss() {
    // Payload trips both SQLi (union select) and XSS (<script>). SQLi is first.
    let c = with_query(ctx(), "q=<script>union select 1</script>");
    let r = first_hit(&c).expect("multi-hit payload must be flagged");
    assert_eq!(r.phase, Phase::SqlInjection);
    assert_eq!(r.rule_name, "SQL Injection");
}

#[test]
fn precedence_xss_wins_over_rce_and_traversal() {
    // No SQLi pattern; trips XSS (<script>), RCE (/etc/passwd) and Traversal
    // (../ and /etc). XSS is the earliest of the three in the vector.
    let c = with_query(ctx(), "q=<script></script>;cat /etc/passwd ../");
    let r = first_hit(&c).expect("multi-hit payload must be flagged");
    assert_eq!(r.phase, Phase::Xss);
    assert_eq!(r.rule_name, "XSS");
}

#[test]
fn precedence_rce_wins_over_traversal() {
    // No SQLi/XSS; trips RCE (;cat /etc/passwd) and Traversal (../ , /etc). RCE
    // precedes Traversal in the vector.
    let c = with_query(ctx(), "file=;cat /etc/passwd ../");
    let r = first_hit(&c).expect("multi-hit payload must be flagged");
    assert_eq!(r.phase, Phase::Rce);
    assert_eq!(r.rule_name, "RCE");
}

#[test]
fn precedence_traversal_alone_when_only_traversal_hits() {
    // Pure traversal payload → Traversal is the only (and therefore first) hit.
    let c = with_path(ctx(), "/a/../../b");
    let r = first_hit(&c).expect("traversal payload must be flagged");
    assert_eq!(r.phase, Phase::DirTraversal);
}

#[test]
fn precedence_clean_request_no_hit() {
    let c = with_query(with_path(ctx(), "/api/v1/users"), "page=2&sort=asc");
    assert!(first_hit(&c).is_none());
}

// ═════════════════════════════════════════════════════════════════════════════
// Fail-closed — NOTE (not force-tested).
//
// Each checker's pattern set is a `LazyLock<Option<RegexSet>>`. When compilation
// fails, `*_SET` is `None` and `check()` returns an unconditional match with
// rule_id "<PREFIX>-000" and a "fail-closed: … failed to compile at startup"
// detail (see sql_injection.rs:94-102 and siblings). Because every pattern is a
// compile-time string literal with no external input, the `None` branch is not
// reachable from outside the crate — there is no input that forces compilation
// to fail. It is therefore documented here and left un-exercised rather than
// forced with an artificial hook (G0 adds no production seam). The fail-closed
// contract to preserve across G1: id suffix "-000", phase unchanged, and a
// match (block) rather than a miss (allow) on compile failure.
// ═════════════════════════════════════════════════════════════════════════════

// ═════════════════════════════════════════════════════════════════════════════
// G0.1 — REAL production subsystem (`ContentSecuritySubsystem::evaluate`).
//
// The precedence tests above run a test-authored `content_checkers()` mirror
// vector: they pin the *intended* order but would stay green even if the real
// subsystem drifted. These tests instead drive the actual G1 production type
// (`ContentSecuritySubsystem`), so a mis-ordered or mis-wired subsystem is
// caught in the default (no-DB) gate. Same-order first-match-wins + each single
// hit + clean → None are pinned against the real `evaluate`. The DB-gated
// sibling additionally pins the full `WafEngine::inspect` entry-point path.
// ═════════════════════════════════════════════════════════════════════════════

/// Run the real production subsystem, returning the `LegacyVeto` detection (if any).
fn subsystem_legacy(c: &RequestCtx) -> Option<waf_common::DetectionResult> {
    match ContentSecuritySubsystem::new().evaluate(c) {
        ContentVerdict::LegacyVeto { result } => Some(result),
        ContentVerdict::None => None,
    }
}

#[test]
fn subsystem_sqli_single_hit() {
    let r = subsystem_legacy(&with_query(ctx(), "id=1 union select 1,2,3")).expect("SQLi LegacyVeto");
    assert_eq!(r.phase, Phase::SqlInjection);
    assert_eq!(r.rule_id.as_deref(), Some("SQLI-001"));
}

#[test]
fn subsystem_xss_single_hit() {
    let r = subsystem_legacy(&with_query(ctx(), "q=<script>alert(1)</script>")).expect("XSS LegacyVeto");
    assert_eq!(r.phase, Phase::Xss);
    assert_eq!(r.rule_id.as_deref(), Some("XSS-001"));
}

#[test]
fn subsystem_rce_single_hit() {
    let r = subsystem_legacy(&with_body(ctx(), "cmd=$(id)")).expect("RCE LegacyVeto");
    assert_eq!(r.phase, Phase::Rce);
    assert_eq!(r.rule_id.as_deref(), Some("RCE-002"));
}

#[test]
fn subsystem_traversal_single_hit() {
    // Pure traversal payload with no `/etc/passwd` and no shell tokens, so RCE
    // (which owns `/etc/passwd`, RCE-004) does not win ahead of Traversal in the
    // ordered subsystem — proving Traversal is reachable as a sole hit.
    let r = subsystem_legacy(&with_path(ctx(), "/a/../../b")).expect("Traversal LegacyVeto");
    assert_eq!(r.phase, Phase::DirTraversal);
    assert_eq!(r.rule_id.as_deref(), Some("TRAV-001"));
}

#[test]
fn subsystem_precedence_sqli_wins_over_xss() {
    // Trips both SQLi (union select) and XSS (<script>). SQLi is first.
    let r = subsystem_legacy(&with_query(ctx(), "q=<script>union select 1</script>")).expect("multi-hit");
    assert_eq!(r.phase, Phase::SqlInjection);
    assert_eq!(r.rule_name, "SQL Injection");
}

#[test]
fn subsystem_precedence_xss_wins_over_rce_and_traversal() {
    // No SQLi; trips XSS (<script>), RCE (/etc/passwd) and Traversal (../, /etc).
    let r = subsystem_legacy(&with_query(ctx(), "q=<script></script>;cat /etc/passwd ../")).expect("multi-hit");
    assert_eq!(r.phase, Phase::Xss);
    assert_eq!(r.rule_name, "XSS");
}

#[test]
fn subsystem_precedence_rce_wins_over_traversal() {
    // No SQLi/XSS; trips RCE (;cat /etc/passwd) and Traversal (../, /etc).
    let r = subsystem_legacy(&with_query(ctx(), "file=;cat /etc/passwd ../")).expect("multi-hit");
    assert_eq!(r.phase, Phase::Rce);
    assert_eq!(r.rule_name, "RCE");
}

#[test]
fn subsystem_traversal_alone() {
    // Pure traversal payload (no /etc, no shell) → Traversal is the only hit.
    let r = subsystem_legacy(&with_path(ctx(), "/a/../../b")).expect("traversal");
    assert_eq!(r.phase, Phase::DirTraversal);
}

#[test]
fn subsystem_clean_request_is_none() {
    let c = with_query(with_path(ctx(), "/api/v1/users"), "page=2&sort=asc");
    assert!(subsystem_legacy(&c).is_none());
}

#[test]
fn subsystem_respects_host_toggle() {
    // Disabling the sqli detector on the host makes the subsystem return None
    // for a pure SQLi payload (no other legacy detector matches it).
    let mut c = with_query(ctx(), "id=1 union select 1,2,3");
    Arc::make_mut(&mut c.host_config).defense_config.sqli = false;
    assert!(subsystem_legacy(&c).is_none());
}
