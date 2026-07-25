//! Fuzz the full two-lane content-security evaluation, end to end.
//!
//! Surface: `ContentSecuritySubsystem::evaluate_scoped` with the semantic lane
//! enabled in shadow mode. One execution runs, over both inspection scopes:
//!
//!   * Lane 1 — the frozen regex detectors (`sql_injection`, `xss`, `rce`,
//!     `dir_traversal`);
//!   * Lane 2 — the preprocessor, then **every** registered semantic detector,
//!     which is where the third-party parsers with real crash risk live:
//!       - `brush-parser`  shell AST      (`RceAstDetector`)
//!       - `sqlparser`     SQL AST        (`AstSqlDetector`)
//!       - `html5ever`     HTML fragment  (`XssDomDetector` → `XssJsTokenDetector`)
//!   * the closed scoring model.
//!
//! This is the production request path, so a crash here is directly a remote
//! DoS. It is deliberately the slowest target (three parsers per view); the
//! narrower `preprocess_header` / `struct_extract` targets exist to reach deep
//! coverage of the decode and extraction layers without paying that cost.
//!
//! Input framing: `[content-type selector][placement selector][payload…]`.
//! Placement decides whether the payload lands in the body or in a header-scope
//! field, because the two scopes run different normaliser limits and different
//! field-collection code.

#![no_main]

use std::collections::HashMap;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use prx_waf_fuzz::{CONTENT_TYPES, HEADER_FIELDS, lane2_enabled_config, pick, place_header_field, request, text};
use waf_engine::checks::content_security::budget::{Budget, ContentInspectionState};
use waf_engine::checks::content_security::{ContentSecuritySubsystem, InspectionScope};

/// The subsystem compiles a large set of regexes and rule tables at
/// construction. Rebuilding it per execution would make the fuzzer measure
/// `Regex::new` rather than the detectors, so it is built exactly once. The
/// evaluation path is `&self`-only and carries no cross-request state (the
/// per-request budget lives in the `ContentInspectionState` recreated below),
/// so sharing it across executions is sound and keeps executions independent.
static SUBSYSTEM: OnceLock<ContentSecuritySubsystem> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let subsystem = SUBSYSTEM.get_or_init(|| ContentSecuritySubsystem::with_config(lane2_enabled_config()));

    let (ct_selector, rest) = match data.split_first() {
        Some(v) => v,
        None => return,
    };
    let (placement, payload) = match rest.split_first() {
        Some(v) => v,
        None => return,
    };
    let payload = prx_waf_fuzz::clamp(payload);
    let content_type = pick(CONTENT_TYPES, *ct_selector);

    // Even placement → body scope carries the payload; odd → a header field
    // does. Both scopes are always evaluated, matching the engine.
    let in_body = placement % 2 == 0;
    let field = pick(HEADER_FIELDS, placement / 2);

    let (path, query, mut headers) = if in_body {
        (String::from("/fuzz"), String::new(), HashMap::new())
    } else {
        place_header_field(field, &text(payload))
    };
    if !content_type.is_empty() {
        headers.insert("content-type".to_string(), content_type.to_string());
    }
    let body: &[u8] = if in_body { payload } else { b"" };

    let req = request(&path, &query, headers, body);

    // One `ContentInspectionState` across both phases, exactly like the engine:
    // the AST / HTML / output-byte counters are per-request and cumulative, so a
    // fresh state per phase would fuzz a budget posture production never has.
    let mut state = ContentInspectionState::new(Budget::default());
    let header_verdict = subsystem.evaluate_scoped(&req, InspectionScope::Header, &mut state);
    let body_verdict = subsystem.evaluate_scoped(&req, InspectionScope::Body, &mut state);

    std::hint::black_box((header_verdict, body_verdict));
});
