//! Fuzz the Lane 2 body-scope structured-field extractor.
//!
//! Surface: `struct_extract::extract_body_fields` (a private module) reached
//! through the public `semantic_preprocessor(InspectionScope::Body, ..)`. That
//! one call fans out into four third-party parsers driven entirely by the
//! request body:
//!
//!   * `serde_json`            — JSON leaves and `$`-prefixed NoSQL operator keys
//!   * `quick-xml`             — XML elements / attributes / numeric char refs
//!   * `async-graphql-parser`  — GraphQL documents; the depth guards live here
//!   * `multer`                — multipart/form-data parts
//!
//! plus the UTF-16 BOM transcode and the full decode chain applied to every
//! extracted leaf.
//!
//! This is the highest-value target in the set: a recursive-descent parser
//! reached from an attacker-controlled POST body is exactly the shape that
//! produced the GraphQL stack overflow this infrastructure was built for.
//! `graphql_max_depth` / `MAX_GRAPHQL_RAW_OPENS` are the guards under test —
//! any input that gets past them and still overflows is a live bug.
//!
//! Input framing: `[content-type selector][body…]`, selector indexing
//! `prx_waf_fuzz::CONTENT_TYPES` (mod its length; the empty entry sends no
//! content-type header at all).

#![no_main]

use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;
use prx_waf_fuzz::{CONTENT_TYPES, pick, request, split_selector};
use waf_engine::checks::content_security::budget::{Budget, ContentInspectionState};
use waf_engine::checks::content_security::{InspectionScope, semantic_preprocessor};

fuzz_target!(|data: &[u8]| {
    let (selector, body) = split_selector(data);
    let content_type = pick(CONTENT_TYPES, selector);

    let mut headers: HashMap<String, String> = HashMap::new();
    if !content_type.is_empty() {
        headers.insert("content-type".to_string(), content_type.to_string());
    }

    let req = request("/fuzz", "", headers, body);
    let mut state = ContentInspectionState::new(Budget::default());
    state.begin_phase();
    let views = semantic_preprocessor(InspectionScope::Body, &req, &mut state);

    let budget = *state.budget();
    let max_views =
        (budget.max_fields_per_phase as usize).saturating_mul((budget.max_views_per_field as usize).saturating_add(1));
    assert!(
        views.len() <= max_views,
        "view explosion: {} views produced for a budget capping at {max_views}",
        views.len()
    );
});
