//! Fuzz the Lane 2 header-scope preprocessor.
//!
//! Surface: `semantic_preprocessor(InspectionScope::Header, ..)`. This is the
//! decode chain applied to the fully attacker-controlled request line and
//! headers: recursive URL decoding, HTML-entity decoding, SQL-comment
//! stripping, blind base64 and hex decoding, UTF-16 BOM transcoding, shell
//! de-obfuscation and the token normaliser — plus every work-budget guard that
//! is supposed to bound them.
//!
//! A crash here means an attacker can panic or stall a worker with a single
//! request line, before any detector even runs.
//!
//! Input framing: `[field selector][payload…]`, where the selector picks a
//! field from `prx_waf_fuzz::HEADER_FIELDS` (mod its length).

#![no_main]

use libfuzzer_sys::fuzz_target;
use prx_waf_fuzz::{HEADER_FIELDS, pick, place_header_field, request, split_selector, text};
use waf_engine::checks::content_security::budget::{Budget, ContentInspectionState};
use waf_engine::checks::content_security::{InspectionScope, semantic_preprocessor};

fuzz_target!(|data: &[u8]| {
    let (selector, payload) = split_selector(data);
    let field = pick(HEADER_FIELDS, selector);
    let (path, query, headers) = place_header_field(field, &text(payload));

    let req = request(&path, &query, headers, b"");
    let mut state = ContentInspectionState::new(Budget::default());
    state.begin_phase();
    let views = semantic_preprocessor(InspectionScope::Header, &req, &mut state);

    // Consume the result so the optimiser cannot delete the work, and check the
    // invariant the budget exists to provide: a bounded budget must yield a
    // bounded number of views. A violation is a real finding (unbudgeted work
    // on the hot path), not a harness artefact.
    let budget = *state.budget();
    let max_views =
        (budget.max_fields_per_phase as usize).saturating_mul((budget.max_views_per_field as usize).saturating_add(1));
    assert!(
        views.len() <= max_views,
        "view explosion: {} views produced for a budget capping at {max_views}",
        views.len()
    );
});
