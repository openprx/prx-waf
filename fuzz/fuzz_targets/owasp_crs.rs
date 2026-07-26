//! Fuzz OWASP CRS rule evaluation against attacker-controlled requests.
//!
//! Surface: `OWASPCheck::check` — the largest regex / aho-corasick surface in
//! the product, with the full CRS rule set applied to the request line, query
//! string, headers and body. The risk model here is less about a panic than
//! about **catastrophic backtracking**: one rule with a nested quantifier turns
//! a short query string into a multi-second stall, which is a remote DoS on the
//! hot path. libFuzzer's `-timeout` is the detector for that, and it is why
//! this target is worth running even though CRS rules are hand-reviewed.
//!
//! The rule set is loaded once from `rules/owasp-crs/` (override with
//! `PRX_WAF_FUZZ_RULES_DIR`). If that directory yields nothing usable the check
//! falls back to its embedded minimal set exactly as the engine does, so the
//! target still runs — but its coverage is then of the fallback, not of CRS.
//! Because the loaded rules are part of this target's behaviour, a crash found
//! here reproduces only against the same rules snapshot; note the commit when
//! filing one.
//!
//! Input framing: `[placement selector][payload…]`.

#![no_main]

use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use prx_waf_fuzz::{clamp, request, split_selector, text};
use waf_engine::checks::owasp::OWASPCheck;

static CHECK: OnceLock<OWASPCheck> = OnceLock::new();

fn load_check() -> OWASPCheck {
    let dir = std::env::var("PRX_WAF_FUZZ_RULES_DIR").unwrap_or_else(|_| "rules/owasp-crs".to_string());
    let path = Path::new(&dir);
    if path.is_dir() {
        let loaded = OWASPCheck::from_directory(path);
        if loaded.rule_count() > 0 {
            return loaded;
        }
    }
    // No usable on-disk rules: `new()` performs the same fallback the engine
    // does, so the target degrades to the embedded set instead of dying.
    OWASPCheck::new()
}

/// Where the payload is injected. CRS targets different variables per rule, so
/// the same payload can be inert in one location and matching in another.
const PLACEMENTS: &[&str] = &[
    "path",
    "query",
    "body",
    "user-agent",
    "referer",
    "cookie",
    "content-type",
];

fuzz_target!(|data: &[u8]| {
    let check = CHECK.get_or_init(load_check);

    let (selector, payload) = split_selector(data);
    let placement = prx_waf_fuzz::pick(PLACEMENTS, selector);
    let as_text = text(payload);

    let mut headers: HashMap<String, String> = HashMap::new();
    let mut path = "/fuzz".to_string();
    let mut query = String::new();
    let mut body: &[u8] = b"";
    match placement {
        "path" => path = as_text.clone(),
        "query" => query = as_text.clone(),
        "body" => body = clamp(payload),
        other => {
            headers.insert(other.to_string(), as_text.clone());
        }
    }

    let req = request(&path, &query, headers, body);
    std::hint::black_box(check.check(&req));
});
