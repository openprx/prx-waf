//! Shared helpers for the prx-waf fuzz targets.
//!
//! Everything here is *test* code, so the workspace's production lint wall does
//! not apply (the fuzz crate is its own workspace — see `fuzz/Cargo.toml`).
//! The rule we do hold ourselves to is narrower and more important: **the
//! harness must never panic on its own**, so that every crash libFuzzer reports
//! is unambiguously an engine bug. Concretely: no `unwrap`/`expect` on anything
//! derived from fuzzer input, no indexing (only `get(..)`), and no arithmetic
//! that can overflow on adversarial lengths.
//!
//! # Input framing
//!
//! Targets that need more than one input field use a hand-rolled framing —
//! `[selector byte] [payload…]` — instead of `arbitrary`'s derive. The reason
//! is operational: a corpus file and a crash artifact are then *readable*. An
//! engineer can `cat` a crash artifact and see the attack payload; a seed can
//! be written by hand with `printf`. With derived `Arbitrary` the same files are
//! opaque blobs whose meaning depends on the field order of a struct, and a
//! reordered field silently invalidates the whole committed corpus.

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use waf_common::content_security_config::ContentSecurityConfig;
use waf_common::{HostConfig, RequestCtx};
use waf_engine::checks::content_security::{EnforcementMode, RuntimeContentSecurityConfig};

/// Hard cap on the number of input bytes any target hands to the engine.
///
/// The production gateway only inspects a bounded body preview, so feeding
/// megabyte inputs would fuzz a shape that cannot occur in production while
/// burning the time budget on memcpy. 64 KiB is comfortably above every
/// per-field / per-request cap in `content_security::budget`, so the
/// budget-exhaustion and degradation paths stay reachable.
pub const MAX_INPUT: usize = 64 * 1024;

/// Split fuzzer input into a leading selector byte and the remaining payload.
///
/// An empty input yields `(0, &[])` so every target has a well-defined
/// behaviour on the empty seed libFuzzer always tries first.
#[must_use]
pub fn split_selector(data: &[u8]) -> (u8, &[u8]) {
    match data.split_first() {
        Some((&sel, rest)) => (sel, clamp(rest)),
        None => (0, &[]),
    }
}

/// Truncate to [`MAX_INPUT`] bytes.
#[must_use]
pub fn clamp(b: &[u8]) -> &[u8] {
    b.get(..MAX_INPUT.min(b.len())).unwrap_or(b"")
}

/// Truncate to [`MAX_INPUT`] on a UTF-8 safe boundary.
#[must_use]
pub fn clamp_str(s: &str) -> &str {
    if s.len() <= MAX_INPUT {
        return s;
    }
    let mut end = MAX_INPUT;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.get(..end).unwrap_or("")
}

/// Lossy-decode a payload to text, then clamp it.
#[must_use]
pub fn text(payload: &[u8]) -> String {
    clamp_str(&String::from_utf8_lossy(payload)).to_string()
}

/// Build a [`RequestCtx`] the detectors will accept.
///
/// Only the fields the content-security lane actually reads are driven by the
/// fuzzer; the rest are fixed so no entropy is spent on inputs that cannot
/// change behaviour.
#[must_use]
pub fn request(path: &str, query: &str, headers: HashMap<String, String>, body: &[u8]) -> RequestCtx {
    let body = Bytes::copy_from_slice(clamp(body));
    RequestCtx {
        req_id: "fuzz".to_string(),
        client_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        client_port: 0,
        method: "POST".to_string(),
        host: "fuzz.invalid".to_string(),
        port: 80,
        path: clamp_str(path).to_string(),
        query: clamp_str(query).to_string(),
        headers,
        content_length: body.len() as u64,
        body_preview: body,
        is_tls: false,
        host_config: Arc::new(HostConfig::default()),
        geo: None,
    }
}

/// Header-scope field names the Lane 2 preprocessor actually inspects.
///
/// Mirrors `preprocess::SEMANTIC_HEADERS` plus the two pseudo-fields (`path`,
/// `query`) and `cookie`. Random header names would be ignored by the
/// preprocessor, so the selector picks from this list instead of wasting
/// executions on names that can never reach a decode.
pub const HEADER_FIELDS: &[&str] = &[
    "path",
    "query",
    "cookie",
    "user-agent",
    "referer",
    "x-forwarded-for",
    "x-real-ip",
    "x-original-url",
    "x-forwarded-host",
    "forwarded",
];

/// Content types worth steering the structured-body extractor with.
///
/// `struct_extract` dispatches on the media type, so a random content-type
/// header would spend nearly every execution on the "unknown type → whole body
/// only" path and never reach the XML / GraphQL / multipart parsers. The empty
/// string means "send no content-type header at all", which exercises the
/// sniff-by-first-byte path.
pub const CONTENT_TYPES: &[&str] = &[
    "application/json",
    "application/json; charset=utf-8",
    "application/ld+json",
    "text/xml",
    "application/xml",
    "application/soap+xml",
    "application/graphql",
    "application/graphql+json",
    "multipart/form-data; boundary=fuzzbound",
    "multipart/form-data; boundary=\"fuzzbound\"",
    "multipart/mixed; boundary=fuzzbound",
    "application/x-www-form-urlencoded",
    "text/plain",
    "",
];

/// Pick an entry from a static table with a selector byte. Never indexes out of
/// range and never panics on an empty table.
#[must_use]
pub fn pick(table: &[&'static str], selector: u8) -> &'static str {
    let len = table.len();
    if len == 0 {
        return "";
    }
    table.get(usize::from(selector) % len).copied().unwrap_or("")
}

/// A Lane 2 runtime config with the semantic lane **on** in shadow mode.
///
/// `ContentSecurityConfig::default()` is `enabled = false` — the **compiled**
/// default, not the shipped one: `configs/default.toml` sets `enabled = true`,
/// so real installs do run this lane. Building the harness config from the
/// compiled default would short-circuit `evaluate_scoped` before any
/// preprocessing and leave the entire semantic engine — the whole point of these
/// targets, and the code an install actually reaches — unfuzzed. Turning
/// `enabled` back on here is what makes the target match production. `LogOnly`
/// (the shipped enforcement mode too) keeps the lane side-effect free while
/// still running preprocess → every detector → scoring.
///
/// Falls back to the compiled default if a future validation rule rejects the
/// programmatic config, so the harness itself can never panic here.
#[must_use]
pub fn lane2_enabled_config() -> RuntimeContentSecurityConfig {
    let cfg = ContentSecurityConfig {
        enabled: true,
        enforcement_mode: "log_only".to_string(),
        hpp: true,
        ..ContentSecurityConfig::default()
    };
    let mut runtime = RuntimeContentSecurityConfig::compile(&cfg).unwrap_or_default();
    // Belt and braces: if `compile` ever changes shape, force the two fields the
    // lane gates on so this target keeps exercising the engine instead of
    // silently degenerating into a no-op.
    runtime.enabled = true;
    runtime.enforcement_mode = EnforcementMode::LogOnly;
    runtime
}

/// Place `payload` into the header-scope field named by `field`, returning
/// `(path, query, headers)` ready for [`request`].
#[must_use]
pub fn place_header_field(field: &str, payload: &str) -> (String, String, HashMap<String, String>) {
    let mut headers = HashMap::new();
    let mut path = "/fuzz".to_string();
    let mut query = String::new();
    match field {
        "path" => path = payload.to_string(),
        "query" => query = payload.to_string(),
        other => {
            headers.insert(other.to_string(), payload.to_string());
        }
    }
    (path, query, headers)
}
