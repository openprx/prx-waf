//! Fuzz HTTP request-smuggling header detection.
//!
//! Surface: `gateway::smuggling::detect`, which walks the parsed
//! `http::HeaderMap` for `Content-Length` / `Transfer-Encoding` desync
//! primitives. Header values are fully attacker-controlled and the detector
//! reads their raw bytes, so this covers the comma-list splitting and
//! `chunked`-token comparison it does by hand.
//!
//! Honest boundary: `http::HeaderName` / `HeaderValue` reject bare CR/LF and
//! other illegal bytes, so this target cannot reach wire-level parsing — the
//! same boundary the module's own docs call out. It fuzzes what is genuinely
//! reachable from `request_filter`, not a shape pingora can never produce.
//!
//! Input framing: newline-separated `name: value` lines, so seeds and crash
//! artifacts read like an actual HTTP header block. A line with no colon is
//! treated as a bare name with an empty value; an unparseable name or value is
//! skipped, because such a header cannot exist in a parsed request.

#![no_main]

use http::{HeaderMap, HeaderName, HeaderValue};
use libfuzzer_sys::fuzz_target;
use prx_waf_fuzz::clamp;

fuzz_target!(|data: &[u8]| {
    let mut headers = HeaderMap::new();
    for line in clamp(data).split(|&b| b == b'\n').take(64) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let (name_bytes, value_bytes) = match line.iter().position(|&b| b == b':') {
            Some(idx) => {
                let name = line.get(..idx).unwrap_or(b"");
                let value = line.get(idx.saturating_add(1)..).unwrap_or(b"");
                // Strip the conventional single space after the colon; leave any
                // further whitespace intact, since odd padding is itself an
                // obfuscation vector the detector is supposed to notice.
                (name, value.strip_prefix(b" ").unwrap_or(value))
            }
            None => (line, &b""[..]),
        };

        let (Ok(name), Ok(value)) = (HeaderName::from_bytes(name_bytes), HeaderValue::from_bytes(value_bytes)) else {
            continue;
        };
        headers.append(name, value);
    }

    std::hint::black_box(gateway::smuggling::detect(&headers));
});
