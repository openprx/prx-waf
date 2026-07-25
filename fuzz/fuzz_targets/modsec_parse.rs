//! Fuzz the ModSecurity `SecRule` parser.
//!
//! Surface: `waf_engine::rules::formats::modsec::parse`. Rule text is not
//! attacker-controlled in a normal deployment, but it *is* operator-supplied,
//! routinely pasted from the internet, and reachable from the admin API's rule
//! import path. A panic on a malformed rule is a self-inflicted outage at
//! reload time — precisely what the project's never-panic rule exists to
//! prevent.
//!
//! Sub-surfaces worth the fuzzer's time: the backslash line-continuation joiner
//! (unbounded accumulation), the `SecRule ` prefix strip (a byte-offset slice
//! taken after a `to_uppercase()` comparison, so a non-ASCII case mapping that
//! changes length is the interesting input), the quoted-argument splitter, and
//! regex compilation of each rule's operator argument.
//!
//! Input is the rule text as lossy UTF-8, so seeds are plain `.conf` snippets.

#![no_main]

use libfuzzer_sys::fuzz_target;
use prx_waf_fuzz::text;
use waf_engine::rules::formats::modsec;

fuzz_target!(|data: &[u8]| {
    std::hint::black_box(modsec::parse(&text(data)).is_ok());
});
