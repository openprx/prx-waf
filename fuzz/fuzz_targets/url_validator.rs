//! Fuzz the SSRF URL validator's parse + scheme check.
//!
//! Surface: `waf_common::url_validator::validate_scheme_only` — `Url::parse`
//! plus the scheme allowlist. URLs reaching this validator come from
//! operator-supplied config (rule feeds, `CrowdSec` LAPI, webhook sinks), so a
//! panic here is a config-triggered crash rather than a remote one. Cheap to
//! run; included for completeness of the input-validation surface.
//!
//! Deliberately **not** fuzzed: `validate_public_url_with_ips` and the
//! deprecated `validate_public_url` that delegates to it. Both call
//! `to_socket_addrs`, i.e. real DNS. Fuzzing them would make executions
//! network-bound, non-deterministic and non-reproducible, and would aim a
//! resolver flood at whatever nameserver the runner uses. Reaching the
//! private-range and blocked-hostname logic under a fuzzer requires the
//! resolver to be injectable — see `fuzz/README.md`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use prx_waf_fuzz::text;
use waf_common::url_validator;

fuzz_target!(|data: &[u8]| {
    std::hint::black_box(url_validator::validate_scheme_only(&text(data)).is_ok());
});
