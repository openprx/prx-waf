//! Client-address normalization.
//!
//! # The problem this solves
//!
//! On a kernel with `net.ipv6.bindv6only = 0` (the Linux default), a socket
//! bound to the IPv6 wildcard `[::]` also accepts IPv4 connections and reports
//! their peer address in **IPv4-mapped** form — `::ffff:a.b.c.d` instead of
//! `a.b.c.d`. Nothing in `std` or in `ipnet` folds the two forms together:
//! `Ipv4Net("203.0.113.0/24").contains(::ffff:203.0.113.9)` is `false`, and so
//! is every other cross-family containment test, in both directions.
//!
//! Left unnormalized, that single fact breaks every IP adjudication in two
//! opposite and equally wrong ways the moment an operator switches a listener
//! to `[::]`:
//!
//! - **fail-open (a bypass):** IP blacklists, threat-intel feeds, `CrowdSec`
//!   decisions and the community blocklist all stop matching, so a banned
//!   IPv4 attacker is admitted.
//! - **fail-closed (a lockout):** the admin IP allowlist, `trusted_proxies`
//!   and `GeoIP` `AllowOnly` also stop matching, so a legitimate IPv4 operator
//!   is rejected.
//!
//! # The invariant
//!
//! **Every client address is folded to its canonical family exactly once, at
//! the point where it enters the process, and never again afterwards.** Each
//! ingress plane has exactly one such point:
//!
//! | Plane | Normalization point |
//! |---|---|
//! | HTTP/1.1 + HTTP/2 data plane | `gateway::proxy::WafProxy::extract_client_ip` |
//! | HTTP/3 data plane | `gateway::http3::handle_h3_request` (peer address) |
//! | Management API | `waf_api::security::request_client_ip` |
//!
//! Downstream consumers — `IpRuleSet`, the `CrowdSec` cache, the CC limiter,
//! `GeoIP`, the admin allowlist — deliberately do **not** normalize. Folding at
//! each consumer instead of at the boundary is what produced this bug in the
//! first place: the decision was made once for the admin allowlist and
//! silently inherited everywhere else. If you add a new consumer of
//! `RequestCtx::client_ip`, it is already canonical; if you add a new
//! *producer* of a client address, normalize it here and add it to the table
//! above.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Fold an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) down to plain IPv4.
///
/// Genuine IPv6 addresses and addresses that are already IPv4 are returned
/// unchanged, so this is a no-op on an `0.0.0.0` listener and never rewrites
/// a real IPv6 client.
///
/// # Why `to_ipv4_mapped` and not `to_canonical`
///
/// [`Ipv6Addr::to_canonical`] additionally folds the IPv4-**compatible** form
/// `::a.b.c.d`, which RFC 4291 §2.5.5.1 deprecated. That form is not something
/// a dual-stack socket ever produces; if it shows up in a client address it
/// arrived through a header or a config file and is better treated as the
/// suspicious input it is than silently reinterpreted as an IPv4 address.
/// Note the one address the two functions disagree about most sharply: `::1`
/// is loopback under `to_ipv4_mapped` (left alone, correctly) but folds to
/// `0.0.0.1` under `to_canonical`.
#[must_use]
pub const fn canonicalize_client_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        IpAddr::V4(_) => ip,
    }
}

/// If a configured IP/CIDR entry is written in IPv4-mapped form, return the
/// plain-IPv4 spelling an operator should replace it with.
///
/// Returns `None` for every entry that is already correct — plain IPv4, a
/// genuine IPv6 address or range, or an unparseable string (which the
/// consuming loader reports separately).
///
/// Because [`canonicalize_client_ip`] folds mapped client addresses before any
/// comparison happens, an entry written as `::ffff:1.2.3.4` can no longer match
/// anything at all. Startup broadcasts and rule loaders use this to name such
/// entries. It deliberately only *reports*: rewriting an operator's blocklist
/// behind their back is worse than telling them it is dead.
///
/// # Examples
///
/// ```
/// use waf_common::net::ipv4_mapped_entry_rewrite;
///
/// assert_eq!(ipv4_mapped_entry_rewrite("::ffff:1.2.3.4"), Some("1.2.3.4".to_owned()));
/// assert_eq!(ipv4_mapped_entry_rewrite("::ffff:10.0.0.0/104"), Some("10.0.0.0/8".to_owned()));
/// assert_eq!(ipv4_mapped_entry_rewrite("1.2.3.4"), None);
/// assert_eq!(ipv4_mapped_entry_rewrite("2001:db8::1"), None);
/// ```
#[must_use]
pub fn ipv4_mapped_entry_rewrite(entry: &str) -> Option<String> {
    let trimmed = entry.trim();
    let (addr_part, prefix_part) = match trimmed.split_once('/') {
        Some((addr, prefix)) => (addr, Some(prefix)),
        None => (trimmed, None),
    };

    let mapped: Ipv4Addr = addr_part.parse::<Ipv6Addr>().ok()?.to_ipv4_mapped()?;

    let Some(prefix) = prefix_part else {
        return Some(mapped.to_string());
    };

    // A v6 prefix shorter than /96 spans more than the `::ffff:0:0/96` block,
    // so it has no exact IPv4 equivalent to suggest. Still worth flagging, just
    // without a rewrite that would be wrong.
    let v4_prefix = prefix.trim().parse::<u8>().ok().and_then(|p| p.checked_sub(96));
    Some(match v4_prefix {
        Some(p) if p <= 32 => format!("{mapped}/{p}"),
        _ => mapped.to_string(),
    })
}

/// Name every IPv4-mapped entry in a configured list, as
/// `"<entry> (use <rewrite>)"` fragments ready to drop into a warning.
///
/// Empty when the list is clean, which is the overwhelmingly common case.
#[must_use]
pub fn ipv4_mapped_entries(entries: &[String]) -> Vec<String> {
    entries
        .iter()
        .filter_map(|entry| ipv4_mapped_entry_rewrite(entry).map(|fixed| format!("{entry} (use {fixed})")))
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn mapped_v6_folds_to_v4() {
        assert_eq!(canonicalize_client_ip(ip("::ffff:127.0.0.1")), ip("127.0.0.1"));
        assert_eq!(canonicalize_client_ip(ip("::ffff:203.0.113.9")), ip("203.0.113.9"));
        // The alternate hex spelling of the same address.
        assert_eq!(canonicalize_client_ip(ip("::ffff:cb00:7109")), ip("203.0.113.9"));
    }

    #[test]
    fn plain_v4_is_untouched() {
        for s in ["0.0.0.0", "127.0.0.1", "10.1.2.3", "255.255.255.255"] {
            assert_eq!(canonicalize_client_ip(ip(s)), ip(s), "{s} must pass through unchanged");
        }
    }

    #[test]
    fn genuine_v6_is_untouched() {
        for s in ["::1", "::", "2001:db8::1", "fe80::1", "fc00::1", "2606:4700::1111"] {
            assert_eq!(canonicalize_client_ip(ip(s)), ip(s), "{s} must stay IPv6");
        }
    }

    /// The reason this module uses `to_ipv4_mapped` rather than
    /// `to_canonical`: the deprecated IPv4-compatible form must not be folded.
    #[test]
    fn deprecated_v4_compatible_form_is_not_folded() {
        assert_eq!(canonicalize_client_ip(ip("::1.2.3.4")), ip("::1.2.3.4"));
        assert!(canonicalize_client_ip(ip("::1.2.3.4")).is_ipv6());
        // `to_canonical` would have turned loopback into 0.0.0.1.
        assert_eq!(canonicalize_client_ip(ip("::1")), ip("::1"));
    }

    #[test]
    fn entry_rewrite_flags_mapped_addresses() {
        assert_eq!(ipv4_mapped_entry_rewrite("::ffff:1.2.3.4"), Some("1.2.3.4".to_owned()));
        assert_eq!(
            ipv4_mapped_entry_rewrite("  ::ffff:192.168.1.1  "),
            Some("192.168.1.1".to_owned())
        );
        assert_eq!(
            ipv4_mapped_entry_rewrite("::ffff:c0a8:0101"),
            Some("192.168.1.1".to_owned())
        );
    }

    #[test]
    fn entry_rewrite_converts_prefix_length() {
        assert_eq!(
            ipv4_mapped_entry_rewrite("::ffff:10.0.0.0/104"),
            Some("10.0.0.0/8".to_owned())
        );
        assert_eq!(
            ipv4_mapped_entry_rewrite("::ffff:203.0.113.0/120"),
            Some("203.0.113.0/24".to_owned())
        );
        assert_eq!(
            ipv4_mapped_entry_rewrite("::ffff:1.2.3.4/128"),
            Some("1.2.3.4/32".to_owned())
        );
        // Shorter than /96: no exact IPv4 range, so no prefix is suggested.
        assert_eq!(
            ipv4_mapped_entry_rewrite("::ffff:1.2.3.4/64"),
            Some("1.2.3.4".to_owned())
        );
        assert_eq!(
            ipv4_mapped_entry_rewrite("::ffff:1.2.3.4/not-a-number"),
            Some("1.2.3.4".to_owned())
        );
    }

    #[test]
    fn entry_rewrite_ignores_correct_entries() {
        for s in [
            "1.2.3.4",
            "10.0.0.0/8",
            "::1",
            "2001:db8::/32",
            "fe80::1",
            "::1.2.3.4",
            "",
            "not-an-ip",
            "example.com",
        ] {
            assert_eq!(ipv4_mapped_entry_rewrite(s), None, "{s} must not be flagged");
        }
    }

    #[test]
    fn entry_list_reports_only_offenders() {
        let entries = vec![
            "127.0.0.1".to_owned(),
            "::ffff:10.0.0.1".to_owned(),
            "2001:db8::1".to_owned(),
        ];
        assert_eq!(ipv4_mapped_entries(&entries), vec!["::ffff:10.0.0.1 (use 10.0.0.1)"]);
        assert!(ipv4_mapped_entries(&["10.0.0.0/8".to_owned()]).is_empty());
        assert!(ipv4_mapped_entries(&[]).is_empty());
    }
}
