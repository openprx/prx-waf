//! Client-address normalization and rate-limit bucketing.
//!
//! Two related questions live here, both of the form *"what is the canonical
//! way to name this client?"*: [`canonicalize_client_ip`] answers it for
//! **identity** (is this the address the operator wrote in their blocklist?)
//! and [`RateLimitKey`] answers it for **accounting** (whose quota does this
//! request spend?). They are deliberately different answers — see
//! [`RateLimitKey`] for why an address is the wrong unit of account over IPv6.
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
//! Downstream consumers — `IpRuleSet`, the `CrowdSec` cache, `GeoIP`, the admin
//! allowlist — deliberately do **not** normalize. Folding at each consumer
//! instead of at the boundary is what produced this bug in the first place: the
//! decision was made once for the admin allowlist and silently inherited
//! everywhere else. If you add a new consumer of `RequestCtx::client_ip`, it is
//! already canonical; if you add a new *producer* of a client address,
//! normalize it here and add it to the table above.
//!
//! [`RateLimitKey::from_client_ip`] is the single exception, and it states its
//! own reason: masking an unfolded address is not merely a missed match, it
//! collapses the whole IPv4 space into one bucket.

use std::fmt;
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

/// Prefix length at which IPv6 client addresses are aggregated into a single
/// rate-limit bucket.
///
/// # Why 64, and why it is a constant rather than a knob
///
/// RFC 4291 §2.5.4 fixes the interface identifier of every non-`000` unicast
/// address at the low 64 bits, so `/64` is not a tuning choice — it is the
/// smallest unit an IPv6 network is ever subdivided into. A single host is
/// routinely handed a whole `/64` (SLAAC, RFC 4941 temporary addresses, a
/// container host, a VPS), which is 2⁶⁴ addresses it can rotate through for
/// free. Any prefix longer than 64 therefore accounts a *fraction of one
/// client*, which is the same as not accounting at all.
///
/// Exposing this as a configuration value was considered and rejected. Its
/// only safe value is this one: raising it silently restores the unbounded
/// bucket space it exists to close, and lowering it to `/56` or `/48` merges
/// entire unrelated customers of an ISP into one quota — a self-inflicted
/// denial of service with no feedback signal. Aggregating at the *site* level
/// (`/56`, `/48`) is a coherent feature, but it is customer-level accounting,
/// not a prefix-length tweak, and it would need its own limits and its own
/// operator-visible semantics.
pub const IPV6_RATE_LIMIT_PREFIX: u8 = 64;

/// The unit of account for per-IP rate limiting: an IPv4 address, or an IPv6
/// [`IPV6_RATE_LIMIT_PREFIX`] network.
///
/// # Why aggregation is required
///
/// Every per-IP limiter is a map from *some notion of a client* to a token
/// bucket. Over IPv4 the address is a serviceable stand-in for the client. Over
/// IPv6 it is not: the standard residential and VPS allocation is a routed
/// `/64`, so one client owns 2⁶⁴ distinct addresses and can present a fresh one
/// per request. Keyed on the full address, a limiter facing such a client:
///
/// * never accumulates violations, so a ban threshold is unreachable — the
///   bucket is created, decremented once, and abandoned;
/// * grows one map entry per request until the map hits its cap, at which point
///   eviction starts discarding the **oldest** entries. Those are the entries
///   belonging to steady, legitimate clients. The limiter does not merely fail
///   to stop the flood, it converts the flood into an eraser for everyone
///   else's state.
///
/// Folding to `/64` makes the flood cost one entry and one bucket, which is
/// what the limiter was designed around.
///
/// # The accepted cost
///
/// Distinct hosts inside one `/64` — the devices on a home LAN, the machines on
/// one enterprise segment — share a quota. This is deliberate and matches what
/// large edge networks (Cloudflare, Fastly) do, on the reasoning that a `/64` is
/// one subscriber and a limiter that cannot be evaded for free is worth more
/// than per-device precision. Operators serving many independent hosts from one
/// `/64` should raise `cc_rps` / `cc_burst` accordingly.
///
/// # Why a newtype and not a plain `IpAddr`
///
/// A masked address is not an address. `2001:db8:1:2::` is a perfectly legal,
/// assignable host address, so a bare `IpAddr` carrying a `/64` network is
/// indistinguishable at the type level from a real client address — and the one
/// mistake that matters here is exactly that confusion: a bucketing key leaking
/// into an attack log, a block decision, or an API response would name a host
/// that never sent the request. The newtype makes that a compile error instead
/// of a review question, and its [`Display`](fmt::Display) writes the prefix
/// length (`203.0.113.9/32`, `2001:db8:1:2::/64`) so that a key which *is*
/// deliberately logged cannot be misread as a client address either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RateLimitKey {
    /// IPv4 verbatim, or an IPv6 address with the low
    /// `128 - IPV6_RATE_LIMIT_PREFIX` bits cleared.
    network: IpAddr,
}

impl RateLimitKey {
    /// Derive the bucketing key for a client address.
    ///
    /// IPv4 is used verbatim (`/32`), preserving the pre-existing behaviour of
    /// every limiter exactly. IPv6 is masked to [`IPV6_RATE_LIMIT_PREFIX`].
    ///
    /// # Why this canonicalizes even though the ingress boundary already did
    ///
    /// The module invariant says a consumer of a client address should not fold
    /// again, and for an *identity* comparison that is right. Bucketing is the
    /// one place where it is not, because the failure is not symmetric: masking
    /// an unfolded `::ffff:a.b.c.d` clears the entire embedded IPv4 address, so
    /// **every** IPv4 client on a `[::]` listener collapses into the single
    /// `::/64` bucket and shares one quota. A missed fold elsewhere costs one
    /// wrong decision; here it would be a self-inflicted global rate limit. The
    /// fold is idempotent, so paying for it twice costs a branch.
    #[must_use]
    pub const fn from_client_ip(ip: IpAddr) -> Self {
        let network = match canonicalize_client_ip(ip) {
            IpAddr::V4(v4) => IpAddr::V4(v4),
            IpAddr::V6(v6) => {
                // Host-bit mask: the low (128 - prefix) bits, cleared.
                let host_bits = u128::MAX >> IPV6_RATE_LIMIT_PREFIX;
                IpAddr::V6(Ipv6Addr::from_bits(v6.to_bits() & !host_bits))
            }
        };
        Self { network }
    }

    /// Prefix length this key accounts at: 32 for IPv4, [`IPV6_RATE_LIMIT_PREFIX`]
    /// for IPv6.
    #[must_use]
    pub const fn prefix_len(&self) -> u8 {
        match self.network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => IPV6_RATE_LIMIT_PREFIX,
        }
    }
}

impl fmt::Display for RateLimitKey {
    /// Renders as a CIDR (`203.0.113.9/32`, `2001:db8:1:2::/64`) so a logged key
    /// is never mistaken for the address of an individual client.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len())
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

    fn key(s: &str) -> RateLimitKey {
        RateLimitKey::from_client_ip(ip(s))
    }

    /// IPv4 keeps /32 accounting: every distinct address is its own bucket,
    /// exactly as before aggregation existed.
    #[test]
    fn ipv4_is_accounted_per_address() {
        assert_eq!(key("203.0.113.9"), key("203.0.113.9"));
        assert_ne!(key("203.0.113.9"), key("203.0.113.10"));
        assert_ne!(key("10.0.0.1"), key("10.0.1.1"));
        // Not even the neighbouring /31 shares a bucket.
        assert_ne!(key("10.0.0.0"), key("10.0.0.1"));
        assert_eq!(key("203.0.113.9").prefix_len(), 32);
        assert_eq!(key("203.0.113.9").to_string(), "203.0.113.9/32");
    }

    /// Every address inside one /64 is one bucket — the whole point.
    #[test]
    fn ipv6_aggregates_within_a_64() {
        let expected = key("2001:db8:1:2::");
        for s in [
            "2001:db8:1:2::",
            "2001:db8:1:2::1",
            "2001:db8:1:2:ffff:ffff:ffff:ffff",
            "2001:db8:1:2:dead:beef:cafe:1",
        ] {
            assert_eq!(key(s), expected, "{s} must land in the 2001:db8:1:2::/64 bucket");
        }
        assert_eq!(expected.prefix_len(), IPV6_RATE_LIMIT_PREFIX);
        assert_eq!(expected.to_string(), "2001:db8:1:2::/64");
    }

    /// ...and no further. Aggregating past /64 would merge unrelated sites.
    #[test]
    fn ipv6_keeps_distinct_64s_apart() {
        let a = key("2001:db8:1:2::1");
        for s in [
            "2001:db8:1:3::1",   // adjacent /64
            "2001:db8:1:2:0::1", // same, sanity anchor below
            "2001:db8:2:2::1",   // different /48
            "2001:db9:1:2::1",   // different /32
            "2a00:1450:4001:80f::1",
        ] {
            let k = key(s);
            if s == "2001:db8:1:2:0::1" {
                assert_eq!(k, a, "same /64 written differently");
            } else {
                assert_ne!(k, a, "{s} is a different /64 and must not share a bucket");
            }
        }
    }

    /// The failure this constructor's extra fold exists to prevent: without it,
    /// masking `::ffff:a.b.c.d` to /64 yields `::` for **every** IPv4 client, so
    /// an operator switching to a `[::]` listener would rate-limit their entire
    /// IPv4 audience as one bucket.
    #[test]
    fn mapped_v4_does_not_collapse_into_one_bucket() {
        assert_eq!(key("::ffff:203.0.113.9"), key("203.0.113.9"));
        assert_ne!(key("::ffff:203.0.113.9"), key("::ffff:203.0.113.10"));
        assert_ne!(key("::ffff:203.0.113.9"), key("::"));
        assert_eq!(key("::ffff:203.0.113.9").to_string(), "203.0.113.9/32");
        // Idempotent: folding twice is folding once.
        let once = RateLimitKey::from_client_ip(canonicalize_client_ip(ip("::ffff:10.0.0.1")));
        assert_eq!(once, key("::ffff:10.0.0.1"));
    }

    /// v4 and v6 buckets never alias each other, in either direction.
    #[test]
    fn families_do_not_alias() {
        assert_ne!(key("0.0.0.0"), key("::"));
        assert_ne!(key("127.0.0.1"), key("::1"));
        // The deprecated IPv4-compatible form stays IPv6 (see
        // `deprecated_v4_compatible_form_is_not_folded`) and therefore masks to
        // ::/64 like any other address in that block.
        assert_eq!(key("::1.2.3.4"), key("::1"));
        assert_eq!(key("::1.2.3.4").to_string(), "::/64");
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
