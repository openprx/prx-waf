//! Outbound URL safety validation — SSRF prevention.
//!
//! Two validation levels:
//!
//! * [`validate_public_url`] — strict: blocks private/loopback IPs, link-local,
//!   CGNAT, IPv4-mapped IPv6, etc.  Use for **webhook** and other user-supplied
//!   URLs that must reach the public internet.
//!
//! * [`validate_public_url_with_ips`] — like `validate_public_url` but also
//!   returns the resolved [`std::net::SocketAddr`]s so callers can **pin** the
//!   HTTP client to those exact addresses and close the DNS-rebinding TOCTOU
//!   window.
//!
//! * [`validate_scheme_only`] — lenient: only enforces the `http`/`https` scheme
//!   allow-list.  Use for **`CrowdSec` LAPI** which legitimately runs on
//!   `127.0.0.1` in on-premise deployments.

use std::net::{IpAddr, SocketAddr};

use url::Url;

// ─── Error type ───────────────────────────────────────────────────────────────

/// Errors produced by URL validation.
#[derive(Debug, thiserror::Error)]
pub enum UrlValidationError {
    /// The raw string is not a valid URL.
    #[error("invalid URL: {0}")]
    Parse(#[from] url::ParseError),

    /// The URL scheme is not in the allow-list.
    #[error("disallowed URL scheme '{0}' (only http/https are permitted)")]
    DisallowedScheme(String),

    /// The host resolves or directly is a private / reserved IP address.
    #[error("blocked host '{0}': {1}")]
    BlockedHost(String, &'static str),
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Parse and strictly validate `raw_url` for use as a **public outbound** endpoint.
///
/// Enforces:
/// 1. Scheme allow-list — `http` / `https` only.
/// 2. Host required.
/// 3. Known-dangerous hostname literals blocked (loopback, link-local metadata, etc.).
/// 4. If the host is an IP literal, private/reserved ranges are blocked.
/// 5. If the host is a DNS name, it is **synchronously** resolved and each
///    returned address is checked against private ranges.
///
/// Note on DNS rebinding: this is a best-effort first layer.  For full
/// protection use [`validate_public_url_with_ips`] to obtain the resolved
/// addresses and pin the HTTP client via `reqwest::ClientBuilder::resolve_to_addrs`.
#[cfg_attr(
    not(test),
    deprecated(
        note = "production code must use validate_public_url_with_ips and pin resolved IPs via reqwest resolve_to_addrs to close the DNS-rebinding TOCTOU window; retained for tests only"
    )
)]
pub fn validate_public_url(raw_url: &str) -> Result<Url, UrlValidationError> {
    validate_public_url_with_ips(raw_url).map(|(url, _)| url)
}

/// Parse, strictly validate, **and return resolved IP addresses** for `raw_url`.
///
/// Identical to [`validate_public_url`] in its safety checks, but additionally
/// returns a `Vec<SocketAddr>` containing every address the hostname resolved to
/// at validation time.  Callers **must** pass these addresses to the HTTP
/// client via `reqwest::ClientBuilder::resolve_to_addrs` to pin the connection
/// to the validated IPs, closing the DNS-rebinding TOCTOU window.
///
/// The port component of each returned `SocketAddr` is `0` — it carries no
/// meaning for validation and callers should **not** rely on it.  The reqwest
/// `resolve_to_addrs` override uses the port from the request URL, not from
/// the override address.
///
/// For IP-literal URLs (no DNS lookup required) the returned `Vec` is empty.
pub fn validate_public_url_with_ips(raw_url: &str) -> Result<(Url, Vec<SocketAddr>), UrlValidationError> {
    let url = Url::parse(raw_url)?;

    validate_scheme(&url)?;

    // Use url::Host enum to correctly distinguish IPv4, IPv6, and DNS names.
    // `host_str()` wraps IPv6 addresses in brackets (e.g. "[::1]"), which
    // prevents direct parsing with `IpAddr::parse`; `host()` gives us the
    // already-parsed value instead.
    let resolved = match url.host() {
        None => {
            return Err(UrlValidationError::BlockedHost(
                String::new(),
                "URL has no host component",
            ));
        }
        Some(url::Host::Ipv4(v4)) => {
            let ip = IpAddr::V4(v4);
            if is_private_or_reserved(&ip) {
                return Err(UrlValidationError::BlockedHost(
                    v4.to_string(),
                    "IP address is in a private or reserved range",
                ));
            }
            // IP literal — no DNS resolution needed; return empty vec.
            vec![]
        }
        Some(url::Host::Ipv6(v6)) => {
            let ip = IpAddr::V6(v6);
            if is_private_or_reserved(&ip) {
                return Err(UrlValidationError::BlockedHost(
                    v6.to_string(),
                    "IP address is in a private or reserved range",
                ));
            }
            // IP literal — no DNS resolution needed; return empty vec.
            vec![]
        }
        Some(url::Host::Domain(hostname)) => {
            // Check literal hostname blocklist before DNS resolution.
            check_forbidden_hostname(hostname)?;
            // Attempt DNS resolution and reject if any address is private.
            // Returns the validated set of addresses for caller IP-pinning.
            resolve_and_check(hostname)?
        }
    };

    Ok((url, resolved))
}

/// Parse and leniently validate `raw_url`: only the **scheme** is checked.
///
/// Use for services that legitimately run on the local machine or private
/// network (e.g., `CrowdSec` LAPI at `http://127.0.0.1:8080`).
pub fn validate_scheme_only(raw_url: &str) -> Result<Url, UrlValidationError> {
    let url = Url::parse(raw_url)?;
    validate_scheme(&url)?;
    Ok(url)
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

fn validate_scheme(url: &Url) -> Result<(), UrlValidationError> {
    match url.scheme() {
        "http" | "https" => Ok(()),
        other => Err(UrlValidationError::DisallowedScheme(other.to_owned())),
    }
}

/// Literal hostname / IP strings that are always blocked, independent of
/// whether `validate_public_url` or the IP-parse path is used.
fn check_forbidden_hostname(host: &str) -> Result<(), UrlValidationError> {
    // Well-known dangerous names (lowercase comparison).
    const BLOCKED: &[&str] = &[
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "broadcasthost",
        "metadata.google.internal", // GCP IMDS
        "169.254.169.254",          // AWS / Azure IMDS (also caught by IP check)
        "fd00:ec2::254",            // AWS IMDSv2 IPv6
        "100.100.100.200",          // Alibaba Cloud IMDS
        "0.0.0.0",
        "::1",
        "::ffff:0:0",
        "::",
    ];
    let lower = host.to_ascii_lowercase();
    for blocked in BLOCKED {
        if lower == *blocked {
            return Err(UrlValidationError::BlockedHost(
                host.to_owned(),
                "hostname is explicitly blocked",
            ));
        }
    }
    Ok(())
}

/// Returns `true` if `ip` is in any private, loopback, or otherwise reserved
/// range that must not be reachable from a user-supplied webhook URL.
const fn is_private_or_reserved(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            // RFC 5735 / IANA special-purpose registries
            v4.is_loopback()         // 127.0.0.0/8
            || v4.is_private()       // 10/8, 172.16/12, 192.168/16
            || v4.is_link_local()    // 169.254.0.0/16
            || v4.is_unspecified()   // 0.0.0.0/8
            || v4.is_broadcast()     // 255.255.255.255
            || v4.is_multicast()     // 224.0.0.0/4
            || {
                // 100.64.0.0/10 — CGNAT (RFC 6598)
                let oct = v4.octets();
                oct[0] == 100 && (oct[1] & 0xC0) == 64
            }
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()          // ::1
            || v6.is_unspecified()    // ::
            || v6.is_multicast()      // ff00::/8
            || {
                let seg = v6.segments();
                // fc00::/7 — Unique Local Address (ULA)
                (seg[0] & 0xfe00) == 0xfc00
                // fe80::/10 — Link-Local
                || (seg[0] & 0xffc0) == 0xfe80
                // ::ffff:0:0/96 — IPv4-mapped (catches 127.x, 10.x etc. via IPv6)
                || (seg[0] == 0 && seg[1] == 0 && seg[2] == 0
                    && seg[3] == 0 && seg[4] == 0 && seg[5] == 0xffff)
                // 2001:db8::/32 — documentation
                || (seg[0] == 0x2001 && seg[1] == 0x0db8)
                // 64:ff9b::/96 — IPv4/IPv6 translation (RFC 6052)
                || (seg[0] == 0x0064 && seg[1] == 0xff9b)
            }
        }
    }
}

/// Resolve `hostname` synchronously (blocking) and reject if any address is
/// in a private/reserved range.
///
/// Returns the full set of validated [`SocketAddr`]s so that callers can pin
/// the HTTP client to these exact IPs and prevent DNS-rebinding attacks.
/// The port component of each returned address is always `0`; it is used only
/// as a placeholder to satisfy the `ToSocketAddrs` trait and carries no
/// semantic meaning.
///
/// This runs synchronously because `waf-common` is a sync utility crate.
/// Callers in async contexts should either:
///   * call this in `tokio::task::spawn_blocking`, or
///   * accept that the DNS round-trip is a short, bounded operation.
fn resolve_and_check(hostname: &str) -> Result<Vec<SocketAddr>, UrlValidationError> {
    use std::net::ToSocketAddrs;

    // Port 80 is used only to satisfy the `ToSocketAddrs` requirement;
    // the port value has no effect on which IP addresses are returned.
    let lookup_target = (hostname, 80_u16);
    match lookup_target.to_socket_addrs() {
        Ok(addrs) => {
            let mut validated: Vec<SocketAddr> = Vec::new();
            for addr in addrs {
                let ip = addr.ip();
                if is_private_or_reserved(&ip) {
                    return Err(UrlValidationError::BlockedHost(
                        hostname.to_owned(),
                        "hostname resolves to a private or reserved IP address",
                    ));
                }
                // Normalise port to 0: the port from the DNS lookup (80) has
                // no bearing on which port the actual request will use.
                validated.push(SocketAddr::new(ip, 0));
            }
            // Fail-closed: an empty result set means we cannot confirm the
            // destination is safe (e.g. DNS returned NODATA).
            if validated.is_empty() {
                return Err(UrlValidationError::BlockedHost(
                    hostname.to_owned(),
                    "hostname resolved to no addresses; cannot verify it is safe",
                ));
            }
            Ok(validated)
        }
        Err(_) => {
            // Fail-closed: if DNS resolution fails we cannot verify the
            // destination is safe, so we reject the URL.  This prevents
            // attackers from supplying hostnames that resolve only inside
            // the target network (split-horizon DNS / DNS exfiltration).
            Err(UrlValidationError::BlockedHost(
                hostname.to_owned(),
                "hostname could not be resolved; cannot verify it is safe",
            ))
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_public_ip_urls() {
        // Use public routable IP literals to test the non-private IP path
        // without relying on DNS resolution (avoids network dependency in tests).
        // 1.1.1.1 = Cloudflare DNS, 8.8.8.8 = Google DNS — both are public.
        assert!(validate_public_url("https://1.1.1.1/notify").is_ok());
        assert!(validate_public_url("http://8.8.8.8/notify").is_ok());
        // Public IPv6 — 2606:4700:4700::1111 = Cloudflare IPv6 DNS
        assert!(validate_public_url("https://[2606:4700:4700::1111]/notify").is_ok());
    }

    #[test]
    fn test_blocked_schemes() {
        assert!(validate_public_url("ftp://example.com/file").is_err());
        assert!(validate_public_url("file:///etc/passwd").is_err());
        assert!(validate_public_url("gopher://example.com/").is_err());
    }

    #[test]
    fn test_blocked_loopback_ips() {
        assert!(validate_public_url("http://127.0.0.1/secret").is_err());
        assert!(validate_public_url("http://127.255.255.255/").is_err());
        assert!(validate_public_url("http://[::1]/").is_err());
    }

    #[test]
    fn test_blocked_private_ips() {
        assert!(validate_public_url("http://10.0.0.1/").is_err());
        assert!(validate_public_url("http://172.16.0.1/").is_err());
        assert!(validate_public_url("http://192.168.1.1/").is_err());
    }

    #[test]
    fn test_blocked_link_local() {
        assert!(validate_public_url("http://169.254.169.254/latest/meta-data/").is_err());
    }

    #[test]
    fn test_blocked_hostnames() {
        assert!(validate_public_url("http://localhost/admin").is_err());
        assert!(validate_public_url("http://metadata.google.internal/").is_err());
    }

    #[test]
    fn test_blocked_cgnat() {
        assert!(validate_public_url("http://100.64.0.1/").is_err());
        assert!(validate_public_url("http://100.127.255.255/").is_err());
    }

    #[test]
    fn test_blocked_ipv4_mapped_ipv6() {
        // ::ffff:127.0.0.1
        assert!(validate_public_url("http://[::ffff:7f00:1]/").is_err());
    }

    #[test]
    fn test_blocked_ula_ipv6() {
        assert!(validate_public_url("http://[fc00::1]/").is_err());
        assert!(validate_public_url("http://[fd12:3456:789a::1]/").is_err());
    }

    #[test]
    fn test_blocked_link_local_ipv6() {
        assert!(validate_public_url("http://[fe80::1]/").is_err());
    }

    #[test]
    fn test_scheme_only_allows_loopback() {
        // CrowdSec LAPI default — must be allowed.
        assert!(validate_scheme_only("http://127.0.0.1:8080").is_ok());
        assert!(validate_scheme_only("https://192.168.1.50:8080").is_ok());
    }

    #[test]
    fn test_scheme_only_rejects_bad_scheme() {
        assert!(validate_scheme_only("ftp://127.0.0.1:21").is_err());
        assert!(validate_scheme_only("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_invalid_url_parse() {
        assert!(validate_public_url("not a url").is_err());
        assert!(validate_public_url("").is_err());
    }
}
