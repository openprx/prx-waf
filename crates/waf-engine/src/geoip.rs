//! GeoIP lookup service backed by ip2region xdb files.
//!
//! Wraps two `ip2region::Searcher` instances (one for IPv4, one for IPv6)
//! behind an `Arc` so the service can be cloned cheaply and shared across
//! threads without any locks.

use std::net::IpAddr;
use std::sync::Arc;

use ip2region::{CachePolicy, Searcher};
use tracing::{info, warn};
use waf_common::GeoIpInfo;

/// Immutable, thread-safe GeoIP lookup service.
///
/// Construct once (during engine initialisation) then share via `Arc<GeoIpService>`.
#[derive(Clone)]
pub struct GeoIpService {
    /// Searcher loaded with the IPv4 xdb file, if available.
    ipv4: Option<Arc<Searcher>>,
    /// Searcher loaded with the IPv6 xdb file, if available.
    ipv6: Option<Arc<Searcher>>,
}

impl GeoIpService {
    /// Initialise the service.
    ///
    /// `ipv4_path` / `ipv6_path` may point to files that don't exist yet;
    /// missing files are silently skipped and the corresponding searcher is
    /// left as `None`.  GeoIP lookups for that address family will return
    /// an empty `GeoIpInfo`.
    pub fn init(
        ipv4_path: &str,
        ipv6_path: &str,
        cache_policy: CachePolicy,
    ) -> anyhow::Result<Self> {
        let ipv4 = load_searcher(ipv4_path, cache_policy, "IPv4");
        let ipv6 = load_searcher(ipv6_path, cache_policy, "IPv6");

        if ipv4.is_none() && ipv6.is_none() {
            warn!(
                "GeoIP: neither IPv4 nor IPv6 xdb files could be loaded; \
                 GeoIP lookups will be disabled. \
                 Run `prx-waf geoip download` to fetch the xdb files."
            );
        }

        Ok(Self { ipv4, ipv6 })
    }

    /// Returns `true` if at least one searcher is available.
    pub fn is_available(&self) -> bool {
        self.ipv4.is_some() || self.ipv6.is_some()
    }

    /// Look up the GeoIP information for `ip`.
    ///
    /// Returns a default (all-empty) `GeoIpInfo` if no searcher is available
    /// for the address family, or if the lookup fails.
    pub fn lookup(&self, ip: IpAddr) -> GeoIpInfo {
        let searcher = match ip {
            IpAddr::V4(_) => self.ipv4.as_deref(),
            IpAddr::V6(_) => self.ipv6.as_deref(),
        };

        let Some(searcher) = searcher else {
            return GeoIpInfo::default();
        };

        let raw = match searcher.search(ip.to_string().as_str()) {
            Ok(r) => r,
            Err(e) => {
                warn!("GeoIP lookup failed for {}: {}", ip, e);
                return GeoIpInfo::default();
            }
        };

        parse_region(&raw)
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Attempt to open an xdb file and build a `Searcher`.
///
/// Returns `None` (with a log warning) if the file is absent or cannot be
/// opened, so callers can continue with degraded but functional behaviour.
fn load_searcher(path: &str, policy: CachePolicy, label: &str) -> Option<Arc<Searcher>> {
    if !std::path::Path::new(path).exists() {
        info!("GeoIP: {} xdb file not found at '{}' — skipping", label, path);
        return None;
    }

    match Searcher::new(path.to_string(), policy) {
        Ok(s) => {
            info!("GeoIP: {} searcher loaded from '{}'", label, path);
            Some(Arc::new(s))
        }
        Err(e) => {
            warn!("GeoIP: failed to load {} searcher from '{}': {}", label, path, e);
            None
        }
    }
}

/// Parse the ip2region result string into a `GeoIpInfo`.
///
/// The canonical format returned by ip2region is:
/// `Country|Province|City|ISP|iso-alpha2-code`
///
/// Fields may be `"0"` for unknown; those are normalised to an empty string.
fn parse_region(raw: &str) -> GeoIpInfo {
    if raw.is_empty() {
        return GeoIpInfo::default();
    }

    let mut parts = raw.splitn(5, '|');
    let country  = normalize(parts.next().unwrap_or(""));
    let province = normalize(parts.next().unwrap_or(""));
    let city     = normalize(parts.next().unwrap_or(""));
    let isp      = normalize(parts.next().unwrap_or(""));
    let iso_code = normalize(parts.next().unwrap_or(""));

    GeoIpInfo { country, province, city, isp, iso_code }
}

/// Return an empty string for the ip2region sentinel value `"0"`.
#[inline]
fn normalize(s: &str) -> String {
    if s == "0" { String::new() } else { s.to_string() }
}

/// Convert a `cache_policy` string (from config) to ip2region's `CachePolicy`.
pub fn cache_policy_from_str(s: &str) -> CachePolicy {
    match s.to_lowercase().as_str() {
        "vector_index" => CachePolicy::VectorIndex,
        "no_cache"     => CachePolicy::NoCache,
        _              => CachePolicy::FullMemory, // "full_memory" is the default
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_region() {
        let info = parse_region("China|Beijing|Beijing|CERNET|CN");
        assert_eq!(info.country, "China");
        assert_eq!(info.province, "Beijing");
        assert_eq!(info.city, "Beijing");
        assert_eq!(info.isp, "CERNET");
        assert_eq!(info.iso_code, "CN");
    }

    #[test]
    fn parse_unknown_fields() {
        let info = parse_region("China|0|0|ChinaNet|CN");
        assert_eq!(info.province, "");
        assert_eq!(info.city, "");
        assert_eq!(info.iso_code, "CN");
    }

    #[test]
    fn parse_empty() {
        let info = parse_region("");
        assert_eq!(info.country, "");
        assert_eq!(info.iso_code, "");
    }

    #[test]
    fn cache_policy_mapping() {
        assert!(matches!(cache_policy_from_str("full_memory"), CachePolicy::FullMemory));
        assert!(matches!(cache_policy_from_str("vector_index"), CachePolicy::VectorIndex));
        assert!(matches!(cache_policy_from_str("no_cache"), CachePolicy::NoCache));
        assert!(matches!(cache_policy_from_str("unknown"), CachePolicy::FullMemory));
    }
}
