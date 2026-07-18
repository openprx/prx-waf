use dashmap::DashMap;
use std::collections::HashSet;
use std::sync::Arc;
use waf_common::HostConfig;

/// Routes incoming requests to the correct upstream based on Host header
pub struct HostRouter {
    /// key: "host:port" or just "host" (for default port)
    routes: DashMap<String, Arc<HostConfig>>,
}

impl Default for HostRouter {
    fn default() -> Self {
        Self { routes: DashMap::new() }
    }
}

impl HostRouter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a host configuration
    pub fn register(&self, config: &Arc<HostConfig>) {
        // Register by "host:port"
        let key = format!("{}:{}", config.host, config.port);
        self.routes.insert(key, Arc::clone(config));

        // Also register by bare hostname for default ports (80/443)
        if config.port == 80 || config.port == 443 {
            self.routes.insert(config.host.clone(), Arc::clone(config));
        }
    }

    /// Remove a host configuration
    pub fn unregister(&self, host: &str, port: u16) {
        let key = format!("{host}:{port}");
        self.routes.remove(&key);
        if port == 80 || port == 443 {
            self.routes.remove(host);
        }
    }

    /// Resolve a request to a host config using the Host header value.
    ///
    /// Resolution order:
    /// 1. Exact match on the full `Host` value (covers `host:port` keys and any
    ///    verbatim-registered bracketed IPv6 literals).
    /// 2. Bare-hostname fallback — but *only* when the port component is absent
    ///    or one of the default ports (80/443). This mirrors [`register`], which
    ///    only inserts the bare-host key for ports 80/443, so a request for
    ///    `a.com:31337` no longer silently matches the `a.com:80` policy.
    pub fn resolve(&self, host_header: &str) -> Option<Arc<HostConfig>> {
        // Try exact match first
        if let Some(entry) = self.routes.get(host_header) {
            let cfg: Arc<HostConfig> = Arc::clone(&*entry);
            return Some(cfg);
        }

        let (bare_host, port) = split_host_port(host_header);

        // Bare-hostname fallback is only valid for default ports. A non-default
        // port must not fall through to the bare-host policy → return None.
        let port_allowed = port.is_none_or(|p| p == "80" || p == "443");
        if !port_allowed {
            return None;
        }

        if bare_host != host_header
            && let Some(entry) = self.routes.get(bare_host)
        {
            let cfg: Arc<HostConfig> = Arc::clone(&*entry);
            return Some(cfg);
        }

        None
    }

    /// List all registered host configs (deduplicated by code)
    pub fn list(&self) -> Vec<Arc<HostConfig>> {
        let mut seen: HashSet<String> = HashSet::new();
        let mut result: Vec<Arc<HostConfig>> = Vec::new();

        for entry in &self.routes {
            let config: &Arc<HostConfig> = entry.value();
            let code = config.code.clone();
            if seen.insert(code) {
                result.push(Arc::clone(config));
            }
        }

        result
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

/// Split a `Host` header value into `(host, Option<port>)`.
///
/// Handles bracketed IPv6 literals (`[::1]`, `[::1]:8080`) so the port is not
/// mistaken for part of the address, and treats an empty/trailing port
/// (`a.com:`) as "no port". Unbracketed multi-colon inputs (malformed per
/// RFC 7230) are split on the last colon, which harmlessly fails to resolve.
fn split_host_port(host_header: &str) -> (&str, Option<&str>) {
    if let Some(rest) = host_header.strip_prefix('[') {
        // IPv6 literal: `[addr]` or `[addr]:port`
        if let Some((addr, tail)) = rest.split_once(']') {
            let port = tail.strip_prefix(':').filter(|p| !p.is_empty());
            return (addr, port);
        }
        // Malformed (missing closing bracket) — treat as opaque host.
        return (host_header, None);
    }

    match host_header.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() => (host, Some(port)),
        // Trailing colon with empty port behaves like "no port".
        Some((host, _)) => (host, None),
        None => (host_header, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use waf_common::HostConfig;

    fn cfg(host: &str, port: u16) -> Arc<HostConfig> {
        Arc::new(HostConfig {
            code: format!("{host}:{port}"),
            host: host.to_string(),
            port,
            ..HostConfig::default()
        })
    }

    #[test]
    fn split_host_port_variants() {
        assert_eq!(split_host_port("a.com"), ("a.com", None));
        assert_eq!(split_host_port("a.com:80"), ("a.com", Some("80")));
        assert_eq!(split_host_port("a.com:31337"), ("a.com", Some("31337")));
        assert_eq!(split_host_port("a.com:"), ("a.com", None));
        assert_eq!(split_host_port("[::1]"), ("::1", None));
        assert_eq!(split_host_port("[2001:db8::1]:443"), ("2001:db8::1", Some("443")));
    }

    #[test]
    fn non_default_port_does_not_match_bare_host() {
        let router = HostRouter::new();
        router.register(&cfg("a.com", 80));

        // Exact and default-port equivalents resolve.
        assert!(router.resolve("a.com").is_some());
        assert!(router.resolve("a.com:80").is_some());
        assert!(router.resolve("a.com:443").is_some());

        // A non-default port must NOT fall through to the a.com:80 policy.
        assert!(router.resolve("a.com:31337").is_none());
    }

    #[test]
    fn ipv6_literal_resolves_by_bare_host() {
        let router = HostRouter::new();
        router.register(&cfg("::1", 443));
        assert!(router.resolve("[::1]:443").is_some());
        assert!(router.resolve("[::1]").is_some());
        assert!(router.resolve("[::1]:31337").is_none());
    }
}
