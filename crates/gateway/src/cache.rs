//! In-memory LRU response cache backed by `moka`.
//!
//! Cache key = `scheme|method|host|port|path?query|ae=<normalised Accept-Encoding>`
//! (see [`ResponseCache::make_key`]).
//! Respects Cache-Control directives: `no-cache`, `no-store`, `private`, `max-age=N`,
//! and never stores a response carrying `Set-Cookie`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use moka::future::Cache;
use tracing::{debug, trace};

/// A cached HTTP response
#[derive(Debug, Clone)]
pub struct CachedResponse {
    pub status: u16,
    /// Response headers as (name, value) pairs
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
    /// Seconds until expiry (from insertion time)
    pub max_age: u64,
}

/// Cache statistics counters
#[derive(Debug, Default)]
pub struct CacheStats {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub evictions: AtomicU64,
    pub stores: AtomicU64,
}

impl CacheStats {
    pub fn snapshot(&self) -> CacheStatsSnapshot {
        CacheStatsSnapshot {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            stores: self.stores.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CacheStatsSnapshot {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub stores: u64,
}

/// Shared response cache
pub struct ResponseCache {
    inner: Cache<String, Arc<CachedResponse>>,
    stats: Arc<CacheStats>,
    default_ttl: Duration,
    max_ttl: Duration,
}

impl ResponseCache {
    /// Create a new cache.
    ///
    /// `max_size_mb`: maximum total size in MiB (approximate, measured by entry count).
    pub fn new(max_size_mb: u64, default_ttl_secs: u64, max_ttl_secs: u64) -> Arc<Self> {
        // Use entry count as capacity (each ~1 MiB avg → × 1024 entries per MB)
        let capacity = (max_size_mb * 16).max(64);
        let stats = Arc::new(CacheStats::default());

        let inner = Cache::builder()
            .max_capacity(capacity)
            .time_to_live(Duration::from_secs(max_ttl_secs))
            .build();

        Arc::new(Self {
            inner,
            stats,
            default_ttl: Duration::from_secs(default_ttl_secs),
            max_ttl: Duration::from_secs(max_ttl_secs),
        })
    }

    /// Build the cache key for a request.
    ///
    /// The key incorporates every request dimension that can change the response
    /// so that entries can never collide across origins or content negotiation:
    ///
    /// * `scheme` (`http`/`https`) + `host` + `port` — a request for
    ///   `https://a.com:443` must not be served from an `http://a.com:80` entry.
    /// * `method` — `GET` and `HEAD` are cached under distinct keys.
    /// * `path` + `query`.
    /// * the `Accept-Encoding` Vary dimension (normalised) — prevents handing a
    ///   `br`-encoded body to a client that only advertised `gzip`.
    ///
    /// Fields are `|`-separated (a byte that cannot appear in a host, scheme,
    /// method or normalised encoding token) so the segments are unambiguous.
    pub fn make_key(
        scheme: &str,
        method: &str,
        host: &str,
        port: u16,
        path: &str,
        query: &str,
        accept_encoding: &str,
    ) -> String {
        let ae = normalize_accept_encoding(accept_encoding);
        format!("{scheme}|{method}|{host}|{port}|{path}?{query}|ae={ae}")
    }

    /// Look up a cached response.  Returns `None` on miss.
    pub async fn get(&self, key: &str) -> Option<Arc<CachedResponse>> {
        let result = self.inner.get(key).await;
        if result.is_some() {
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            trace!(key = %key, "cache hit");
        } else {
            self.stats.misses.fetch_add(1, Ordering::Relaxed);
            trace!(key = %key, "cache miss");
        }
        result
    }

    /// Store a response, honouring Cache-Control directives.
    ///
    /// Returns `false` if the response must not be cached.
    pub async fn put(
        &self,
        key: String,
        status: u16,
        headers: Vec<(String, String)>,
        body: Bytes,
        cache_control: Option<&str>,
    ) -> bool {
        // Only cache 2xx responses.
        if !(200..300).contains(&status) {
            return false;
        }

        // Never cache a response that sets a cookie: it is, by definition,
        // user/session specific and caching it would serve one user's cookie
        // (and cached body) to everyone else — a cache-poisoning / cross-user
        // leak. This is a hard safety net independent of the request-side
        // Authorization/Cookie checks performed by the proxy.
        if headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("set-cookie")) {
            debug!(key = %key, "skipping cache: response carries Set-Cookie");
            return false;
        }

        let ttl = match parse_cache_control(cache_control) {
            CacheDecision::NoStore | CacheDecision::NoCache | CacheDecision::Private => {
                debug!(key = %key, "skipping cache: Cache-Control directive");
                return false;
            }
            CacheDecision::MaxAge(secs) => Duration::from_secs(secs.min(self.max_ttl.as_secs())),
            CacheDecision::Default => self.default_ttl,
        };

        let entry = Arc::new(CachedResponse {
            status,
            headers,
            body,
            max_age: ttl.as_secs(),
        });

        self.inner.insert(key, entry).await;
        self.stats.stores.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Invalidate all entries for a given host.
    pub async fn purge_host(&self, host: &str) {
        // moka doesn't support prefix-based invalidation; collect keys first
        let keys: Vec<String> = self
            .inner
            .iter()
            .filter(|(k, _)| {
                // key format: scheme|method|host|port|path?query|ae=...
                k.split('|').nth(2) == Some(host)
            })
            .map(|(k, _)| k.to_string())
            .collect();
        for k in keys {
            self.inner.remove(&k).await;
        }
    }

    /// Invalidate a single cache key.
    pub async fn purge_key(&self, key: &str) {
        self.inner.remove(key).await;
    }

    /// Flush the entire cache.
    pub async fn flush(&self) {
        self.inner.invalidate_all();
        self.inner.run_pending_tasks().await;
    }

    /// Return current statistics.
    pub fn stats(&self) -> CacheStatsSnapshot {
        self.stats.snapshot()
    }

    /// Approximate entry count.
    pub fn entry_count(&self) -> u64 {
        self.inner.entry_count()
    }
}

/// Normalise an `Accept-Encoding` request header into a single canonical token
/// used as the cache Vary dimension.
///
/// The upstream may choose at most one content-coding; by collapsing the header
/// to the single best coding the client advertised we ensure two requests only
/// share a cache entry when they would accept the same encoding. Preference
/// order mirrors what most origins pick: `br` > `gzip` > `deflate` > `identity`.
fn normalize_accept_encoding(header: &str) -> &'static str {
    let lower = header.to_ascii_lowercase();
    let accepts = |tok: &str| lower.split(',').any(|part| part.trim().starts_with(tok));
    if accepts("br") {
        "br"
    } else if accepts("gzip") {
        "gzip"
    } else if accepts("deflate") {
        "deflate"
    } else {
        "identity"
    }
}

// ─── Cache-Control parser ─────────────────────────────────────────────────────

enum CacheDecision {
    Default,
    NoStore,
    NoCache,
    Private,
    MaxAge(u64),
}

fn parse_cache_control(header: Option<&str>) -> CacheDecision {
    let Some(header) = header else {
        return CacheDecision::Default;
    };
    let lower = header.to_lowercase();
    if lower.contains("no-store") {
        return CacheDecision::NoStore;
    }
    if lower.contains("no-cache") {
        return CacheDecision::NoCache;
    }
    if lower.contains("private") {
        return CacheDecision::Private;
    }
    for part in lower.split(',') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("max-age=")
            && let Ok(secs) = rest.trim().parse::<u64>()
        {
            return CacheDecision::MaxAge(secs);
        }
    }
    CacheDecision::Default
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_key_includes_scheme_host_port_and_method() {
        let http = ResponseCache::make_key("http", "GET", "a.com", 80, "/x", "", "");
        let https = ResponseCache::make_key("https", "GET", "a.com", 443, "/x", "", "");
        let head = ResponseCache::make_key("http", "HEAD", "a.com", 80, "/x", "", "");
        // scheme+port and method are part of the key → no collisions.
        assert_ne!(http, https);
        assert_ne!(http, head);
    }

    #[test]
    fn make_key_varies_on_accept_encoding() {
        let gz = ResponseCache::make_key("http", "GET", "a.com", 80, "/x", "", "gzip, deflate");
        let br = ResponseCache::make_key("http", "GET", "a.com", 80, "/x", "", "br, gzip");
        let none = ResponseCache::make_key("http", "GET", "a.com", 80, "/x", "", "");
        // A br-capable client must not share an entry with a gzip-only client.
        assert_ne!(gz, br);
        assert_ne!(gz, none);
        // Clients that both prefer the same coding share the entry.
        let gz2 = ResponseCache::make_key("http", "GET", "a.com", 80, "/x", "", "gzip");
        assert_eq!(gz, gz2);
    }

    #[test]
    fn normalize_accept_encoding_prefers_br_then_gzip() {
        assert_eq!(normalize_accept_encoding("gzip, deflate, br"), "br");
        assert_eq!(normalize_accept_encoding("gzip, deflate"), "gzip");
        assert_eq!(normalize_accept_encoding("deflate"), "deflate");
        assert_eq!(normalize_accept_encoding(""), "identity");
        assert_eq!(normalize_accept_encoding("identity"), "identity");
    }

    #[tokio::test]
    async fn does_not_cache_response_with_set_cookie() {
        let cache = ResponseCache::new(8, 60, 3600);
        let key = ResponseCache::make_key("http", "GET", "a.com", 80, "/x", "", "");
        let stored = cache
            .put(
                key.clone(),
                200,
                vec![("set-cookie".to_string(), "sid=abc".to_string())],
                Bytes::from_static(b"body"),
                None,
            )
            .await;
        assert!(!stored, "responses with Set-Cookie must never be cached");
        assert!(cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn caches_plain_get_and_serves_hit() {
        let cache = ResponseCache::new(8, 60, 3600);
        let key = ResponseCache::make_key("http", "GET", "a.com", 80, "/x", "", "");
        let stored = cache
            .put(
                key.clone(),
                200,
                vec![("content-type".to_string(), "text/plain".to_string())],
                Bytes::from_static(b"hello"),
                None,
            )
            .await;
        assert!(stored);
        let hit = cache.get(&key).await.expect("expected a cache hit");
        assert_eq!(hit.status, 200);
        assert_eq!(hit.body, Bytes::from_static(b"hello"));
    }

    #[tokio::test]
    async fn respects_no_store_cache_control() {
        let cache = ResponseCache::new(8, 60, 3600);
        let key = ResponseCache::make_key("http", "GET", "a.com", 80, "/x", "", "");
        let stored = cache
            .put(key.clone(), 200, Vec::new(), Bytes::from_static(b"x"), Some("no-store"))
            .await;
        assert!(!stored);
        assert!(cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn purge_host_removes_only_matching_host() {
        let cache = ResponseCache::new(8, 60, 3600);
        let a = ResponseCache::make_key("http", "GET", "a.com", 80, "/x", "", "");
        let b = ResponseCache::make_key("http", "GET", "b.com", 80, "/x", "", "");
        cache
            .put(a.clone(), 200, Vec::new(), Bytes::from_static(b"a"), None)
            .await;
        cache
            .put(b.clone(), 200, Vec::new(), Bytes::from_static(b"b"), None)
            .await;
        cache.purge_host("a.com").await;
        assert!(cache.get(&a).await.is_none(), "a.com entry should be purged");
        assert!(cache.get(&b).await.is_some(), "b.com entry should remain");
    }
}
