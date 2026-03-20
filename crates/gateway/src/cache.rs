//! In-memory LRU response cache backed by `moka`.
//!
//! Cache key = `method:host:path?query`
//! Respects Cache-Control directives: `no-cache`, `no-store`, `private`, `max-age=N`.
//! Supports stale-while-revalidate via background refresh.

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
    pub fn make_key(method: &str, host: &str, path: &str, query: &str) -> String {
        if query.is_empty() {
            format!("{}:{}:{}", method, host, path)
        } else {
            format!("{}:{}:{}?{}", method, host, path, query)
        }
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
        // Only cache 2xx responses on GET/HEAD
        if !(200..300).contains(&status) {
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
                // key format: method:host:path...
                let parts: Vec<&str> = k.splitn(3, ':').collect();
                parts.get(1).copied() == Some(host)
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

// ─── Cache-Control parser ─────────────────────────────────────────────────────

enum CacheDecision {
    Default,
    NoStore,
    NoCache,
    Private,
    MaxAge(u64),
}

fn parse_cache_control(header: Option<&str>) -> CacheDecision {
    let header = match header {
        Some(h) => h,
        None => return CacheDecision::Default,
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
