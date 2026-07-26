//! In-memory LRU response cache backed by `moka`.
//!
//! Cache key = `scheme|method|host|port|path?query|ae=<normalised Accept-Encoding>`
//! (see [`ResponseCache::make_key`]).
//! Respects Cache-Control directives: `no-cache`, `no-store`, `private`, `max-age=N`,
//! and never stores a response carrying `Set-Cookie`.
//!
//! The cache is bounded **by bytes, not by entries**: `cache.max_size_mb` is
//! converted to a byte budget and handed to moka as a weighted capacity, with
//! [`entry_weight`] charging every entry for the memory it actually holds. See
//! [`ResponseCache::new`] for the accounting and the per-entry admission cap.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use moka::future::Cache;
use moka::notification::RemovalCause;
use tracing::{debug, trace};

// ─── Memory accounting constants ──────────────────────────────────────────────

/// Fixed bookkeeping charged to every entry on top of the bytes it owns: the
/// `Arc<CachedResponse>` allocation header and the struct itself, the key
/// `String`'s control block, the header `Vec`'s control block, and moka's own
/// per-entry hash-map node plus TinyLFU/LRU links.
///
/// Deliberately a round over-estimate rather than a measurement — erring high
/// means the process uses *less* memory than the operator budgeted, which is
/// the safe direction for a bound whose whole purpose is to stop an OOM.
const ENTRY_OVERHEAD_BYTES: u64 = 256;

/// Charged per response header on top of `name.len() + value.len()`: two
/// `String` control blocks (24 B each) plus allocator size-class rounding on
/// two small heap allocations.
const HEADER_OVERHEAD_BYTES: u64 = 64;

/// Floor for the byte budget. `max_size_mb = 0` (or any value that rounds to
/// less than this) would otherwise produce a cache that can hold nothing while
/// still paying for every lookup; 1 MiB keeps it functional and is far below
/// any level at which the cache is a memory concern.
const MIN_CACHE_BYTES: u64 = 1024 * 1024;

/// A single entry may occupy at most `budget / MAX_ENTRY_FRACTION`.
///
/// Rationale: an entry that is a large fraction of the budget cannot coexist
/// with a working set. Admitting one 200 MiB object into a 256 MiB cache
/// evicts everything else, is itself evicted by the next such object, and
/// converts the cache into a per-request memcpy that never serves a hit —
/// strictly worse than not caching it at all. Capping at 1/16 guarantees the
/// cache always holds at least 16 entries, so there is always a working set to
/// hit against.
///
/// At the shipped default (256 MiB) the cap is 16 MiB, which is *above* the
/// proxy's own `CACHE_BODY_LIMIT` of 8 MiB — so at defaults this cap never
/// binds and hit rate is unchanged. It only starts rejecting when an operator
/// configures a budget small enough that individual responses would thrash it.
const MAX_ENTRY_FRACTION: u64 = 16;

/// Memory (bytes) a cache entry is charged for.
///
/// Called **once per insert**, never on the read path: the result is stored in
/// [`CachedResponse::weight`] and the moka weigher just reads that field, so
/// the weigher itself is a `u32` load with no iteration.
///
/// Saturating throughout, and clamped to `u32::MAX` because moka weights are
/// `u32`. The clamp can never be reached in practice — the per-entry admission
/// cap in [`ResponseCache::put`] rejects anything near 4 GiB long before it,
/// and the proxy caps a cacheable body at 8 MiB — but saturating rather than
/// wrapping means a hypothetical >4 GiB entry is charged the maximum possible
/// weight (and so rejected), never a small wrapped one (and so admitted).
fn entry_weight(key_len: usize, headers: &[(String, String)], body_len: usize) -> u32 {
    let as_u64 = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
    let mut bytes = ENTRY_OVERHEAD_BYTES
        .saturating_add(as_u64(key_len))
        .saturating_add(as_u64(body_len));
    for (name, value) in headers {
        bytes = bytes
            .saturating_add(HEADER_OVERHEAD_BYTES)
            .saturating_add(as_u64(name.len()))
            .saturating_add(as_u64(value.len()));
    }
    u32::try_from(bytes).unwrap_or(u32::MAX)
}

/// A cached HTTP response
#[derive(Debug, Clone)]
pub struct CachedResponse {
    pub status: u16,
    /// Response headers as (name, value) pairs
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
    /// Seconds until expiry (from insertion time)
    pub max_age: u64,
    /// Precomputed memory footprint in bytes (see [`entry_weight`]).
    ///
    /// Private and computed at construction so the moka weigher — which runs
    /// inside the cache's own bookkeeping on every insert and eviction pass —
    /// is a single field read instead of a walk over the header vector.
    weight: u32,
}

/// Cache statistics counters
#[derive(Debug, Default)]
pub struct CacheStats {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    /// Involuntary removals only: evicted for size, or expired by TTL.
    /// Explicit purges (`purge_key` / `purge_host` / `flush`) are not counted.
    pub evictions: AtomicU64,
    pub stores: AtomicU64,
    /// Responses refused because one entry would exceed
    /// [`ResponseCache::max_entry_bytes`]. Refused, never truncated.
    pub oversize_rejects: AtomicU64,
}

impl CacheStats {
    pub fn snapshot(&self) -> CacheStatsSnapshot {
        CacheStatsSnapshot {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            stores: self.stores.load(Ordering::Relaxed),
            oversize_rejects: self.oversize_rejects.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CacheStatsSnapshot {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub stores: u64,
    pub oversize_rejects: u64,
}

/// Shared response cache
pub struct ResponseCache {
    inner: Cache<String, Arc<CachedResponse>>,
    stats: Arc<CacheStats>,
    default_ttl: Duration,
    max_ttl: Duration,
    /// Total byte budget (`max_size_mb` × 1 MiB, floored at [`MIN_CACHE_BYTES`]).
    max_bytes: u64,
    /// Largest single entry that will be admitted, in bytes.
    max_entry_bytes: u64,
}

impl ResponseCache {
    /// Create a new cache bounded by **bytes**.
    ///
    /// `max_size_mb` is converted to a byte budget and handed to moka as a
    /// *weighted* capacity: every entry is charged [`entry_weight`] bytes
    /// (body, headers, key and fixed bookkeeping) and moka evicts until the
    /// sum of those weights is within budget.
    ///
    /// Without a weigher moka's `max_capacity` counts **entries**, which is
    /// what this cache used to do: `max_size_mb = 256` meant 4 096 entries of
    /// up to 8 MiB each — a nominal 256 MiB budget that permitted ~32 GiB of
    /// resident response bodies. The weigher is what makes the configured
    /// number mean what it says.
    ///
    /// A single entry may not exceed `budget / 16` (see [`MAX_ENTRY_FRACTION`]);
    /// larger responses are refused by [`Self::put`] rather than admitted and
    /// never truncated.
    pub fn new(max_size_mb: u64, default_ttl_secs: u64, max_ttl_secs: u64) -> Arc<Self> {
        // MiB → bytes. Saturating: an absurd `max_size_mb` clamps to u64::MAX
        // instead of wrapping to a tiny budget.
        let max_bytes = max_size_mb.saturating_mul(1024 * 1024).max(MIN_CACHE_BYTES);
        // Clamped to u32::MAX because no entry can ever weigh more than that.
        let max_entry_bytes = (max_bytes / MAX_ENTRY_FRACTION).min(u64::from(u32::MAX));
        let stats = Arc::new(CacheStats::default());
        let evict_stats = Arc::clone(&stats);

        let inner = Cache::builder()
            .max_capacity(max_bytes)
            // O(1): the weight was computed once, at insert time.
            .weigher(|_key: &String, value: &Arc<CachedResponse>| value.weight)
            .eviction_listener(move |_key, _value, cause| {
                // Only involuntary removals are "evictions"; an operator
                // purging a key is not cache pressure.
                if matches!(cause, RemovalCause::Size | RemovalCause::Expired) {
                    evict_stats.evictions.fetch_add(1, Ordering::Relaxed);
                }
            })
            .time_to_live(Duration::from_secs(max_ttl_secs))
            .build();

        Arc::new(Self {
            inner,
            stats,
            default_ttl: Duration::from_secs(default_ttl_secs),
            max_ttl: Duration::from_secs(max_ttl_secs),
            max_bytes,
            max_entry_bytes,
        })
    }

    /// Total byte budget this cache will keep its contents within.
    pub const fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Largest single entry (bytes) that [`Self::put`] will admit.
    ///
    /// The proxy reads this to stop buffering a response body it already knows
    /// the cache would refuse.
    pub const fn max_entry_bytes(&self) -> u64 {
        self.max_entry_bytes
    }

    /// Record a response refused for size **before** it reached [`Self::put`].
    ///
    /// The proxy abandons its accumulation buffer as soon as a body passes the
    /// size it could ever store, so the refusal never reaches `put` and would
    /// otherwise go uncounted — leaving `oversize_rejects` reading 0 on a node
    /// that is in fact refusing responses all day. Calling this keeps the
    /// counter meaning what its name says on the path that actually produces
    /// refusals.
    pub fn note_oversize_reject(&self) {
        self.stats.oversize_rejects.fetch_add(1, Ordering::Relaxed);
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

        // Per-entry admission cap. Refuse the whole response — never store a
        // truncated body, which would serve a corrupt response on every
        // subsequent hit.
        let weight = entry_weight(key.len(), &headers, body.len());
        if u64::from(weight) > self.max_entry_bytes {
            debug!(
                key = %key,
                weight,
                max_entry_bytes = self.max_entry_bytes,
                "skipping cache: entry exceeds the per-entry size cap"
            );
            self.stats.oversize_rejects.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        let entry = Arc::new(CachedResponse {
            status,
            headers,
            body,
            max_age: ttl.as_secs(),
            weight,
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

    /// Settle moka's pending maintenance and report `(entries, bytes)`.
    ///
    /// moka applies inserts and evictions from a write buffer during
    /// housekeeping, so [`Self::entry_count`] and the weighted size are only
    /// approximate until that buffer is drained. This forces the drain first,
    /// which makes the numbers exact — at a cost that is fine for the admin
    /// stats endpoint and would not be on the request path.
    pub async fn usage(&self) -> (u64, u64) {
        self.inner.run_pending_tasks().await;
        (self.inner.entry_count(), self.inner.weighted_size())
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

    #[test]
    fn max_size_mb_is_a_byte_budget_not_an_entry_count() {
        let cache = ResponseCache::new(256, 60, 3600);
        assert_eq!(cache.max_bytes(), 256 * 1024 * 1024);
        // 1/16 of the budget, and above the proxy's own 8 MiB body limit, so
        // the per-entry cap does not bind at the shipped default.
        assert_eq!(cache.max_entry_bytes(), 16 * 1024 * 1024);
        assert!(cache.max_entry_bytes() > 8 * 1024 * 1024);
    }

    #[test]
    fn tiny_and_absurd_budgets_stay_sane() {
        // 0 is floored, not turned into a cache that can hold nothing.
        let zero = ResponseCache::new(0, 60, 3600);
        assert_eq!(zero.max_bytes(), MIN_CACHE_BYTES);
        assert_eq!(zero.max_entry_bytes(), MIN_CACHE_BYTES / 16);
        // u64::MAX MiB saturates instead of wrapping to a tiny budget, and the
        // per-entry cap stays inside the u32 the moka weigher can express.
        let huge = ResponseCache::new(u64::MAX, 60, 3600);
        assert_eq!(huge.max_bytes(), u64::MAX);
        assert_eq!(huge.max_entry_bytes(), u64::from(u32::MAX));
    }

    #[test]
    fn entry_weight_counts_key_body_and_headers() {
        let headers = vec![("content-type".to_string(), "text/plain".to_string())];
        let bare = entry_weight(0, &[], 0);
        assert_eq!(u64::from(bare), ENTRY_OVERHEAD_BYTES);
        // body and key bytes are charged one-for-one
        assert_eq!(entry_weight(10, &[], 1000), bare + 1010);
        // headers cost their own bytes plus the fixed per-header charge
        let with_header = entry_weight(0, &headers, 0);
        let expected = u64::from(bare)
            + HEADER_OVERHEAD_BYTES
            + u64::try_from("content-type".len()).unwrap_or(u64::MAX)
            + u64::try_from("text/plain".len()).unwrap_or(u64::MAX);
        assert_eq!(u64::from(with_header), expected);
    }

    #[tokio::test]
    async fn oversize_response_is_refused_not_truncated() {
        // 1 MiB budget → 64 KiB per-entry cap.
        let cache = ResponseCache::new(1, 60, 3600);
        assert_eq!(cache.max_entry_bytes(), 64 * 1024);
        let key = ResponseCache::make_key("http", "GET", "a.com", 80, "/big", "", "");
        let body = Bytes::from(vec![b'x'; 128 * 1024]);
        let stored = cache.put(key.clone(), 200, Vec::new(), body, None).await;
        assert!(!stored, "an entry over the per-entry cap must be refused");
        // Refused entirely: no truncated body is served on a later request.
        assert!(cache.get(&key).await.is_none());
        assert_eq!(cache.stats().oversize_rejects, 1);
        assert_eq!(cache.stats().stores, 0);

        // A response just under the cap is still cached, byte-exact.
        let small_key = ResponseCache::make_key("http", "GET", "a.com", 80, "/small", "", "");
        let small = Bytes::from(vec![b'y'; 60 * 1024]);
        assert!(cache.put(small_key.clone(), 200, Vec::new(), small.clone(), None).await);
        let hit = cache.get(&small_key).await.expect("under-cap entry should be cached");
        assert_eq!(hit.body, small);
    }

    #[tokio::test]
    async fn total_bytes_stay_within_budget_under_churn() {
        // 4 MiB budget, 64 KiB bodies → ~64 entries fit; insert 20× that many
        // under distinct keys and the cache must evict rather than grow.
        let cache = ResponseCache::new(4, 60, 3600);
        let body = Bytes::from(vec![b'z'; 64 * 1024]);
        for i in 0..1280 {
            let key = ResponseCache::make_key("http", "GET", "a.com", 80, &format!("/{i}"), "", "");
            cache.put(key, 200, Vec::new(), body.clone(), None).await;
        }
        let (entries, bytes) = cache.usage().await;
        assert!(
            bytes <= cache.max_bytes(),
            "weighted size {bytes} exceeded the {} byte budget",
            cache.max_bytes()
        );
        // Sanity: it did not simply refuse everything — the budget is being
        // used, and the eviction listener saw the pressure.
        assert!(entries > 0, "cache should still hold entries");
        assert!(bytes > cache.max_bytes() / 2, "budget should be substantially used");
        assert_eq!(cache.stats().oversize_rejects, 0);
        assert!(cache.stats().evictions > 0, "size pressure should report evictions");
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
