use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::RwLock;

use dashmap::DashMap;
use ipnet::IpNet;

use super::config::CrowdSecConfig;
use super::models::{CacheStats, CachedDecision, Decision, DecisionStream};

/// In-memory decision cache with exact-IP and CIDR-range matching.
///
/// Thread-safe via `DashMap` (exact IPs), `RwLock<Vec>` (CIDR ranges), and
/// atomic counters for statistics.
pub struct DecisionCache {
    /// Exact IP address decisions
    ip_decisions: DashMap<IpAddr, CachedDecision>,
    /// CIDR range decisions
    range_decisions: RwLock<Vec<(IpNet, CachedDecision)>>,
    /// Other scope decisions (Country/AS keyed by value string)
    other_decisions: DashMap<String, CachedDecision>,
    /// Running total of cached decisions
    total_cached: AtomicU64,
    /// Cache hit counter
    pub hits: AtomicU64,
    /// Cache miss counter
    pub misses: AtomicU64,
    /// Optional override TTL in seconds (0 = use decision duration)
    cache_ttl_secs: u64,
}

impl DecisionCache {
    pub fn new(cache_ttl_secs: u64) -> Self {
        Self {
            ip_decisions: DashMap::new(),
            range_decisions: RwLock::new(Vec::new()),
            other_decisions: DashMap::new(),
            total_cached: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            cache_ttl_secs,
        }
    }

    /// Check if `ip` has an active decision. Returns the first match found.
    pub fn check_ip(&self, ip: &IpAddr) -> Option<CachedDecision> {
        // 1. Exact IP match
        if let Some(entry) = self.ip_decisions.get(ip)
            && !entry.is_expired()
        {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Some(entry.clone());
        }

        // 2. CIDR range match
        {
            let ranges = self.range_decisions.read();
            for (net, cached) in ranges.iter() {
                if net.contains(ip) && !cached.is_expired() {
                    self.hits.fetch_add(1, Ordering::Relaxed);
                    return Some(cached.clone());
                }
            }
        }

        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Apply a decision stream: insert new decisions and remove deleted ones.
    pub fn apply_stream(&self, stream: DecisionStream, config: &CrowdSecConfig) {
        if let Some(new_decisions) = stream.new {
            for decision in new_decisions {
                if !Self::should_cache(&decision, config) {
                    continue;
                }
                let expires_at = self.compute_expiry(&decision);
                let cached = CachedDecision {
                    decision: decision.clone(),
                    expires_at,
                    // Straight from LAPI: this entry *is* confirmed upstream
                    // state, and it also confirms (overwrites) any restored
                    // entry for the same value.
                    restored: false,
                };
                self.insert_decision(&decision, cached);
            }
        }

        if let Some(deleted) = stream.deleted {
            for decision in deleted {
                self.remove_decision(&decision);
            }
        }

        self.update_total();
    }

    /// Load decisions restored from the durable mirror (`crowdsec_decisions`).
    ///
    /// Called **before** the proxy starts serving, so a process that comes up
    /// while LAPI is unreachable still knows which IPs are banned instead of
    /// allowing every one of them through until the next successful poll.
    ///
    /// Each entry carries its own remaining TTL (computed by the caller from
    /// the decision's stored expiry), and every entry is marked
    /// [`CachedDecision::restored`] so the first full LAPI pull can evict the
    /// ones upstream no longer holds. Returns the number of entries inserted.
    pub fn insert_restored(&self, restored: Vec<(Decision, Duration)>) -> usize {
        let now = Instant::now();
        let mut inserted = 0usize;
        for (decision, ttl) in restored {
            let cached = CachedDecision {
                decision: decision.clone(),
                expires_at: now + ttl,
                restored: true,
            };
            self.insert_decision(&decision, cached);
            inserted += 1;
        }
        self.update_total();
        inserted
    }

    /// Evict every entry still marked [`CachedDecision::restored`].
    ///
    /// Run immediately after a **full** LAPI pull has been applied: that pull
    /// carries the complete active decision set, so anything the pull did not
    /// overwrite is a decision upstream no longer holds — typically a ban
    /// lifted while this process was down. Without this, a restored entry would
    /// keep blocking until its stored expiry, i.e. the mirror would resurrect a
    /// revoked ban.
    ///
    /// Returns the number of evicted entries.
    pub fn drop_unconfirmed_restored(&self) -> usize {
        let mut dropped = 0usize;
        self.ip_decisions.retain(|_, v| {
            if v.restored {
                dropped += 1;
            }
            !v.restored
        });
        {
            let mut ranges = self.range_decisions.write();
            ranges.retain(|(_, v)| {
                if v.restored {
                    dropped += 1;
                }
                !v.restored
            });
        }
        self.other_decisions.retain(|_, v| {
            if v.restored {
                dropped += 1;
            }
            !v.restored
        });
        self.update_total();
        dropped
    }

    /// Remove all expired entries from the cache.
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        self.ip_decisions.retain(|_, v| v.expires_at > now);
        {
            let mut ranges = self.range_decisions.write();
            ranges.retain(|(_, v)| v.expires_at > now);
        }
        self.other_decisions.retain(|_, v| v.expires_at > now);
        self.update_total();
    }

    /// Return all non-expired decisions as a flat Vec (for API listing).
    pub fn list_decisions(&self) -> Vec<Decision> {
        let mut result = Vec::new();

        for entry in &self.ip_decisions {
            if !entry.is_expired() {
                result.push(entry.decision.clone());
            }
        }

        {
            let ranges = self.range_decisions.read();
            for (_, cached) in ranges.iter() {
                if !cached.is_expired() {
                    result.push(cached.decision.clone());
                }
            }
        }

        for entry in &self.other_decisions {
            if !entry.is_expired() {
                result.push(entry.decision.clone());
            }
        }

        result
    }

    /// Get cache hit/miss statistics.
    pub fn stats(&self) -> CacheStats {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total_lookups = hits + misses;
        #[allow(clippy::cast_precision_loss)]
        let hit_rate_pct = if total_lookups > 0 {
            (hits as f64 / total_lookups as f64) * 100.0
        } else {
            0.0
        };
        CacheStats {
            total_cached: self.total_cached.load(Ordering::Relaxed),
            hits,
            misses,
            hit_rate_pct,
        }
    }

    /// The TTL to give a decision restored from the durable mirror.
    ///
    /// `remaining` is how much of the decision's own lifetime is left. When
    /// `cache_ttl_secs` overrides the decision duration it is applied as a
    /// *ceiling*, never an extension: a cache TTL longer than what upstream
    /// still enforces would keep blocking an IP `CrowdSec` has already
    /// released.
    #[must_use]
    pub const fn restore_ttl(&self, remaining: Duration) -> Duration {
        if self.cache_ttl_secs > 0 {
            let override_ttl = Duration::from_secs(self.cache_ttl_secs);
            if override_ttl.as_secs() < remaining.as_secs() {
                return override_ttl;
            }
        }
        remaining
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    /// Whether the configured scenario filters admit this decision.
    ///
    /// Visible to the `crowdsec` module so the durable mirror applies exactly
    /// the same filter as the in-memory cache — the mirror must never hold a
    /// decision the cache would have rejected, in either direction.
    pub(super) fn should_cache(decision: &Decision, config: &CrowdSecConfig) -> bool {
        if !config.scenarios_containing.is_empty() {
            let matches = config
                .scenarios_containing
                .iter()
                .any(|s| decision.scenario.contains(s.as_str()));
            if !matches {
                return false;
            }
        }
        for excluded in &config.scenarios_not_containing {
            if decision.scenario.contains(excluded.as_str()) {
                return false;
            }
        }
        true
    }

    fn compute_expiry(&self, decision: &Decision) -> Instant {
        if self.cache_ttl_secs > 0 {
            return Instant::now() + Duration::from_secs(self.cache_ttl_secs);
        }
        Instant::now() + Duration::from_secs(decision_lifetime_secs(decision))
    }

    fn insert_decision(&self, decision: &Decision, cached: CachedDecision) {
        let scope = decision.scope.to_lowercase();
        match scope.as_str() {
            "ip" => {
                if let Ok(ip) = decision.value.parse::<IpAddr>() {
                    self.ip_decisions.insert(ip, cached);
                }
            }
            "range" => {
                if let Ok(net) = decision.value.parse::<IpNet>() {
                    let mut ranges = self.range_decisions.write();
                    ranges.retain(|(n, _)| *n != net);
                    ranges.push((net, cached));
                }
            }
            _ => {
                self.other_decisions.insert(decision.value.clone(), cached);
            }
        }
    }

    fn remove_decision(&self, decision: &Decision) {
        let scope = decision.scope.to_lowercase();
        match scope.as_str() {
            "ip" => {
                if let Ok(ip) = decision.value.parse::<IpAddr>() {
                    self.ip_decisions.remove(&ip);
                }
            }
            "range" => {
                if let Ok(net) = decision.value.parse::<IpNet>() {
                    let mut ranges = self.range_decisions.write();
                    ranges.retain(|(n, _)| *n != net);
                }
            }
            _ => {
                self.other_decisions.remove(&decision.value);
            }
        }
    }

    fn update_total(&self) {
        let n = self.ip_decisions.len() + self.range_decisions.read().len() + self.other_decisions.len();
        self.total_cached.store(n as u64, Ordering::Relaxed);
    }
}

/// Lifetime assumed for a decision whose LAPI duration string is missing or
/// unparseable.
pub const DEFAULT_DECISION_LIFETIME_SECS: u64 = 4 * 3600;

/// The decision's own lifetime in seconds, independent of any cache TTL
/// override: its LAPI duration string, or [`DEFAULT_DECISION_LIFETIME_SECS`].
///
/// Shared by the in-memory expiry calculation and the durable mirror, so a
/// restored decision expires at the same wall-clock moment the live one would
/// have.
#[must_use]
pub fn decision_lifetime_secs(decision: &Decision) -> u64 {
    decision
        .duration
        .as_deref()
        .and_then(parse_cs_duration)
        .unwrap_or(DEFAULT_DECISION_LIFETIME_SECS)
}

/// Parse a `CrowdSec` duration string like "4h35m6.571762785s" into total seconds.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn parse_cs_duration(s: &str) -> Option<u64> {
    let mut total = 0u64;
    let mut current = String::new();
    for c in s.chars() {
        if c.is_ascii_digit() || c == '.' {
            current.push(c);
        } else {
            let n: f64 = current.parse().ok()?;
            match c {
                'h' => total += (n * 3600.0) as u64,
                'm' => total += (n * 60.0) as u64,
                's' => total += n as u64,
                _ => {}
            }
            current.clear();
        }
    }
    Some(total)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn decision(id: i64, value: &str) -> Decision {
        Decision {
            id,
            origin: "crowdsec".to_string(),
            scope: if value.contains('/') { "Range" } else { "Ip" }.to_string(),
            value: value.to_string(),
            type_: "ban".to_string(),
            scenario: "crowdsecurity/ssh-bf".to_string(),
            duration: Some("1h".to_string()),
            created_at: None,
        }
    }

    /// The reconciliation guarantee: a ban lifted upstream while this process
    /// was down must not survive the first full pull, even though the restore
    /// put it in the cache.
    #[test]
    fn a_restored_entry_the_full_pull_does_not_confirm_is_evicted() {
        let cache = DecisionCache::new(0);
        let config = CrowdSecConfig::default();

        cache.insert_restored(vec![
            (decision(1, "203.0.113.20"), Duration::from_hours(1)),
            (decision(2, "203.0.113.21"), Duration::from_hours(1)),
            (decision(3, "198.51.100.0/24"), Duration::from_hours(1)),
        ]);
        assert_eq!(cache.stats().total_cached, 3);

        // The full pull confirms only .20; .21 and the range were revoked.
        cache.apply_stream(
            DecisionStream {
                new: Some(vec![decision(1, "203.0.113.20")]),
                deleted: None,
            },
            &config,
        );
        let dropped = cache.drop_unconfirmed_restored();

        assert_eq!(dropped, 2, "both unconfirmed restored entries must go");
        assert!(cache.check_ip(&"203.0.113.20".parse().unwrap()).is_some());
        assert!(
            cache.check_ip(&"203.0.113.21".parse().unwrap()).is_none(),
            "a revoked ban must not be resurrected by the restore"
        );
        assert!(
            cache.check_ip(&"198.51.100.7".parse().unwrap()).is_none(),
            "a revoked range must not be resurrected by the restore"
        );
        assert_eq!(cache.stats().total_cached, 1);
    }

    /// A confirmed entry is no longer "restored", so a second reconciliation
    /// (or a later one after a reconnect) must not evict it.
    #[test]
    fn a_confirmed_entry_survives_reconciliation() {
        let cache = DecisionCache::new(0);
        let config = CrowdSecConfig::default();
        cache.insert_restored(vec![(decision(1, "203.0.113.22"), Duration::from_hours(1))]);
        cache.apply_stream(
            DecisionStream {
                new: Some(vec![decision(1, "203.0.113.22")]),
                deleted: None,
            },
            &config,
        );

        assert_eq!(cache.drop_unconfirmed_restored(), 0);
        assert_eq!(cache.drop_unconfirmed_restored(), 0);
        assert!(cache.check_ip(&"203.0.113.22".parse().unwrap()).is_some());
    }
}
