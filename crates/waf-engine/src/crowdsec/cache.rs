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

    // ── Private helpers ──────────────────────────────────────────────────────

    fn should_cache(decision: &Decision, config: &CrowdSecConfig) -> bool {
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
        if let Some(ref dur_str) = decision.duration
            && let Some(secs) = parse_cs_duration(dur_str)
        {
            return Instant::now() + Duration::from_secs(secs);
        }
        // Default fallback: 4 hours
        Instant::now() + Duration::from_hours(4)
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
