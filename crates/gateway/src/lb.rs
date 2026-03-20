//! Enhanced Load Balancer for PRX-WAF
//!
//! Strategies:
//!   - **Round Robin** — default, equal distribution
//!   - **IP Hash** — sticky sessions based on client IP (FNV hash)
//!   - **Weighted Round Robin** — backends with higher weight receive more traffic
//!   - **Least Connections** — always pick the backend with the fewest active connections
//!
//! Health checks run as a background Tokio task (TCP connect).

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::RwLock;

use dashmap::DashMap;
use tracing::{debug, info, warn};

use waf_common::LoadBalanceStrategy;

// ── Backend ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Backend {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub weight: u32,
    pub is_healthy: Arc<std::sync::atomic::AtomicBool>,
    /// Active connection counter (Least Connections strategy)
    pub active_connections: Arc<AtomicUsize>,
}

impl Backend {
    pub fn new(id: impl Into<String>, host: impl Into<String>, port: u16, weight: u32) -> Self {
        Self {
            id: id.into(),
            host: host.into(),
            port,
            weight,
            is_healthy: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            active_connections: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub fn is_healthy(&self) -> bool {
        self.is_healthy.load(Ordering::Relaxed)
    }

    pub fn set_healthy(&self, healthy: bool) {
        self.is_healthy.store(healthy, Ordering::Relaxed);
    }

    pub fn acquire_connection(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn release_connection(&self) {
        let prev = self.active_connections.fetch_sub(1, Ordering::Relaxed);
        // Guard against underflow
        if prev == 0 {
            self.active_connections.store(0, Ordering::Relaxed);
        }
    }
}

// ── LoadBalancer ──────────────────────────────────────────────────────────────

/// A per-host load balancer instance.
pub struct LoadBalancer {
    backends: Arc<RwLock<Vec<Backend>>>,
    strategy: LoadBalanceStrategy,
    /// Round-robin / weighted round-robin counter
    rr_counter: AtomicUsize,
}

impl LoadBalancer {
    pub fn new(strategy: LoadBalanceStrategy) -> Self {
        Self {
            backends: Arc::new(RwLock::new(Vec::new())),
            strategy,
            rr_counter: AtomicUsize::new(0),
        }
    }

    /// Add or update a backend.
    pub fn add_backend(&self, backend: Backend) {
        let mut backends = self.backends.write();
        if let Some(existing) = backends.iter_mut().find(|b| b.id == backend.id) {
            *existing = backend;
        } else {
            backends.push(backend);
        }
    }

    /// Remove a backend by ID.
    pub fn remove_backend(&self, id: &str) {
        self.backends.write().retain(|b| b.id != id);
    }

    /// Replace all backends.
    pub fn set_backends(&self, backends: Vec<Backend>) {
        *self.backends.write() = backends;
    }

    /// Get healthy backends only.
    pub fn healthy_backends(&self) -> Vec<Backend> {
        self.backends
            .read()
            .iter()
            .filter(|b| b.is_healthy())
            .cloned()
            .collect()
    }

    pub fn all_backends(&self) -> Vec<Backend> {
        self.backends.read().clone()
    }

    /// Pick the next backend according to the strategy.
    ///
    /// Returns `None` if there are no healthy backends.
    pub fn next_backend(&self, client_ip: IpAddr) -> Option<String> {
        let healthy = self.healthy_backends();
        if healthy.is_empty() {
            // Fall back to all backends if none are healthy
            let all = self.backends.read();
            if all.is_empty() {
                return None;
            }
            let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % all.len();
            return Some(all[idx].addr());
        }

        match &self.strategy {
            LoadBalanceStrategy::RoundRobin => self.round_robin(&healthy),
            LoadBalanceStrategy::IpHash => self.ip_hash(client_ip, &healthy),
            LoadBalanceStrategy::WeightedRoundRobin => self.weighted_round_robin(&healthy),
            LoadBalanceStrategy::LeastConnections => self.least_connections(&healthy),
        }
    }

    // ── Strategies ────────────────────────────────────────────────────────────

    fn round_robin(&self, backends: &[Backend]) -> Option<String> {
        let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % backends.len();
        Some(backends[idx].addr())
    }

    fn ip_hash(&self, ip: IpAddr, backends: &[Backend]) -> Option<String> {
        let hash = fnv_hash_ip(ip);
        let idx = (hash as usize) % backends.len();
        Some(backends[idx].addr())
    }

    fn weighted_round_robin(&self, backends: &[Backend]) -> Option<String> {
        // Build a weighted list: each backend appears `weight` times
        let total_weight: u32 = backends.iter().map(|b| b.weight.max(1)).sum();
        if total_weight == 0 {
            return self.round_robin(backends);
        }

        let counter = self.rr_counter.fetch_add(1, Ordering::Relaxed);
        let pos = (counter as u32) % total_weight;

        let mut cumulative = 0u32;
        for backend in backends {
            cumulative += backend.weight.max(1);
            if pos < cumulative {
                return Some(backend.addr());
            }
        }

        // Fallback
        Some(backends[0].addr())
    }

    fn least_connections(&self, backends: &[Backend]) -> Option<String> {
        backends
            .iter()
            .min_by_key(|b| b.active_connections.load(Ordering::Relaxed))
            .map(|b| b.addr())
    }
}

// ── FNV hash for IP addresses ─────────────────────────────────────────────────

fn fnv_hash_ip(ip: IpAddr) -> u64 {
    const FNV_OFFSET: u64 = 14_695_981_039_346_656_037;
    const FNV_PRIME: u64 = 1_099_511_628_211;

    let bytes: Vec<u8> = match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };

    let mut hash = FNV_OFFSET;
    for byte in bytes {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

// ── LoadBalancerRegistry ──────────────────────────────────────────────────────

/// Global registry mapping host_code → LoadBalancer.
pub struct LoadBalancerRegistry {
    lbs: DashMap<String, Arc<LoadBalancer>>,
}

impl LoadBalancerRegistry {
    pub fn new() -> Self {
        Self {
            lbs: DashMap::new(),
        }
    }

    pub fn get(&self, host_code: &str) -> Option<Arc<LoadBalancer>> {
        self.lbs.get(host_code).map(|e| Arc::clone(&*e))
    }

    pub fn register(&self, host_code: &str, lb: LoadBalancer) {
        self.lbs.insert(host_code.to_string(), Arc::new(lb));
    }

    pub fn remove(&self, host_code: &str) {
        self.lbs.remove(host_code);
    }

    pub fn len(&self) -> usize {
        self.lbs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lbs.is_empty()
    }
}

impl Default for LoadBalancerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Health checker ────────────────────────────────────────────────────────────

/// Run a TCP health check against `host:port`.
///
/// Returns `true` if the connection succeeds within `timeout`.
pub async fn tcp_health_check(host: &str, port: u16, timeout: Duration) -> bool {
    match tokio::time::timeout(
        timeout,
        tokio::net::TcpStream::connect(format!("{}:{}", host, port)),
    )
    .await
    {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            debug!("Health check {}:{} failed: {}", host, port, e);
            false
        }
        Err(_) => {
            debug!("Health check {}:{} timed out", host, port);
            false
        }
    }
}

/// Spawn a background health-check task for a LoadBalancer.
///
/// Periodically checks each backend and updates the `is_healthy` flag.
pub fn spawn_health_checker(
    lb: Arc<LoadBalancer>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let timeout = Duration::from_secs(5);
        loop {
            tokio::time::sleep(interval).await;

            let backends = lb.all_backends();
            for backend in &backends {
                let healthy = tcp_health_check(&backend.host, backend.port, timeout).await;
                let was_healthy = backend.is_healthy();
                backend.set_healthy(healthy);

                if was_healthy && !healthy {
                    warn!("Backend {}:{} is now UNHEALTHY", backend.host, backend.port);
                } else if !was_healthy && healthy {
                    info!("Backend {}:{} is now HEALTHY", backend.host, backend.port);
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_lb(strategy: LoadBalanceStrategy) -> LoadBalancer {
        let lb = LoadBalancer::new(strategy);
        lb.add_backend(Backend::new("b1", "10.0.0.1", 8080, 1));
        lb.add_backend(Backend::new("b2", "10.0.0.2", 8080, 2));
        lb.add_backend(Backend::new("b3", "10.0.0.3", 8080, 1));
        lb
    }

    #[test]
    fn test_round_robin() {
        let lb = make_lb(LoadBalanceStrategy::RoundRobin);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let backends: std::collections::HashSet<String> =
            (0..6).map(|_| lb.next_backend(ip).unwrap()).collect();
        // Should hit all 3 backends over 6 requests
        assert_eq!(backends.len(), 3);
    }

    #[test]
    fn test_ip_hash_sticky() {
        let lb = make_lb(LoadBalanceStrategy::IpHash);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let first = lb.next_backend(ip).unwrap();
        for _ in 0..10 {
            assert_eq!(
                lb.next_backend(ip).unwrap(),
                first,
                "IP hash should be sticky"
            );
        }
    }

    #[test]
    fn test_least_connections() {
        let lb = make_lb(LoadBalanceStrategy::LeastConnections);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        // Simulate b1 having many connections
        let backends = lb.all_backends();
        for _ in 0..10 {
            backends[0].acquire_connection();
        }

        // Next picks b2 or b3 (both have 0 connections)
        let next = lb.next_backend(ip).unwrap();
        assert!(
            next == "10.0.0.2:8080" || next == "10.0.0.3:8080",
            "Should pick backend with fewest connections, got {}",
            next
        );
    }

    #[test]
    fn test_weighted_round_robin() {
        use std::collections::HashMap;
        let lb = make_lb(LoadBalanceStrategy::WeightedRoundRobin);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        let mut counts: HashMap<String, usize> = HashMap::new();
        for _ in 0..100 {
            let addr = lb.next_backend(ip).unwrap();
            *counts.entry(addr).or_insert(0) += 1;
        }

        // b2 has weight 2, b1 and b3 have weight 1
        // Expected distribution: b2 ≈ 50%, b1 ≈ 25%, b3 ≈ 25%
        let b2 = counts.get("10.0.0.2:8080").copied().unwrap_or(0);
        let b1 = counts.get("10.0.0.1:8080").copied().unwrap_or(0);
        assert!(
            b2 > b1,
            "b2 (weight 2) should get more traffic than b1 (weight 1)"
        );
    }

    #[test]
    fn test_unhealthy_backend_skipped() {
        let lb = make_lb(LoadBalanceStrategy::RoundRobin);
        // Mark b1 and b3 unhealthy
        let backends = lb.all_backends();
        backends[0].set_healthy(false);
        backends[2].set_healthy(false);

        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        for _ in 0..10 {
            let addr = lb.next_backend(ip).unwrap();
            assert_eq!(
                addr, "10.0.0.2:8080",
                "Should only pick the healthy backend"
            );
        }
    }
}
