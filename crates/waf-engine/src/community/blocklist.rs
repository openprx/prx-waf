use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::RwLock;
use serde::Deserialize;
use tokio::sync::watch;
use tracing::{info, warn};

use super::client::CommunityClient;

/// Version response from `GET /api/v1/waf/blocklist/version`.
#[derive(Debug, Deserialize)]
struct BlocklistVersionResponse {
    version: u64,
}

/// Full blocklist response from `GET /api/v1/waf/blocklist/decoded`.
#[derive(Debug, Deserialize)]
struct BlocklistFullResponse {
    version: u64,
    entries: Vec<BlocklistEntry>,
}

/// A single blocklist entry from the community server.
#[derive(Debug, Clone, Deserialize)]
pub struct BlocklistEntry {
    pub ip: String,
    pub reason: String,
    pub source: String,
}

/// Community IP decision stored in the local cache.
#[derive(Debug, Clone)]
pub struct CommunityDecision {
    pub reason: String,
    pub source: String,
}

/// Maximum response body size for blocklist fetches (8 MiB).
const MAX_BLOCKLIST_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Synchronises the community blocklist in the background.
///
/// On startup, performs a full pull of all blocked IPs.
/// Afterwards, periodically checks the version endpoint and only
/// re-fetches when the server version has changed.
///
/// Uses `parking_lot::RwLock<HashMap>` for atomic map replacement:
/// a new map is built entirely, then swapped in a single write-lock,
/// so readers never see a partially-populated or empty state.
pub struct CommunityBlocklistSync {
    client: Arc<CommunityClient>,
    api_key: String,
    sync_interval_secs: u64,
    /// Blocked IPs from the community server (atomically swapped).
    blocked_ips: RwLock<HashMap<IpAddr, CommunityDecision>>,
    /// Current blocklist version from the server.
    current_version: AtomicU64,
}

impl CommunityBlocklistSync {
    pub fn new(client: Arc<CommunityClient>, api_key: String, sync_interval_secs: u64) -> Self {
        Self {
            client,
            api_key,
            sync_interval_secs,
            blocked_ips: RwLock::new(HashMap::new()),
            current_version: AtomicU64::new(0),
        }
    }

    /// Check if an IP is on the community blocklist.
    pub fn check_ip(&self, ip: &IpAddr) -> Option<CommunityDecision> {
        let map = self.blocked_ips.read();
        map.get(ip).cloned()
    }

    /// Return the number of blocked IPs in the cache.
    pub fn len(&self) -> usize {
        let map = self.blocked_ips.read();
        map.len()
    }

    /// Whether the blocklist cache is empty.
    pub fn is_empty(&self) -> bool {
        let map = self.blocked_ips.read();
        map.is_empty()
    }

    /// Background sync loop: full pull on startup, then periodic version checks.
    pub async fn run_sync_task(self: Arc<Self>, mut shutdown_rx: watch::Receiver<bool>) {
        info!(
            sync_interval_secs = self.sync_interval_secs,
            "Community blocklist sync task started"
        );

        // Full startup pull
        self.full_pull().await;

        let interval = Duration::from_secs(self.sync_interval_secs.max(10));

        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                result = shutdown_rx.changed() => {
                    if result.is_err() || *shutdown_rx.borrow() {
                        info!("Community blocklist sync task shutting down");
                        return;
                    }
                }
            }

            // Check if server has a newer version
            match self.fetch_version().await {
                Ok(server_version) => {
                    let local = self.current_version.load(Ordering::Relaxed);
                    if server_version > local {
                        info!(
                            local_version = local,
                            server_version, "Community blocklist version changed, re-fetching"
                        );
                        self.full_pull().await;
                    }
                }
                Err(e) => {
                    warn!("Failed to check community blocklist version: {e}");
                }
            }
        }
    }

    /// Fetch the full blocklist from the community server and replace the cache.
    async fn full_pull(&self) {
        let url = format!("{}/api/v1/waf/blocklist/decoded", self.client.base_url);

        let resp = match self
            .client
            .http
            .get(&url)
            .bearer_auth(&self.api_key)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!("Community blocklist full pull failed: {e}");
                return;
            }
        };

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!("Community blocklist full pull returned {status}: {body}");
            return;
        }

        // Enforce response size limit before parsing
        let bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                warn!("Failed to read community blocklist response: {e}");
                return;
            }
        };
        if bytes.len() > MAX_BLOCKLIST_RESPONSE_BYTES {
            warn!(
                size = bytes.len(),
                limit = MAX_BLOCKLIST_RESPONSE_BYTES,
                "Community blocklist response too large, skipping"
            );
            return;
        }

        let data: BlocklistFullResponse = match serde_json::from_slice(&bytes) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to parse community blocklist: {e}");
                return;
            }
        };

        // Build new map off-thread, then atomically swap
        let mut new_map = HashMap::with_capacity(data.entries.len());
        let mut loaded = 0u64;
        for entry in &data.entries {
            if let Ok(ip) = entry.ip.parse::<IpAddr>() {
                new_map.insert(
                    ip,
                    CommunityDecision {
                        reason: entry.reason.clone(),
                        source: entry.source.clone(),
                    },
                );
                loaded += 1;
            }
        }

        // Atomic swap: single write-lock replaces entire map
        {
            let mut map = self.blocked_ips.write();
            *map = new_map;
        }
        self.current_version.store(data.version, Ordering::Relaxed);

        info!(
            version = data.version,
            loaded,
            total_entries = data.entries.len(),
            "Community blocklist loaded"
        );
    }

    /// Fetch just the version number from the community server.
    async fn fetch_version(&self) -> anyhow::Result<u64> {
        let url = format!("{}/api/v1/waf/blocklist/version", self.client.base_url);

        let resp = self
            .client
            .http
            .get(&url)
            .bearer_auth(&self.api_key)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("blocklist version request failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("blocklist version returned {status}: {body}");
        }

        let data: BlocklistVersionResponse = resp
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("failed to parse blocklist version: {e}"))?;
        Ok(data.version)
    }
}
