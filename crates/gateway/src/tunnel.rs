//! Cloudflare-tunnel-style reverse tunnel.
//!
//! A tunnel client (running behind NAT) connects to the WAF's `/ws/tunnel/:token`
//! WebSocket endpoint.  The tunnel server keeps the connection alive and can
//! forward inbound HTTP requests over the multiplexed WebSocket channel.
//!
//! Protocol (text frames):
//!   C→S  `HELLO <name>`                 — authentication handshake
//!   S→C  `OK`                           — accepted
//!   S→C  `REQ <req_id> <method> <path>` — forward request
//!   C→S  `RSP <req_id> <status>`        — response status
//!   S→C  `PING`                         — keepalive
//!   C→S  `PONG`                         — keepalive reply

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, mpsc};
use tracing::info;
use uuid::Uuid;

// ─── Tunnel info ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelStatus {
    pub id: Uuid,
    pub name: String,
    pub target_host: String,
    pub target_port: u16,
    pub enabled: bool,
    pub connected: bool,
    pub last_seen: Option<DateTime<Utc>>,
}

// ─── Active tunnel connection ─────────────────────────────────────────────────

/// A live tunnel connection (backed by a WebSocket)
pub struct TunnelConnection {
    pub tunnel_id: Uuid,
    pub name: String,
    pub target_host: String,
    pub target_port: u16,
    /// Channel for sending messages down to the tunnel client
    pub tx: mpsc::Sender<String>,
    pub connected_at: Instant,
    pub last_seen: tokio::sync::Mutex<Option<Instant>>,
}

impl TunnelConnection {
    pub fn new(
        tunnel_id: Uuid,
        name: String,
        target_host: String,
        target_port: u16,
        tx: mpsc::Sender<String>,
    ) -> Arc<Self> {
        Arc::new(Self {
            tunnel_id,
            name,
            target_host,
            target_port,
            tx,
            connected_at: Instant::now(),
            last_seen: tokio::sync::Mutex::new(None),
        })
    }

    pub async fn ping(&self) {
        let _ = self.tx.send("PING".to_string()).await;
    }

    pub async fn touch(&self) {
        *self.last_seen.lock().await = Some(Instant::now());
    }
}

// ─── Tunnel registry ──────────────────────────────────────────────────────────

/// Registry of all configured and connected tunnels.
///
/// `configs`     — persisted tunnel configs loaded from the database
/// `connections` — currently live WebSocket connections, keyed by tunnel ID
pub struct TunnelRegistry {
    configs: RwLock<HashMap<Uuid, TunnelConfig>>,
    connections: RwLock<HashMap<Uuid, Arc<TunnelConnection>>>,
}

/// A persisted tunnel configuration (mirrors the `tunnels` DB table)
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub id: Uuid,
    pub name: String,
    pub token_hash: String,
    pub target_host: String,
    pub target_port: u16,
    pub enabled: bool,
}

impl TunnelRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            configs: RwLock::new(HashMap::new()),
            connections: RwLock::new(HashMap::new()),
        })
    }

    // ── Config management ─────────────────────────────────────────────────────

    pub async fn register(&self, cfg: TunnelConfig) {
        self.configs.write().await.insert(cfg.id, cfg);
    }

    pub async fn unregister(&self, id: Uuid) {
        self.configs.write().await.remove(&id);
        self.connections.write().await.remove(&id);
    }

    pub async fn list_configs(&self) -> Vec<TunnelConfig> {
        self.configs.read().await.values().cloned().collect()
    }

    pub async fn get_config(&self, id: Uuid) -> Option<TunnelConfig> {
        self.configs.read().await.get(&id).cloned()
    }

    /// Look up a tunnel by its token hash (SHA-256 hex of the pre-shared key).
    pub async fn find_by_token(&self, token_hash: &str) -> Option<TunnelConfig> {
        self.configs
            .read()
            .await
            .values()
            .find(|c| c.enabled && c.token_hash == token_hash)
            .cloned()
    }

    // ── Connection management ─────────────────────────────────────────────────

    pub async fn connect(&self, conn: Arc<TunnelConnection>) {
        info!(tunnel = %conn.name, "Tunnel client connected");
        self.connections.write().await.insert(conn.tunnel_id, conn);
    }

    pub async fn disconnect(&self, tunnel_id: Uuid) {
        let removed = self.connections.write().await.remove(&tunnel_id);
        if let Some(conn) = removed {
            info!(tunnel = %conn.name, "Tunnel client disconnected");
        }
    }

    pub async fn is_connected(&self, tunnel_id: Uuid) -> bool {
        self.connections.read().await.contains_key(&tunnel_id)
    }

    pub async fn get_connection(&self, tunnel_id: Uuid) -> Option<Arc<TunnelConnection>> {
        self.connections.read().await.get(&tunnel_id).cloned()
    }

    pub async fn list_status(&self) -> Vec<TunnelStatus> {
        let configs = self.configs.read().await;
        let connections = self.connections.read().await;

        configs
            .values()
            .map(|c| {
                let connected = connections.contains_key(&c.id);
                let last_seen = connections
                    .get(&c.id)
                    .and_then(|conn| conn.last_seen.try_lock().ok().and_then(|g| *g).map(|_| Utc::now()));
                TunnelStatus {
                    id: c.id,
                    name: c.name.clone(),
                    target_host: c.target_host.clone(),
                    target_port: c.target_port,
                    enabled: c.enabled,
                    connected,
                    last_seen,
                }
            })
            .collect()
    }
}

impl Default for TunnelRegistry {
    fn default() -> Self {
        Self {
            configs: RwLock::new(HashMap::new()),
            connections: RwLock::new(HashMap::new()),
        }
    }
}

// ─── Token hashing helper ─────────────────────────────────────────────────────

/// Compute a SHA-256 hex digest of a pre-shared key.
pub fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate a random tunnel token (32 hex bytes = 256 bits).
pub fn generate_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
