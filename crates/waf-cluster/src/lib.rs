pub mod cluster_forward;
pub mod crypto;
pub mod discovery;
pub mod election;
pub mod health;
pub mod node;
pub mod protocol;
pub mod sync;
pub mod transport;

pub use cluster_forward::PendingForwards;
pub use node::{NodeState, PeerInfo, StorageMode};
pub use protocol::ClusterMessage;
pub use waf_common::config::{ClusterConfig, NodeRole};
pub use waf_engine::RuleReloader;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::crypto::ca::CertificateAuthority;
use crate::crypto::node_cert::NodeCertificate;
use crate::election::run_election_loop;
use crate::health::{run_heartbeat_sender, run_peer_eviction};
use crate::transport::client::ClusterClient;
use crate::transport::server::ClusterServer;

/// Top-level cluster node handle.
///
/// Create with [`ClusterNode::new`] and then call [`ClusterNode::run`] inside a
/// dedicated tokio runtime (usually a background `std::thread`).
pub struct ClusterNode {
    config: ClusterConfig,
}

impl ClusterNode {
    /// Create a cluster node from configuration.
    pub const fn new(config: ClusterConfig) -> Result<Self> {
        Ok(Self { config })
    }

    /// Start the cluster node: generate or load certificates, launch QUIC server,
    /// dial seed peers, and run the heartbeat and election loops.
    ///
    /// This function does not return under normal operation.
    pub async fn run(self) -> Result<()> {
        let listen_addr: SocketAddr = self.config.listen_addr.parse().context("invalid cluster listen_addr")?;

        // ── NodeState (resolves node_id before cert generation) ──────────────

        let storage_mode = StorageMode::Full;
        let node_state = Arc::new(
            NodeState::new(self.config.clone(), storage_mode).context("failed to initialise cluster node state")?,
        );

        // ── Certificate setup ─────────────────────────────────────────────────

        let (ca_cert_der, node_cert) = if self.config.crypto.auto_generate {
            // Generate fresh CA and node certificate in-memory.
            let ca = CertificateAuthority::generate(self.config.crypto.ca_validity_days)
                .context("failed to generate cluster CA")?;
            let ca_cert_der = ca.cert_der().context("failed to DER-encode cluster CA")?;

            // Store CA private key in node state for replication to workers at join time.
            *node_state.ca_key_pem.lock() = Some(ca.key_pem().to_string());

            let node_cert = NodeCertificate::generate(&node_state.node_id, &ca, self.config.crypto.node_validity_days)
                .context("failed to generate node certificate")?;

            (ca_cert_der, node_cert)
        } else {
            // Load certificates from files (auto_generate = false).
            // This is the production path used with docker-compose or pre-provisioned certs.
            let ca_cert_path = &self.config.crypto.ca_cert;
            let ca_cert_pem = std::fs::read_to_string(ca_cert_path)
                .with_context(|| format!("failed to read CA cert from '{ca_cert_path}'"))?;
            let ca = CertificateAuthority::from_cert_pem(ca_cert_pem);
            let ca_cert_der = ca.cert_der().context("failed to DER-encode CA cert")?;

            // CA key is optional — only the main node has it.
            let ca_key_path = &self.config.crypto.ca_key;
            if !ca_key_path.is_empty() {
                match std::fs::read_to_string(ca_key_path) {
                    Ok(key_pem) => *node_state.ca_key_pem.lock() = Some(key_pem),
                    Err(e) => warn!(path = %ca_key_path, "CA key file not readable: {e}"),
                }
            }

            let node_cert_path = &self.config.crypto.node_cert;
            let node_cert_pem = std::fs::read_to_string(node_cert_path)
                .with_context(|| format!("failed to read node cert from '{node_cert_path}'"))?;
            let node_key_path = &self.config.crypto.node_key;
            let node_key_pem = std::fs::read_to_string(node_key_path)
                .with_context(|| format!("failed to read node key from '{node_key_path}'"))?;
            let node_cert = NodeCertificate::from_pem(node_cert_pem, node_key_pem);

            (ca_cert_der, node_cert)
        };

        info!(
            node_id = %node_state.node_id,
            listen = %listen_addr,
            "Cluster node starting"
        );

        // ── Dial seed peers ──────────────────────────────────────────────────

        let mut peer_senders: Vec<mpsc::Sender<ClusterMessage>> = Vec::with_capacity(self.config.seeds.len());

        for seed_str in &self.config.seeds {
            // Resolve hostname+port to SocketAddr (supports DNS names used in docker etc.)
            let Some(seed_addr) = resolve_seed_addr(seed_str).await else {
                continue;
            };

            if seed_addr == listen_addr {
                // Never dial ourselves.
                continue;
            }

            let (tx, rx) = mpsc::channel::<ClusterMessage>(256);

            // Register channel with NodeState so broadcast() reaches this peer.
            node_state.add_peer_channel(tx.clone());
            peer_senders.push(tx.clone());

            // Send JoinRequest as the initial handshake message
            let join_req = ClusterMessage::JoinRequest(crate::protocol::JoinRequest {
                token: String::new(),
                csr_pem: String::new(),
                node_info: crate::protocol::NodeInfo {
                    node_id: node_state.node_id.clone(),
                    hostname: node_state.node_id.clone(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    listen_addr: self.config.listen_addr.clone(),
                    capabilities: vec!["waf".to_string()],
                },
            });
            if let Err(e) = tx.try_send(join_req) {
                warn!(seed = %seed_str, "Failed to queue JoinRequest: {e}");
            }

            let client = ClusterClient::new(
                seed_addr,
                node_state.node_id.clone(),
                ca_cert_der.clone(),
                node_cert.cert_pem.clone(),
                node_cert.key_pem.clone(),
            );

            let state_clone = Arc::clone(&node_state);
            tokio::spawn(async move {
                if let Err(e) = client.run_with_reconnect(state_clone, rx).await {
                    tracing::error!("Cluster client for {seed_addr} failed: {e}");
                }
            });
        }

        // ── Heartbeat sender ─────────────────────────────────────────────────

        if !peer_senders.is_empty() {
            let state_hb = Arc::clone(&node_state);
            let interval_ms = self.config.election.heartbeat_interval_ms;
            tokio::spawn(async move {
                run_heartbeat_sender(state_hb, interval_ms, peer_senders).await;
            });
        }

        // ── Peer eviction (dead-peer cleanup) ─────────────────────────────────

        {
            let eviction_state = Arc::clone(&node_state);
            // Check 3x the heartbeat interval — gives peers enough time to respond
            // before being declared dead by the phi-accrual detector.
            let eviction_interval_ms = self.config.election.heartbeat_interval_ms.saturating_mul(3);
            tokio::spawn(async move {
                run_peer_eviction(eviction_state, eviction_interval_ms).await;
            });
        }

        // ── Election loop ────────────────────────────────────────────────────

        let state_election = Arc::clone(&node_state);
        tokio::spawn(async move {
            run_election_loop(state_election).await;
        });

        // ── QUIC server (blocks) ─────────────────────────────────────────────

        let server = ClusterServer::new(listen_addr, ca_cert_der, node_cert.cert_pem, node_cert.key_pem);

        server.serve(node_state).await
    }
}

/// Resolve a seed address string (hostname:port or ip:port) to a `SocketAddr`.
///
/// Returns `None` and logs a warning if resolution fails or yields no addresses.
async fn resolve_seed_addr(seed_str: &str) -> Option<SocketAddr> {
    match tokio::net::lookup_host(seed_str).await {
        Ok(mut addrs) => addrs.next().or_else(|| {
            warn!(addr = %seed_str, "Cluster seed resolved to no addresses; skipping");
            None
        }),
        Err(e) => {
            warn!(addr = %seed_str, error = %e, "Cannot resolve cluster seed address; skipping");
            None
        }
    }
}
