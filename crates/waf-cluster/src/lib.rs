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
use crate::health::run_heartbeat_sender;
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
    pub fn new(config: ClusterConfig) -> Result<Self> {
        Ok(Self { config })
    }

    /// Start the cluster node: generate certificates, launch QUIC server, dial
    /// seed peers, and run the heartbeat loop.
    ///
    /// This function does not return under normal operation.
    pub async fn run(self) -> Result<()> {
        let listen_addr: SocketAddr = self
            .config
            .listen_addr
            .parse()
            .context("invalid cluster listen_addr")?;

        // ── Certificate setup ──────────────────────────────────────────────

        // In P3 this will load from disk / join-handshake; for now always generate fresh.
        let ca = CertificateAuthority::generate(self.config.crypto.ca_validity_days)
            .context("failed to generate cluster CA")?;
        let ca_cert_der = ca.cert_der().context("failed to DER-encode cluster CA")?;

        // NodeState is created first so we use the auto-resolved node_id in the cert SAN.
        let storage_mode = StorageMode::Full;
        let node_state = Arc::new(
            NodeState::new(self.config.clone(), storage_mode)
                .context("failed to initialise cluster node state")?,
        );

        let node_cert = NodeCertificate::generate(
            &node_state.node_id,
            &ca,
            self.config.crypto.node_validity_days,
        )
        .context("failed to generate node certificate")?;

        info!(
            node_id = %node_state.node_id,
            listen = %listen_addr,
            "Cluster node starting"
        );

        // ── Dial seed peers ────────────────────────────────────────────────

        let mut peer_senders: Vec<mpsc::Sender<ClusterMessage>> =
            Vec::with_capacity(self.config.seeds.len());

        for seed_str in &self.config.seeds {
            let seed_addr: SocketAddr = match seed_str.parse() {
                Ok(a) => a,
                Err(e) => {
                    warn!(addr = %seed_str, "Invalid cluster seed address: {e}; skipping");
                    continue;
                }
            };

            if seed_addr == listen_addr {
                // Never dial ourselves.
                continue;
            }

            let (tx, rx) = mpsc::channel::<ClusterMessage>(256);
            peer_senders.push(tx);

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

        // ── Heartbeat sender ───────────────────────────────────────────────

        if !peer_senders.is_empty() {
            let state_hb = Arc::clone(&node_state);
            let interval_ms = self.config.election.heartbeat_interval_ms;
            tokio::spawn(async move {
                run_heartbeat_sender(state_hb, interval_ms, peer_senders).await;
            });
        }

        // ── QUIC server (blocks) ───────────────────────────────────────────

        let server = ClusterServer::new(
            listen_addr,
            ca_cert_der,
            node_cert.cert_pem,
            node_cert.key_pem,
        );

        server.serve(node_state).await
    }
}
