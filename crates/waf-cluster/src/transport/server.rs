//! QUIC mTLS listener for cluster communication.
//!
//! Reuses the same quinn + rustls pattern from gateway/http3.rs, with the
//! addition of `WebPkiClientVerifier` to require and verify peer certificates
//! against the cluster CA.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::Engine as _;
use quinn::Connection;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use tracing::{debug, info, warn};

use crate::node::NodeState;
use crate::protocol::{ClusterMessage, ClusterState, ElectionVote, JoinResponse, NodeInfo};
use crate::transport::frame;

/// QUIC mTLS server for cluster communication.
pub struct ClusterServer {
    listen_addr: SocketAddr,
    /// DER-encoded cluster CA certificate (added to client verifier root store)
    ca_cert_der: CertificateDer<'static>,
    /// Node certificate chain (PEM) presented to connecting peers
    node_cert_pem: String,
    /// Node private key (PEM) — never log
    node_key_pem: String,
}

impl ClusterServer {
    /// Create a new cluster server.
    pub fn new(
        listen_addr: SocketAddr,
        ca_cert_der: CertificateDer<'static>,
        node_cert_pem: String,
        node_key_pem: String,
    ) -> Self {
        Self {
            listen_addr,
            ca_cert_der,
            node_cert_pem,
            node_key_pem,
        }
    }

    /// Build the rustls `ServerConfig` with mTLS client cert verification.
    fn build_tls_config(&self) -> Result<rustls::ServerConfig> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(self.ca_cert_der.clone())
            .context("failed to add CA cert to root store")?;

        let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .context("failed to build client cert verifier")?;

        let certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut self.node_cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .context("failed to parse node cert PEM")?;

        let key: PrivateKeyDer<'static> =
            rustls_pemfile::private_key(&mut self.node_key_pem.as_bytes())
                .context("failed to read node key PEM")?
                .context("no private key found in node key PEM")?;

        let mut tls_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(certs, key)
            .context("invalid node TLS certificate or key")?;

        tls_config.alpn_protocols = vec![b"prx-cluster/1".to_vec()];

        Ok(tls_config)
    }

    /// Start accepting inbound QUIC connections from peer nodes.
    ///
    /// Runs forever; returns only on fatal error.
    pub async fn serve(self, node_state: Arc<NodeState>) -> Result<()> {
        let tls_config = self.build_tls_config()?;
        let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .map_err(|e| anyhow::anyhow!("QUIC server TLS config error: {e:?}"))?;
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));

        let endpoint = quinn::Endpoint::server(server_config, self.listen_addr)
            .context("failed to bind QUIC cluster endpoint")?;

        info!(addr = %self.listen_addr, "Cluster QUIC mTLS server listening");

        while let Some(incoming) = endpoint.accept().await {
            let state = Arc::clone(&node_state);
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        if let Err(e) = handle_peer_connection(conn, state).await {
                            warn!("Cluster peer connection error: {e}");
                        }
                    }
                    Err(e) => warn!("QUIC cluster accept error: {e}"),
                }
            });
        }

        Ok(())
    }

    /// Returns the configured listen address.
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }
}

/// Handle a single authenticated peer connection.
async fn handle_peer_connection(conn: Connection, node_state: Arc<NodeState>) -> Result<()> {
    let peer = conn.remote_address();
    debug!(%peer, "Cluster peer connected");

    loop {
        match conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                let state = Arc::clone(&node_state);
                tokio::spawn(async move {
                    if let Err(e) = handle_stream(&mut send, &mut recv, state).await {
                        debug!("Cluster stream closed: {e}");
                    }
                });
            }
            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                debug!(%peer, "Cluster peer disconnected gracefully");
                break;
            }
            Err(e) => {
                debug!(%peer, "Cluster connection error: {e}");
                break;
            }
        }
    }

    Ok(())
}

/// Read and process messages from a single bidirectional stream.
///
/// Writes a response frame back through `send` when `dispatch_message` returns `Some`.
async fn handle_stream(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    node_state: Arc<NodeState>,
) -> Result<()> {
    loop {
        let msg: ClusterMessage = frame::read_frame(recv).await?;
        if let Some(response) = dispatch_message(msg, &node_state).await {
            frame::write_frame(send, &response).await?;
        }
    }
}

/// Route an inbound cluster message to the appropriate handler.
///
/// Returns `Some(response)` when the message requires a reply over the same stream.
async fn dispatch_message(msg: ClusterMessage, node_state: &NodeState) -> Option<ClusterMessage> {
    match msg {
        ClusterMessage::Heartbeat(hb) => {
            let now_ms = unix_ms();
            {
                let mut peers = node_state.peers.write().await;
                if let Some(peer) = peers.iter_mut().find(|p| p.node_id == hb.node_id) {
                    peer.last_seen_ms = now_ms;
                }
            }
            node_state
                .heartbeat_tracker
                .lock()
                .record(&hb.node_id, now_ms);
            debug!(
                from = %hb.node_id,
                seq = hb.sequence,
                role = ?hb.role,
                "Heartbeat received"
            );
            None
        }

        ClusterMessage::JoinRequest(req) => {
            debug!(from = %req.node_info.node_id, "JoinRequest received");

            // Encrypt CA key for worker failover if passphrase is configured.
            // Clone under a short-lived parking_lot lock — no await held while locked.
            let ca_passphrase = node_state.config.crypto.ca_passphrase.clone();
            let encrypted_ca_key_b64 = if !ca_passphrase.is_empty() {
                let ca_key_opt = node_state.ca_key_pem.lock().clone();
                ca_key_opt.and_then(|ca_key_pem| {
                    match crate::crypto::store::encrypt_blob(ca_key_pem.as_bytes(), &ca_passphrase)
                    {
                        Ok(enc) => Some(base64::engine::general_purpose::STANDARD.encode(&enc)),
                        Err(e) => {
                            warn!("Failed to encrypt CA key for JoinResponse: {e}");
                            None
                        }
                    }
                })
            } else {
                None
            };

            let rules_version = *node_state.rules_version.read().await;
            let config_version = *node_state.config_version.read().await;
            let nodes: Vec<NodeInfo> = {
                let peers = node_state.peers.read().await;
                peers
                    .iter()
                    .map(|p| NodeInfo {
                        node_id: p.node_id.clone(),
                        hostname: p.node_id.clone(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        listen_addr: p.addr.to_string(),
                        capabilities: vec!["waf".to_string()],
                    })
                    .collect()
            };

            let cluster_state = ClusterState {
                main_node_id: node_state.node_id.clone(),
                nodes,
                rules_version,
                config_version,
                term: node_state.election.current_term_sync(),
            };

            info!(
                from = %req.node_info.node_id,
                ca_key_replicated = encrypted_ca_key_b64.is_some(),
                "Accepting JoinRequest"
            );

            Some(ClusterMessage::JoinResponse(JoinResponse {
                accepted: true,
                reason: None,
                // Full CSR signing is handled in a future phase.
                node_cert_pem: String::new(),
                ca_cert_pem: String::new(),
                cluster_state,
                encrypted_ca_key_b64,
            }))
        }

        ClusterMessage::ElectionVote(vote) => {
            if vote.voter_id.is_some() {
                // Vote-grant echoes should only arrive on the client recv path.
                debug!(
                    candidate = %vote.candidate_id,
                    "Ignoring unexpected vote-grant on server recv path"
                );
                return None;
            }
            // Process a vote request from a candidate.
            match node_state.election.process_vote(&vote).await {
                Ok(true) => {
                    // Grant — echo back with our node_id as voter.
                    Some(ClusterMessage::ElectionVote(ElectionVote {
                        term: vote.term,
                        candidate_id: vote.candidate_id,
                        last_log_index: vote.last_log_index,
                        voter_id: Some(node_state.node_id.clone()),
                    }))
                }
                Ok(false) => None,
                Err(e) => {
                    warn!("process_vote error: {e}");
                    None
                }
            }
        }

        ClusterMessage::ElectionResult(result) => {
            debug!(
                elected = %result.elected_id,
                term = result.term,
                "ElectionResult received"
            );
            match node_state.election.process_result(&result).await {
                Ok(new_role) => node_state.transition_to(new_role).await,
                Err(e) => warn!("process_result error: {e}"),
            }
            None
        }

        other => {
            debug!(
                msg_type = ?std::mem::discriminant(&other),
                "Unhandled cluster message"
            );
            None
        }
    }
}

fn unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
