//! QUIC mTLS dialer for outbound connections to cluster peers.
//!
//! Implements exponential back-off reconnection and bidirectional framed
//! JSON messaging over a long-lived QUIC control stream.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::crypto::ca::CLUSTER_SERVER_NAME;
use crate::node::NodeState;
use crate::protocol::ClusterMessage;
use crate::transport::frame;

/// Minimum reconnect back-off delay (ms).
const BACKOFF_MIN_MS: u64 = 500;
/// Maximum reconnect back-off delay (ms).
const BACKOFF_MAX_MS: u64 = 30_000;

/// QUIC mTLS client that maintains a persistent connection to one cluster peer.
///
/// Call [`ClusterClient::run_with_reconnect`] to start the client loop which
/// will reconnect automatically with exponential back-off on failure.
pub struct ClusterClient {
    peer_addr: SocketAddr,
    node_id: String,
    /// DER-encoded cluster CA cert — used as the only trust anchor
    ca_cert_der: CertificateDer<'static>,
    /// Node certificate chain (PEM) presented during TLS handshake
    node_cert_pem: String,
    /// Node private key (PEM) — never log
    node_key_pem: String,
}

impl ClusterClient {
    /// Create a new cluster client.
    pub fn new(
        peer_addr: SocketAddr,
        node_id: String,
        ca_cert_der: CertificateDer<'static>,
        node_cert_pem: String,
        node_key_pem: String,
    ) -> Self {
        Self {
            peer_addr,
            node_id,
            ca_cert_der,
            node_cert_pem,
            node_key_pem,
        }
    }

    /// Build the rustls `ClientConfig` with mTLS (client cert + CA root).
    fn build_tls_config(&self) -> Result<rustls::ClientConfig> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(self.ca_cert_der.clone())
            .context("failed to add cluster CA to client root store")?;

        let certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut self.node_cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .context("failed to parse node cert PEM")?;

        let key: PrivateKeyDer<'static> =
            rustls_pemfile::private_key(&mut self.node_key_pem.as_bytes())
                .context("failed to read node key PEM")?
                .context("no private key found in node key PEM")?;

        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(certs, key)
            .context("invalid node TLS certificate or key for client config")?;

        tls_config.alpn_protocols = vec![b"prx-cluster/1".to_vec()];

        Ok(tls_config)
    }

    /// Establish one QUIC connection to the peer and run the control stream loop.
    ///
    /// Returns `Ok(())` when the peer closes gracefully, or an error on failure.
    async fn connect_and_run(
        &self,
        node_state: &Arc<NodeState>,
        msg_rx: &mut mpsc::Receiver<ClusterMessage>,
    ) -> Result<()> {
        let tls_config = self.build_tls_config()?;
        let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .map_err(|e| anyhow::anyhow!("QUIC client TLS config error: {e:?}"))?;
        let client_config = quinn::ClientConfig::new(Arc::new(quic_config));

        let mut endpoint = quinn::Endpoint::client(
            "0.0.0.0:0".parse().context("failed to parse ephemeral bind addr")?,
        )
        .context("failed to bind QUIC client endpoint")?;
        endpoint.set_default_client_config(client_config);

        let conn = endpoint
            .connect(self.peer_addr, CLUSTER_SERVER_NAME)
            .context("QUIC connect initiation failed")?
            .await
            .context("QUIC connect to cluster peer failed")?;

        info!(
            peer = %self.peer_addr,
            node_id = %self.node_id,
            "Connected to cluster peer"
        );

        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .context("failed to open cluster control stream")?;

        let state = Arc::clone(node_state);
        tokio::select! {
            r = send_loop(&mut send, msg_rx) => r,
            r = recv_loop(&mut recv, &state) => r,
        }
    }

    /// Connect to the peer and reconnect on failure with exponential back-off.
    ///
    /// Runs until the process exits; call this inside a `tokio::spawn`.
    pub async fn run_with_reconnect(
        self,
        node_state: Arc<NodeState>,
        mut msg_rx: mpsc::Receiver<ClusterMessage>,
    ) -> Result<()> {
        let mut delay_ms = BACKOFF_MIN_MS;
        loop {
            match self.connect_and_run(&node_state, &mut msg_rx).await {
                Ok(()) => {
                    debug!(peer = %self.peer_addr, "Cluster peer closed cleanly; reconnecting");
                    delay_ms = BACKOFF_MIN_MS;
                }
                Err(e) => {
                    warn!(
                        peer = %self.peer_addr,
                        delay_ms,
                        "Cluster connection error: {e}; reconnecting"
                    );
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                    delay_ms = delay_ms.saturating_mul(2).min(BACKOFF_MAX_MS);
                }
            }
        }
    }

    /// Peer address this client dials.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

/// Write queued outbound messages to the control stream.
///
/// Returns `Ok(())` when `msg_rx` is closed (no more senders).
async fn send_loop(
    send: &mut quinn::SendStream,
    msg_rx: &mut mpsc::Receiver<ClusterMessage>,
) -> Result<()> {
    loop {
        match msg_rx.recv().await {
            Some(msg) => frame::write_frame(send, &msg)
                .await
                .context("failed to write cluster frame to peer")?,
            None => {
                debug!("Cluster outbound channel closed; send loop exiting");
                return Ok(());
            }
        }
    }
}

/// Read inbound messages from the control stream and dispatch them.
async fn recv_loop(recv: &mut quinn::RecvStream, node_state: &Arc<NodeState>) -> Result<()> {
    loop {
        let msg: ClusterMessage = frame::read_frame(recv)
            .await
            .context("failed to read cluster frame from peer")?;
        dispatch_incoming(msg, node_state).await;
    }
}

/// Route an inbound message received from a peer.
async fn dispatch_incoming(msg: ClusterMessage, node_state: &NodeState) {
    match msg {
        ClusterMessage::Heartbeat(hb) => {
            debug!(
                from = %hb.node_id,
                seq = hb.sequence,
                role = ?hb.role,
                "Inbound heartbeat from peer"
            );
            let now_ms = unix_ms();
            let mut peers = node_state.peers.write().await;
            if let Some(peer) = peers.iter_mut().find(|p| p.node_id == hb.node_id) {
                peer.last_seen_ms = now_ms;
            }
        }
        ClusterMessage::JoinResponse(resp) => {
            debug!(
                accepted = resp.accepted,
                "JoinResponse received (handled in P3)"
            );
        }
        ClusterMessage::ElectionVote(v) => {
            debug!(candidate = %v.candidate_id, term = v.term, "ElectionVote from peer");
        }
        ClusterMessage::ElectionResult(r) => {
            debug!(elected = %r.elected_id, term = r.term, "ElectionResult from peer");
        }
        other => {
            debug!(
                msg_type = ?std::mem::discriminant(&other),
                "Unhandled cluster message from peer"
            );
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
