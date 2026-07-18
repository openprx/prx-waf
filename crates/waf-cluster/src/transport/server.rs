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
use rustls_pki_types::pem::PemObject as _;
use tracing::{debug, info, warn};

use crate::node::{NodeState, PeerInfo};
use crate::protocol::{ClusterMessage, ClusterState, ElectionVote, JoinResponse, NodeInfo};
use crate::transport::{frame, identity};

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
    pub const fn new(
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

        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(self.node_cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .context("failed to parse node cert PEM")?;

        let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_slice(self.node_key_pem.as_bytes())
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

        let endpoint =
            quinn::Endpoint::server(server_config, self.listen_addr).context("failed to bind QUIC cluster endpoint")?;

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
    pub const fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }
}

/// Handle a single authenticated peer connection.
async fn handle_peer_connection(conn: Connection, node_state: Arc<NodeState>) -> Result<()> {
    let peer = conn.remote_address();

    // H-9: bind this connection to the node_id proven by the peer's mTLS
    // certificate. Every message received on this connection is asserted against
    // this identity so a peer cannot impersonate another node.
    let auth_id = match identity::authenticated_node_id(&conn) {
        Ok(id) => id,
        Err(e) => {
            warn!(%peer, "Rejecting cluster peer with unreadable certificate identity: {e}");
            return Ok(());
        }
    };
    debug!(%peer, %auth_id, "Cluster peer connected");

    loop {
        match conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                let state = Arc::clone(&node_state);
                let auth_id = auth_id.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_stream(&mut send, &mut recv, state, &auth_id).await {
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
    auth_id: &str,
) -> Result<()> {
    loop {
        let msg: ClusterMessage = frame::read_frame(recv).await?;
        if let Some(response) = dispatch_message(msg, &node_state, auth_id).await {
            frame::write_frame(send, &response).await?;
        }
    }
}

/// Route an inbound cluster message to the appropriate handler.
///
/// `auth_id` is the node identity proven by the peer's mTLS certificate (H-9);
/// messages whose self-declared identity does not match it are dropped.
///
/// Returns `Some(response)` when the message requires a reply over the same stream.
async fn dispatch_message(msg: ClusterMessage, node_state: &NodeState, auth_id: &str) -> Option<ClusterMessage> {
    match msg {
        ClusterMessage::Heartbeat(hb) => {
            if hb.node_id != auth_id {
                warn!(
                    declared = %hb.node_id,
                    authenticated = %auth_id,
                    "Dropping heartbeat: node_id does not match peer certificate identity"
                );
                return None;
            }
            let now_ms = unix_ms();
            {
                let mut peers = node_state.peers.write().await;
                if let Some(peer) = peers.iter_mut().find(|p| p.node_id == hb.node_id) {
                    peer.last_seen_ms = now_ms;
                    peer.role = hb.role;
                } else {
                    // Auto-register unknown peer on first heartbeat
                    peers.push(PeerInfo {
                        node_id: hb.node_id.clone(),
                        addr: std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
                        role: hb.role,
                        last_seen_ms: now_ms,
                    });
                }
            }
            node_state.heartbeat_tracker.lock().record(&hb.node_id, now_ms);
            debug!(
                from = %hb.node_id,
                seq = hb.sequence,
                role = ?hb.role,
                "Heartbeat received"
            );
            None
        }

        ClusterMessage::JoinRequest(req) => {
            if req.node_info.node_id != auth_id {
                warn!(
                    declared = %req.node_info.node_id,
                    authenticated = %auth_id,
                    "Dropping JoinRequest: node_id does not match peer certificate identity"
                );
                return None;
            }
            debug!(from = %req.node_info.node_id, "JoinRequest received");

            // Snapshot the CA key once under a short-lived lock (never held across await).
            let ca_key_opt = node_state.ca_key_pem.lock().clone();

            // H-10: validate the join token against the cluster CA key BEFORE
            // accepting. Previously `validate_token` was never called on the
            // production path, so any peer could join. A node without the CA key
            // cannot validate tokens and therefore must not accept joins.
            let token_valid = ca_key_opt
                .as_deref()
                .is_some_and(|ca_key_pem| crate::crypto::token::validate_token(ca_key_pem, &req.token).is_ok());

            let cluster_state = build_cluster_state(node_state).await;

            if !token_valid {
                warn!(
                    from = %req.node_info.node_id,
                    "Rejecting JoinRequest: invalid or missing join token"
                );
                return Some(ClusterMessage::JoinResponse(JoinResponse {
                    accepted: false,
                    reason: Some("invalid or missing join token".to_string()),
                    node_cert_pem: String::new(),
                    ca_cert_pem: String::new(),
                    cluster_state,
                    encrypted_ca_key_b64: None,
                }));
            }

            // H-10: CA key replication is now double-gated — the token must be
            // valid (checked above) AND the operator must have explicitly opted
            // in via `replicate_ca_key`, and a passphrase must be configured.
            let ca_passphrase = node_state.config.crypto.ca_passphrase.clone();
            let encrypted_ca_key_b64 = if node_state.config.replicate_ca_key && !ca_passphrase.is_empty() {
                ca_key_opt.as_deref().and_then(|ca_key_pem| {
                    match crate::crypto::store::encrypt_blob(ca_key_pem.as_bytes(), &ca_passphrase) {
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

            info!(
                from = %req.node_info.node_id,
                ca_key_replicated = encrypted_ca_key_b64.is_some(),
                "Accepting JoinRequest"
            );

            // Register the joining peer in the cluster topology
            let peer_addr = req
                .node_info
                .listen_addr
                .parse()
                .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
            node_state
                .add_or_update_peer(PeerInfo {
                    node_id: req.node_info.node_id.clone(),
                    addr: peer_addr,
                    role: waf_common::config::NodeRole::Worker,
                    last_seen_ms: unix_ms(),
                })
                .await;

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
            // H-9: a vote request must be signed by the candidate itself.
            if vote.candidate_id != auth_id {
                warn!(
                    declared = %vote.candidate_id,
                    authenticated = %auth_id,
                    "Dropping vote request: candidate_id does not match peer certificate identity"
                );
                return None;
            }
            // Process a vote request from a candidate.
            match node_state.election.process_vote(&vote) {
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
            // H-9: only the winner itself may announce its own election result.
            if result.elected_id != auth_id {
                warn!(
                    declared = %result.elected_id,
                    authenticated = %auth_id,
                    "Dropping ElectionResult: elected_id does not match peer certificate identity"
                );
                return None;
            }
            debug!(
                elected = %result.elected_id,
                term = result.term,
                "ElectionResult received"
            );
            match node_state.election.process_result(&result) {
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

/// Build the current [`ClusterState`] snapshot advertised in a `JoinResponse`.
async fn build_cluster_state(node_state: &NodeState) -> ClusterState {
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
    ClusterState {
        main_node_id: node_state.node_id.clone(),
        nodes,
        rules_version,
        config_version,
        term: node_state.election.current_term_sync(),
    }
}

#[allow(clippy::cast_possible_truncation)]
fn unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::StorageMode;
    use crate::protocol::{ElectionVote, Heartbeat, JoinRequest};
    use waf_common::config::{ClusterConfig, ClusterCryptoConfig, NodeRole};

    fn node(id: &str) -> Arc<NodeState> {
        let cfg = ClusterConfig {
            node_id: id.to_string(),
            ..ClusterConfig::default()
        };
        Arc::new(NodeState::new(cfg, StorageMode::Full).expect("NodeState::new"))
    }

    /// A main node holding a CA key, plus a valid join token minted from it.
    fn main_node_with_token(replicate_ca_key: bool, ca_passphrase: &str) -> (Arc<NodeState>, String) {
        let cfg = ClusterConfig {
            node_id: "main".to_string(),
            replicate_ca_key,
            crypto: ClusterCryptoConfig {
                ca_passphrase: ca_passphrase.to_string(),
                ..ClusterCryptoConfig::default()
            },
            ..ClusterConfig::default()
        };
        let n = Arc::new(NodeState::new(cfg, StorageMode::Full).expect("NodeState::new"));
        let ca_key = "fake-ca-private-key-pem-material-for-tests";
        *n.ca_key_pem.lock() = Some(ca_key.to_string());
        let token = crate::crypto::token::generate_token(ca_key, 3_600_000).expect("generate_token");
        (n, token)
    }

    fn join_request(node_id: &str, token: &str) -> ClusterMessage {
        ClusterMessage::JoinRequest(JoinRequest {
            token: token.to_string(),
            csr_pem: String::new(),
            node_info: NodeInfo {
                node_id: node_id.to_string(),
                hostname: node_id.to_string(),
                version: "test".to_string(),
                listen_addr: "127.0.0.1:9000".to_string(),
                capabilities: vec!["waf".to_string()],
            },
        })
    }

    fn as_join_response(msg: Option<ClusterMessage>) -> JoinResponse {
        match msg {
            Some(ClusterMessage::JoinResponse(r)) => r,
            other => panic!("expected a JoinResponse, got {other:?}"),
        }
    }

    fn heartbeat(node_id: &str) -> ClusterMessage {
        ClusterMessage::Heartbeat(Heartbeat {
            sequence: 1,
            timestamp_ms: 0,
            node_id: node_id.to_string(),
            role: NodeRole::Worker,
            uptime_secs: 0,
            cpu_percent: 0.0,
            memory_used_bytes: 0,
            total_requests: 0,
            blocked_requests: 0,
            rules_version: 0,
            config_version: 0,
        })
    }

    #[tokio::test]
    async fn heartbeat_with_mismatched_identity_is_dropped() {
        let n = node("self");
        // Peer authenticated as "peer-P" but claims to be "victim".
        let resp = dispatch_message(heartbeat("victim"), &n, "peer-P").await;
        assert!(resp.is_none());
        let registered = { n.peers.read().await.iter().any(|p| p.node_id == "victim") };
        assert!(!registered, "forged heartbeat must not register a peer");
    }

    #[tokio::test]
    async fn heartbeat_with_matching_identity_is_recorded() {
        let n = node("self");
        let resp = dispatch_message(heartbeat("peer-P"), &n, "peer-P").await;
        assert!(resp.is_none());
        let registered = { n.peers.read().await.iter().any(|p| p.node_id == "peer-P") };
        assert!(registered, "authenticated heartbeat must register the peer");
    }

    #[tokio::test]
    async fn vote_request_with_forged_candidate_is_dropped() {
        let n = node("self");
        let forged = ClusterMessage::ElectionVote(ElectionVote {
            term: 1,
            candidate_id: "impersonated".to_string(),
            last_log_index: 0,
            voter_id: None,
        });
        // Authenticated as "peer-P" but claims candidacy for "impersonated".
        let resp = dispatch_message(forged, &n, "peer-P").await;
        assert!(resp.is_none(), "forged candidacy must not be granted a vote");
    }

    #[tokio::test]
    async fn vote_request_from_authenticated_candidate_is_granted() {
        let n = node("self");
        let genuine = ClusterMessage::ElectionVote(ElectionVote {
            term: 1,
            candidate_id: "peer-P".to_string(),
            last_log_index: 0,
            voter_id: None,
        });
        let resp = dispatch_message(genuine, &n, "peer-P").await;
        match resp {
            Some(ClusterMessage::ElectionVote(v)) => {
                assert_eq!(v.candidate_id, "peer-P");
                assert_eq!(v.voter_id.as_deref(), Some("self"));
            }
            other => panic!("expected a vote grant, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn election_result_with_forged_winner_is_dropped() {
        let n = node("self");
        let forged = ClusterMessage::ElectionResult(crate::protocol::ElectionResult {
            term: 5,
            elected_id: "usurper".to_string(),
            voter_ids: vec!["a".to_string(), "b".to_string()],
        });
        let resp = dispatch_message(forged, &n, "peer-P").await;
        assert!(resp.is_none());
        // Role must remain unchanged (not coerced by a forged result).
        assert_eq!(n.current_role().await, NodeRole::Worker);
    }

    #[tokio::test]
    async fn join_with_bad_token_is_rejected() {
        let (n, _valid) = main_node_with_token(true, "supersecret-passphrase-16");
        let resp = as_join_response(dispatch_message(join_request("worker-1", "garbage.token"), &n, "worker-1").await);
        assert!(!resp.accepted, "invalid token must be rejected");
        assert!(resp.encrypted_ca_key_b64.is_none(), "CA key must not leak on rejection");
        // The rejected worker must NOT be registered as a peer.
        let registered = { n.peers.read().await.iter().any(|p| p.node_id == "worker-1") };
        assert!(!registered, "rejected worker must not be registered");
    }

    #[tokio::test]
    async fn join_with_valid_token_is_accepted() {
        let (n, token) = main_node_with_token(false, "");
        let resp = as_join_response(dispatch_message(join_request("worker-1", &token), &n, "worker-1").await);
        assert!(resp.accepted, "valid token must be accepted");
    }

    #[tokio::test]
    async fn join_without_ca_key_cannot_validate_and_is_rejected() {
        // Node has no CA key → cannot validate any token → must reject.
        let n = node("worker-standalone");
        let resp = as_join_response(dispatch_message(join_request("worker-1", "any.token"), &n, "worker-1").await);
        assert!(!resp.accepted, "a node without a CA key cannot accept joins");
    }

    #[tokio::test]
    async fn ca_key_not_replicated_without_optin() {
        // Valid token + passphrase set, but replicate_ca_key = false.
        let (n, token) = main_node_with_token(false, "supersecret-passphrase-16");
        let resp = as_join_response(dispatch_message(join_request("worker-1", &token), &n, "worker-1").await);
        assert!(resp.accepted);
        assert!(
            resp.encrypted_ca_key_b64.is_none(),
            "CA key must not be replicated unless replicate_ca_key is enabled"
        );
    }

    #[tokio::test]
    async fn ca_key_replicated_when_enabled() {
        // Valid token + passphrase set + replicate_ca_key = true.
        let (n, token) = main_node_with_token(true, "supersecret-passphrase-16");
        let resp = as_join_response(dispatch_message(join_request("worker-1", &token), &n, "worker-1").await);
        assert!(resp.accepted);
        assert!(
            resp.encrypted_ca_key_b64.is_some(),
            "CA key should be replicated when explicitly enabled with a valid token"
        );
    }
}
