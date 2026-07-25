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
use crate::protocol::{ApiForwardResponse, ClusterMessage, ClusterState, ElectionVote, JoinResponse, NodeInfo};
use crate::transport::{apply_election_result, frame, identity};

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

            // N-M: only the Main may answer a join. A `JoinResponse` makes the
            // joiner record the responder as its authoritative Main (the
            // responder always names *itself* in `cluster_state.main_node_id`,
            // and the joiner's H-9 check — "declared main == peer certificate
            // identity" — is then satisfied by construction). Without this gate
            // any authenticated worker could answer a join and be adopted as
            // Main, after which its rule/config pushes pass the
            // `is_current_main` gate. Mirrors the `RuleSyncRequest` role check.
            if node_state.current_role().await != waf_common::config::NodeRole::Main {
                warn!(
                    from = %req.node_info.node_id,
                    "Rejecting JoinRequest: this node is not the cluster Main"
                );
                return Some(reject_join(node_state, crate::transport::JOIN_REJECT_NOT_MAIN).await);
            }

            // M-16: with a declared membership, only listed nodes may enrol.
            if !node_state.election.is_declared_member(auth_id) {
                warn!(
                    from = %req.node_info.node_id,
                    "Rejecting JoinRequest: node is not in the declared cluster membership"
                );
                return Some(reject_join(node_state, "node is not a declared cluster member").await);
            }

            // Snapshot the CA key once under a short-lived lock (never held across await).
            let ca_key_opt = node_state.ca_key_pem.lock().clone();

            // H-10 / AUD-L4: validate the join token against the cluster CA key
            // BEFORE accepting, then burn its nonce so it cannot be replayed by
            // a different node. A node without the CA key cannot validate tokens
            // and therefore must not accept joins.
            let token_check = ca_key_opt.as_deref().map_or_else(
                || Err(anyhow::anyhow!("no cluster CA key available to validate join tokens")),
                |ca_key_pem| {
                    let claims = crate::crypto::token::verify_token(ca_key_pem, &req.token, auth_id)?;
                    node_state.claim_join_token(&claims, auth_id)?;
                    Ok(())
                },
            );

            if let Err(e) = token_check {
                warn!(
                    from = %req.node_info.node_id,
                    "Rejecting JoinRequest: {e}"
                );
                return Some(reject_join(node_state, "invalid or missing join token").await);
            }

            let cluster_state = build_cluster_state(node_state).await;

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
                    // Grant — echo back with our node_id as voter, plus the
                    // signature that lets every node recount the ballot (H-12).
                    // Without a certificate identity we cannot produce one, and
                    // an unsigned grant is worthless to the candidate, so the
                    // echo is suppressed rather than sent unprovable.
                    let Some(grant) = node_state.election.sign_grant(vote.term, &vote.candidate_id) else {
                        warn!(
                            candidate = %vote.candidate_id,
                            term = vote.term,
                            "Cannot sign vote grant: no cluster certificate identity attached"
                        );
                        return None;
                    };
                    Some(ClusterMessage::ElectionVote(ElectionVote {
                        term: vote.term,
                        candidate_id: vote.candidate_id,
                        last_log_index: vote.last_log_index,
                        voter_id: Some(node_state.node_id.clone()),
                        grant: Some(grant),
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
            apply_election_result(node_state, auth_id, &result).await;
            None
        }

        // ── Data-plane sync ────────────────────────────────────────────────
        ClusterMessage::RuleSyncRequest(req) => {
            // Only the authoritative Main serves rules. A non-Main node dropping
            // the request avoids handing out a stale rule view; the worker will
            // retry and its response filter (H-9) would reject a non-Main answer
            // anyway.
            if node_state.current_role().await != waf_common::config::NodeRole::Main {
                debug!(%auth_id, "Ignoring RuleSyncRequest: this node is not the Main");
                return None;
            }
            let rules: Vec<waf_engine::Rule> = {
                let reg = node_state.rule_registry.read();
                reg.list().into_iter().cloned().collect()
            };
            let changelog = node_state.rule_changelog.lock().await;
            match crate::sync::rules::handle_sync_request(&changelog, &req, &rules) {
                Ok(response) => Some(ClusterMessage::RuleSyncResponse(response)),
                Err(e) => {
                    warn!("Failed to build rule sync response: {e}");
                    None
                }
            }
        }

        ClusterMessage::RuleSyncResponse(response) => {
            // A push arriving on the server recv path (full-mesh peer). Applied
            // only when the sender is the authenticated Main (H-9).
            crate::sync::apply_incoming_rule_sync(node_state, auth_id, response).await;
            None
        }

        ClusterMessage::ConfigSync(sync) => {
            crate::sync::apply_incoming_config_sync(node_state, auth_id, &sync).await;
            None
        }

        ClusterMessage::EventBatch(batch) => {
            // H-9: a worker may only report events under its own identity.
            if batch.node_id != auth_id {
                warn!(
                    declared = %batch.node_id,
                    authenticated = %auth_id,
                    "Dropping EventBatch: node_id does not match peer certificate identity"
                );
                return None;
            }
            debug!(from = %batch.node_id, count = batch.events.len(), "EventBatch received from worker");
            None
        }

        ClusterMessage::ApiForward(fwd) => {
            // Execute the forwarded write via the attached handler (main side)
            // and reply on the same stream. Without a handler the node cannot
            // service writes, so it returns a clear 503.
            let request_id = fwd.request_id.clone();
            let response = match node_state.api_forward_handler() {
                Some(handler) => handler.handle(fwd).await,
                None => ApiForwardResponse {
                    request_id,
                    status: 503,
                    body: b"cluster API forwarding is not configured on this node".to_vec(),
                },
            };
            Some(ClusterMessage::ApiForwardResponse(response))
        }

        ClusterMessage::ApiForwardResponse(response) => {
            node_state.pending_forwards.resolve(response).await;
            None
        }

        ClusterMessage::NodeLeave { node_id } => {
            // H-9: a node may only announce its own departure.
            if node_id != auth_id {
                warn!(
                    declared = %node_id,
                    authenticated = %auth_id,
                    "Dropping NodeLeave: node_id does not match peer certificate identity"
                );
                return None;
            }
            node_state.remove_peer(&node_id).await;
            None
        }

        // Datagram-only message; never expected on a reliable stream.
        ClusterMessage::StatsBatch(_) => None,

        // Client-side responses; never expected inbound on the server path.
        ClusterMessage::JoinResponse(_) => {
            debug!(%auth_id, "Ignoring unexpected JoinResponse on server recv path");
            None
        }
    }
}

/// Build a rejecting `JoinResponse` carrying `reason`.
///
/// Never leaks CA key material or a node certificate, whatever the reason.
async fn reject_join(node_state: &NodeState, reason: &str) -> ClusterMessage {
    ClusterMessage::JoinResponse(JoinResponse {
        accepted: false,
        reason: Some(reason.to_string()),
        node_cert_pem: String::new(),
        ca_cert_pem: String::new(),
        cluster_state: build_cluster_state(node_state).await,
        encrypted_ca_key_b64: None,
    })
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
    use crate::protocol::{ElectionVote, Heartbeat, JoinRequest, SignedGrant};
    use crate::test_support::TestPki;
    use waf_common::config::{ClusterConfig, ClusterCryptoConfig, NodeRole};

    fn node(id: &str) -> Arc<NodeState> {
        let cfg = ClusterConfig {
            node_id: id.to_string(),
            ..ClusterConfig::default()
        };
        Arc::new(NodeState::new(cfg, StorageMode::Full).expect("NodeState::new"))
    }

    /// A node wired to a signing identity minted under `pki`.
    fn node_with_identity(id: &str, pki: &TestPki) -> Arc<NodeState> {
        let n = node(id);
        n.attach_cluster_identity(pki.identity(id));
        n
    }

    /// A node with a declared membership and a signing identity.
    fn member_node(id: &str, members: &[&str], pki: &TestPki) -> Arc<NodeState> {
        let cfg = ClusterConfig {
            node_id: id.to_string(),
            members: members.iter().map(|s| (*s).to_string()).collect(),
            ..ClusterConfig::default()
        };
        let n = Arc::new(NodeState::new(cfg, StorageMode::Full).expect("NodeState::new"));
        n.attach_cluster_identity(pki.identity(id));
        n
    }

    const TEST_CA_KEY: &str = "fake-ca-private-key-pem-material-for-tests";

    /// A main node holding a CA key, plus a valid join token minted from it.
    fn main_node_with_token(replicate_ca_key: bool, ca_passphrase: &str) -> (Arc<NodeState>, String) {
        let cfg = ClusterConfig {
            node_id: "main".to_string(),
            role: "main".to_string(),
            replicate_ca_key,
            crypto: ClusterCryptoConfig {
                ca_passphrase: ca_passphrase.to_string(),
                ..ClusterCryptoConfig::default()
            },
            ..ClusterConfig::default()
        };
        let n = Arc::new(NodeState::new(cfg, StorageMode::Full).expect("NodeState::new"));
        *n.ca_key_pem.lock() = Some(TEST_CA_KEY.to_string());
        let token = crate::crypto::token::generate_token(TEST_CA_KEY, 3_600_000).expect("generate_token");
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
        let pki = TestPki::new();
        let n = node_with_identity("self", &pki);
        let forged = ClusterMessage::ElectionVote(ElectionVote {
            term: 1,
            candidate_id: "impersonated".to_string(),
            last_log_index: 0,
            voter_id: None,
            grant: None,
        });
        // Authenticated as "peer-P" but claims candidacy for "impersonated".
        let resp = dispatch_message(forged, &n, "peer-P").await;
        assert!(resp.is_none(), "forged candidacy must not be granted a vote");
    }

    #[tokio::test]
    async fn vote_request_from_authenticated_candidate_is_granted() {
        let pki = TestPki::new();
        let n = node_with_identity("self", &pki);
        let resp = dispatch_message(vote_request(1, "peer-P"), &n, "peer-P").await;
        match resp {
            Some(ClusterMessage::ElectionVote(v)) => {
                assert_eq!(v.candidate_id, "peer-P");
                assert_eq!(v.voter_id.as_deref(), Some("self"));
                let grant = v.grant.expect("a granted vote must carry its signature");
                // Anybody under the cluster CA can recount it — including the
                // candidate, which is exactly the point.
                let signer = pki
                    .identity("bystander")
                    .verify_grant(&grant, 1, "peer-P")
                    .expect("the grant must verify against the cluster CA");
                assert_eq!(signer, "self");
            }
            other => panic!("expected a vote grant, got {other:?}"),
        }
    }

    /// A node with no certificate identity cannot produce a provable grant, so
    /// it withholds the echo rather than send one nobody can count.
    #[tokio::test]
    async fn vote_grant_is_withheld_without_a_signing_identity() {
        let n = node("self");
        let resp = dispatch_message(vote_request(1, "peer-P"), &n, "peer-P").await;
        assert!(resp.is_none(), "an unsigned grant must not be sent");
    }

    #[tokio::test]
    async fn election_result_with_forged_winner_is_dropped() {
        let pki = TestPki::new();
        let n = node_with_identity("self", &pki);
        let forged = ClusterMessage::ElectionResult(crate::protocol::ElectionResult {
            term: 5,
            elected_id: "usurper".to_string(),
            grants: pki.grants(&["a", "b"], 5, "usurper"),
        });
        let resp = dispatch_message(forged, &n, "peer-P").await;
        assert!(resp.is_none());
        // Role must remain unchanged (not coerced by a forged result).
        assert_eq!(n.current_role().await, NodeRole::Worker);
    }

    // ── H-12: ElectionResult over the real dispatch path ─────────────────────

    fn vote_request(term: u64, candidate: &str) -> ClusterMessage {
        ClusterMessage::ElectionVote(ElectionVote {
            term,
            candidate_id: candidate.to_string(),
            last_log_index: 0,
            voter_id: None,
            grant: None,
        })
    }

    fn election_result(term: u64, elected: &str, grants: Vec<SignedGrant>) -> ClusterMessage {
        ClusterMessage::ElectionResult(crate::protocol::ElectionResult {
            term,
            elected_id: elected.to_string(),
            grants,
        })
    }

    /// **Attack ①** — an authenticated worker announces itself Main with an
    /// empty ballot and `u64::MAX`. It must not become the recorded Main (which
    /// is what would let its rule pushes through `is_current_main`), and it must
    /// not be able to pin the term.
    #[tokio::test]
    async fn self_declared_main_with_empty_ballot_is_not_adopted() {
        let pki = TestPki::new();
        let n = node_with_identity("victim", &pki);
        n.add_or_update_peer(PeerInfo {
            node_id: "usurper".to_string(),
            addr: std::net::SocketAddr::from(([127, 0, 0, 1], 1)),
            role: NodeRole::Worker,
            last_seen_ms: 0,
        })
        .await;

        let resp = dispatch_message(election_result(u64::MAX, "usurper", Vec::new()), &n, "usurper").await;
        assert!(resp.is_none());
        assert!(
            !n.is_current_main("usurper").await,
            "a self-declared winner must not be recorded as the authoritative Main"
        );
        assert_eq!(n.current_role().await, NodeRole::Worker);
        assert_eq!(
            n.election.current_term_sync(),
            0,
            "an unverifiable result must not advance the term"
        );
    }

    /// **Attack ①f (H-12 core)** — the usurper really did win our vote, and
    /// fabricates the rest of the ballot to reach a quorum it never had. This is
    /// exactly the minority-usurpation case the H-11 local-vote anchor could not
    /// stop: our own anchor holds, so only a recount of the *other* votes can
    /// refuse it.
    #[tokio::test]
    async fn minority_winner_cannot_fabricate_the_rest_of_the_quorum() {
        let pki = TestPki::new();
        let n = member_node("victim", &["victim", "n3", "n4", "n5", "usurper"], &pki);

        // We genuinely grant our vote to the usurper this term.
        let granted = dispatch_message(vote_request(1, "usurper"), &n, "usurper").await;
        let Some(ClusterMessage::ElectionVote(echo)) = granted else {
            panic!("the victim must grant its vote");
        };
        let real_grant = echo.grant.expect("our own grant");

        // Two real grants (the usurper's own and ours) plus three fabrications.
        // 3 of 5 would be a quorum; only the two real ones survive the recount.
        let forged_ballot = vec![
            pki.grant("usurper", 1, "usurper"),
            real_grant,
            // Valid certificate, signature taken from a different key.
            SignedGrant {
                cert_b64: pki.grant("n3", 1, "usurper").cert_b64,
                chain_b64: Vec::new(),
                signature_b64: pki.grant("n3", 1, "usurper").signature_b64,
            },
            // A grant the usurper collected in an earlier term, replayed here.
            pki.grant("n4", 0, "usurper"),
            // Pure garbage.
            SignedGrant {
                cert_b64: "not-a-certificate".to_string(),
                chain_b64: Vec::new(),
                signature_b64: "not-a-signature".to_string(),
            },
        ];
        dispatch_message(election_result(1, "usurper", forged_ballot), &n, "usurper").await;

        assert!(
            !n.is_current_main("usurper").await,
            "a minority winner must not be installed as Main by fabricating the rest of the ballot"
        );
        assert_eq!(n.current_role().await, NodeRole::Worker);
        assert_eq!(
            n.election.current_term_sync(),
            1,
            "the term we voted in stands; the forged result does not advance it further"
        );
    }

    /// The same attack, where the usurper's own grant is genuine but the
    /// remaining "voters" are certificates minted by a CA of its own.
    #[tokio::test]
    async fn ballot_padded_with_foreign_ca_grants_is_not_a_quorum() {
        let pki = TestPki::new();
        let foreign = TestPki::new();
        let n = member_node("victim", &["victim", "n3", "n4", "n5", "usurper"], &pki);

        let mut ballot = pki.grants(&["usurper"], 1, "usurper");
        ballot.extend(foreign.grants(&["victim", "n3", "n4"], 1, "usurper"));
        dispatch_message(election_result(1, "usurper", ballot), &n, "usurper").await;

        assert!(
            !n.is_current_main("usurper").await,
            "grants signed under a foreign CA must not count toward quorum"
        );
    }

    /// Duplicate entries for the same voter are counted once.
    #[tokio::test]
    async fn repeated_grants_from_one_voter_do_not_make_a_quorum() {
        let pki = TestPki::new();
        let n = member_node("victim", &["victim", "n3", "n4", "n5", "usurper"], &pki);

        let mut ballot = pki.grants(&["usurper"], 1, "usurper");
        // Four more grants, all from the same voter (fresh certificates, same SAN).
        for _ in 0..4 {
            ballot.push(pki.grant("n3", 1, "usurper"));
        }
        dispatch_message(election_result(1, "usurper", ballot), &n, "usurper").await;

        assert!(
            !n.is_current_main("usurper").await,
            "one voter stuffing the ballot must count as a single vote"
        );
    }

    /// Positive control: a real majority, signed, is adopted as Main over the
    /// same dispatch path — including by a node that voted for somebody else.
    #[tokio::test]
    async fn genuine_signed_quorum_is_adopted_as_main() {
        let pki = TestPki::new();
        let n = member_node("voter", &["voter", "winner", "n3"], &pki);

        let granted = dispatch_message(vote_request(1, "winner"), &n, "winner").await;
        assert!(granted.is_some());

        let ballot = pki.grants(&["winner", "voter"], 1, "winner");
        dispatch_message(election_result(1, "winner", ballot), &n, "winner").await;
        assert!(
            n.is_current_main("winner").await,
            "a verified quorum certificate installs the winner as the authoritative Main"
        );
        assert_eq!(n.current_role().await, NodeRole::Worker);
        assert_eq!(n.election.current_term_sync(), 1, "the winner's term is adopted");
    }

    /// Liveness case that H-11 could not serve: this node voted for the *losing*
    /// candidate, so it holds no supporting local evidence — yet the winner's
    /// quorum certificate is self-evident and is accepted.
    #[tokio::test]
    async fn node_that_voted_for_the_loser_still_accepts_the_winner() {
        let pki = TestPki::new();
        let n = member_node("voter", &["voter", "winner", "loser", "n4", "n5"], &pki);

        let granted = dispatch_message(vote_request(1, "loser"), &n, "loser").await;
        assert!(granted.is_some(), "our vote went to the losing candidate");

        // The winner carried n4 and n5: a 3-of-5 majority that does not include us.
        let ballot = pki.grants(&["winner", "n4", "n5"], 1, "winner");
        dispatch_message(election_result(1, "winner", ballot), &n, "winner").await;
        assert!(
            n.is_current_main("winner").await,
            "a node in the losing minority must still follow the proven winner"
        );
    }

    /// An incumbent Main keeps its role when an unprovable claim arrives: with
    /// verifiable ballots a real leader is always provable, so an unverifiable
    /// claim is simply false. This is what removes the deposition denial of
    /// service that the H-11 compensating step-down created.
    #[tokio::test]
    async fn incumbent_main_ignores_an_unverifiable_claim() {
        let (n, _token) = main_node_with_token(false, "");
        let pki = TestPki::new();
        n.attach_cluster_identity(pki.identity("main"));
        assert_eq!(n.current_role().await, NodeRole::Main);

        for _ in 0..3 {
            dispatch_message(
                election_result(7, "challenger", pki.grants(&["challenger"], 7, "challenger")),
                &n,
                "challenger",
            )
            .await;
        }

        assert_eq!(
            n.current_role().await,
            NodeRole::Main,
            "an unprovable claim must not be able to depose the real Main"
        );
        assert!(n.main_node_id().await.is_none());
        assert_eq!(
            n.election.current_term_sync(),
            0,
            "an unverifiable claim still does not move the term"
        );
    }

    /// A deposed Main does stand down once the challenger proves its quorum.
    #[tokio::test]
    async fn incumbent_main_stands_down_for_a_proven_winner() {
        let pki = TestPki::new();
        let cfg = ClusterConfig {
            node_id: "old-main".to_string(),
            role: "main".to_string(),
            members: ["old-main", "challenger", "n3"].into_iter().map(String::from).collect(),
            ..ClusterConfig::default()
        };
        let n = Arc::new(NodeState::new(cfg, StorageMode::Full).expect("NodeState::new"));
        n.attach_cluster_identity(pki.identity("old-main"));
        assert_eq!(n.current_role().await, NodeRole::Main);

        let ballot = pki.grants(&["challenger", "n3"], 4, "challenger");
        dispatch_message(election_result(4, "challenger", ballot), &n, "challenger").await;

        assert_eq!(n.current_role().await, NodeRole::Worker);
        assert!(n.is_current_main("challenger").await);
        assert_eq!(n.election.current_term_sync(), 4);
    }

    /// A worker is unaffected by an unprovable claim: it keeps its recorded Main.
    #[tokio::test]
    async fn worker_keeps_its_main_when_an_unverifiable_claim_arrives() {
        let pki = TestPki::new();
        let n = node_with_identity("worker-1", &pki);
        n.set_main_node_id("main-A".to_string()).await;
        dispatch_message(
            election_result(7, "challenger", pki.grants(&["challenger"], 7, "challenger")),
            &n,
            "challenger",
        )
        .await;
        assert_eq!(n.main_node_id().await.as_deref(), Some("main-A"));
        assert_eq!(n.current_role().await, NodeRole::Worker);
    }

    // ── N-M: only the Main may answer a join ─────────────────────────────────

    /// **Attack ②** — a non-Main node answering a `JoinRequest` would be adopted
    /// as Main by the joiner (its self-named `main_node_id` always matches its
    /// own certificate). It must refuse instead.
    #[tokio::test]
    async fn non_main_node_refuses_to_answer_a_join() {
        // Worker role, but it does hold a replicated CA key and a valid token.
        let cfg = ClusterConfig {
            node_id: "rogue-worker".to_string(),
            role: "worker".to_string(),
            replicate_ca_key: true,
            crypto: ClusterCryptoConfig {
                ca_passphrase: "supersecret-passphrase-16".to_string(),
                ..ClusterCryptoConfig::default()
            },
            ..ClusterConfig::default()
        };
        let n = Arc::new(NodeState::new(cfg, StorageMode::Full).expect("NodeState::new"));
        *n.ca_key_pem.lock() = Some(TEST_CA_KEY.to_string());
        let token = crate::crypto::token::generate_token(TEST_CA_KEY, 3_600_000).expect("token");

        let resp = as_join_response(dispatch_message(join_request("worker-2", &token), &n, "worker-2").await);
        assert!(!resp.accepted, "a non-Main node must not accept a join");
        assert_eq!(resp.reason.as_deref(), Some("responder is not the cluster main"));
        assert!(
            resp.encrypted_ca_key_b64.is_none(),
            "a non-Main node must not hand out CA key material"
        );
        let registered = { n.peers.read().await.iter().any(|p| p.node_id == "worker-2") };
        assert!(!registered);
    }

    /// A node that wins an election and becomes Main may then answer joins.
    #[tokio::test]
    async fn promoted_main_answers_joins() {
        let (n, token) = main_node_with_token(false, "");
        n.demote_to_worker().await;
        let rejected = as_join_response(dispatch_message(join_request("worker-1", &token), &n, "worker-1").await);
        assert!(!rejected.accepted, "still a worker → refuse");

        n.promote_to_main().await;
        let accepted = as_join_response(dispatch_message(join_request("worker-1", &token), &n, "worker-1").await);
        assert!(accepted.accepted, "after promotion the same join succeeds");
    }

    /// M-16: a node outside the declared membership cannot enrol.
    #[tokio::test]
    async fn join_from_undeclared_member_is_rejected() {
        let cfg = ClusterConfig {
            node_id: "main".to_string(),
            role: "main".to_string(),
            members: ["main", "worker-1"].into_iter().map(String::from).collect(),
            ..ClusterConfig::default()
        };
        let n = Arc::new(NodeState::new(cfg, StorageMode::Full).expect("NodeState::new"));
        *n.ca_key_pem.lock() = Some(TEST_CA_KEY.to_string());
        let token = crate::crypto::token::generate_token(TEST_CA_KEY, 3_600_000).expect("token");

        let resp = as_join_response(dispatch_message(join_request("stranger", &token), &n, "stranger").await);
        assert!(!resp.accepted);
        assert_eq!(resp.reason.as_deref(), Some("node is not a declared cluster member"));

        let ok = as_join_response(dispatch_message(join_request("worker-1", &token), &n, "worker-1").await);
        assert!(ok.accepted, "a declared member still joins");
    }

    // ── AUD-L4: join-token replay ────────────────────────────────────────────

    /// **Attack ③** — a token lifted from a worker's config is replayed by a
    /// second node inside the TTL. The first (legitimate) node may keep using
    /// it across restarts.
    #[tokio::test]
    async fn join_token_replay_by_another_node_is_rejected() {
        let (n, token) = main_node_with_token(false, "");

        let first = as_join_response(dispatch_message(join_request("worker-1", &token), &n, "worker-1").await);
        assert!(first.accepted, "first use of the token succeeds");

        let replay = as_join_response(dispatch_message(join_request("rogue-2", &token), &n, "rogue-2").await);
        assert!(!replay.accepted, "the same token must not enrol a second node");
        let registered = { n.peers.read().await.iter().any(|p| p.node_id == "rogue-2") };
        assert!(!registered, "the replaying node must not be registered");

        let restart = as_join_response(dispatch_message(join_request("worker-1", &token), &n, "worker-1").await);
        assert!(restart.accepted, "the original node may re-present its token");
    }

    /// A node-bound token is refused when presented by anybody else, even on
    /// its very first use.
    #[tokio::test]
    async fn node_bound_join_token_is_refused_for_another_node() {
        let (n, _wildcard) = main_node_with_token(false, "");
        let bound =
            crate::crypto::token::generate_token_for_node(TEST_CA_KEY, 3_600_000, "worker-1").expect("bound token");

        let wrong = as_join_response(dispatch_message(join_request("worker-2", &bound), &n, "worker-2").await);
        assert!(!wrong.accepted, "a token pinned to worker-1 must not admit worker-2");

        let right = as_join_response(dispatch_message(join_request("worker-1", &bound), &n, "worker-1").await);
        assert!(right.accepted, "the pinned node is admitted");
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
        // Main-role node, but no CA key → cannot validate any token → must reject.
        let cfg = ClusterConfig {
            node_id: "main-no-ca".to_string(),
            role: "main".to_string(),
            ..ClusterConfig::default()
        };
        let n = Arc::new(NodeState::new(cfg, StorageMode::Full).expect("NodeState::new"));
        assert!(n.ca_key_pem.lock().is_none());

        let resp = as_join_response(dispatch_message(join_request("worker-1", "any.token"), &n, "worker-1").await);
        assert!(!resp.accepted, "a node without a CA key cannot accept joins");
        assert_eq!(resp.reason.as_deref(), Some("invalid or missing join token"));
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
