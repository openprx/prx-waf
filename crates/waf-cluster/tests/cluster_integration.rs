//! Integration tests: two-node QUIC mTLS cluster — connect and exchange heartbeats.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

/// Install the ring crypto provider once per process.
///
/// rustls 0.23 requires an explicit provider when multiple feature flags are
/// enabled (e.g., both `ring` and `aws-lc-rs` pulled in via transitive deps).
fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
use waf_cluster::{
    ClusterMessage, NodeState, StorageMode,
    crypto::{ca::CertificateAuthority, node_cert::NodeCertificate},
    node::PeerInfo,
    transport::{client::ClusterClient, server::ClusterServer},
};
use waf_common::config::{ClusterConfig, NodeRole};

/// Bind to a random available port on loopback and return its `SocketAddr`.
fn random_loopback_addr() -> SocketAddr {
    let listener = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind UDP");
    listener.local_addr().expect("local_addr")
}

/// Build a minimal `ClusterConfig` pointing to the given listen address.
fn minimal_config(listen_addr: SocketAddr) -> ClusterConfig {
    let mut cfg = ClusterConfig::default();
    cfg.enabled = true;
    cfg.listen_addr = listen_addr.to_string();
    cfg
}

/// Helper: build a `NodeState` with the given id and addr.
fn make_node_state(node_id: &str, config: ClusterConfig) -> Arc<NodeState> {
    let mut cfg = config;
    cfg.node_id = node_id.to_string();
    Arc::new(
        NodeState::new(cfg, StorageMode::Full)
            .expect("NodeState::new failed"),
    )
}

#[tokio::test]
async fn two_nodes_connect_and_exchange_heartbeat() {
    install_crypto_provider();

    // ── Addresses ──────────────────────────────────────────────────────────
    let server_addr = random_loopback_addr();
    let client_addr = random_loopback_addr();

    // ── Shared cluster CA ──────────────────────────────────────────────────
    let ca = CertificateAuthority::generate(365).expect("CA generate");
    let ca_cert_der = ca.cert_der().expect("CA DER");

    // ── Server node cert ───────────────────────────────────────────────────
    let server_cert =
        NodeCertificate::generate("integration-server", &ca, 1).expect("server cert");

    // ── Client node cert ───────────────────────────────────────────────────
    let client_cert =
        NodeCertificate::generate("integration-client", &ca, 1).expect("client cert");

    // ── Server state — pre-register client as known peer ──────────────────
    let server_state = make_node_state("integration-server", minimal_config(server_addr));
    {
        let mut peers = server_state.peers.write().await;
        peers.push(PeerInfo {
            node_id: "integration-client".to_string(),
            addr: client_addr,
            role: NodeRole::Worker,
            last_seen_ms: 0,
        });
    }

    // ── Start server ───────────────────────────────────────────────────────
    let server = ClusterServer::new(
        server_addr,
        ca_cert_der.clone(),
        server_cert.cert_pem.clone(),
        server_cert.key_pem.clone(),
    );

    let server_state_srv = Arc::clone(&server_state);
    tokio::spawn(async move {
        if let Err(e) = server.serve(server_state_srv).await {
            eprintln!("Server error: {e}");
        }
    });

    // Give the server a moment to start listening.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // ── Client state ───────────────────────────────────────────────────────
    let client_state = make_node_state("integration-client", minimal_config(client_addr));

    // ── Client channel: send a heartbeat ──────────────────────────────────
    let (tx, rx) = mpsc::channel::<ClusterMessage>(16);

    let client = ClusterClient::new(
        server_addr,
        "integration-client".to_string(),
        ca_cert_der,
        client_cert.cert_pem,
        client_cert.key_pem,
    );

    let client_state_for_task = Arc::clone(&client_state);
    tokio::spawn(async move {
        if let Err(e) = client.run_with_reconnect(client_state_for_task, rx).await {
            eprintln!("Client error: {e}");
        }
    });

    // ── Send a heartbeat from client ───────────────────────────────────────
    tokio::time::sleep(Duration::from_millis(80)).await;

    let hb = waf_cluster::protocol::Heartbeat {
        sequence: 1,
        timestamp_ms: 0,
        node_id: "integration-client".to_string(),
        role: NodeRole::Worker,
        uptime_secs: 0,
        cpu_percent: 0.0,
        memory_used_bytes: 0,
        total_requests: 0,
        blocked_requests: 0,
        rules_version: 0,
        config_version: 0,
    };

    tx.send(ClusterMessage::Heartbeat(hb))
        .await
        .expect("send heartbeat");

    // ── Verify server updated peer last_seen_ms ────────────────────────────
    tokio::time::sleep(Duration::from_millis(200)).await;

    let peers = server_state.peers.read().await;
    let client_peer = peers
        .iter()
        .find(|p| p.node_id == "integration-client")
        .expect("client peer not found in server state");

    assert!(
        client_peer.last_seen_ms > 0,
        "server should have recorded a heartbeat from the client (last_seen_ms={})",
        client_peer.last_seen_ms
    );
}

#[tokio::test]
async fn cert_generation_and_roundtrip() {
    let ca = CertificateAuthority::generate(365).expect("CA generate");
    assert!(!ca.cert_pem().is_empty());
    assert!(ca.cert_pem().starts_with("-----BEGIN CERTIFICATE-----"));
    let _der = ca.cert_der().expect("CA DER");

    let node_cert = NodeCertificate::generate("test-node", &ca, 1).expect("node cert");
    assert!(!node_cert.cert_pem.is_empty());
    assert!(!node_cert.key_pem.is_empty());

    let chain = node_cert.cert_chain_der().expect("cert chain DER");
    assert!(!chain.is_empty());
    node_cert.private_key_der().expect("private key DER");
}
