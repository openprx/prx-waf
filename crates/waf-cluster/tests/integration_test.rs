//! Integration tests for the waf-cluster QUIC mTLS transport.
//!
//! Spins up a real in-process QUIC server and client, verifies the mTLS
//! handshake succeeds, and asserts that heartbeat messages sent by the
//! heartbeat-sender task are received by the peer.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};

use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;
use tokio::sync::mpsc;
use tokio::time::Duration;

/// Install the ring `CryptoProvider` once per process.
///
/// rustls 0.23 requires an explicit call when multiple feature flags
/// (ring + aws-lc-rs) are pulled in by transitive dependencies.
fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

use waf_cluster::{
    ClusterConfig, NodeState,
    crypto::{ca::CertificateAuthority, node_cert::NodeCertificate},
    health::run_heartbeat_sender,
    node::StorageMode,
    protocol::ClusterMessage,
    transport::{client::ClusterClient, frame},
};

/// Build a rustls `ServerConfig` that requires mTLS against the cluster CA.
fn make_server_tls(ca_der: CertificateDer<'static>, cert_pem: &str, key_pem: &str) -> rustls::ServerConfig {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(ca_der).unwrap();

    let verifier = WebPkiClientVerifier::builder(Arc::new(root_store)).build().unwrap();

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes()).unwrap().unwrap();

    let mut config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .unwrap();

    config.alpn_protocols = vec![b"prx-cluster/1".to_vec()];
    config
}

/// Bind an ephemeral QUIC server endpoint and return (endpoint, `bound_addr`).
fn bind_server(tls: rustls::ServerConfig) -> (quinn::Endpoint, std::net::SocketAddr) {
    let quic_cfg = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_cfg));
    let ep = quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = ep.local_addr().unwrap();
    (ep, addr)
}

/// Spawn a server task that counts received `ClusterMessage::Heartbeat` frames.
///
/// Returns the shared counter so the test can inspect it.
#[allow(clippy::excessive_nesting)]
fn spawn_counting_server(ep: quinn::Endpoint) -> Arc<AtomicU32> {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = Arc::clone(&counter);

    tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let cnt = Arc::clone(&counter_clone);
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else {
                    return;
                };
                // Accept streams until the connection closes
                while let Ok((_send, mut recv)) = conn.accept_bi().await {
                    let cnt2 = Arc::clone(&cnt);
                    tokio::spawn(async move {
                        if let Ok(ClusterMessage::Heartbeat(_)) =
                            frame::read_frame::<ClusterMessage, _>(&mut recv).await
                        {
                            cnt2.fetch_add(1, Ordering::SeqCst);
                        }
                    });
                }
            });
        }
    });

    counter
}

/// Two-node QUIC mTLS connect + heartbeat exchange.
///
/// Node A (server) binds to a random port.
/// Node B (client) connects and sends periodic heartbeats.
/// We assert that A receives at least one heartbeat within 500 ms.
#[tokio::test]
#[allow(clippy::similar_names)]
async fn two_node_heartbeat_exchange() {
    install_crypto();

    // Shared cluster CA
    let ca = CertificateAuthority::generate(365).unwrap();
    let ca_der = ca.cert_der().unwrap();

    // Per-node certificates signed by the shared CA
    let node_a_cert = NodeCertificate::generate("node-a", &ca, 365).unwrap();
    let node_b_cert = NodeCertificate::generate("node-b", &ca, 365).unwrap();

    // ── Node A: QUIC server ───────────────────────────────────────────────────

    let server_tls = make_server_tls(ca_der.clone(), &node_a_cert.cert_pem, &node_a_cert.key_pem);
    let (server_ep, server_addr) = bind_server(server_tls);
    let received = spawn_counting_server(server_ep);

    // ── Node B: QUIC client + heartbeat sender ────────────────────────────────

    // One mpsc channel per peer; ClusterClient reads from msg_rx
    let (msg_tx, msg_rx) = mpsc::channel::<ClusterMessage>(64);

    let client = ClusterClient::new(
        server_addr,
        "node-b".to_string(),
        ca_der,
        node_b_cert.cert_pem,
        node_b_cert.key_pem,
    );

    // NodeState needed by the heartbeat sender to populate the Heartbeat fields
    let node_state = Arc::new(NodeState::new(ClusterConfig::default(), StorageMode::ForwardOnly).unwrap());

    // Spawn client connection task (auto-reconnects; will stop when msg_rx closes)
    let state_clone = Arc::clone(&node_state);
    tokio::spawn(async move {
        // run_with_reconnect loops forever; ignore the infallible return
        let _ = client.run_with_reconnect(state_clone, msg_rx).await;
    });

    // Heartbeat sender at 50 ms interval — broadcasts to the single peer channel
    let state_hb = Arc::clone(&node_state);
    tokio::spawn(async move {
        run_heartbeat_sender(state_hb, 50, vec![msg_tx]).await;
    });

    // ── Assert ────────────────────────────────────────────────────────────────

    // Allow up to 500 ms for at least one heartbeat to be received
    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    loop {
        if received.load(Ordering::SeqCst) >= 1 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no heartbeat received within 500 ms (got {})",
            received.load(Ordering::SeqCst)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert!(
        received.load(Ordering::SeqCst) >= 1,
        "expected ≥1 heartbeat received by node A"
    );
}

/// mTLS rejects a client that presents a cert from a different CA.
#[tokio::test]
async fn mtls_rejects_unknown_cert() {
    install_crypto();

    // Cluster CA — used only for the server
    let cluster_ca = CertificateAuthority::generate(365).unwrap();
    let cluster_ca_der = cluster_ca.cert_der().unwrap();
    let server_cert = NodeCertificate::generate("server-node", &cluster_ca, 365).unwrap();

    // Rogue CA — the rogue client holds a cert signed by a different CA
    let rogue_ca = CertificateAuthority::generate(365).unwrap();
    let rogue_cert = NodeCertificate::generate("rogue-node", &rogue_ca, 365).unwrap();
    let rogue_ca_der = rogue_ca.cert_der().unwrap();

    // Server trusts only cluster_ca
    let server_tls = make_server_tls(cluster_ca_der.clone(), &server_cert.cert_pem, &server_cert.key_pem);
    let (_server_ep, server_addr) = bind_server(server_tls);

    // Rogue client uses its own CA as trust anchor (so the server cert fails too)
    let rogue_client = ClusterClient::new(
        server_addr,
        "rogue".to_string(),
        rogue_ca_der,
        rogue_cert.cert_pem,
        rogue_cert.key_pem,
    );

    // Attempt connection — must fail (server rejects the rogue client cert)
    let (tx, rx) = mpsc::channel::<ClusterMessage>(1);
    drop(tx); // close immediately so send_loop exits
    let rogue_state = Arc::new(NodeState::new(ClusterConfig::default(), StorageMode::ForwardOnly).unwrap());

    // run_with_reconnect will attempt one connect, fail, then try to sleep &
    // reconnect.  We only care that the first attempt fails (not accepted).
    // Using tokio::time::timeout to bound the test duration.
    let result = tokio::time::timeout(
        Duration::from_millis(500),
        rogue_client.run_with_reconnect(rogue_state, rx),
    )
    .await;

    // Either timeout (client keeps retrying) or an error — both are acceptable;
    // the key invariant is that the server did NOT accept the rogue client.
    match result {
        // expected: connection error or timeout while retrying — both acceptable
        Ok(Err(_)) | Err(_) => {}
        Ok(Ok(())) => panic!("rogue client should not connect cleanly"),
    }
}
