pub mod cluster_forward;
pub mod crypto;
pub mod discovery;
pub mod election;
pub mod health;
pub mod node;
pub mod protocol;
pub mod sync;
#[cfg(test)]
mod test_support;
pub mod transport;

pub use cluster_forward::PendingForwards;
pub use node::{NodeState, PeerInfo, StorageMode};
pub use protocol::ClusterMessage;
pub use sync::{ApiForwardHandler, NoopRuleReloader};
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
    /// Data-plane rule reloader attached by the cluster↔engine wiring. When set,
    /// applied rule syncs notify the running `WafEngine`.
    rule_reloader: Option<Arc<dyn RuleReloader>>,
    /// Handler that executes forwarded API writes on the main node.
    api_forward_handler: Option<Arc<dyn ApiForwardHandler>>,
    /// Externally-constructed node state shared with the API layer / data plane.
    /// When `None`, [`ClusterNode::run`] builds its own (backward-compatible).
    node_state: Option<Arc<NodeState>>,
}

impl ClusterNode {
    /// Create a cluster node from configuration.
    pub fn new(config: ClusterConfig) -> Result<Self> {
        Ok(Self {
            config,
            rule_reloader: None,
            api_forward_handler: None,
            node_state: None,
        })
    }

    /// Attach a pre-built [`NodeState`] to run on.
    ///
    /// This lets the caller (`main.rs`) share the same `Arc<NodeState>` with the
    /// management API (`AppState.cluster_state`) and the data-plane engine (so
    /// admin writes can broadcast and synced rules can be consumed) instead of
    /// the node building a private state only it can see.
    #[must_use]
    pub fn with_node_state(mut self, node_state: Arc<NodeState>) -> Self {
        self.node_state = Some(node_state);
        self
    }

    /// Attach the data-plane rule reloader (the running `WafEngine`).
    ///
    /// Applied rule syncs land in the shared rule registry and then invoke this
    /// hook so the engine refreshes. Without it, syncs still update the registry
    /// but the engine is not notified.
    #[must_use]
    pub fn with_rule_reloader(mut self, reloader: Arc<dyn RuleReloader>) -> Self {
        self.rule_reloader = Some(reloader);
        self
    }

    /// Attach the handler that executes forwarded API writes on the main node.
    #[must_use]
    pub fn with_api_forward_handler(mut self, handler: Arc<dyn ApiForwardHandler>) -> Self {
        self.api_forward_handler = Some(handler);
        self
    }

    /// Start the cluster node: generate or load certificates, launch QUIC server,
    /// dial seed peers, and run the heartbeat and election loops.
    ///
    /// This function does not return under normal operation.
    pub async fn run(self) -> Result<()> {
        // M-17: refuse an unworkable crypto topology up front rather than
        // failing every mTLS handshake at runtime.
        validate_crypto_topology(&self.config)?;

        let listen_addr: SocketAddr = self.config.listen_addr.parse().context("invalid cluster listen_addr")?;

        // ── NodeState (resolves node_id before cert generation) ──────────────

        // Prefer the externally-shared node state (wired into the API + engine by
        // `main.rs`); otherwise build a private one for backward compatibility.
        let node_state = match self.node_state.clone() {
            Some(state) => state,
            None => Arc::new(
                NodeState::new(self.config.clone(), StorageMode::Full)
                    .context("failed to initialise cluster node state")?,
            ),
        };

        // ── Data-plane sync hooks (cluster↔engine wiring) ────────────────────
        if let Some(reloader) = &self.rule_reloader {
            node_state.attach_rule_reloader(Arc::clone(reloader));
        }
        if let Some(handler) = &self.api_forward_handler {
            node_state.attach_api_forward_handler(Arc::clone(handler));
        }

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

        // ── Election signing identity (H-12) ─────────────────────────────────
        // Built from the same certificate material the QUIC transport presents,
        // so a signed vote grant and an mTLS connection prove the same node.
        // Fail fast: without it this node can neither win nor accept an
        // election, which is far harder to diagnose at 03:00 than a startup
        // error naming the broken certificate.
        let identity = crate::crypto::vote::ClusterIdentity::new(&node_cert.cert_pem, &node_cert.key_pem, &ca_cert_der)
            .context("failed to build the cluster election signing identity from the node certificate")?;
        node_state.attach_cluster_identity(Arc::new(identity));

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

            // The JoinRequest is no longer queued here: `ClusterClient` sends it
            // on every (re)connection, so a node that drops its link — or that
            // never received the last ElectionResult (H-12) — re-learns the Main
            // identity instead of never joining again.

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

        // ── Re-join loop (re-learn the Main without forcing an election) ──────

        {
            let state_rejoin = Arc::clone(&node_state);
            tokio::spawn(async move {
                crate::discovery::run_rejoin_loop(state_rejoin, crate::discovery::REJOIN_INTERVAL_MS).await;
            });
        }

        // ── Election loop ────────────────────────────────────────────────────

        let state_election = Arc::clone(&node_state);
        tokio::spawn(async move {
            run_election_loop(state_election).await;
        });

        // ── Data-plane sync schedulers ───────────────────────────────────────
        // Worker rule-pull loop: periodically ask the Main for newer rules.
        {
            let state_pull = Arc::clone(&node_state);
            tokio::spawn(async move {
                crate::sync::run_rule_pull_loop(state_pull, crate::sync::SYNC_INTERVAL_MS).await;
            });
        }
        // Main config-broadcast loop: advertise the current config to peers.
        {
            let state_cfg = Arc::clone(&node_state);
            tokio::spawn(async move {
                crate::sync::run_config_broadcast_loop(state_cfg, crate::sync::SYNC_INTERVAL_MS).await;
            });
        }

        // ── QUIC server (blocks) ─────────────────────────────────────────────

        let server = ClusterServer::new(listen_addr, ca_cert_der, node_cert.cert_pem, node_cert.key_pem);

        server.serve(node_state).await
    }
}

/// Validate that the configured crypto topology can actually form a cluster (M-17).
///
/// With `crypto.auto_generate = true` every node mints its **own** self-signed
/// CA, so no two nodes share a trust anchor and mTLS to any seed can never
/// succeed. That combination silently prevents the cluster from ever forming.
/// We fail fast instead — while still allowing the common single-node bootstrap
/// (`auto_generate = true`, no seeds) to work out of the box.
fn validate_crypto_topology(config: &ClusterConfig) -> Result<()> {
    if config.crypto.auto_generate && !config.seeds.is_empty() {
        anyhow::bail!(
            "invalid cluster crypto topology: crypto.auto_generate=true with {} seed(s) configured. \
             Each auto-generating node creates its own CA, so mTLS to seeds will always fail. \
             Provision a shared CA + node certs and set auto_generate=false to join an existing \
             cluster, or leave seeds empty for a single-node bootstrap.",
            config.seeds.len()
        );
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn config(auto_generate: bool, seeds: &[&str]) -> ClusterConfig {
        let mut cfg = ClusterConfig::default();
        cfg.crypto.auto_generate = auto_generate;
        cfg.seeds = seeds.iter().map(|s| (*s).to_string()).collect();
        cfg
    }

    #[test]
    fn auto_generate_with_seeds_is_rejected() {
        let cfg = config(true, &["10.0.0.2:16851"]);
        assert!(
            validate_crypto_topology(&cfg).is_err(),
            "auto_generate + seeds must fail fast"
        );
    }

    #[test]
    fn single_node_auto_generate_is_allowed() {
        let cfg = config(true, &[]);
        assert!(validate_crypto_topology(&cfg).is_ok());
    }

    #[test]
    fn provisioned_certs_with_seeds_is_allowed() {
        let cfg = config(false, &["10.0.0.2:16851"]);
        assert!(validate_crypto_topology(&cfg).is_ok());
    }

    // ── IPv6 address surface ────────────────────────────────────────────────

    /// `listen_addr` goes through `SocketAddr::parse` (`lib.rs:100`), which is
    /// bracket-aware, so a v6 wildcard listener is expressible.
    #[test]
    fn cluster_listen_addr_accepts_ipv6_forms() {
        for s in ["[::]:16851", "[::1]:16851", "[2001:db8::1]:16851", "0.0.0.0:16851"] {
            let parsed: SocketAddr = s.parse().unwrap_or_else(|e| panic!("{s} must parse: {e}"));
            assert_eq!(parsed.to_string(), s, "{s} must round-trip through Display");
        }
        // Unbracketed v6 is correctly refused rather than silently mis-parsed.
        assert!("2001:db8::1:16851".parse::<SocketAddr>().is_err());
    }

    /// Seeds are resolved with `tokio::net::lookup_host`, which accepts a
    /// bracketed v6 literal as well as a hostname.
    #[tokio::test]
    async fn seed_resolution_accepts_bracketed_ipv6_literals() {
        assert_eq!(
            resolve_seed_addr("[2001:db8::1]:16851").await,
            Some("[2001:db8::1]:16851".parse().expect("v6 seed"))
        );
        assert_eq!(
            resolve_seed_addr("10.0.0.2:16851").await,
            Some("10.0.0.2:16851".parse().expect("v4 seed"))
        );
        // An unbracketed v6 literal is *resolver-dependent*: glibc's
        // `getaddrinfo` splits at the last colon and happens to accept
        // `2001:db8::1:16851`, other resolvers reject it. Do not assert which —
        // assert only that it can never resolve to some *other* address, so an
        // operator who omits the brackets is either served correctly or skipped
        // with a warning, never silently pointed somewhere else.
        if let Some(addr) = resolve_seed_addr("2001:db8::1:16851").await {
            assert_eq!(addr, "[2001:db8::1]:16851".parse().expect("v6 seed"));
        }
    }

    /// A peer address survives the round trip the cluster actually performs:
    /// `SocketAddr` → `String` (`transport/server.rs:504`, `discovery.rs:52`)
    /// → `parse` (`transport/client.rs:306`). `Display` brackets v6, so no
    /// hand-rolled `format!("{host}:{port}")` exists on this path to break it.
    #[test]
    fn peer_address_round_trips_through_the_wire_string() {
        for s in ["[2001:db8::1]:16851", "[::1]:16851", "10.0.0.2:16851"] {
            let addr: SocketAddr = s.parse().unwrap_or_else(|e| panic!("{s}: {e}"));
            let on_the_wire = addr.to_string();
            assert_eq!(
                on_the_wire.parse::<SocketAddr>().unwrap_or_else(|e| panic!("{s}: {e}")),
                addr
            );
        }
    }
}
