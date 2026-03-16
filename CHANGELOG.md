# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Version numbers follow [Semantic Versioning](https://semver.org/).

---

## [0.1.0-rc.1] — 2026-03-16

### Added

#### Cluster — Full QUIC mTLS mesh (P1–P5 complete)

- **waf-cluster crate**: New crate implementing the full cluster protocol.

- **P1 — Transport & Certificates**
  - QUIC mTLS server/client (`transport/server.rs`, `transport/client.rs`) using
    quinn 0.11 + rustls 0.23 + rcgen 0.13 — reusing patterns from `gateway/http3.rs`.
  - Ed25519 cluster CA generation via `rcgen` (`crypto/ca.rs`).
  - Per-node certificate signing (`crypto/node_cert.rs`).
  - AES-GCM CA key storage for encrypted replication to workers (`crypto/store.rs`).
  - HMAC-SHA256 join token generation and validation (`crypto/token.rs`).
  - Length-prefixed JSON frame codec over QUIC streams (`transport/frame.rs`).
  - Static seed discovery from `ClusterConfig.seeds` (`discovery.rs`).
  - Heartbeat sender (periodic) and heartbeat tracker per peer (`health/`).

- **P2 — Rule & Config Sync**
  - `RuleChangelog` ring buffer (500-entry VecDeque) on main for incremental sync.
  - Full rule snapshot: serialize `RuleRegistry` → lz4-compressed JSON.
  - Incremental sync: workers send `RuleSyncRequest { current_version }` and receive
    only changed entries since their last known version.
  - Config sync protocol (TOML string) over a dedicated stream.
  - Attack event batching on workers with periodic flush to main.
  - `StorageMode` enum: `Full` (DB available) / `ForwardOnly` (writes forwarded).
  - `PendingForwards` for in-flight API write forwarding from workers to main.

- **P3 — Raft-lite Election & Failover**
  - `ElectionManager`: in-memory Raft-lite state machine (term, vote, timeout).
  - Phi-accrual failure detector (Cassandra-style) per-peer (`health/detector.rs`).
  - Role transitions: `Worker → Candidate → Main` and `Main → Worker`.
  - Split-brain prevention: fencing tokens + quorum requirement (N/2+1 votes).
  - CA key replication: encrypted CA key distributed to workers in `JoinResponse`.
  - CLI subcommands: `status`, `nodes`, `token generate`, `promote`, `demote`, `remove`.
  - 20 cluster tests across election, heartbeat, mTLS, and sync scenarios.

- **P4 — Admin UI Cluster Panel**
  - REST API under `/api/cluster/*` (5 endpoints: status, nodes, node detail,
    token generate, node remove).
  - `AppState.cluster_state: Option<Arc<NodeState>>` (None = standalone mode).
  - Four Vue 3 + Tailwind cluster views: Overview, Node Detail, Tokens, Sync Status.
  - i18n keys for English, Chinese, Russian, and Georgian.

- **P5 — Integration Test & Docker (this release)**
  - `docker-compose.cluster.yml`: 3-node cluster (1 main + 2 workers) using
    the existing `Dockerfile.prebuilt` pattern. Nodes communicate on port 16851
    via an internal `cluster_net` Docker network.
  - `tests/e2e-cluster.sh`: end-to-end test script verifying:
    - All 3 nodes healthy
    - Rule created on main syncs to workers within 15s
    - Election completes after stopping the main (new main elected)
    - Node rejoin after restart
  - `configs/cluster-node-{a,b,c}.toml`: per-node configuration files for the
    3-node docker-compose setup.
  - `docs/cluster-guide.md`: quick-start guide, full configuration reference,
    certificate management, troubleshooting, and architecture notes.
  - `cluster cert-init` CLI command: generates cluster CA + per-node certs
    offline for pre-provisioned deployments (`prx-waf cluster cert-init --nodes
    node-a,node-b,node-c --output-dir /certs`).
  - `ClusterCryptoConfig.ca_key` field: path to the CA private key file (main
    node only; empty on workers).
  - `CertificateAuthority::from_cert_pem()`: load CA cert without private key
    (used by worker nodes that only need to verify peer certs, not sign new ones).
  - Hostname resolution for cluster seeds: seeds can now be specified as
    `hostname:port` (e.g., `"node-a:16851"`) instead of requiring IP addresses —
    critical for docker-compose DNS names.
  - `auto_generate = false` path in `ClusterNode::run()`: loads certificates from
    files instead of always generating ephemeral in-memory certs.

### Changed

- `waf-common::config::ClusterCryptoConfig`: added `ca_key` field (empty default —
  fully backward-compatible with existing configs).
- `waf-cluster::crypto::ca::CertificateAuthority::as_rcgen_issuer()`: now returns
  an error if called on a cert-only instance (constructed via `from_cert_pem`).
- `waf-cluster::ClusterNode::run()`: restructured to support both in-memory cert
  generation (`auto_generate = true`) and file-based loading (`auto_generate = false`).
  NodeState is now created before cert setup to resolve `node_id` first.
- Cluster seed parsing: migrated from `str::parse::<SocketAddr>()` to
  `tokio::net::lookup_host()` for DNS/hostname support.

### Architecture Notes

- All cluster inter-node traffic runs over QUIC (UDP port 16851) with mutual TLS.
- Workers maintain an in-memory `RuleRegistry` populated via cluster sync.
  No SQLite required — workers operate database-free if needed.
- The entire cluster feature adds exactly **one new workspace dependency**: `lz4_flex`
  (all other deps — quinn, rustls, rcgen — were already in the workspace).
- WASM plugins are not synced to worker nodes in v1 (documented limitation).
- Standalone mode (no `[cluster]` section) continues to work with zero behavior change.

---

## [0.0.x] — Prior Releases

Phase 1–7 internal development milestones. Cluster P1–P4 completed 2026-03-16.
