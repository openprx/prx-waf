# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Version numbers follow [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

Security hardening pass following a full-codebase audit (7 crates, ~27K LOC).
The headline fix is C-1: the core WAF detection pipeline was not running at
all for GET/bodyless requests. See "Breaking Changes" below before upgrading
— four conditions now refuse to start the process.

### Security

#### WAF detection engine

- **(C-1)** Fix WAF inspection never running on GET / bodyless requests: the
  per-request `request_ctx` was only ever built in `upstream_peer`, which
  Pingora invokes *after* `request_filter` — so `request_filter` always saw
  `None` and let every request without a body through with zero checks
  (SQLi/XSS/RCE/traversal, IP/URL blocklists, rate limiting, GeoIP all
  bypassed). Detection now runs during `request_filter`; a new
  `inspect_body` pass handles content-only checks, and empty-body POST/PUT
  requests are now inspected too (H-6).
- **(H-7)** Align the HTTP/3 request path with HTTP/1.1: unknown hosts no
  longer pass through unchecked, backend selection now honours per-host
  routing instead of a hardcoded loopback target, and request/response
  headers are no longer silently dropped.
- **(H-5, M-5)** Scan a curated set of request headers (User-Agent, Referer,
  X-Forwarded-For, etc.) for SQLi/XSS/RCE, closing a header-injection
  detection gap; unify directory-traversal detection to also cover
  body/cookies with recursive decoding.
- **(H-4)** Apply the configured CrowdSec AppSec `failure_action`
  (Block/Log/Allow) instead of always treating an unavailable AppSec
  backend as allow.
- Fail closed instead of open when a built-in detection `RegexSet` fails to
  compile, and when GeoIP cannot resolve a client's country while in
  allow-only mode (M-10).
- **(M-6)** Normalise the decoded path before matching URL blocklist entries
  and the custom-rule `Path` field, closing an encoded-path bypass
  (e.g. `/%61dmin`).
- **(M-7, M-8)** Honour the custom rule's configured `action`
  (Allow/Log/Block) instead of always blocking on match; precompile custom
  rule regexes once at load time instead of per request.
- **(M-9)** Fix connection-rate-limit counting each request-with-body twice
  (once at header phase, once at body phase), which had halved the
  effective rate limit for POST/PUT traffic.
- **(M-1)** Use the right-most (server-appended) `X-Forwarded-For` entry
  instead of the client-controlled left-most one.
- **(M-2)** Reject non-default ports on the bare-host routing fallback,
  closing a host/port routing ambiguity.
- **(M-19)** Deprecate the DNS-rebinding-vulnerable bare
  `validate_public_url` as a regression guard; production SSRF checks
  (webhooks, remote rule sources) already use the IP-pinned
  `validate_public_url_with_ips` variant.

#### Admin API

- **(H-2)** Add RBAC: a new `require_admin` middleware gates all
  write/sensitive routes. A logged-in but non-admin user can no longer
  delete hosts, issue cluster join tokens, upload WASM plugins, or change
  CrowdSec configuration.
- **(H-1)** Enforce JWT secret strength at startup: reject empty, short
  (<32 chars), known-placeholder, or low-entropy `JWT_SECRET` values.
- **(H-3)** Implement TOTP two-factor authentication end-to-end: RFC 6238
  codes verified over a ±1 time-step window with constant-time comparison
  and replay protection; two-step self-service enable/verify/disable flow
  so operators cannot lock themselves out.
- **(M-13)** Tighten CORS: an empty `cors_origins` no longer allows any
  origin — cross-origin requests are rejected by default.
- **(M-14)** Stop leaking internal/database error detail to API clients;
  return a generic message and log details server-side instead.
- **(M-15)** Enforce a global request body size limit and a 16 MiB cap on
  WASM plugin uploads.
- **(L-1)** Guard the login/logout/refresh endpoints with the admin IP
  allowlist (`/health` remains unguarded for liveness probes).
- Compare tunnel auth tokens in constant time; prefer the `Authorization`
  header over the `?token=` query parameter for tunnel WebSocket auth
  (query-parameter auth is now deprecated).

#### Cluster

- **(H-9)** Bind cluster protocol messages to the authenticated mTLS peer
  certificate, preventing a peer from forging another node's ID in
  heartbeats or election votes.
- **(H-10)** Validate the join token on the main node before accepting a
  `JoinRequest` (it was previously never checked in production); gate
  encrypted CA-key replication behind an explicit `replicate_ca_key`
  opt-in, default off.
- **(H-8)** Enforce a frame-size cap on the cluster transport to prevent an
  out-of-memory DoS from an oversized length-prefixed frame.
- **(M-16)** Use a fixed, configured `members` set for election quorum
  instead of the live (evictable) peer view, closing a split-brain window
  during network partitions.
- **(M-17)** Fail fast at startup when `crypto.auto_generate=true` is
  combined with a non-empty `seeds` list — that combination can never form
  a working cluster, since every node would mint its own untrusted CA.
- **(M-12)** Switch CA-key and encrypted-field-at-rest key derivation from
  unsalted single-round SHA-256 to Argon2id with a random per-blob salt
  (legacy blobs remain decryptable for migration); enforce a ≥16-character
  floor on `MASTER_KEY` and the CA passphrase.
- **(M-18)** Cap lz4 snapshot decompression at 256 MiB to prevent a
  decompression-bomb DoS.

#### Storage / SSRF

- **(M-11)** Fix CrowdSec configuration "upsert" silently inserting a new
  row instead of updating (the `ON CONFLICT` target never matched on the
  `SERIAL` primary key) — every configuration change had been a no-op, and
  reads always returned the oldest row.
- Confirmed production SSRF-guarded call sites (webhook delivery, remote
  rule fetching) already pin resolved IPs and reject redirects; hardened
  the bare validator as a regression guard only (see M-19 above).

### ⚠️ Breaking Changes

Startup now **refuses to boot** under any of the following conditions.
Update your configuration/environment before upgrading:

1. **`JWT_SECRET` is weak** — empty, shorter than 32 characters, or matches
   a known placeholder value.
2. **`trust_proxy_headers=true` with an empty `trusted_proxies`** — this
   previously only logged a warning and trusted `X-Forwarded-For` from any
   source.
3. **`cluster.crypto.auto_generate=true` combined with a non-empty
   `seeds`** — each node would mint its own untrusted CA and the cluster
   could never actually form; this is now a startup error instead of a
   silent hang.
4. **Multi-node clusters now require a configured `join_token`** — a
   `JoinRequest` without a valid token is rejected by the main node.

Also note:

- `MASTER_KEY` and the cluster CA `ca_passphrase` now require **at least 16
  characters**.
- The shipped `docker-compose.yml` / `docker-compose.cluster.yml` no longer
  ship a default `JWT_SECRET` — you must set one via `.env` (see the new
  `.env.example`) or the containers will fail to start.

### Added

- Migration `0009_totp_replay.sql` — adds `totp_last_step` for TOTP replay
  protection.
- Migration `0010_crowdsec_config_unique.sql` — de-duplicates existing
  CrowdSec config rows per scope and adds a functional unique index
  enforcing at most one row per host (or global).
- ACME auto-TLS wiring: new `AcmeConfig`
  (enabled/email/staging/renewal_check_interval_secs); `init_async` now
  constructs the `SslManager`, spawns the certificate-renewal task, and
  triggers one-time issuance for SSL hosts without an active certificate.
  The ACME HTTP-01 challenge path is now actually served.
- TOTP self-service endpoints: `POST /api/account/totp/{setup,verify,disable}`.
- `ClusterConfig.members`, `ClusterConfig.join_token`,
  `ClusterConfig.replicate_ca_key` configuration fields.
- `.env.example` documenting the `JWT_SECRET` requirement.

### Fixed

- CrowdSec configuration updates silently had no effect (M-11, see above).
- Custom rule `action` (Allow/Log/Block) was ignored — every match was
  treated as Block regardless of configuration.
- Connection-count rate limiting double-counted requests that had a body,
  halving the effective limit for POST/PUT traffic relative to GET.
- ACME certificate download could hang indefinitely on a slow/unresponsive
  CA; it now times out after 60s and marks the certificate as errored.

---

## [0.2.0] — 2026-03-27

### Security

- Eliminate 8 `panic!` calls in LazyLock regex initializers — replaced with
  `tracing::error!` + safe degradation (`RegexSet::empty()`) so a malformed
  compiled-in pattern never crashes the process.
- Add SSRF protection for Webhook and CrowdSec URLs with dual-mode validation
  (`url_validator.rs`): `validate_public_url()` resolves DNS and rejects RFC-1918
  / loopback / link-local / multicast addresses; `validate_scheme_only()` for
  contexts where DNS resolution is not yet available.
- Implement DNS rebinding guard using `resolve_to_addrs()` IP pinning — the
  resolved address set is cached and re-validated on each outbound connection to
  defeat time-of-check / time-of-use DNS rebinding attacks.
- Add iterative URL decoding (`url_decode_recursive`) to prevent double / triple
  encoding bypass of WAF rules (e.g., `%2527` → `%27` → `'`).
- Harden remote rule fetching: redirect following disabled, 30 s connect/read
  timeout enforced, response body capped at 10 MB.
- Add Admin API security middleware: IP allowlist enforcement, per-IP rate
  limiting, and strict security response headers (`X-Frame-Options`,
  `X-Content-Type-Options`, `Referrer-Policy`, `Content-Security-Policy`).
- Add login rate limiting (per-IP, configurable) and WebSocket upgrade IP
  allowlist to the Admin UI server.
- Fix cluster peer registration fencing: stale peer records are evicted before a
  new node with the same ID is accepted, preventing split-brain from rapid
  restart cycles.
- Fix XFF trusted-proxy CIDR validation: malformed CIDR strings in
  `trusted_proxies` now produce a config error at startup instead of a runtime
  panic.
- Fix rule deletion memory sync: rule removal now performs an atomic swap of the
  in-memory `RuleRegistry` so in-flight requests never observe a partially
  updated rule set.

### Added

- `detect_sqli` and `detect_xss` operators via the `libinjectionrs` pure-Rust
  crate — OWASP CRS core rules `CRS-942100` (SQL injection) and `CRS-941100`
  (XSS) are now fully evaluated at runtime instead of being silently skipped.
- Async `load_remote_sources()` method on `RuleRegistry` / `RemoteUrl` rule
  sources: remote rule sets are fetched in the background after startup so cold
  boot latency is unaffected.
- `url_validator` module (`waf-engine/src/security/url_validator.rs`) exposing
  `validate_public_url()` and `validate_scheme_only()`.
- `.cargo/audit.toml` policy file that suppresses known upstream transitive
  dependency advisories originating from the Pingora crate family (documented
  with justification comments).
- 116 new regression tests (suite total: 243) covering SSRF validation, encoding
  bypass, SQLi/XSS detection, cluster fencing, and dependency-upgrade
  compatibility.

### Changed

#### Dependency Upgrades

- **wasmtime**: 23.0.3 → 43.0.0 — resolves 5 published CVEs in the WASM
  runtime.
- **axum**: 0.7 → 0.8.8; **axum-extra**: 0.9 → 0.12 — aligns with the current
  stable axum ecosystem.
- **tower**: 0.4 → 0.5.3; **tower-http**: 0.5 → 0.6.8.
- **jsonwebtoken**: 9 → 10, switching to the `rust_crypto` backend to remove
  the OpenSSL dependency from the JWT path.
- **reqwest**: 0.12 → 0.13.
- **tokio-tungstenite**: 0.23 → 0.26.
- **toml**: 0.8 → 1.1.
- **serde_yaml**: deprecated 0.9 → **serde_yaml_ng** 0.10.
- **rustls-pemfile**: unmaintained crate replaced with the built-in PEM parser
  from **rustls-pki-types**.
- **sqlx**: set `default-features = false` to drop the unused `rsa` transitive
  dependency from the build graph.

### Fixed

- Remote URL rule sources were silently skipped in `load_all()` due to a missing
  async dispatch path — they are now loaded via `load_remote_sources()` after
  startup and on each scheduled refresh.
- OWASP CRS rules that use the `detect_sqli` / `detect_xss` operators were
  silently skipped because the operator was unregistered — the `libinjectionrs`
  integration now registers both operators at engine initialisation.
- Dead peer automatic eviction in cluster mode: peers that fail the phi-accrual
  threshold and do not reconnect within the configured grace period are now
  removed from the peer table and from the Admin UI node list.

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
