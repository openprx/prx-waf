# PRX-WAF Cluster Guide

## Overview

PRX-WAF clustering enables multiple WAF instances to form a self-organizing mesh
network. Nodes communicate over **QUIC** (TLS 1.3 mTLS) on port 16851.

```
Node A (Main) ◄───► Node B (Worker)
     ▲                     ▲
     └───────────────► Node C (Worker)
```

One node is elected **Main** and serves as the control plane:
- Holds the PostgreSQL database connection
- Distributes rules to all workers
- Aggregates attack logs from workers

**Workers** are data-plane nodes:
- Maintain in-memory rule cache (synced from main)
- Process traffic independently
- Forward write operations to main

---

## Quick Start (3-Node Docker Cluster)

### Prerequisites

- Docker Compose / Podman Compose v1.3+
- Rust toolchain (for building the binary)

### 1. Build the binary

```bash
~/.cargo/bin/cargo build --release
```

### 2. Generate cluster certificates

Certificates are generated once and shared across all nodes via a Docker volume.

```bash
# With podman-compose
podman-compose -f docker-compose.cluster.yml run --rm cluster-init

# With docker compose
docker compose -f docker-compose.cluster.yml run --rm cluster-init
```

Output:
```
Generated cluster CA:
  Cert: /certs/cluster-ca.pem
  Key:  /certs/cluster-ca.key (keep this secret)

  Node 'node-a':
    Cert: /certs/node-a.pem
    Key:  /certs/node-a.key
  Node 'node-b':
    ...
  Node 'node-c':
    ...
```

### 3. Start the cluster

```bash
podman-compose -f docker-compose.cluster.yml up -d
```

### 4. Verify the cluster is healthy

```bash
# All 3 nodes should respond
curl -s http://localhost:16827/health    # node-a (main)
curl -s http://localhost:16828/health    # node-b (worker)
curl -s http://localhost:16829/health    # node-c (worker)

# Check cluster topology
curl -s http://localhost:16827/api/cluster/status | python3 -m json.tool
```

### 5. Access the Admin UI

Open http://localhost:16827/ui/ in your browser.

Default credentials: `admin` / `admin123`

The Cluster section (sidebar) shows:
- Node topology and health
- Current main node and election term
- Rule sync status per worker
- Join token management

### 6. Run the end-to-end test

```bash
./tests/e2e-cluster.sh
```

---

## Configuration Reference

### Minimal cluster config (Main node)

```toml
[cluster]
enabled     = true
node_id     = "node-a"           # unique per node; auto-generated if empty
role        = "main"             # "main" | "worker" | "auto"
listen_addr = "0.0.0.0:16851"
seeds       = []                 # main needs no seeds

[cluster.crypto]
ca_cert       = "/certs/cluster-ca.pem"
ca_key        = "/certs/cluster-ca.key"   # only main node needs the CA key
node_cert     = "/certs/node-a.pem"
node_key      = "/certs/node-a.key"
auto_generate = false
```

### Minimal cluster config (Worker node)

```toml
[cluster]
enabled     = true
node_id     = "node-b"
role        = "worker"
listen_addr = "0.0.0.0:16851"
seeds       = ["node-a:16851"]   # or IP: ["10.0.0.1:16851"]

[cluster.crypto]
ca_cert       = "/certs/cluster-ca.pem"
ca_key        = ""               # workers do NOT need the CA key
node_cert     = "/certs/node-b.pem"
node_key      = "/certs/node-b.key"
auto_generate = false
```

### Auto-generate mode (development / single-node testing)

Set `auto_generate = true` to have each node generate its own in-memory CA and
node certificate. This is only useful for development and testing where all nodes
run in the same process or share a test CA.

```toml
[cluster.crypto]
auto_generate = true    # generates ephemeral CA + node cert on every start
```

> **Note:** With `auto_generate = true`, each node generates a *different* CA, so
> mTLS between nodes will fail unless they share a CA via a shared volume or
> a proper certificate provisioning step.

### Full configuration reference

```toml
[cluster]
# Enable clustering. Default: false — zero behavior change for standalone.
enabled = true

# Unique node identifier. Auto-generated from random suffix if empty.
node_id = ""

# Role: "auto" | "main" | "worker"
# "auto" — starts as Worker and participates in Raft-lite election.
role = "auto"

# QUIC listen address for inter-node communication.
listen_addr = "0.0.0.0:16851"

# Static seed nodes. At least one reachable seed required to join.
# Supports both IP addresses and hostnames (DNS resolution is attempted).
seeds = ["10.0.0.1:16851"]

[cluster.crypto]
ca_cert              = "/app/certs/cluster-ca.pem"
ca_key               = ""             # path to CA key (main only); empty = no CA key
node_cert            = "/app/certs/node.pem"
node_key             = "/app/certs/node.key"
auto_generate        = true           # generate certs in-memory on startup
ca_validity_days     = 3650           # 10 years
node_validity_days   = 365            # 1 year
renewal_before_days  = 7              # auto-renew node cert 7 days before expiry
# ca_passphrase is used to encrypt the CA key when replicating to workers
# for failover. Leave empty to disable CA key replication.
ca_passphrase        = ""

[cluster.sync]
rules_interval_secs        = 10     # periodic rule version check
config_interval_secs       = 30
events_batch_size          = 100    # flush event batch at this count
events_flush_interval_secs = 5      # flush even if batch not full
stats_interval_secs        = 10
events_queue_size          = 10000  # drop oldest if worker falls behind

[cluster.election]
timeout_min_ms        = 150   # random election timeout (ms)
timeout_max_ms        = 300
heartbeat_interval_ms = 50    # main → workers heartbeat interval
phi_suspect           = 8.0   # phi-accrual: suspect threshold
phi_dead              = 12.0  # phi-accrual: dead threshold → trigger election

[cluster.health]
check_interval_secs   = 5
max_missed_heartbeats = 3
```

---

## Certificate Management

### Generating certificates for a new cluster

Use the built-in `cert-init` command:

```bash
# Generate CA + 3 node certs
prx-waf cluster cert-init \
    --nodes node-a,node-b,node-c \
    --output-dir /opt/prx-waf/certs \
    --ca-validity-days 3650 \
    --node-validity-days 365
```

Files created:
| File | Purpose | Distribute to |
|------|---------|---------------|
| `cluster-ca.pem` | CA certificate | All nodes (read-only) |
| `cluster-ca.key` | CA private key | Main node only (keep secret) |
| `node-a.pem` | Node A certificate | Node A only |
| `node-a.key` | Node A private key | Node A only |
| `node-b.pem` | Node B certificate | Node B only |
| `node-b.key` | Node B private key | Node B only |

### Adding a new node to an existing cluster

```bash
# 1. Generate a certificate for the new node using the existing CA
#    (must be done on a machine that has access to cluster-ca.key)
prx-waf cluster cert-init \
    --nodes node-d \
    --output-dir /tmp/node-d-certs \
    --node-validity-days 365

# 2. Copy cluster-ca.pem and node-d.{pem,key} to the new node

# 3. Configure the new node:
#    [cluster]
#    role = "worker"
#    seeds = ["<main-node>:16851"]
#    [cluster.crypto]
#    ca_cert = "/path/to/cluster-ca.pem"
#    node_cert = "/path/to/node-d.pem"
#    node_key = "/path/to/node-d.key"
#    auto_generate = false
```

---

## Network & Port Reference

| Port | Protocol | Purpose |
|------|----------|---------|
| 80 | TCP | HTTP proxy |
| 443 | TCP | HTTPS proxy |
| 9527 | TCP | Management API + Admin UI |
| **16851** | **UDP** | **QUIC cluster communication (inter-node only)** |

The cluster port (16851) should only be reachable between cluster nodes. Use a
firewall or private network to prevent external access.

---

## Troubleshooting

### Nodes cannot connect to each other

1. **Verify network reachability:** Each node must reach others on port 16851 UDP.
2. **Check seeds configuration:** Workers need at least one seed pointing to the main.
3. **Verify certificates:** All nodes must use certificates signed by the same CA.
   - `auto_generate = false` must point to cert files from `cert-init`
   - CA cert must be the same `cluster-ca.pem` across all nodes
4. **Check logs:** `RUST_LOG=debug` for verbose cluster transport logs.

```bash
# Check QUIC port reachability
nc -u <node-a-ip> 16851

# View cluster logs
podman-compose -f docker-compose.cluster.yml logs node-a
```

### Election not completing

- Default election timeout: 150-300ms. If heartbeats are delayed (high latency
  WAN), increase `timeout_min_ms` and `timeout_max_ms`.
- The phi-accrual detector adapts automatically to network jitter.
- Split-brain is prevented: a node needs `N/2 + 1` votes (majority) to win.

```toml
# For WAN deployments (50ms+ RTT):
[cluster.election]
timeout_min_ms        = 1000
timeout_max_ms        = 2000
heartbeat_interval_ms = 200
phi_dead              = 8.0    # lower threshold for faster detection
```

### Rule sync is slow or not working

- Default sync interval: 10 seconds (periodic poll). Workers also sync immediately
  on connect.
- Reduce `rules_interval_secs` for faster sync at the cost of more traffic.
- Check that node-b/node-c can reach node-a on port 16851.

### Worker shows "stale" rules after reconnection

After a network partition heals, workers automatically request a full rule snapshot
on reconnection (safer than relying on a potentially outdated incremental log).
This is expected behavior; the sync completes within `rules_interval_secs`.

### High memory usage on workers

Workers maintain an in-memory rule cache. With 10,000+ rules, this can be
significant. Reduce the rule set or increase node memory.

> **v1 Limitation:** WASM plugins are not synced to worker nodes. Workers run the
> WAF engine without plugin support. This will be addressed in v2.

---

## Architecture Notes

### Raft-lite Election

PRX-WAF uses a simplified Raft election (no log replication — rules sync handles
consistency separately):

1. Workers start an election timer (random 150-300ms)
2. If no heartbeat from main within timeout → become Candidate
3. Candidate increments term, votes for self, requests votes from peers
4. Needs majority votes (`N/2 + 1`) to win
5. Winner broadcasts `ElectionResult` → becomes new Main
6. Split vote → random backoff, retry next term

### Failure Detection

Phi-accrual failure detector (Cassandra-style):
- Tracks heartbeat inter-arrival times per peer
- Computes `φ = −log₁₀(P(t > now − last_heartbeat))`
- `φ > 8.0` → suspect failure
- `φ > 12.0` → declare dead → trigger election

This adapts automatically to network jitter — no fixed timeout needed.

### Rule Sync Protocol

```
Worker: RuleSyncRequest { current_version: 42 }

Main logic:
  if registry.version == 42 → no-op response
  else if changelog covers [42..current] → incremental delta
  else (worker too far behind) → full snapshot (lz4-compressed JSON)
```

Incremental sync is bounded by a 500-entry ring buffer on the main node.

---

## CLI Reference

```bash
# Show cluster configuration (from config file, not live state)
prx-waf cluster status

# List configured seed nodes
prx-waf cluster nodes

# Generate a join token (live cluster — requires running API)
prx-waf cluster token generate --ttl 24h

# Generate certificates for N nodes (offline, no running cluster needed)
prx-waf cluster cert-init \
    --nodes node-a,node-b,node-c \
    --output-dir /certs \
    --ca-validity-days 3650 \
    --node-validity-days 365

# Promote / demote / remove nodes (requires live cluster API)
prx-waf cluster promote <node-id>
prx-waf cluster demote  <node-id>
prx-waf cluster remove  <node-id>
```
