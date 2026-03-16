# PRX-WAF Cluster — Automated Execution Plan

**Created:** 2026-03-16  
**Executor:** Claude AI (via claude CLI)  
**Total estimated:** ~54 Claude-hours  
**Parallel capacity:** 1-2 Claude instances at a time

---

## Timeline Overview

| Phase | Content | Claude-hours | Start | Checkpoint |
|-------|---------|-------------|-------|------------|
| P0 | Scaffold + Dependencies | 2h | Immediate | +2h |
| P1 | QUIC Transport + mTLS | 12h | After P0 | +14h |
| P2 | Rule & Config Sync | 14h | After P1 | +28h |
| P3 | Election + Failover | 16h | After P2 | +44h |
| P4 | Admin UI Cluster Panel | 8h | After P3 | +52h |
| P5 | Integration Test + Docker | 2h | After P4 | +54h |

**Realistic wall-clock estimate:** ~3-4 days (Claude runs ~14-16h/day with rate limit gaps)

---

## P0: Scaffold + Dependencies (2 Claude-hours)

### Tasks
- [ ] Create `crates/waf-cluster/` directory structure
- [ ] Write `Cargo.toml` with dependencies (quinn, rcgen, lz4_flex — others already in workspace)
- [ ] Register in workspace `Cargo.toml`
- [ ] Add `ClusterConfig`, `NodeRole`, `NodeId` to `waf-common/src/config.rs`
- [ ] Add `[cluster]` section to `configs/default.toml` (disabled by default)
- [ ] Create all module stubs (`lib.rs`, `node.rs`, `transport/`, `crypto/`, `sync/`, `election/`, `health/`, `protocol/`)
- [ ] `cargo check --all-features` must pass

### Checkpoint Criteria
- `waf-cluster` crate compiles
- ClusterConfig parseable from TOML
- Zero warnings

### Deliverable
```
crates/waf-cluster/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── node.rs
│   ├── protocol.rs
│   ├── transport/mod.rs
│   ├── crypto/mod.rs
│   ├── sync/mod.rs
│   ├── election/mod.rs
│   └── health/mod.rs
```

---

## P1: QUIC Transport + mTLS (12 Claude-hours)

### Tasks
- [ ] Protocol message types with serde (ClusterMessage, Heartbeat, JoinRequest/Response, etc.)
- [ ] Length-prefixed JSON frame codec (u32 + JSON over quinn streams)
- [ ] QUIC server with mTLS (reuse gateway/http3.rs pattern, add client cert verifier)
- [ ] QUIC client dialer (connect to peer, TLS client cert)
- [ ] CA certificate generation (Ed25519 via rcgen)
- [ ] Node certificate signing + CSR validation
- [ ] Encrypted CA key storage (AES-GCM, passphrase-derived)
- [ ] Join token: HMAC-SHA256 generate + validate
- [ ] Heartbeat send/receive on control stream
- [ ] Static seed discovery (from config)
- [ ] Thread launch in `prx-waf/src/main.rs` (std::thread::spawn + own tokio runtime)
- [ ] Integration test: 2-node connect + heartbeat exchange

### Checkpoint Criteria
- Two prx-waf instances connect via QUIC with mTLS
- Heartbeats exchanged every 50ms
- Invalid certs rejected
- Join token flow works end-to-end
- `cargo test` all pass

### Verification Command
```bash
# Start node A (main)
prx-waf --config test-main.toml run &
# Start node B (worker, join main)
prx-waf run --cluster-join 127.0.0.1:16851 --token <token>
# Check logs for: "Peer connected", "Heartbeat received"
```

---

## P2: Rule & Config Sync (14 Claude-hours)

### Tasks
- [ ] RuleChangelog ring buffer on main (VecDeque, max 500 entries, versioned)
- [ ] Full snapshot: serialize RuleRegistry → lz4 compressed bytes
- [ ] Incremental sync: send changelog delta by version range
- [ ] Worker: receive + apply rule updates to in-memory RuleRegistry
- [ ] RuleReloader trait + WafEngine callback on sync
- [ ] Config sync protocol (TOML string, version tracked)
- [ ] Attack event batching on worker (batch_size + flush_interval)
- [ ] Event forwarding to main via EventBatch stream
- [ ] Main: write forwarded events to PostgreSQL (existing db.create_security_event)
- [ ] Stats aggregation via QUIC datagrams (unreliable, loss-tolerant)
- [ ] API write forwarding: worker detects write → forwards to main via ApiForward stream
- [ ] StorageMode enum (internal to waf-cluster, no waf-storage changes)
- [ ] Integration test: create rule on main → appears on worker within 10s

### Checkpoint Criteria
- Rule created on main UI → worker has it within `rules_interval_secs`
- Attack blocked on worker → event visible on main dashboard
- API POST to worker → forwarded to main, returns result
- Stats from all nodes aggregated on main
- `cargo test` all pass

### Verification Command
```bash
# On main: create a rule via API
curl -X POST http://main:16827/api/rules -d '{"name":"test","action":"block"}'
# On worker: verify rule exists
curl http://worker:16827/api/rules | grep "test"
```

---

## P3: Election + Failover (16 Claude-hours)

### Tasks
- [ ] Raft-lite election state machine (term, vote, random timeout 150-300ms)
- [ ] Phi-accrual failure detector (sliding window, phi threshold 8/12)
- [ ] Main → Worker demotion on new election result
- [ ] Worker → Main promotion (connect PostgreSQL if configured)
- [ ] CA key replication (encrypted, sent to workers on join for failover)
- [ ] Split-brain prevention (fencing token, reject stale-term leaders)
- [ ] CLI: `prx-waf cluster status/nodes/promote/demote/remove`
- [ ] Integration test: kill main → new main elected within 500ms
- [ ] Chaos test: network partition → no split-brain
- [ ] Concurrent election test: single winner guaranteed

### Checkpoint Criteria
- Kill main process → worker auto-promoted within 500ms
- Promoted worker starts accepting API writes
- Rules continue syncing to remaining workers
- No split-brain under any partition scenario
- CLI shows correct cluster topology
- `cargo test` all pass

### Verification Command
```bash
# 3-node cluster running
prx-waf cluster status
# Kill main
kill $(prx-waf cluster status | grep MAIN | awk '{print $3}')
# Wait 1s, check new main elected
prx-waf cluster status  # should show new main
```

---

## P4: Admin UI Cluster Panel (8 Claude-hours)

### Tasks
- [ ] API endpoints: GET /api/cluster/status, /nodes, /nodes/:id, /tokens, /sync
- [ ] POST /api/cluster/token (generate), /nodes/remove
- [ ] Vue 3 page: Cluster Overview (topology, node status, health)
- [ ] Vue 3 page: Node Detail (health metrics, sync status, last events)
- [ ] Vue 3 page: Join Tokens (generate, revoke, list)
- [ ] Vue 3 page: Sync Status (rule versions, config versions, drift alerts)
- [ ] i18n for all cluster pages (en/zh/ru/ka)
- [ ] Lucide icons for cluster UI elements
- [ ] `npm run build` must pass

### Checkpoint Criteria
- Cluster Overview shows all nodes with real-time status
- Can generate join token from UI
- Can see per-node health and sync status
- All 4 languages working
- `npm run build` passes

---

## P5: Integration Test + Docker Compose (2 Claude-hours)

### Tasks
- [ ] `docker-compose.cluster.yml` — 3-node cluster (1 main + 2 workers + 1 postgres)
- [ ] Automated test script: start cluster → create rule → verify sync → kill main → verify election
- [ ] Documentation: `docs/cluster-deployment.md`
- [ ] Update main README with cluster feature
- [ ] Final `cargo test --all-features` + `cargo clippy`
- [ ] Tag release candidate

### Checkpoint Criteria
- `docker-compose -f docker-compose.cluster.yml up` → 3 healthy nodes
- Full test script passes end-to-end
- Documentation complete
- Zero clippy warnings

### Docker Compose (3-node)
```yaml
services:
  postgres:
    image: docker.io/library/postgres:16-alpine
    ...
  
  waf-main:
    build: { context: ., dockerfile: Dockerfile.prebuilt }
    environment:
      CLUSTER_ROLE: main
      CLUSTER_LISTEN: "0.0.0.0:16851"
    ports:
      - "16827:9527"   # Admin UI
      - "16880:80"     # HTTP proxy
      - "16851:16851"  # Cluster QUIC
  
  waf-worker-1:
    build: { context: ., dockerfile: Dockerfile.prebuilt }
    environment:
      CLUSTER_ROLE: worker
      CLUSTER_SEEDS: "waf-main:16851"
    ports:
      - "16828:9527"
      - "16881:80"
  
  waf-worker-2:
    build: { context: ., dockerfile: Dockerfile.prebuilt }
    environment:
      CLUSTER_ROLE: worker
      CLUSTER_SEEDS: "waf-main:16851"
    ports:
      - "16829:9527"
      - "16882:80"
```

---

## Automated Checkpoint Schedule

Each phase completion triggers a cron check. If the phase isn't done, the cron re-dispatches Claude.

| Cron ID | Fires | Check |
|---------|-------|-------|
| waf-cluster-p0 | P0 start + 3h | Is P0 done? cargo check passes? |
| waf-cluster-p1 | P0 done + 14h | Is P1 done? 2-node heartbeat test passes? |
| waf-cluster-p2 | P1 done + 16h | Is P2 done? Rule sync test passes? |
| waf-cluster-p3 | P2 done + 18h | Is P3 done? Election test passes? |
| waf-cluster-p4 | P3 done + 10h | Is P4 done? npm run build passes? |
| waf-cluster-p5 | P4 done + 3h | Is P5 done? 3-node docker-compose works? |

---

## Rollback Strategy

Each phase is a separate git branch. If a phase fails:
1. `git checkout main` — revert to pre-cluster state
2. Standalone mode continues working (cluster is opt-in)
3. No existing functionality affected at any point
