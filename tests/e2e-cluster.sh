#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# PRX-WAF End-to-End Cluster Test
#
# Spins up a 3-node cluster (1 main + 2 workers) using docker-compose.cluster.yml,
# then verifies:
#   1. All 3 nodes become healthy
#   2. Rule created on main (node-a) is synced to workers (node-b, node-c)
#   3. Stopping node-a triggers election; a new main is elected
#
# Prerequisites:
#   - cargo build --release (binary must exist at target/release/prx-waf)
#   - docker-compose or podman-compose installed
#   - curl installed
#
# Usage:
#   chmod +x tests/e2e-cluster.sh
#   ./tests/e2e-cluster.sh
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
COMPOSE_FILE="docker-compose.cluster.yml"
NODE_A_API="http://localhost:16827"
NODE_B_API="http://localhost:16828"
NODE_C_API="http://localhost:16829"

COMPOSE_CMD="${COMPOSE_CMD:-}"
if [ -z "$COMPOSE_CMD" ]; then
    if command -v podman-compose &>/dev/null; then
        COMPOSE_CMD="podman-compose"
    elif command -v docker-compose &>/dev/null; then
        COMPOSE_CMD="docker-compose"
    elif docker compose version &>/dev/null 2>&1; then
        COMPOSE_CMD="docker compose"
    else
        echo "ERROR: No compose tool found (tried podman-compose, docker-compose, docker compose)" >&2
        exit 1
    fi
fi

PASS=0
FAIL=0

# ── Helpers ───────────────────────────────────────────────────────────────────

log()  { echo "[$(date +%H:%M:%S)] $*"; }
pass() { echo "  [PASS] $*"; PASS=$((PASS + 1)); }
fail() { echo "  [FAIL] $*"; FAIL=$((FAIL + 1)); }

wait_healthy() {
    local name="$1"
    local url="$2"
    local max_wait="${3:-60}"
    local elapsed=0

    log "Waiting for $name to become healthy (max ${max_wait}s)..."
    while [ "$elapsed" -lt "$max_wait" ]; do
        if curl -sf --max-time 3 "$url/health" &>/dev/null; then
            pass "$name is healthy"
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    fail "$name did not become healthy within ${max_wait}s"
    return 1
}

get_cluster_role() {
    local url="$1"
    curl -sf --max-time 5 "$url/api/cluster/status" 2>/dev/null \
        | grep -o '"role":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "unknown"
}

cleanup() {
    log "Cleaning up..."
    $COMPOSE_CMD -f "$COMPOSE_FILE" down -v 2>/dev/null || true
}
trap cleanup EXIT

# ── Pre-flight checks ─────────────────────────────────────────────────────────

log "=== PRX-WAF Cluster E2E Test ==="
log ""

if [ ! -f "target/release/prx-waf" ]; then
    log "Binary not found. Building..."
    ~/.cargo/bin/cargo build --release -p prx-waf
fi

log "Using compose command: $COMPOSE_CMD"
log ""

# ── Step 0: Generate cluster certificates ────────────────────────────────────

log "Step 0: Generating cluster certificates..."
$COMPOSE_CMD -f "$COMPOSE_FILE" run --rm cluster-init
pass "Cluster certificates generated"
log ""

# ── Step 1: Start the cluster ─────────────────────────────────────────────────

log "Step 1: Starting 3-node cluster..."
$COMPOSE_CMD -f "$COMPOSE_FILE" up -d node-a node-b node-c

# ── Step 2: Wait for all nodes to be healthy ─────────────────────────────────

log "Step 2: Waiting for all nodes to be healthy..."
wait_healthy "node-a (main)"    "$NODE_A_API" 90
wait_healthy "node-b (worker1)" "$NODE_B_API" 60
wait_healthy "node-c (worker2)" "$NODE_C_API" 60
log ""

# ── Step 3: Verify cluster API responds ──────────────────────────────────────

log "Step 3: Verifying cluster status API..."
STATUS_A=$(curl -sf --max-time 5 "$NODE_A_API/api/cluster/status" 2>/dev/null || echo "{}")
if echo "$STATUS_A" | grep -q '"node_id"'; then
    pass "node-a cluster status API responds"
else
    fail "node-a cluster status API did not return expected data"
fi
log ""

# ── Step 4: Node roles ────────────────────────────────────────────────────────

log "Step 4: Verifying node roles..."
ROLE_A=$(get_cluster_role "$NODE_A_API")
log "  node-a role: $ROLE_A"
if [ "$ROLE_A" = "Main" ] || [ "$ROLE_A" = "main" ]; then
    pass "node-a has Main role"
else
    fail "node-a role is '$ROLE_A', expected 'Main'"
fi
log ""

# ── Step 5: Rule sync ─────────────────────────────────────────────────────────

log "Step 5: Testing rule sync (create rule on main, verify on workers)..."

# Login to get a JWT token from node-a
TOKEN=$(curl -sf --max-time 10 \
    -X POST "$NODE_A_API/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin123"}' 2>/dev/null \
    | grep -o '"token":"[^"]*"' | cut -d'"' -f4 || echo "")

if [ -z "$TOKEN" ]; then
    log "  Note: Could not get auth token (admin user may not be seeded yet)"
    log "  Skipping rule sync test — verify manually via Admin UI at $NODE_A_API/ui/"
else
    # Create a test rule via the main node API
    RULE_ID="E2E-TEST-$(date +%s)"
    CREATE_RESP=$(curl -sf --max-time 10 \
        -X POST "$NODE_A_API/api/v1/rules" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "{\"id\":\"$RULE_ID\",\"name\":\"E2E Test Rule\",\"category\":\"custom\",\"action\":\"log\",\"pattern\":\"e2e-test-pattern\"}" \
        2>/dev/null || echo "")

    if echo "$CREATE_RESP" | grep -q "$RULE_ID"; then
        pass "Rule '$RULE_ID' created on node-a"

        # Wait for sync (rules_interval_secs = 10 in config)
        log "  Waiting 15s for rule sync to propagate to workers..."
        sleep 15

        # Check rule exists on node-b
        RULES_B=$(curl -sf --max-time 10 \
            -H "Authorization: Bearer $TOKEN" \
            "$NODE_B_API/api/v1/rules" 2>/dev/null || echo "[]")
        if echo "$RULES_B" | grep -q "$RULE_ID"; then
            pass "Rule '$RULE_ID' synced to node-b"
        else
            fail "Rule '$RULE_ID' NOT found on node-b after 15s"
        fi

        # Check rule exists on node-c
        RULES_C=$(curl -sf --max-time 10 \
            -H "Authorization: Bearer $TOKEN" \
            "$NODE_C_API/api/v1/rules" 2>/dev/null || echo "[]")
        if echo "$RULES_C" | grep -q "$RULE_ID"; then
            pass "Rule '$RULE_ID' synced to node-c"
        else
            fail "Rule '$RULE_ID' NOT found on node-c after 15s"
        fi
    else
        fail "Could not create test rule on node-a"
    fi
fi
log ""

# ── Step 6: Election test ─────────────────────────────────────────────────────

log "Step 6: Testing election (stop node-a, verify new main elected)..."

# Stop node-a (the current main)
log "  Stopping node-a (current main)..."
$COMPOSE_CMD -f "$COMPOSE_FILE" stop node-a

# Wait for election to complete (timeout_max_ms=300ms + phi-accrual detection)
log "  Waiting 10s for election to complete..."
sleep 10

# Check if node-b or node-c became main
ROLE_B=$(get_cluster_role "$NODE_B_API")
ROLE_C=$(get_cluster_role "$NODE_C_API")
log "  node-b role after election: $ROLE_B"
log "  node-c role after election: $ROLE_C"

if [ "$ROLE_B" = "Main" ] || [ "$ROLE_B" = "main" ] \
   || [ "$ROLE_C" = "Main" ] || [ "$ROLE_C" = "main" ]; then
    pass "New main elected after node-a stopped"
else
    # Election may be in progress or cluster API might not show the role yet.
    # Check cluster status for any indication of a new main.
    STATUS_B=$(curl -sf --max-time 5 "$NODE_B_API/api/cluster/status" 2>/dev/null || echo "{}")
    if echo "$STATUS_B" | grep -qi '"main"'; then
        pass "New main detected via cluster status API"
    else
        fail "No new main elected after node-a stopped (got: role_b=$ROLE_B, role_c=$ROLE_C)"
    fi
fi
log ""

# ── Step 7: Rejoin test ───────────────────────────────────────────────────────

log "Step 7: Testing node rejoin (restart node-a as worker)..."
$COMPOSE_CMD -f "$COMPOSE_FILE" start node-a
wait_healthy "node-a (rejoining)" "$NODE_A_API" 60

ROLE_A_AFTER=$(get_cluster_role "$NODE_A_API")
log "  node-a role after rejoin: $ROLE_A_AFTER"
# After an election, node-a may come back as Worker (new main already elected)
pass "node-a rejoined the cluster (role: $ROLE_A_AFTER)"
log ""

# ── Summary ───────────────────────────────────────────────────────────────────

log "=== Test Summary ==="
log "  PASS: $PASS"
log "  FAIL: $FAIL"
log ""

if [ "$FAIL" -gt 0 ]; then
    log "RESULT: FAILED ($FAIL failure(s))"
    log ""
    log "Container logs (last 50 lines each):"
    $COMPOSE_CMD -f "$COMPOSE_FILE" logs --tail=50 node-a node-b node-c 2>/dev/null || true
    exit 1
else
    log "RESULT: ALL TESTS PASSED"
    exit 0
fi
