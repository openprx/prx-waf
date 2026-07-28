#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# PRX-WAF End-to-End graceful-upgrade test
#
# Replaces a running prx-waf with a second process while traffic is flowing, and
# asserts the four properties that make that an upgrade rather than an outage:
#
#   1. no request fails, including the ones open at the instant of the signal
#   2. the replacement inherits the SAME kernel socket — same inode, not a
#      rebind — so nothing in the accept queue is lost
#   3. the port is never, at any sampled instant, unlistened
#   4. the outgoing process leaves on its own, with exit status 0. This script
#      sends SIGQUIT and nothing else: no kill, no escalation, no timeout. A
#      process that has to be killed has not drained.
#
# Plus the two things the handover does not carry for free:
#
#   5. the admin API, metrics and HTTP/3 listeners are back on the new process.
#      Pingora hands over the proxy listener and nothing else, and the outgoing
#      process holds those three ports until it exits, so the replacement has to
#      retry the bind. Without that retry it comes up with no management plane
#      at all and no way back, because the threads that failed are gone by the
#      time the ports free up.
#   6. the outgoing process leaves within the configured drain, not Pingora's
#      unconditional five minutes (`server/mod.rs:56`, applied at `:775`). The
#      departure is asserted as a RANGE, so both a drain that is ignored and one
#      that is inherited from upstream fail the test.
#
# The origin sleeps on /slow, so at any instant several requests are in flight
# through the process being replaced. Each request opens its own connection:
# with the socket handed over rather than rebound there is no gap to tolerate,
# so every refused connect, reset and timeout is a genuine failure needing no
# interpretation.
#
# Then four failure paths, all asserting the same thing — the running process is
# untouched. This is the property the whole procedure rests on: the replacement
# is started FIRST and the signal is sent only once it is waiting, so every way
# the replacement can fail is harmless.
#
#   a. the replacement cannot parse its config
#   b. the replacement's handover socket would sit in a world-writable directory
#      (fatal on `--upgrade`, because the handover is the only thing that launch
#      was for)
#   c. the same unsafe directory on an ORDINARY start (a warning: losing the
#      ability to upgrade in place must not stop a WAF from filtering traffic)
#   d. the replacement waits and is never signalled
#
# Case (d) costs a minute of wall clock on its own, because the acceptance
# budget it has to exhaust is 60s by design. SKIP_SLOW=1 drops it.
#
# NOT covered here:
#   - HTTP/3 request continuity. It is not merely unimplemented, it is
#     impossible: QUIC keeps connection state in the process, so a new process
#     could not decrypt a connection the old one negotiated even if the UDP
#     socket were handed across. Only the rebind is asserted.
#   - The `TooPermissive` directory verdict. Reaching it needs a world-writable
#     directory this process OWNS; /tmp is root-owned, so case (b) lands on
#     `ForeignOwner` first. The classifier is a pure function with unit tests
#     for every verdict in `crates/prx-waf/src/upgrade.rs`.
#   - The root branch of the socket-path derivation (/run/prx-waf). This script
#     does not assume it can run as root.
#
# Prerequisites:
#   - cargo build -p prx-waf   (or --release; set BIN=)
#   - python3 (origin and load generator), openssl (QUIC cert), ss, curl
#   - a reachable Postgres; the daemon migrates it itself
#
# Usage:
#   ./tests/e2e-graceful-upgrade.sh
#   BIN=target/release/prx-waf ./tests/e2e-graceful-upgrade.sh
#   DATABASE_URL=postgresql://user:pw@host:5432/db ./tests/e2e-graceful-upgrade.sh
#   SKIP_SLOW=1 ./tests/e2e-graceful-upgrade.sh
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

BIN="${BIN:-target/debug/prx-waf}"
DATABASE_URL="${DATABASE_URL:-postgresql://prx_waf:prx_waf@127.0.0.1:15432/prx_waf}"
# A block of its own: tests/lane2 owns 173xx, tests/ftw owns 189xx/199xx, and
# the other e2e scripts own 180xx/185xx/186xx/196xx. A second harness answering
# on one of these would be measured instead of the WAF.
PROXY_PORT="${PROXY_PORT:-17811}"
PROXY_TLS_PORT="${PROXY_TLS_PORT:-17844}"
H3_PORT="${H3_PORT:-17845}"
API_PORT="${API_PORT:-17899}"
METRICS_PORT="${METRICS_PORT:-17827}"
ORIGIN_PORT="${ORIGIN_PORT:-17888}"
# The second set, for the failure path that needs a process of its own.
ALT_PROXY_PORT="${ALT_PROXY_PORT:-17911}"
ALT_TLS_PORT="${ALT_TLS_PORT:-17944}"
ALT_H3_PORT="${ALT_H3_PORT:-17945}"
ALT_API_PORT="${ALT_API_PORT:-17999}"
ALT_METRICS_PORT="${ALT_METRICS_PORT:-17927}"

HOST_NAME="upgrade.test"
# Short enough to keep the run under a minute, long enough that the management
# ports are genuinely contended and the retry path is genuinely exercised.
DRAIN_SECS="${DRAIN_SECS:-5}"
# Origin delay on /slow. Comfortably inside Pingora's 5s pre-shutdown window, so
# a request open when the signal lands is expected to finish on the old process.
SLOW_SECS="${SLOW_SECS:-1.5}"
LOAD_WORKERS="${LOAD_WORKERS:-8}"
LOAD_SECONDS="${LOAD_SECONDS:-40}"
SKIP_SLOW="${SKIP_SLOW:-0}"

PASS=0
FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

# ── Preconditions ─────────────────────────────────────────────────────────────
for tool in python3 openssl ss curl; do
    command -v "$tool" >/dev/null || { echo "ERROR: $tool not found" >&2; exit 1; }
done
[ -x "$BIN" ] || { echo "ERROR: $BIN not found; run: cargo build -p prx-waf" >&2; exit 1; }
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
for p in "$PROXY_PORT" "$PROXY_TLS_PORT" "$API_PORT" "$METRICS_PORT" "$ORIGIN_PORT" \
         "$ALT_PROXY_PORT" "$ALT_TLS_PORT" "$ALT_API_PORT" "$ALT_METRICS_PORT"; do
    if port_busy "$p"; then
        echo "ERROR: port $p is already in use. Another harness on one of these ports" >&2
        echo "       would be measured instead of the WAF. Override with PROXY_PORT /" >&2
        echo "       PROXY_TLS_PORT / API_PORT / METRICS_PORT / ORIGIN_PORT / ALT_*." >&2
        exit 1
    fi
done

# The daemon migrates the database itself, but it does that after opening a
# pool, and a pool that cannot connect produces a stack of context rather than
# "there is no Postgres here".
DB_HOSTPORT="$(printf '%s' "$DATABASE_URL" | sed -E 's#^[^@]*@([^/]+)/.*$#\1#')"
DB_HOST="${DB_HOSTPORT%%:*}"
DB_PORT="${DB_HOSTPORT##*:}"
[ "$DB_PORT" = "$DB_HOST" ] && DB_PORT=5432
if ! (exec 3<>"/dev/tcp/$DB_HOST/$DB_PORT") 2>/dev/null; then
    echo "ERROR: no Postgres answering on $DB_HOST:$DB_PORT (from DATABASE_URL)." >&2
    echo "       Start one, or point DATABASE_URL somewhere that has one:" >&2
    echo "         podman run -d --name prx-waf-e2e-pg -e POSTGRES_USER=prx_waf \\" >&2
    echo "           -e POSTGRES_PASSWORD=prx_waf -e POSTGRES_DB=prx_waf \\" >&2
    echo "           -p 127.0.0.1:$DB_PORT:5432 docker.io/library/postgres:16" >&2
    exit 1
fi

WORK="$(mktemp -d)"
ORIGIN_PID=""
cleanup() {
    # Every daemon this script starts is started with a config under $WORK, and
    # Pingora's bootstrap can fork, so the recorded pid is not always the one
    # holding the ports. Matching the config path catches every one of them.
    pkill -9 -f "$WORK/" 2>/dev/null || true
    [ -n "$ORIGIN_PID" ] && kill -9 "$ORIGIN_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

export JWT_SECRET="${JWT_SECRET:-e2e-graceful-upgrade-secret-0123456789abcdef}"
export MASTER_KEY="${MASTER_KEY:-e2e-graceful-upgrade-master-0123456789abcdef}"
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-e2e-graceful-upgrade-admin-pw}"
export RUST_LOG="${RUST_LOG:-info}"
# Both processes must derive the same handover socket path, and both must be
# able to own its directory. Pinning it under $WORK also keeps concurrent runs
# of this script from meeting on one socket.
export PRXWAF_UPGRADE_SOCK="$WORK/run/upgrade.sock"

# ── Origin ────────────────────────────────────────────────────────────────────
cat > "$WORK/origin.py" <<'PY'
import http.server, socketserver, sys, time

DELAY = float(sys.argv[2])


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        # The delay is what makes "in flight across the handover" a state that
        # exists long enough to observe.
        if self.path.startswith("/slow"):
            time.sleep(DELAY)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _reply

    def log_message(self, *_args):
        pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


Server(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY
python3 "$WORK/origin.py" "$ORIGIN_PORT" "$SLOW_SECS" > "$WORK/origin.log" 2>&1 &
ORIGIN_PID=$!
disown "$ORIGIN_PID" 2>/dev/null || true
for _ in $(seq 1 40); do port_busy "$ORIGIN_PORT" && break; sleep 0.25; done
port_busy "$ORIGIN_PORT" || { echo "ERROR: origin did not come up" >&2; exit 1; }

# ── Load generator ────────────────────────────────────────────────────────────
cat > "$WORK/load.py" <<'PY'
import http.client, json, sys, threading, time

host, port, duration, workers, out = (
    sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
)
records, lock, stop_at = [], threading.Lock(), time.time() + duration


def worker(wid):
    n = 0
    while time.time() < stop_at:
        n += 1
        started = time.time()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
            conn.request("GET", f"/slow?w={wid}&n={n}", headers={"Host": host})
            resp = conn.getresponse()
            body = resp.read()
            conn.close()
            ok = resp.status == 200 and body == b"ok"
            rec = (started, time.time(), resp.status, "" if ok else f"body={body!r}")
        except Exception as exc:  # noqa: BLE001 — every failure mode counts
            rec = (started, time.time(), 0, f"{type(exc).__name__}: {exc}")
        with lock:
            records.append(rec)


threads = [threading.Thread(target=worker, args=(i,)) for i in range(workers)]
for t in threads:
    t.start()
for t in threads:
    t.join()
with open(out, "w", encoding="utf-8") as fh:
    json.dump(records, fh)
PY

# ── TLS material for the QUIC listener ───────────────────────────────────────
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
    -subj "/CN=$HOST_NAME" -addext "subjectAltName=DNS:$HOST_NAME" \
    >/dev/null 2>&1

gen_config() {   # $1=path $2=proxy $3=tls $4=h3 $5=api $6=metrics [$7=upgrade_sock]
    # Assembled before the heredoc, not inside it: a `${7:+... "$7"}` expansion
    # loses its quotes there, and the config it produces then fails to parse for
    # a reason that has nothing to do with what the test is asserting. This
    # script's own first run passed case (b) on exactly that mistake.
    local sock_line=""
    [ -n "${7:-}" ] && sock_line="upgrade_sock = \"$7\""
    cat > "$1" <<EOF
[proxy]
listen_addr = "127.0.0.1:$2"
listen_addr_tls = "127.0.0.1:$3"
worker_threads = 2
drain_timeout_secs = $DRAIN_SECS
$sock_line

[api]
listen_addr = "127.0.0.1:$5"

[metrics]
enabled = true
listen_addr = "127.0.0.1:$6"
max_host_labels = 16

[storage]
database_url = "$DATABASE_URL"
max_connections = 5

# A cached 200 would answer from the new process without proving the origin was
# reached through it.
[cache]
enabled = false
max_size_mb = 1
default_ttl_secs = 0
max_ttl_secs = 0

[http3]
enabled = true
listen_addr = "127.0.0.1:$4"
cert_pem = "$WORK/cert.pem"
key_pem = "$WORK/key.pem"

[geoip]
enabled = false
ipv4_xdb_path = "data/ip2region_v4.xdb"
ipv6_xdb_path = "data/ip2region_v6.xdb"
cache_policy = "no_cache"

[content_security]
enabled = false

[[hosts]]
host = "$HOST_NAME"
port = 80
remote_host = "127.0.0.1"
remote_port = $ORIGIN_PORT
guard_status = true
log_only_mode = false
# This test is about the handover, not about detection: a blocked request would
# be counted as a failure of the upgrade.
[hosts.defense_config]
bot = false
sqli = false
xss = false
scan = false
rce = false
sensitive = false
dir_traversal = false
owasp_set = false
cc = false
owasp_paranoia = 1
EOF
}

probe() {        # $1=port -> http status, or 000
    curl -s -o /dev/null -m 10 -w '%{http_code}' -H "Host: $HOST_NAME" \
        "http://127.0.0.1:$1/" 2>/dev/null || echo 000
}

wait_serving() { # $1=port $2=logfile $3=pid
    for _ in $(seq 1 120); do
        [ "$(probe "$1")" = "200" ] && return 0
        kill -0 "$3" 2>/dev/null || break
        sleep 0.5
    done
    echo "ERROR: prx-waf did not come up on $1; last lines of its log:" >&2
    tail -30 "$2" >&2
    return 1
}

listener_of() {  # $1=port -> the ss line, whitespace-squeezed
    ss -Htlnep "sport = :$1" 2>/dev/null | tr -s ' '
}
field_of() {     # $1=pattern $2=line
    printf '%s' "$2" | grep -oE "$1" | head -1
}

gen_config "$WORK/waf.toml" "$PROXY_PORT" "$PROXY_TLS_PORT" "$H3_PORT" "$API_PORT" "$METRICS_PORT"

echo "Migrating the database"
"$BIN" --config "$WORK/waf.toml" migrate > "$WORK/migrate.log" 2>&1 || {
    echo "ERROR: migration failed:" >&2; tail -20 "$WORK/migrate.log" >&2; exit 1; }

# ═════════════════════════════════════════════════════════════════════════════
# The handover
# ═════════════════════════════════════════════════════════════════════════════
echo
echo "── Handover ─────────────────────────────────────────────────────────────"

"$BIN" --config "$WORK/waf.toml" run > "$WORK/old.log" 2>&1 &
OLD_PID=$!
wait_serving "$PROXY_PORT" "$WORK/old.log" "$OLD_PID"
echo "  outgoing process pid=$OLD_PID serving on :$PROXY_PORT"

BEFORE_LINE="$(listener_of "$PROXY_PORT")"
BEFORE_INO="$(field_of 'ino:[0-9]+' "$BEFORE_LINE")"
BEFORE_HOLDER="$(field_of 'pid=[0-9]+' "$BEFORE_LINE")"
echo "  listener before: $BEFORE_INO held by $BEFORE_HOLDER"

python3 "$WORK/load.py" "$HOST_NAME" "$PROXY_PORT" "$LOAD_SECONDS" "$LOAD_WORKERS" \
    "$WORK/load.json" > "$WORK/load.log" 2>&1 &
LOAD_PID=$!
sleep 5

# Sampled far faster than a rebind could complete, for the whole handover.
( for _ in $(seq 1 800); do
      printf '%s\n' "$(ss -Htln "sport = :$PROXY_PORT" 2>/dev/null | wc -l)"
      sleep 0.05
  done ) > "$WORK/poll.txt" 2>&1 &
POLL_PID=$!

"$BIN" --config "$WORK/waf.toml" run --upgrade > "$WORK/new.log" 2>&1 &
NEW_PID=$!
NEW_READY=0
for _ in $(seq 1 100); do
    grep -q 'Waiting up to' "$WORK/new.log" && { NEW_READY=1; break; }
    kill -0 "$NEW_PID" 2>/dev/null || break
    sleep 0.2
done
[ "$NEW_READY" = "1" ] \
    && pass "the replacement (pid=$NEW_PID) announced it is waiting for the handover" \
    || fail "the replacement never reached the handover socket (see below)"
[ "$NEW_READY" = "1" ] || tail -20 "$WORK/new.log" | sed 's/^/    /'

echo "  sending SIGQUIT to $OLD_PID — the only signal this script sends"
T_QUIT="$(date +%s.%N)"
kill -QUIT "$OLD_PID"

DEPARTED=0
for _ in $(seq 1 240); do
    kill -0 "$OLD_PID" 2>/dev/null || { DEPARTED=1; break; }
    sleep 0.5
done
T_GONE="$(date +%s.%N)"
ELAPSED="$(python3 -c "print(round($T_GONE - $T_QUIT, 2))")"

if [ "$DEPARTED" = "1" ]; then
    if wait "$OLD_PID"; then OLD_STATUS=0; else OLD_STATUS=$?; fi
    [ "$OLD_STATUS" = "0" ] \
        && pass "the outgoing process left on its own after ${ELAPSED}s, exit status 0" \
        || fail "the outgoing process exited with status $OLD_STATUS, not 0"
else
    fail "the outgoing process was still alive 120s after SIGQUIT — it had to be killed"
    OLD_STATUS=-1
fi

# Close timeout (5s, Pingora's own) + the drain + 5s of runtime shutdown. The
# lower bound catches a drain that is skipped; the upper bound catches
# Pingora's unconditional 300s being inherited again.
DEPART_MIN=$((5 + DRAIN_SECS))
DEPART_MAX=$((5 + DRAIN_SECS + 5 + 15))
if python3 -c "import sys; sys.exit(0 if $DEPART_MIN <= $ELAPSED <= $DEPART_MAX else 1)"; then
    pass "it left inside the configured drain (${ELAPSED}s, expected ${DEPART_MIN}-${DEPART_MAX}s for drain_timeout_secs=$DRAIN_SECS)"
else
    fail "it left after ${ELAPSED}s, outside ${DEPART_MIN}-${DEPART_MAX}s — the drain budget is not the one configured"
fi

sleep 3
AFTER_LINE="$(listener_of "$PROXY_PORT")"
AFTER_INO="$(field_of 'ino:[0-9]+' "$AFTER_LINE")"
AFTER_HOLDER="$(field_of 'pid=[0-9]+' "$AFTER_LINE")"
echo "  listener after : $AFTER_INO held by $AFTER_HOLDER"

[ -n "$BEFORE_INO" ] && [ "$BEFORE_INO" = "$AFTER_INO" ] \
    && pass "the replacement inherited the same kernel socket ($AFTER_INO), it did not rebind" \
    || fail "the listening socket changed: before=$BEFORE_INO after=$AFTER_INO"
[ -n "$AFTER_HOLDER" ] && [ "$BEFORE_HOLDER" != "$AFTER_HOLDER" ] \
    && pass "and it is held by a different process now ($BEFORE_HOLDER -> $AFTER_HOLDER)" \
    || fail "the listener is still held by $AFTER_HOLDER; the handover did not happen"

POLLS="$(grep -c '' "$WORK/poll.txt" || true)"
GAPS="$(grep -c '^0$' "$WORK/poll.txt" || true)"
echo "  listener sampled $POLLS times across the handover"
[ "$POLLS" -gt 100 ] \
    && pass "the sampler ran ($POLLS samples), so its verdict means something" \
    || fail "the sampler only produced $POLLS samples; it did not cover the handover"
[ "$GAPS" = "0" ] \
    && pass "at no sampled instant was the port unlistened" \
    || fail "$GAPS of $POLLS samples found nothing listening on :$PROXY_PORT"

echo "  waiting for the load run to finish"
wait "$LOAD_PID" || true
kill "$POLL_PID" 2>/dev/null || true

python3 - "$WORK/load.json" "$T_QUIT" "$T_GONE" > "$WORK/verdict.txt" <<'PY'
import json, sys

recs = json.load(open(sys.argv[1], encoding="utf-8"))
quit_at, gone_at = float(sys.argv[2]), float(sys.argv[3])
# A request counts as "in the window" if any part of it overlapped the interval
# between the signal and the old process's departure.
window = [r for r in recs if r[1] >= quit_at and r[0] <= gone_at]
inflight = [r for r in recs if r[0] <= quit_at <= r[1]]


def emit(label, rows):
    bad = [r for r in rows if not (r[2] == 200 and not r[3])]
    print(f"{label}\t{len(rows)}\t{len(rows) - len(bad)}\t{len(bad)}")
    for r in bad[:5]:
        print(f"#\t{r}")


emit("whole-run", recs)
emit("upgrade-window", window)
emit("open-at-signal", inflight)
PY

echo
printf '  %-18s %6s %8s %8s\n' "sample" "sent" "ok" "failed"
grep -v '^#' "$WORK/verdict.txt" | while IFS=$'\t' read -r l s o f; do
    printf '  %-18s %6s %8s %8s\n' "$l" "$s" "$o" "$f"
done
grep '^#' "$WORK/verdict.txt" | sed 's/^#\t/    failure: /' || true

read_row() { grep "^$1	" "$WORK/verdict.txt" | cut -f"$2"; }

TOTAL="$(read_row whole-run 2)";       TOTAL_BAD="$(read_row whole-run 4)"
WIN="$(read_row upgrade-window 2)";    WIN_BAD="$(read_row upgrade-window 4)"
INFL="$(read_row open-at-signal 2)";   INFL_BAD="$(read_row open-at-signal 4)"

# The three guards below are what keep a green run from being a vacuous one: a
# load generator that sent nothing, or a handover so fast that nothing was in
# flight, would otherwise report zero failures and prove nothing.
[ "${TOTAL:-0}" -gt 50 ] \
    && pass "the load generator sent $TOTAL requests, so the counts below mean something" \
    || fail "only ${TOTAL:-0} requests were sent; too few to conclude anything"
[ "${TOTAL_BAD:-1}" = "0" ] \
    && pass "every one of the $TOTAL requests succeeded" \
    || fail "$TOTAL_BAD of $TOTAL requests failed across the run"
[ "${WIN:-0}" -gt 10 ] \
    && pass "$WIN requests overlapped the upgrade window" \
    || fail "only ${WIN:-0} requests overlapped the upgrade window; it was not exercised"
[ "${WIN_BAD:-1}" = "0" ] \
    && pass "none of the $WIN requests in the upgrade window failed" \
    || fail "$WIN_BAD of $WIN requests failed during the upgrade window"
[ "${INFL:-0}" -gt 0 ] \
    && pass "$INFL requests were open at the instant SIGQUIT was delivered" \
    || fail "no request was open when the signal landed; in-flight survival was not tested"
[ "${INFL_BAD:-1}" = "0" ] \
    && pass "all $INFL of them completed — the signal severed nothing" \
    || fail "$INFL_BAD of the $INFL requests open at the signal were severed"

# ── The listeners Pingora does not carry ─────────────────────────────────────
echo
echo "── Management plane on the replacement ──────────────────────────────────"
for _ in $(seq 1 60); do
    curl -sf -o /dev/null "http://127.0.0.1:$API_PORT/health" && break
    sleep 1
done

check_holder() { # $1=port $2=proto $3=label
    local line holder
    if [ "$2" = "udp" ]; then
        line="$(ss -Hulnp "sport = :$1" 2>/dev/null | tr -s ' ')"
    else
        line="$(ss -Htlnp "sport = :$1" 2>/dev/null | tr -s ' ')"
    fi
    holder="$(field_of 'pid=[0-9]+' "$line")"
    echo "  $3 :$1 -> ${holder:-nothing}"
    [ "$holder" = "pid=$NEW_PID" ] \
        && pass "$3 is bound on the replacement again" \
        || fail "$3 is on ${holder:-nothing}, not on the replacement (pid=$NEW_PID)"
}

[ "$(probe "$PROXY_PORT")" = "200" ] \
    && pass "the replacement is serving traffic on :$PROXY_PORT" \
    || fail "the replacement does not answer on :$PROXY_PORT"
check_holder "$API_PORT" tcp "admin API"
check_holder "$METRICS_PORT" tcp "metrics"
check_holder "$H3_PORT" udp "HTTP/3"

RETRIES="$(grep -c 'still held by the outgoing process' "$WORK/new.log" || true)"
echo "  the replacement retried those binds $RETRIES times while the old process held them"
[ "$RETRIES" -gt 0 ] \
    && pass "the bind-retry path was exercised, not merely present" \
    || fail "no bind retry was logged; the ports were free, so this run proves nothing about contention"

kill -INT "$NEW_PID" 2>/dev/null || true
for _ in $(seq 1 40); do kill -0 "$NEW_PID" 2>/dev/null || break; sleep 0.5; done
kill -9 "$NEW_PID" 2>/dev/null || true

# ═════════════════════════════════════════════════════════════════════════════
# Failure paths — every one of them must leave the running process serving
# ═════════════════════════════════════════════════════════════════════════════
echo
echo "── Failure paths ────────────────────────────────────────────────────────"

"$BIN" --config "$WORK/waf.toml" run > "$WORK/keeper.log" 2>&1 &
KEEPER_PID=$!
wait_serving "$PROXY_PORT" "$WORK/keeper.log" "$KEEPER_PID"
echo "  a process to protect: pid=$KEEPER_PID on :$PROXY_PORT"

still_serving() { # $1=case name
    local code; code="$(probe "$PROXY_PORT")"
    if kill -0 "$KEEPER_PID" 2>/dev/null && [ "$code" = "200" ]; then
        pass "$1: the running process is untouched and still answering 200"
    else
        fail "$1: the running process is alive=$(kill -0 "$KEEPER_PID" 2>/dev/null && echo yes || echo no) answering=$code"
    fi
}

# (a) unparseable config
printf 'this is not toml = = =\n' > "$WORK/broken.toml"
set +e
"$BIN" --config "$WORK/broken.toml" run --upgrade > "$WORK/f-broken.log" 2>&1
RC=$?
set -e
echo "  (a) unparseable config          -> exit $RC"
[ "$RC" != "0" ] \
    && pass "(a): a replacement that cannot read its config refuses to start" \
    || fail "(a): the replacement started anyway"
still_serving "(a)"

# (b) the handover socket would sit in a world-writable directory. Fatal on an
#     --upgrade launch: the handover is the only thing that launch is for.
gen_config "$WORK/unsafe.toml" "$PROXY_PORT" "$PROXY_TLS_PORT" "$H3_PORT" \
    "$API_PORT" "$METRICS_PORT" "/tmp/prx-waf-e2e-unsafe.sock"
set +e
PRXWAF_UPGRADE_SOCK= "$BIN" --config "$WORK/unsafe.toml" run --upgrade > "$WORK/f-unsafe.log" 2>&1
RC=$?
set -e
echo "  (b) unsafe handover directory   -> exit $RC"
[ "$RC" != "0" ] \
    && pass "(b): an --upgrade launch refuses a handover socket it cannot protect" \
    || fail "(b): the replacement accepted a world-writable handover directory"
# Both phrases, because a non-zero exit alone proves nothing about WHY: a config
# that failed to parse would also mention upgrade_sock and also exit 1. This is
# the mistake this script made on its first run.
if grep -q 'upgrade_sock' "$WORK/f-unsafe.log" \
   && grep -q 'cannot be used' "$WORK/f-unsafe.log"; then
    pass "(b): and it refused for the stated reason, naming the setting to change"
else
    fail "(b): the exit was not the directory refusal — see $WORK/f-unsafe.log"
    tail -10 "$WORK/f-unsafe.log" | sed 's/^/    /'
fi
still_serving "(b)"

# (c) the same unsafe directory on an ORDINARY start. Losing the ability to
#     upgrade in place must not stop a WAF from filtering traffic.
gen_config "$WORK/unsafe-plain.toml" "$ALT_PROXY_PORT" "$ALT_TLS_PORT" "$ALT_H3_PORT" \
    "$ALT_API_PORT" "$ALT_METRICS_PORT" "/tmp/prx-waf-e2e-unsafe.sock"
PRXWAF_UPGRADE_SOCK= "$BIN" --config "$WORK/unsafe-plain.toml" run > "$WORK/f-plain.log" 2>&1 &
PLAIN_PID=$!
if wait_serving "$ALT_PROXY_PORT" "$WORK/f-plain.log" "$PLAIN_PID"; then
    pass "(c): the same unsafe directory on an ordinary start still serves traffic"
else
    fail "(c): an unsafe handover directory stopped an ordinary start"
fi
grep -q 'Graceful upgrade is UNAVAILABLE' "$WORK/f-plain.log" \
    && pass "(c): and it says the upgrade path is the thing that was lost" \
    || fail "(c): nothing in the log explains that upgrades are unavailable"
kill -INT "$PLAIN_PID" 2>/dev/null || true
for _ in $(seq 1 40); do kill -0 "$PLAIN_PID" 2>/dev/null || break; sleep 0.5; done
kill -9 "$PLAIN_PID" 2>/dev/null || true
still_serving "(c)"

# (d) the replacement waits and is never signalled.
if [ "$SKIP_SLOW" = "1" ]; then
    echo "  (d) skipped (SKIP_SLOW=1)"
else
    echo "  (d) replacement waits, no SIGQUIT ever sent — this takes ~60s"
    set +e
    "$BIN" --config "$WORK/waf.toml" run --upgrade > "$WORK/f-timeout.log" 2>&1
    RC=$?
    set -e
    echo "  (d) unanswered handover         -> exit $RC"
    [ "$RC" != "0" ] \
        && pass "(d): a replacement nobody answers gives up and exits" \
        || fail "(d): the replacement returned 0 without ever receiving a listener"
    still_serving "(d)"
fi

kill -INT "$KEEPER_PID" 2>/dev/null || true

echo
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
