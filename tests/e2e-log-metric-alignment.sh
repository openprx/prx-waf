#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# PRX-WAF End-to-End log ↔ metric alignment test
#
# The claim under test is the one `docs/logs-and-metrics.md` is written to
# support: an operator who sees a series move can find the same requests in the
# log by grepping the token the series is labelled with.
#
# So this drives one real daemon with a batch of real requests covering the
# outcomes that share a label, then — from the *same* run — reconciles the
# `/metrics` deltas against `grep` counts over the process log. A row passes
# only when both sides report the same number for the same word.
#
#   requests | outcome                        | metric                                   | log token
#   ---------|--------------------------------|------------------------------------------|-----------
#   3        | clean GET, relayed by origin   | requests_total{action="allow"}            | (none — an allow is the absence of a decision)
#   2        | SQLi in the query              | requests_total{action="block"}            | action="block" + phase="sql_injection"
#   2        | host matching no route → 404   | requests_total{action="block"}            | action="block"
#   1        | site closed is NOT exercised   | —                                        | —
#   1        | duplicate Host → 400           | requests_total{action="block"}            | action="block"
#   1        | body over the ceiling → 413    | requests_total{action="block"}            | action="block"
#   1        | oversize header fold → 431     | requests_total{action="block"}            | action="block"
#
# Before this pass the five non-detection refusals contributed to
# `action="block"` and wrote no line containing the word, which is the whole
# finding; the assertion below is that the counts now agree.
#
# It also checks the host fold: the daemon runs with `max_host_labels = 2`, the
# traffic uses more than two hostnames, and the run asserts that (a) the
# exposition holds exactly three host label values including `__other__`, and
# (b) the log carries exactly one line announcing the fold.
#
# Prerequisites:
#   - cargo build -p prx-waf   (or --release; set BIN=)
#   - python3 (stands in for the origin)
#   - a reachable Postgres; the daemon migrates it itself
#
# Usage:
#   ./tests/e2e-log-metric-alignment.sh
#   DATABASE_URL=postgresql://user:pw@host:5432/db ./tests/e2e-log-metric-alignment.sh
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

BIN="${BIN:-target/debug/prx-waf}"
DATABASE_URL="${DATABASE_URL:-postgresql://prx_waf:prx_waf@127.0.0.1:15632/prx_waf}"
HTTP_PORT="${HTTP_PORT:-18781}"
TLS_PORT="${TLS_PORT:-18782}"
ORIGIN_PORT="${ORIGIN_PORT:-18783}"
API_PORT="${API_PORT:-19781}"
# Deliberately not the shipped default, so the test cannot pass against a
# daemon someone else left running.
METRICS_PORT="${METRICS_PORT:-19782}"

ROUTED_HOST="align-a.test"
ROUTED_HOST_B="align-b.test"
UNKNOWN_HOST="align-unrouted.test"
FOLD_HOST_1="align-fold-1.test"
FOLD_HOST_2="align-fold-2.test"

# Two named hosts plus `__other__` is the whole label set; every hostname past
# the second folds. Small enough that four hostnames prove it.
MAX_HOST_LABELS=2
# The body-inspection ceiling, lowered so a 413 costs two kilobytes rather than
# ten megabytes. The overflow policy stays at its fail-closed default.
INSPECT_CAP=1024
# A browser-shaped agent: the bot detector blocks `curl/*` outright, and this
# test is about accounting, not about bot detection.
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36'

PASS=0
FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

# ── Preconditions ─────────────────────────────────────────────────────────────
command -v python3 >/dev/null || { echo "ERROR: python3 not found" >&2; exit 1; }
[ -x "$BIN" ] || { echo "ERROR: $BIN not found; run: cargo build -p prx-waf" >&2; exit 1; }
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

WORK="$(mktemp -d)"
ORIGIN_PID=""
cleanup() {
    # Pingora's bootstrap forks, so the recorded pid is not the process holding
    # the ports. Match on this run's config path, which is unique to $WORK.
    pkill -9 -f "$WORK/waf.toml" 2>/dev/null || true
    [ -n "$ORIGIN_PID" ] && kill -9 "$ORIGIN_PID" 2>/dev/null || true
    # A failing run is worked on by reading the log and the two scrapes side by
    # side, and deleting them is exactly the wrong default when that happens.
    if [ -n "${KEEP_WORK:-}" ]; then
        echo "KEEP_WORK: artifacts left in $WORK" >&2
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

# ── Origin ────────────────────────────────────────────────────────────────────
cat > "$WORK/origin.py" <<'PY'
import http.server, sys

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self):
        body = b"ORIGIN-REACHED\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _reply

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self._reply()

    def log_message(self, fmt, *args):
        print("ORIGIN " + (fmt % args), flush=True)

http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY
python3 "$WORK/origin.py" "$ORIGIN_PORT" > "$WORK/origin.log" 2>&1 &
ORIGIN_PID=$!
disown "$ORIGIN_PID" 2>/dev/null || true

cat > "$WORK/waf.toml" <<EOF
[proxy]
listen_addr = "127.0.0.1:$HTTP_PORT"
# Required by the schema; this test drives plaintext HTTP/1.1 only, so the TLS
# listener is pointed at an unused loopback port rather than the 0.0.0.0:443
# default, which would need root and would be a surprise on a developer's box.
listen_addr_tls = "127.0.0.1:$TLS_PORT"
worker_threads = 2

[api]
listen_addr = "127.0.0.1:$API_PORT"

[metrics]
enabled = true
listen_addr = "127.0.0.1:$METRICS_PORT"
max_host_labels = $MAX_HOST_LABELS

[storage]
database_url = "$DATABASE_URL"
max_connections = 5

[[hosts]]
host = "$ROUTED_HOST"
port = $HTTP_PORT
ssl = false
remote_host = "127.0.0.1"
remote_port = $ORIGIN_PORT

[[hosts]]
host = "$ROUTED_HOST_B"
port = $HTTP_PORT
ssl = false
remote_host = "127.0.0.1"
remote_port = $ORIGIN_PORT
EOF

# ── Daemon ────────────────────────────────────────────────────────────────────
JWT_SECRET="${JWT_SECRET:-e2e-log-metric-alignment-secret-0123456789abcdef}" \
PRXWAF_BODY_INSPECT_MAX_BYTES="$INSPECT_CAP" \
    "$BIN" --config "$WORK/waf.toml" run > "$WORK/waf.log" 2>&1 &

for _ in $(seq 1 60); do
    curl -sf "http://127.0.0.1:$METRICS_PORT/metrics" -o /dev/null && break
    sleep 1
done
if ! curl -sf "http://127.0.0.1:$METRICS_PORT/metrics" -o /dev/null; then
    echo "ERROR: no metrics endpoint on 127.0.0.1:$METRICS_PORT" >&2
    tail -30 "$WORK/waf.log" >&2
    exit 1
fi

scrape() { curl -s "http://127.0.0.1:$METRICS_PORT/metrics"; }

# `name{labels} value`, or 0 when the series has never been touched.
value_of() {
    awk -v want="$1$2 " 'index($0, want) == 1 { print $NF; found = 1 }
                         END { if (!found) print 0 }' "$3"
}

req() {
    local host="$1"; shift
    curl -s -o /dev/null --http1.1 -A "$UA" \
        --resolve "$host:$HTTP_PORT:127.0.0.1" \
        -w '%{http_code}\n' "$@" || echo "000"
}

scrape > "$WORK/before.txt"
LOG_LINES_BEFORE="$(wc -l < "$WORK/waf.log")"

# ── Drive the batch ───────────────────────────────────────────────────────────
echo "Driving the batch: 3 benign, 2 attack, 6 refusals, across 5 hostnames"

echo "  benign x3"
for i in 1 2 3; do
    printf '    GET %s /probe?n=%s -> %s\n' "$ROUTED_HOST" "$i" \
        "$(req "$ROUTED_HOST" "http://$ROUTED_HOST:$HTTP_PORT/probe?n=$i")"
done

echo "  SQLi x2"
for i in 1 2; do
    printf "    GET %s /search?q=' OR 1=1-- -> %s\n" "$ROUTED_HOST" \
        "$(req "$ROUTED_HOST" --get --data-urlencode "q=' OR 1=1-- -" \
            "http://$ROUTED_HOST:$HTTP_PORT/search")"
done

echo "  unrouted host x2"
for i in 1 2; do
    printf '    GET %s / -> %s\n' "$UNKNOWN_HOST" \
        "$(req "$UNKNOWN_HOST" "http://$UNKNOWN_HOST:$HTTP_PORT/")"
done

# Two more distinct hostnames, past the bound. They are unrouted (404) because
# what is being exercised is the label table, not the router — `resolve_host`
# runs before routing precisely so that 404 volume is attributable per requested
# hostname. These are the requests that make the fold happen; the refusals below
# do not, because duplicate-Host and over-long-fold are both answered *before* a
# host is resolved at all, which is why they land on `__other__` without ever
# having been folded into it.
echo "  past-the-bound hostnames x2"
for h in "$FOLD_HOST_1" "$FOLD_HOST_2"; do
    printf '    GET %s / -> %s\n' "$h" "$(req "$h" "http://$h:$HTTP_PORT/")"
done

echo "  duplicate Host x1"
# curl folds a `-H Host:` into the one it derives from the URL, so two Host
# lines have to be written onto the socket directly.
python3 - "$FOLD_HOST_1" "$HTTP_PORT" <<'PY' || true
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
req = (f"GET /dup HTTP/1.1\r\nHost: {host}\r\nHost: evil.invalid\r\n"
       f"Connection: close\r\n\r\n").encode()
s = socket.create_connection(("127.0.0.1", port), timeout=10)
s.sendall(req)
print("   ", s.recv(64).split(b"\r\n")[0].decode(errors="replace"))
s.close()
PY

echo "  over-ceiling body x1"
head -c $((INSPECT_CAP * 4)) /dev/zero | tr '\0' 'A' > "$WORK/big.txt"
printf '    POST %s /upload (%s bytes) -> %s\n' "$ROUTED_HOST" "$((INSPECT_CAP * 4))" \
    "$(req "$ROUTED_HOST" -X POST --data-binary "@$WORK/big.txt" \
        -H 'Content-Type: text/plain' "http://$ROUTED_HOST:$HTTP_PORT/upload")"

echo "  oversize header fold x1"
python3 - "$FOLD_HOST_2" "$HTTP_PORT" <<'PY' || true
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
# 40 KiB across one repeated header name: over the 32 KiB fold ceiling.
chunk = "x" * 4096
lines = "".join(f"X-Pad: {chunk}\r\n" for _ in range(10))
req = (f"GET /fold HTTP/1.1\r\nHost: {host}\r\n{lines}Connection: close\r\n\r\n").encode()
s = socket.create_connection(("127.0.0.1", port), timeout=10)
s.sendall(req)
data = s.recv(64)
print("   ", data.split(b"\r\n")[0].decode(errors="replace"))
s.close()
PY

sleep 2
scrape > "$WORK/after.txt"

# ── Reconcile ─────────────────────────────────────────────────────────────────
echo
echo "Metrics vs log, same run"

delta() {
    local before after
    before="$(value_of "$1" "$2" "$WORK/before.txt")"
    after="$(value_of "$1" "$2" "$WORK/after.txt")"
    awk -v a="$after" -v b="$before" 'BEGIN { printf "%d", a - b }'
}

# Only the lines this batch produced.
tail -n "+$((LOG_LINES_BEFORE + 1))" "$WORK/waf.log" > "$WORK/window.log"

# The five refusal paths plus the two detection blocks all land on
# `action="block"`. Summed over every host label, because the fold means the
# hostnames are not individually addressable.
metric_block="$(awk '/^prxwaf_requests_total\{/ && /action="block"/ { n += $NF } END { print n + 0 }' "$WORK/after.txt")"
metric_block_before="$(awk '/^prxwaf_requests_total\{/ && /action="block"/ { n += $NF } END { print n + 0 }' "$WORK/before.txt")"
metric_block_delta=$((metric_block - metric_block_before))
log_block="$(grep -c 'action="block"' "$WORK/window.log" || true)"

echo "  requests_total{action=\"block\"} delta = $metric_block_delta"
echo "  log lines carrying action=\"block\" = $log_block"
if [ "$metric_block_delta" -eq "$log_block" ] && [ "$metric_block_delta" -gt 0 ]; then
    pass "every counted block wrote a log line spelling the metric's own label"
else
    fail "block counter and block log lines disagree ($metric_block_delta vs $log_block)"
fi

# The detection blocks additionally carry the phase, spelled as the metric
# spells it.
metric_sqli="$(delta 'prxwaf_detections_total' '{phase="sql_injection",action="block"}')"
log_sqli="$(grep -c 'phase="sql_injection"' "$WORK/window.log" || true)"
echo "  detections_total{phase=\"sql_injection\",action=\"block\"} delta = $metric_sqli"
echo "  log lines carrying phase=\"sql_injection\" = $log_sqli"
if [ "$metric_sqli" -eq "$log_sqli" ] && [ "$metric_sqli" -gt 0 ]; then
    pass "the phase label and the phase log field are the same word and the same count"
else
    fail "sql_injection phase disagrees ($metric_sqli vs $log_sqli)"
fi

# Budget counters that the refusals must also have moved, each named by the
# `(subsystem, limit)` pair `docs/dos-budget.md` documents.
for pair in \
    'request_headers|duplicate_host' \
    'request_headers|folded_bytes' \
    'request_body|inspect_ceiling_reject'
do
    subsystem="${pair%%|*}"; limit="${pair##*|}"
    d="$(delta 'prxwaf_budget_events_total' "{subsystem=\"$subsystem\",limit=\"$limit\"}")"
    if [ "$d" -ge 1 ]; then
        pass "budget_events_total{subsystem=\"$subsystem\", limit=\"$limit\"} moved by $d"
    else
        fail "budget_events_total{subsystem=\"$subsystem\", limit=\"$limit\"} did not move"
    fi
done

# ── The host fold ─────────────────────────────────────────────────────────────
echo
echo "Host label fold, bound = $MAX_HOST_LABELS"
host_labels="$(grep -o 'prxwaf_requests_total{host="[^"]*"' "$WORK/after.txt" \
    | sed 's/.*host="\([^"]*\)".*/\1/' | sort -u)"
n_labels="$(printf '%s\n' "$host_labels" | grep -c . || true)"
echo "  distinct host label values: $n_labels"
printf '    %s\n' $host_labels
if [ "$n_labels" -eq $((MAX_HOST_LABELS + 1)) ]; then
    pass "exactly max_host_labels + 1 host label values, whatever the traffic sent"
else
    fail "expected $((MAX_HOST_LABELS + 1)) host label values, got $n_labels"
fi
if printf '%s\n' "$host_labels" | grep -qx '__other__'; then
    pass "the fold bucket is present and spelled __other__"
else
    fail "no __other__ bucket, so nothing folded"
fi

fold_warnings="$(grep -c 'Metrics host labels exhausted' "$WORK/waf.log" || true)"
echo "  log lines announcing the fold: $fold_warnings"
if [ "$fold_warnings" -eq 1 ]; then
    pass "the fold is announced exactly once per process"
else
    fail "expected exactly one fold announcement, got $fold_warnings"
fi

# ── The words themselves ──────────────────────────────────────────────────────
echo
echo "Log excerpt (the lines a dashboard sends you to)"
grep -E 'action="(block|redirect)"|Metrics host labels exhausted' "$WORK/window.log" \
    | sed 's/^/    /' || true

echo
echo "Metric excerpt"
grep -E '^prxwaf_requests_total\{|^prxwaf_detections_total\{.*action="block"\} [1-9]' "$WORK/after.txt" \
    | sed 's/^/    /' || true

echo
echo "PASS: $PASS   FAIL: $FAIL"
[ "$FAIL" -eq 0 ]
