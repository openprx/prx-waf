#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# PRX-WAF End-to-End HTTP/3 RED metrics test
#
# Drives a real prx-waf process with a real HTTP/3 client (curl over QUIC),
# produces four different request outcomes, and then scrapes `/metrics` and
# reconciles it request by request.
#
# The property under test is "exactly once, on the HTTP/1.1 labels". HTTP/1.1
# records from Pingora's `logging()` callback, which runs once per request on
# every completion path; the H3 forwarder does not run under Pingora and has no
# such callback, so its recording point is a wrapper around the handler
# (`crates/gateway/src/http3.rs`). A wrapper is only correct if *every* return
# path funnels through it, which is what the reconciliation below checks:
# eight requests sent, eight counted, each on the series its outcome names.
#
# The outcomes exercised, and the label each must land on:
#
#   requests | protocol | outcome                       | action | status class
#   ---------|----------|-------------------------------|--------|-------------
#   3        | HTTP/3   | routed, relayed by the origin | allow  | 2xx
#   1        | HTTP/3   | WAF block (SQLi in the query) | block  | 4xx
#   1        | HTTP/3   | body over the inspection cap  | block  | 4xx (413)
#   2        | HTTP/3   | authority matching no route   | block  | 4xx (404)
#   1        | HTTP/1.1 | host matching no route        | block  | 4xx (404)
#
# The last row is the cross-protocol control: the same outcome driven over
# HTTP/1.1 has to produce the same action label and the same host-label
# convention, or the two protocols cannot share a dashboard.
#
# Counts are taken as before/after deltas, so nothing else the daemon does
# during the run can be mistaken for the traffic this test sent.
#
# NOT covered here: the 503 an administratively closed site answers. That flag
# (`start_status`) has no config-file spelling — `waf_common::config::HostEntry`
# does not carry it — so a closed site can only be produced through the admin
# API or a database row, which is a different test's setup cost. Its accounting
# is asserted in the unit table in `crates/gateway/src/http3.rs`.
#
# Prerequisites:
#   - cargo build -p prx-waf   (or --release; set BIN=)
#   - curl built with HTTP3 (check: curl --version | grep -o HTTP3)
#   - python3 (stands in for the origin)
#   - a reachable Postgres; the daemon migrates it itself
#
# Usage:
#   ./tests/e2e-http3-red-metrics.sh
#   DATABASE_URL=postgresql://user:pw@host:5432/db ./tests/e2e-http3-red-metrics.sh
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

BIN="${BIN:-target/debug/prx-waf}"
DATABASE_URL="${DATABASE_URL:-postgresql://prx_waf:prx_waf@127.0.0.1:15432/prx_waf}"
H3_PORT="${H3_PORT:-18543}"
ORIGIN_PORT="${ORIGIN_PORT:-18599}"
API_PORT="${API_PORT:-19627}"
HTTP_PORT="${HTTP_PORT:-18580}"
# Deliberately not the shipped default: this test must not depend on which port
# `configs/default.toml` happens to name.
METRICS_PORT="${METRICS_PORT:-19699}"
ROUTED_HOST="h3red.test"
UNKNOWN_HOST="unrouted.test"
# Both protocols intern the authority the *client* sent, verbatim — HTTP/1.1
# from the `Host` line, HTTP/3 from `:authority` — so on a non-default port the
# label carries the port on both. On 443 neither does, and a site reached over
# both protocols lands on one series.
ROUTED_LABEL="$ROUTED_HOST:$H3_PORT"
UNKNOWN_H3_LABEL="$UNKNOWN_HOST:$H3_PORT"
UNKNOWN_H1_LABEL="$UNKNOWN_HOST:$HTTP_PORT"
# The body-inspection ceiling, lowered so a 413 costs two kilobytes instead of
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
if ! curl --version | grep -qw HTTP3; then
    echo "SKIP: this curl has no HTTP/3 support (curl --version | grep HTTP3)" >&2
    exit 0
fi
for tool in python3 openssl; do
    command -v "$tool" >/dev/null || { echo "ERROR: $tool not found" >&2; exit 1; }
done
[ -x "$BIN" ] || { echo "ERROR: $BIN not found; run: cargo build -p prx-waf" >&2; exit 1; }
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

WORK="$(mktemp -d)"
ORIGIN_PID=""
cleanup() {
    # Pingora's bootstrap forks, so the recorded pid is not the process holding
    # the ports. Match on this run's config path, which is unique to $WORK.
    pkill -9 -f "$WORK/waf.toml" 2>/dev/null || true
    [ -n "$ORIGIN_PID" ] && kill -9 "$ORIGIN_PID" 2>/dev/null || true
    rm -rf "$WORK"
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
# The cleanup trap SIGKILLs it, and a still-tracked job prints "Killed" after
# the last line of output, where it reads as a test failure. It is not one.
disown "$ORIGIN_PID" 2>/dev/null || true

# ── TLS material for the QUIC listener ───────────────────────────────────────
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
    -subj "/CN=$ROUTED_HOST" \
    -addext "subjectAltName=DNS:$ROUTED_HOST,DNS:$UNKNOWN_HOST" \
    >/dev/null 2>&1

cat > "$WORK/waf.toml" <<EOF
[proxy]
listen_addr = "127.0.0.1:$HTTP_PORT"
listen_addr_tls = "127.0.0.1:$H3_PORT"
worker_threads = 2

[api]
listen_addr = "127.0.0.1:$API_PORT"

[metrics]
enabled = true
listen_addr = "127.0.0.1:$METRICS_PORT"
max_host_labels = 128

[storage]
database_url = "$DATABASE_URL"
max_connections = 5

[http3]
enabled = true
listen_addr = "127.0.0.1:$H3_PORT"
cert_pem = "$WORK/cert.pem"
key_pem = "$WORK/key.pem"

[[hosts]]
host = "$ROUTED_HOST"
port = $H3_PORT
ssl = false
remote_host = "127.0.0.1"
remote_port = $ORIGIN_PORT
EOF

# ── Daemon ────────────────────────────────────────────────────────────────────
JWT_SECRET="${JWT_SECRET:-e2e-http3-red-metrics-secret-0123456789abcdef}" \
PRXWAF_BODY_INSPECT_MAX_BYTES="$INSPECT_CAP" \
    "$BIN" --config "$WORK/waf.toml" run > "$WORK/waf.log" 2>&1 &

for _ in $(seq 1 60); do
    grep -qE "HTTP/3 listener on|HTTP/3 server error" "$WORK/waf.log" && break
    sleep 1
done
if ! grep -q "HTTP/3 listener on" "$WORK/waf.log"; then
    echo "ERROR: the HTTP/3 listener never came up; last lines of the daemon log:" >&2
    tail -20 "$WORK/waf.log" >&2
    exit 1
fi
for _ in $(seq 1 30); do
    curl -sf "http://127.0.0.1:$METRICS_PORT/metrics" -o /dev/null && break
    sleep 1
done

scrape() { curl -s "http://127.0.0.1:$METRICS_PORT/metrics"; }

# `name{labels} value`, or 0 when the series has never been touched — a counter
# at zero is not exported.
value_of() {
    awk -v want="$1$2 " 'index($0, want) == 1 { print $NF; found = 1 }
                         END { if (!found) print 0 }' "$3"
}

if ! scrape > "$WORK/before.txt" || [ ! -s "$WORK/before.txt" ]; then
    echo "ERROR: no metrics endpoint on 127.0.0.1:$METRICS_PORT" >&2
    tail -20 "$WORK/waf.log" >&2
    exit 1
fi

h3() {
    local host="$1"; shift
    curl -s -o /dev/null --http3-only -k -A "$UA" \
        --resolve "$host:$H3_PORT:127.0.0.1" \
        -w '%{http_code} h%{http_version}\n' "$@" || echo "000 -"
}

h1() {
    local host="$1"; shift
    curl -s -o /dev/null --http1.1 -A "$UA" \
        --resolve "$host:$HTTP_PORT:127.0.0.1" \
        -w '%{http_code} h%{http_version}\n' "$@" || echo "000 -"
}

# ── Drive the outcomes ────────────────────────────────────────────────────────
echo "Driving seven HTTP/3 requests across four outcomes, plus one HTTP/1.1 control"

for i in 1 2 3; do
    r="$(h3 "$ROUTED_HOST" "https://$ROUTED_HOST:$H3_PORT/probe?n=$i")"
    echo "  h3 relay $i          -> $r"
    [ "${r%% *}" = "200" ] && [ "${r##* }" = "h3" ] \
        || fail "relay $i: expected 200 over HTTP/3, got '$r'"
done

r="$(h3 "$ROUTED_HOST" --get --data-urlencode "id=1' OR '1'='1' -- " \
        "https://$ROUTED_HOST:$H3_PORT/probe")"
echo "  h3 waf block         -> $r"
case "${r%% *}" in
    4??) pass "the WAF answered the SQLi probe itself (${r%% *})" ;;
    *)   fail "expected a 4xx WAF block, got '$r'" ;;
esac

head -c $((INSPECT_CAP * 2)) /dev/zero | tr '\0' 'a' > "$WORK/body.txt"
r="$(h3 "$ROUTED_HOST" -X POST --data-binary "@$WORK/body.txt" \
        -H 'content-type: text/plain' "https://$ROUTED_HOST:$H3_PORT/upload")"
echo "  h3 body over cap     -> $r"
[ "${r%% *}" = "413" ] \
    && pass "a body over the ${INSPECT_CAP}-byte inspection cap is refused with 413" \
    || fail "expected 413, got '$r'"

for i in 1 2; do
    r="$(h3 "$UNKNOWN_HOST" "https://$UNKNOWN_HOST:$H3_PORT/probe")"
    echo "  h3 unknown authority -> $r"
    [ "${r%% *}" = "404" ] \
        || fail "unknown authority $i: expected 404, got '$r'"
done

r="$(h1 "$UNKNOWN_HOST" "http://$UNKNOWN_HOST:$HTTP_PORT/probe")"
echo "  h1 unknown host      -> $r"
[ "${r%% *}" = "404" ] && [ "${r##* }" = "h1.1" ] \
    && pass "the HTTP/1.1 control refused the same authority with 404" \
    || fail "HTTP/1.1 control: expected 404 over HTTP/1.1, got '$r'"

# The duration histogram is observed after the response is written, and the
# client returns as soon as it has the body.
sleep 2
scrape > "$WORK/after.txt"

# ── Reconcile ─────────────────────────────────────────────────────────────────
echo
echo "Reconciliation (after - before):"
printf '  %-64s %6s %8s\n' "series" "sent" "counted"

check() {
    local metric="$1" labels="$2" expected="$3" b a got
    b="$(value_of "$metric" "$labels" "$WORK/before.txt")"
    a="$(value_of "$metric" "$labels" "$WORK/after.txt")"
    got=$((a - b))
    printf '  %-64s %6s %8s\n' "$metric$labels" "$expected" "$got"
    [ "$got" = "$expected" ] \
        && pass "$metric$labels == $expected" \
        || fail "$metric$labels: sent $expected, counted $got"
}

R=prxwaf_requests_total
S=prxwaf_responses_total
D=prxwaf_request_duration_seconds_count

# Requests, by the WAF's decision. Three allows and two blocks on the routed
# host, two blocks for the unrouted authority over HTTP/3, one over HTTP/1.1.
check "$R" "{host=\"$ROUTED_LABEL\",action=\"allow\"}"    3
check "$R" "{host=\"$ROUTED_LABEL\",action=\"block\"}"    2
check "$R" "{host=\"$UNKNOWN_H3_LABEL\",action=\"block\"}" 2
check "$R" "{host=\"$UNKNOWN_H1_LABEL\",action=\"block\"}" 1

# Nothing landed on the other two actions, and nothing landed on the fold: every
# one of these requests carried a routable-looking authority, so a count in
# `__other__` would mean the host label was resolved from the wrong place.
check "$R" "{host=\"$ROUTED_LABEL\",action=\"log_only\"}" 0
check "$R" "{host=\"$ROUTED_LABEL\",action=\"redirect\"}" 0
check "$R" '{host="__other__",action="allow"}' 0
check "$R" '{host="__other__",action="block"}' 0

# Responses, by the status actually written. The 413 and the WAF block are both
# 4xx on the routed host; nothing 5xx'd, so the origin was reached every time it
# should have been.
check "$S" "{host=\"$ROUTED_LABEL\",status=\"2xx\"}"    3
check "$S" "{host=\"$ROUTED_LABEL\",status=\"4xx\"}"    2
check "$S" "{host=\"$ROUTED_LABEL\",status=\"5xx\"}"    0
check "$S" "{host=\"$UNKNOWN_H3_LABEL\",status=\"4xx\"}" 2
check "$S" "{host=\"$UNKNOWN_H1_LABEL\",status=\"4xx\"}" 1

# Durations: one observation per request, refusals included — the histogram
# starts before routing, so a 404 for an unrouted authority is in it.
check "$D" "{host=\"$ROUTED_LABEL\"}"    5
check "$D" "{host=\"$UNKNOWN_H3_LABEL\"}" 2
check "$D" "{host=\"$UNKNOWN_H1_LABEL\"}" 1

# Whole-endpoint arithmetic: eight requests in, eight counted, nowhere else.
sum_of() {
    awk -v m="$1{" 'index($0, m) == 1 { sum += $NF } END { printf "%d", sum }' "$2"
}
moved=$(( $(sum_of "$R" "$WORK/after.txt") - $(sum_of "$R" "$WORK/before.txt") ))
printf '  %-64s %6s %8s\n' "$R (every series summed)" 8 "$moved"
[ "$moved" = "8" ] \
    && pass "eight requests sent, eight counted across the whole metric" \
    || fail "sent 8, the metric moved by $moved"

moved_responses=$(( $(sum_of "$S" "$WORK/after.txt") - $(sum_of "$S" "$WORK/before.txt") ))
printf '  %-64s %6s %8s\n' "$S (every series summed)" 8 "$moved_responses"
[ "$moved_responses" = "8" ] \
    && pass "every request wrote exactly one response" \
    || fail "sent 8, the response metric moved by $moved_responses"

echo
echo "── RED series, verbatim from the scrape ─────────────────────────────────"
grep -E "^(prxwaf_requests_total|prxwaf_responses_total|prxwaf_request_duration_seconds_count)\{" \
    "$WORK/after.txt" | sed 's/^/  /'

echo
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
