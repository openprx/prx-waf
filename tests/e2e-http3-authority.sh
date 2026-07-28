#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# PRX-WAF End-to-End HTTP/3 routing test
#
# Drives a real prx-waf process with a real HTTP/3 client (curl over QUIC) and
# asserts the two properties the H3 route resolver has to hold at once:
#
#   1. A compliant request — `:authority` pseudo-header, NO Host header, which
#      is what RFC 9114 §4.3.1 tells clients to send — is routed to the host's
#      configured upstream, and the origin sees the requested authority as its
#      Host. Before the `:authority` fix this 404'd, so every HTTP/3 request to
#      every route did.
#   2. An authority matching no configured route is still refused with 404 and
#      never reaches an upstream (audit H-7: no default-config fall-through).
#
# Prerequisites:
#   - cargo build -p prx-waf   (or --release; set BIN=)
#   - curl built with HTTP3 (check: curl --version | grep -o HTTP3)
#   - python3 (stands in for the origin)
#   - a reachable Postgres; the daemon migrates it itself
#
# Usage:
#   ./tests/e2e-http3-authority.sh
#   DATABASE_URL=postgresql://user:pw@host:5432/db ./tests/e2e-http3-authority.sh
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

BIN="${BIN:-target/debug/prx-waf}"
DATABASE_URL="${DATABASE_URL:-postgresql://prx_waf:prx_waf@127.0.0.1:15432/prx_waf}"
H3_PORT="${H3_PORT:-18443}"
ORIGIN_PORT="${ORIGIN_PORT:-18099}"
API_PORT="${API_PORT:-19527}"
HTTP_PORT="${HTTP_PORT:-18080}"
KNOWN_HOST="h3.test"
UNKNOWN_HOST="evil.test"
# A browser-shaped agent: the bot detector blocks `curl/*` outright, and this
# test is about routing, not about bot detection.
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

# ── Origin: echoes back the Host header the WAF forwarded ────────────────────
cat > "$WORK/origin.py" <<'PY'
import http.server, sys

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = ("ORIGIN-REACHED\nhost-header=%s\npath=%s\n"
                % (self.headers.get("Host"), self.path)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("ORIGIN " + (fmt % args), flush=True)

http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY
python3 "$WORK/origin.py" "$ORIGIN_PORT" > "$WORK/origin.log" 2>&1 &
ORIGIN_PID=$!

# ── TLS material for the QUIC listener ───────────────────────────────────────
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
    -subj "/CN=$KNOWN_HOST" -addext "subjectAltName=DNS:$KNOWN_HOST,DNS:$UNKNOWN_HOST" \
    >/dev/null 2>&1

cat > "$WORK/waf.toml" <<EOF
[proxy]
listen_addr = "127.0.0.1:$HTTP_PORT"
listen_addr_tls = "127.0.0.1:$H3_PORT"
worker_threads = 2

[api]
listen_addr = "127.0.0.1:$API_PORT"

[storage]
database_url = "$DATABASE_URL"
max_connections = 5

[http3]
enabled = true
listen_addr = "127.0.0.1:$H3_PORT"
cert_pem = "$WORK/cert.pem"
key_pem = "$WORK/key.pem"

[[hosts]]
host = "$KNOWN_HOST"
port = $H3_PORT
ssl = false
remote_host = "127.0.0.1"
remote_port = $ORIGIN_PORT
EOF

# ── Daemon ────────────────────────────────────────────────────────────────────
JWT_SECRET="${JWT_SECRET:-e2e-http3-authority-secret-0123456789abcdef}" \
    "$BIN" --config "$WORK/waf.toml" run > "$WORK/waf.log" 2>&1 &

for _ in $(seq 1 60); do
    grep -qE "HTTP/3 listener on|HTTP/3 server error" "$WORK/waf.log" && break
    sleep 1
done
# A stale daemon on $H3_PORT would make every assertion below measure the wrong
# process, so a failed bind is a hard error rather than a test failure.
if ! grep -q "HTTP/3 listener on" "$WORK/waf.log"; then
    echo "ERROR: the HTTP/3 listener never came up; last lines of the daemon log:" >&2
    tail -20 "$WORK/waf.log" >&2
    exit 1
fi

# ── 1. Compliant request to a configured authority ───────────────────────────
echo "Test 1: :authority alone reaches the configured upstream"
body="$(curl -s --http3-only -k -A "$UA" \
    --resolve "$KNOWN_HOST:$H3_PORT:127.0.0.1" \
    -w '\nHTTP_STATUS=%{http_code}\nALPN_VERSION=%{http_version}\n' \
    "https://$KNOWN_HOST:$H3_PORT/probe" || true)"
echo "$body" | sed 's/^/    /'

echo "$body" | grep -q 'ALPN_VERSION=3' \
    && pass "the request really was HTTP/3" \
    || fail "curl did not negotiate HTTP/3"
echo "$body" | grep -q 'HTTP_STATUS=200' \
    && pass "routed and proxied (200)" \
    || fail "expected 200; the :authority route did not resolve"
echo "$body" | grep -q "host-header=$KNOWN_HOST:$H3_PORT" \
    && pass "origin saw the requested authority as its Host" \
    || fail "origin saw the wrong Host — vhosts behind this route would break"

# ── 2. Unknown authority is refused and never forwarded ──────────────────────
echo "Test 2: an unknown authority is refused, and no upstream is dialled"
before="$(grep -c 'ORIGIN "GET' "$WORK/origin.log" || true)"
status="$(curl -s -o /dev/null --http3-only -k -A "$UA" \
    --resolve "$UNKNOWN_HOST:$H3_PORT:127.0.0.1" \
    -w '%{http_code}' "https://$UNKNOWN_HOST:$H3_PORT/probe" || true)"
after="$(grep -c 'ORIGIN "GET' "$WORK/origin.log" || true)"
echo "    status=$status origin_requests_before=$before after=$after"

[ "$status" = "404" ] \
    && pass "unknown authority refused with 404" \
    || fail "expected 404, got $status"
[ "$before" = "$after" ] \
    && pass "no upstream was dialled for the unknown authority" \
    || fail "the origin was reached for an unrouted authority (H-7 regression)"

echo
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
