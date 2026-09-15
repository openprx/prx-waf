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
# and, since Pingora 0.9 parses absolute-form request targets, the HTTP/1.1
# half of the same resolver on the plaintext listener (Test 3): Host alone
# routes, a target authority alone routes, a disagreeing pair is refused below
# the WAF, a target that is neither origin-form nor absolute-form is refused by
# the WAF, and CONNECT never reaches it.
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
# Deliberately not 18443 / 18080: both are generic enough to be taken by
# something else on a developer host, and a listener that silently fails to
# bind would make every assertion below measure the wrong process.
H3_PORT="${H3_PORT:-18446}"
ORIGIN_PORT="${ORIGIN_PORT:-18099}"
API_PORT="${API_PORT:-19527}"
HTTP_PORT="${HTTP_PORT:-18086}"
METRICS_PORT="${METRICS_PORT:-18981}"
KNOWN_HOST="h3.test"
UNKNOWN_HOST="evil.test"
# The HTTP/1.1 site, on the plaintext listener: routes are keyed by
# `host:port`, so the h3 site above is not addressable from HTTP_PORT.
H1_HOST="h1.test"
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

# Every port this run binds must be free: the daemon logs a failed bind and
# carries on, and the script would then be talking to whatever else is there.
for port in "$H3_PORT" "$HTTP_PORT" "$API_PORT" "$ORIGIN_PORT" "$METRICS_PORT"; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
        echo "ERROR: 127.0.0.1:$port is already in use; set the *_PORT variables to free ports" >&2
        exit 1
    fi
done

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
        body = ("ORIGIN-REACHED\nhost-header=%s\npath=%s\nrequestline=%s\n"
                % (self.headers.get("Host"), self.path, self.requestline)).encode()
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

[metrics]
enabled = true
listen_addr = "127.0.0.1:$METRICS_PORT"

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

[[hosts]]
host = "$H1_HOST"
port = $HTTP_PORT
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

# ── 3. HTTP/1.1: the request target can name a site too ──────────────────────
# Pingora 0.9 parses absolute-form request targets (`GET http://host/x`), which
# Pingora 0.8 refused, so an HTTP/1.1 request can now name a site in two
# places. The rules (`crates/gateway/src/authority.rs`): `Host` alone routes; a
# target authority alone routes; a disagreeing pair is refused; a target that is
# neither origin-form nor absolute-form (authority-form outside CONNECT, an
# opaque `scheme:rest`) is refused, because Pingora would write it to the origin
# verbatim while the WAF had inspected a path of `/`.
#
# Two layers answer these. Pingora itself refuses the disagreeing pair inside
# `read_request`, before the WAF sees the request, and its 400 carries no body;
# the WAF's own 400 carries `Bad Request`, moves a budget counter and writes a
# log line. The body therefore says which layer answered, and the assertions
# pin that too: a Pingora release that stops checking shows up here as the
# WAF's layer taking over, not as a silent pass.
#
# Every request uses its own path — the response cache would otherwise answer
# a repeated path itself and the origin count would stop meaning "forwarded".
echo
echo "Test 3: HTTP/1.1 request targets that carry an authority"
h1() {
    # h1 METHOD TARGET [header line]... -> "STATUS|BODY", written on the socket
    # directly: curl cannot be made to send absolute-form to a plain proxy port,
    # nor to omit Host.
    python3 - "$HTTP_PORT" "$UA" "$@" <<'PY'
import socket, sys
port, ua, method, target = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
lines = [f"{method} {target} HTTP/1.1"] + sys.argv[5:] + [f"User-Agent: {ua}", "Connection: close", "", ""]
s = socket.create_connection(("127.0.0.1", port), timeout=10)
s.sendall("\r\n".join(lines).encode())
data = b""
while True:
    chunk = s.recv(65536)
    if not chunk:
        break
    data += chunk
s.close()
status_line = data.split(b"\r\n", 1)[0].split(b" ")
body = data.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in data else b""
print("%s|%s" % (status_line[1].decode() if len(status_line) > 1 else "none",
                 body.decode("utf-8", "replace").replace("\n", " ").strip()))
PY
}
origin_hits() { grep -c 'ORIGIN "' "$WORK/origin.log" || true; }
budget() {
    curl -s --max-time 5 "http://127.0.0.1:$METRICS_PORT/metrics" 2>/dev/null \
        | awk -v pat="subsystem=\"request_headers\",limit=\"$1\"" \
              '$0 ~ /^prxwaf_budget_events_total\{/ && index($0, pat) { print $NF; found=1 }
               END { if (!found) print 0 }' \
        | head -1
}
h1_authority="$H1_HOST:$HTTP_PORT"

# Rule 1, the control: Host alone still routes, on the same listener.
before="$(origin_hits)"
out="$(h1 GET /h1-host-only "Host: $h1_authority")"
echo "    origin-form + Host                 -> $out"
[ "${out%%|*}" = "200" ] && echo "$out" | grep -q "host-header=$h1_authority" \
    && pass "HTTP/1.1 Host alone routes to the configured origin" \
    || fail "the HTTP/1.1 control request did not route"

# Rules 2 and 3: an absolute-form target that agrees with Host routes. The
# origin must receive the request in origin-form — the path the detectors
# inspected, not the absolute-form bytes Pingora would otherwise write
# verbatim — with the client's own Host.
out="$(h1 GET "http://$h1_authority/h1-abs-agree" "Host: $h1_authority")"
echo "    absolute-form + agreeing Host      -> $out"
[ "${out%%|*}" = "200" ] && echo "$out" | grep -q "host-header=$h1_authority" \
    && pass "absolute-form agreeing with Host routes on the agreed authority" \
    || fail "an agreeing absolute-form request was not routed"
echo "$out" | grep -q "requestline=GET /h1-abs-agree HTTP/1.1" \
    && pass "the origin received the agreeing request in origin-form" \
    || fail "the origin's request line was not origin-form: $out"

# Rule 2: the target authority alone routes; the origin sees it as Host (the
# WAF supplies the header, since the client sent none) and the request line
# is origin-form.
out="$(h1 GET "http://$h1_authority/h1-abs-no-host")"
echo "    absolute-form, no Host             -> $out"
[ "${out%%|*}" = "200" ] && echo "$out" | grep -q "host-header=$h1_authority" \
    && pass "absolute-form without Host routes on the target authority, and the origin got Host = that authority" \
    || fail "an absolute-form request without Host was not routed on its authority"
echo "$out" | grep -q "requestline=GET /h1-abs-no-host HTTP/1.1" \
    && pass "the origin received the Host-less request in origin-form" \
    || fail "the origin's request line was not origin-form: $out"
after="$(origin_hits)"
[ "$((after - before))" -eq 3 ] \
    && pass "the three routed requests each reached the origin exactly once" \
    || fail "expected 3 origin requests, saw $((after - before))"

# Rule 3: a disagreeing pair is refused and never forwarded. Pingora 0.9 makes
# this refusal itself, byte-exact, inside `read_request`: no body, no counter,
# no WAF log line. If the WAF's layer answered instead, the body would read
# `Bad Request` and the counter would move by one.
before="$(origin_hits)"
budget_before="$(budget contradicted_authority)"
out="$(h1 GET "http://$h1_authority/h1-abs-disagree" "Host: $UNKNOWN_HOST:$HTTP_PORT")"
after="$(origin_hits)"
budget_after="$(budget contradicted_authority)"
echo "    absolute-form + disagreeing Host   -> $out  (contradicted_authority $budget_before -> $budget_after, origin $before -> $after)"
[ "${out%%|*}" = "400" ] \
    && pass "absolute-form disagreeing with Host is refused with 400" \
    || fail "the disagreeing pair was not refused (status ${out%%|*})"
[ "$before" = "$after" ] \
    && pass "the disagreeing pair never reached the origin under either name" \
    || fail "the disagreeing pair was forwarded"
if [ "${out#*|}" = "" ] && [ "$((budget_after - budget_before))" -eq 0 ] \
    && ! grep -q 'Rejecting request whose Host disagrees' "$WORK/waf.log"; then
    pass "Pingora refused the pair below the WAF (empty body, counter unmoved, no WAF log line)"
elif [ "${out#*|}" = "Bad Request" ] && [ "$((budget_after - budget_before))" -eq 1 ]; then
    fail "the WAF's own layer answered: Pingora no longer refuses a Host/target mismatch in read_request — re-check the boundary"
else
    fail "the refusal came from neither layer cleanly (body '${out#*|}', counter moved by $((budget_after - budget_before)))"
fi

# Rule 4: authority-form outside CONNECT is refused by the WAF — Pingora admits
# it, roots the URI at `/`, and would forward `GET h1.test:PORT HTTP/1.1`.
before="$(origin_hits)"
budget_before="$(budget unsupported_request_target)"
out="$(h1 GET "$h1_authority" "Host: $h1_authority")"
after="$(origin_hits)"
budget_after="$(budget unsupported_request_target)"
echo "    authority-form GET                 -> $out  (unsupported_request_target $budget_before -> $budget_after, origin $before -> $after)"
[ "${out%%|*}" = "400" ] && [ "${out#*|}" = "Bad Request" ] \
    && pass "authority-form outside CONNECT is refused with the WAF's 400" \
    || fail "an authority-form GET was not refused by the WAF (got '$out')"
[ "$before" = "$after" ] \
    && pass "the authority-form request never reached the origin" \
    || fail "an authority-form request was forwarded"
[ "$((budget_after - budget_before))" -eq 1 ] \
    && pass "budget_events_total{request_headers,unsupported_request_target} moved by exactly 1" \
    || fail "the unsupported-target counter moved by $((budget_after - budget_before)), not 1"
grep 'Rejecting request whose target is neither origin-form nor absolute-form' "$WORK/waf.log" | grep -q 'action="block"' \
    && pass "the refusal wrote a log line carrying action=\"block\"" \
    || fail "the authority-form refusal is invisible in the log"

# An absolute-form authority matching no route is the same 404 as an unknown
# Host — never a default config, never a forward.
before="$(origin_hits)"
out="$(h1 GET "http://$UNKNOWN_HOST:$HTTP_PORT/h1-abs-unrouted")"
after="$(origin_hits)"
echo "    absolute-form, unrouted authority  -> $out"
[ "${out%%|*}" = "404" ] && [ "$before" = "$after" ] \
    && pass "an unrouted absolute-form authority is refused with 404 and not forwarded" \
    || fail "an unrouted absolute-form authority got ${out%%|*} (origin $before -> $after)"

# CONNECT never reaches the WAF: pingora-proxy answers 405 unless CONNECT
# proxying is switched on, and this proxy does not switch it on.
out="$(h1 CONNECT "$h1_authority" "Host: $h1_authority")"
echo "    CONNECT                            -> $out"
[ "${out%%|*}" = "405" ] \
    && pass "CONNECT is refused with 405 below the WAF" \
    || fail "CONNECT got ${out%%|*}; the tunnel path is reachable and unreviewed"

echo
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
