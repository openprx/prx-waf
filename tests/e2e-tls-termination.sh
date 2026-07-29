#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# PRX-WAF End-to-End TLS termination test
#
# Drives a real prx-waf process with a real HTTPS client and asserts the whole
# chain `[proxy] listen_addr_tls` is supposed to close:
#
#   1. With no certificate anywhere, the address is NOT bound and startup says
#      so. The setting must never be a key that looks configured and does
#      nothing, which is exactly what it was before TLS termination existed.
#   2. With a certificate in the `certificates` table — the table ACME issues
#      into, and until now the only readers of which were the management API
#      and the ACME loop's own "do I already have one?" check — the address IS
#      bound and a real client completes a real handshake against it.
#   3. The certificate on the wire is byte-for-byte the one in that table.
#      Compared by SHA-256 fingerprint, because "HTTPS worked" would also be
#      true of a self-signed fallback or anything hardcoded.
#   4. TLS is terminated HERE. The origin is plaintext HTTP and sees the
#      request arrive decrypted, with the client's Host, on a connection this
#      proxy opened. A CONNECT-style passthrough could not produce that.
#   5. The WAF still inspects. A SQL injection sent inside the TLS session is
#      answered 403 and never reaches the origin — detection that only worked
#      on plaintext would be a hole the day HTTPS was switched on.
#   6. The negotiated protocol is TLS 1.2 or 1.3, never 1.0/1.1.
#   7. The private key written out of the database is mode 0600.
#
# Prerequisites:
#   - cargo build -p prx-waf   (or --release; set BIN=)
#   - curl, openssl, psql, python3
#   - a reachable Postgres; the daemon migrates it itself
#
# Usage:
#   ./tests/e2e-tls-termination.sh
#   DATABASE_URL=postgresql://user:pw@host:5432/db ./tests/e2e-tls-termination.sh
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

BIN="${BIN:-target/debug/prx-waf}"
DATABASE_URL="${DATABASE_URL:-postgresql://prx_waf:prx_waf@127.0.0.1:15932/prx_waf}"
TLS_PORT="${TLS_PORT:-18543}"
HTTP_PORT="${HTTP_PORT:-18580}"
ORIGIN_PORT="${ORIGIN_PORT:-18599}"
API_PORT="${API_PORT:-19627}"
HOSTNAME_UNDER_TEST="tls.test"
# The bot detector blocks `curl/*` outright and this test is about TLS, not
# about bot detection.
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36'

PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

# ── Preconditions ─────────────────────────────────────────────────────────────
for tool in curl openssl psql python3; do
    command -v "$tool" >/dev/null || { echo "ERROR: $tool not found" >&2; exit 1; }
done
[ -x "$BIN" ] || { echo "ERROR: $BIN not found; run: cargo build -p prx-waf" >&2; exit 1; }
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

WORK="$(mktemp -d)"
ORIGIN_PID=""
cleanup() {
    # Pingora's bootstrap forks, so the recorded pid is not the process holding
    # the ports. Match on this run's config paths, which are unique to $WORK.
    pkill -9 -f "$WORK/" 2>/dev/null || true
    [ -n "$ORIGIN_PID" ] && kill -9 "$ORIGIN_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

psql "$DATABASE_URL" -c 'SELECT 1' >/dev/null 2>&1 \
    || { echo "ERROR: cannot reach $DATABASE_URL" >&2; exit 1; }

# The daemon writes the store's certificate into a per-pid directory under its
# private runtime directory. Isolating HOME/TMPDIR would not move it — the path
# is derived from the effective uid — so the test clears the tree before the run
# that should populate it and then asserts on whatever pid appeared.
MATERIAL_DIR="/run/prx-waf/tls"
[ -w /run/prx-waf ] 2>/dev/null || MATERIAL_DIR="/tmp/prx-waf-$(id -u)/tls"

# ── Origin: plaintext HTTP, echoes what it was actually sent ─────────────────
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

write_config() {
    cat > "$1" <<EOF
[proxy]
listen_addr = "127.0.0.1:$HTTP_PORT"
listen_addr_tls = "127.0.0.1:$TLS_PORT"
worker_threads = 2

[api]
listen_addr = "127.0.0.1:$API_PORT"

[storage]
database_url = "$DATABASE_URL"
max_connections = 5

[[hosts]]
host = "$HOSTNAME_UNDER_TEST"
port = $TLS_PORT
ssl = true
upstream_ssl = false
remote_host = "127.0.0.1"
remote_port = $ORIGIN_PORT

# The router keys on host:port and neither listener is on 80/443 here, so the
# plaintext control requests need their own entry. Same origin, so a verdict
# that differs between the two listeners is a difference in the listener, not
# in the route.
[[hosts]]
host = "$HOSTNAME_UNDER_TEST"
port = $HTTP_PORT
ssl = false
upstream_ssl = false
remote_host = "127.0.0.1"
remote_port = $ORIGIN_PORT
EOF
}

# Waits on a line every version of this daemon prints, NOT on the TLS line.
# Gating readiness on the TLS line would turn "this build says nothing at all
# about listen_addr_tls" — the exact defect under test — into a setup error
# instead of a failed assertion.
start_daemon() {
    local cfg="$1" log="$2"
    JWT_SECRET="${JWT_SECRET:-e2e-tls-termination-secret-0123456789abcdef}" \
        "$BIN" --config "$cfg" run > "$log" 2>&1 &
    disown || true
    for _ in $(seq 1 60); do
        grep -q "Press Ctrl+C to stop" "$log" && { sleep 2; return 0; }
        sleep 1
    done
    return 1
}

# Every launch must account for listen_addr_tls, whichever way it goes. A build
# that says nothing has the setting configured and inert, which is what this
# whole test exists to prevent.
assert_tls_line_present() {
    grep -qE "TLS termination (active|is NOT active|is off)" "$1" \
        && pass "startup accounts for [proxy] listen_addr_tls" \
        || fail "startup said nothing about [proxy] listen_addr_tls — the setting is inert"
}

stop_daemon() {
    # Matches only the daemon's config paths. `$WORK/` alone would also match
    # the origin, which has to outlive the restart between the two phases.
    pkill -9 -f "$WORK/waf-" 2>/dev/null || true
    for _ in $(seq 1 30); do
        ss -ltn 2>/dev/null | grep -q ":$TLS_PORT " || return 0
        sleep 1
    done
    return 0
}

# ═════════════════════════════════════════════════════════════════════════════
# Test 1: an empty store must not produce a silently-inert setting
# ═════════════════════════════════════════════════════════════════════════════
echo "Test 1: no certificate anywhere — the port is not bound, and startup says why"
# Empty the store, not drop it: migrations are recorded as applied, so a
# dropped table would never be recreated and the daemon would report a database
# error instead of the empty-store case this test is about. Failing here is
# fine and expected on a database the daemon has never migrated.
psql "$DATABASE_URL" -q -c 'DELETE FROM certificates' >/dev/null 2>&1 || true

write_config "$WORK/waf-nocert.toml"
if ! start_daemon "$WORK/waf-nocert.toml" "$WORK/waf-nocert.log"; then
    echo "ERROR: the daemon never started; last lines:" >&2
    tail -30 "$WORK/waf-nocert.log" >&2
    exit 1
fi

assert_tls_line_present "$WORK/waf-nocert.log"
grep -q "TLS termination is NOT active" "$WORK/waf-nocert.log" \
    && pass "startup reports the TLS listener as not active" \
    || fail "startup said nothing about listen_addr_tls being unusable"
grep -q "no usable certificate exists" "$WORK/waf-nocert.log" \
    && pass "the reason names the empty certificate store" \
    || fail "the reason did not explain which source was consulted"

# curl reports an unanswered connection as http_code 000, so that is the
# assertion rather than the exit status, which also covers a listener that
# accepts the TCP connection and then fails the handshake.
nocert_status="$(curl -s -o /dev/null -k --max-time 5 \
    --resolve "$HOSTNAME_UNDER_TEST:$TLS_PORT:127.0.0.1" \
    -w '%{http_code}' "https://$HOSTNAME_UNDER_TEST:$TLS_PORT/probe" 2>/dev/null || true)"
[ "$nocert_status" = "000" ] \
    && pass "nothing answers on the TLS port with no certificate" \
    || fail "something answered on the TLS port (status=$nocert_status)"
ss -ltn 2>/dev/null | grep -q "127.0.0.1:$TLS_PORT " \
    && fail "the TLS port is bound even though no certificate resolved" \
    || pass "the TLS port is not bound at all"

# The plaintext listener must be untouched by the missing certificate.
plain_status="$(curl -s -o /dev/null -A "$UA" --max-time 5 \
    -H "Host: $HOSTNAME_UNDER_TEST:$HTTP_PORT" -w '%{http_code}' \
    "http://127.0.0.1:$HTTP_PORT/probe" || true)"
[ "$plain_status" = "200" ] \
    && pass "the plaintext listener still serves (200)" \
    || fail "the plaintext listener broke too (status=$plain_status)"

stop_daemon

# ═════════════════════════════════════════════════════════════════════════════
# Certificate into the store, the way ACME leaves one there
# ═════════════════════════════════════════════════════════════════════════════
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$WORK/store-key.pem" -out "$WORK/store-cert.pem" \
    -subj "/CN=$HOSTNAME_UNDER_TEST" -addext "subjectAltName=DNS:$HOSTNAME_UNDER_TEST" \
    >/dev/null 2>&1

# Fingerprint of the certificate as it goes IN. Everything downstream is
# compared against this, so a listener serving anything else cannot pass.
STORED_FP="$(openssl x509 -in "$WORK/store-cert.pem" -noout -fingerprint -sha256 | cut -d= -f2)"

# The daemon recreates the table on startup; write the row through psql exactly
# as SslManager would, then let the daemon read it back.
psql "$DATABASE_URL" -q -v ON_ERROR_STOP=1 \
    -v cert="$(cat "$WORK/store-cert.pem")" \
    -v key="$(cat "$WORK/store-key.pem")" \
    -v domain="$HOSTNAME_UNDER_TEST" <<'SQL'
INSERT INTO certificates (host_code, domain, cert_pem, key_pem, status, not_after, issuer, subject)
VALUES ('e2etls', :'domain', :'cert', :'key', 'active', NOW() + INTERVAL '1 day',
        'e2e-self-signed', :'domain');
SQL

# ═════════════════════════════════════════════════════════════════════════════
# Test 2: the stored certificate reaches the wire
# ═════════════════════════════════════════════════════════════════════════════
echo
echo "Test 2: the certificate in the store is the certificate on the wire"
# Clear anything an earlier run left behind, so "the key is 0600" cannot pass on
# a stale file written by a different binary.
rm -rf "$MATERIAL_DIR"
write_config "$WORK/waf-cert.toml"
if ! start_daemon "$WORK/waf-cert.toml" "$WORK/waf-cert.log"; then
    echo "ERROR: the daemon never started; last lines:" >&2
    tail -30 "$WORK/waf-cert.log" >&2
    exit 1
fi

assert_tls_line_present "$WORK/waf-cert.log"
grep -q "TLS termination active on 127.0.0.1:$TLS_PORT" "$WORK/waf-cert.log" \
    && pass "startup reports the TLS listener as active" \
    || fail "startup did not report an active TLS listener"
grep -q "certificate from the certificates table, domain $HOSTNAME_UNDER_TEST" "$WORK/waf-cert.log" \
    && pass "startup names the certificates table as the source" \
    || fail "startup did not attribute the certificate to the store"

SERVED_FP="$(echo | openssl s_client -connect "127.0.0.1:$TLS_PORT" \
    -servername "$HOSTNAME_UNDER_TEST" 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 || true)"
echo "    stored=$STORED_FP"
echo "    served=$SERVED_FP"
[ -n "$SERVED_FP" ] && [ "$SERVED_FP" = "$STORED_FP" ] \
    && pass "the served leaf is the row in the certificates table, byte for byte" \
    || fail "the served certificate is not the stored one — a fallback or hardcoded cert is in play"

# ── 6. Protocol floor ────────────────────────────────────────────────────────
NEGOTIATED="$(echo | openssl s_client -connect "127.0.0.1:$TLS_PORT" \
    -servername "$HOSTNAME_UNDER_TEST" 2>/dev/null | grep -oE 'TLSv1\.[0-9]' | tail -1 || true)"
case "$NEGOTIATED" in TLSv1.2 | TLSv1.3) NEGOTIATED="$NEGOTIATED" ;; *) NEGOTIATED="${NEGOTIATED:-none}" ;; esac
echo "    negotiated=$NEGOTIATED"
case "$NEGOTIATED" in
    TLSv1.2 | TLSv1.3) pass "negotiated $NEGOTIATED" ;;
    *) fail "negotiated $NEGOTIATED, which is below the TLS 1.2 floor" ;;
esac
# Only meaningful once something is known to answer: a refused connection
# rejects TLS 1.1 too, and would score a pass for a listener that does not exist.
case "$NEGOTIATED" in
    TLSv1.2 | TLSv1.3)
        if echo | openssl s_client -connect "127.0.0.1:$TLS_PORT" -tls1_1 \
                -servername "$HOSTNAME_UNDER_TEST" >/dev/null 2>&1; then
            fail "TLS 1.1 was accepted"
        else
            pass "TLS 1.1 is refused by a listener that accepts $NEGOTIATED"
        fi
        ;;
    *) fail "TLS 1.1 could not be tested: nothing completes a handshake on this port" ;;
esac

# ── 7. The materialized key is not readable by anyone else ───────────────────
keyfile="$(find "$MATERIAL_DIR" -name listener.key -type f 2>/dev/null | head -1 || true)"
if [ -n "$keyfile" ]; then
    keymode="$(stat -c '%a' "$keyfile")"
    dirmode="$(stat -c '%a' "$(dirname "$keyfile")")"
    echo "    key=$keyfile mode=$keymode dir_mode=$dirmode"
    [ "$keymode" = "600" ] \
        && pass "the key written out of the database is mode 0600" \
        || fail "the key is mode $keymode — readable beyond this process"
    [ "$dirmode" = "700" ] \
        && pass "the directory holding it is mode 0700" \
        || fail "the directory holding the key is mode $dirmode"
else
    fail "no key was materialized under $MATERIAL_DIR"
    fail "no directory was created to hold one"
fi

# ═════════════════════════════════════════════════════════════════════════════
# Test 3: TLS is terminated here, and the WAF still inspects what is inside
# ═════════════════════════════════════════════════════════════════════════════
echo
echo "Test 3: the session is terminated here and inspected"
before="$(grep -c 'ORIGIN "GET' "$WORK/origin.log" || true)"

body="$(curl -s -A "$UA" --cacert "$WORK/store-cert.pem" \
    --resolve "$HOSTNAME_UNDER_TEST:$TLS_PORT:127.0.0.1" \
    -w '\nHTTP_STATUS=%{http_code}\nHTTP_VERSION=%{http_version}\n' \
    "https://$HOSTNAME_UNDER_TEST:$TLS_PORT/probe" || true)"
echo "$body" | sed 's/^/    /'

echo "$body" | grep -q 'HTTP_STATUS=200' \
    && pass "a real HTTPS client completed the handshake and got 200" \
    || fail "the HTTPS request did not succeed"
# No ALPN is advertised on purpose; h2 would route on an absent Host header.
echo "$body" | grep -q 'HTTP_VERSION=1.1' \
    && pass "the session is HTTP/1.1, as the listener advertises" \
    || fail "an unexpected HTTP version was negotiated"
echo "$body" | grep -q "host-header=$HOSTNAME_UNDER_TEST:$TLS_PORT" \
    && pass "the plaintext origin saw the decrypted request with the client's Host" \
    || fail "the origin did not see the request — TLS was not terminated here"

after="$(grep -c 'ORIGIN "GET' "$WORK/origin.log" || true)"
[ "$after" -gt "$before" ] \
    && pass "the origin was reached over plaintext (terminate, not passthrough)" \
    || fail "no plaintext request reached the origin"

# ── 5. Detection inside the TLS session ──────────────────────────────────────
before="$(grep -c 'ORIGIN "GET' "$WORK/origin.log" || true)"
sqli_status="$(curl -s -o /dev/null -A "$UA" --cacert "$WORK/store-cert.pem" \
    --resolve "$HOSTNAME_UNDER_TEST:$TLS_PORT:127.0.0.1" -w '%{http_code}' \
    "https://$HOSTNAME_UNDER_TEST:$TLS_PORT/probe?id=1%27%20OR%20%271%27%3D%271%27%20--%20" || true)"
after="$(grep -c 'ORIGIN "GET' "$WORK/origin.log" || true)"
echo "    sqli_status=$sqli_status origin_requests_before=$before after=$after"

[ "$sqli_status" = "403" ] \
    && pass "SQL injection inside the TLS session is blocked with 403" \
    || fail "expected 403 for the SQLi over HTTPS, got $sqli_status"
[ "$before" = "$after" ] \
    && pass "the blocked request never reached the origin" \
    || fail "the blocked request was forwarded anyway"

# The same payload over plaintext must behave identically; a detection chain
# that only fires on one of the two listeners is the bug this guards against.
plain_sqli="$(curl -s -o /dev/null -A "$UA" -H "Host: $HOSTNAME_UNDER_TEST:$HTTP_PORT" -w '%{http_code}' \
    "http://127.0.0.1:$HTTP_PORT/probe?id=1%27%20OR%20%271%27%3D%271%27%20--%20" || true)"
[ "$plain_sqli" = "$sqli_status" ] \
    && pass "HTTP and HTTPS agree on the verdict ($plain_sqli)" \
    || fail "HTTP said $plain_sqli and HTTPS said $sqli_status for the same payload"

echo
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
