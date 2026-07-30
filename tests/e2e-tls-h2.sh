#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# PRX-WAF End-to-End HTTP/2 test
#
# `e2e-tls-termination.sh` proves the TLS listener terminates and inspects.
# This proves the *other* protocol that listener now speaks. h2 was held back
# for one reason: Pingora delivers `:authority` in `RequestHeader::uri` and
# leaves the field map alone, so a proxy that routes on the `Host` field routes
# every compliant h2 request on the empty string and 404s it. Routing now goes
# through `gateway::authority::route_authority`, shared with HTTP/1.1 and
# HTTP/3, and this is the measurement of that.
#
# What is asserted:
#
#   1. ALPN offers `h2` and `http/1.1`, in that order, and the order is the
#      *server's* preference: a client that lists `http/1.1` first still gets
#      h2, and a client that speaks only `http/1.1` is still served.
#   2. A real HTTPS client negotiates h2 and its request is ROUTED — 200 from
#      the configured origin, not the 404 an unrouted authority earns. An
#      authority with no route still 404s, so the 200 is routing and not a
#      wildcard.
#   3. The detection chain runs on h2 exactly as on HTTP/1.1: a SQLi in the
#      query is 403 and never reaches the origin, a SQLi in a POST body is 403
#      (the body phase reads h2 DATA frames), and both agree with the verdict
#      the same payload gets over HTTP/1.1.
#   4. The `Host` field the detectors see is the authority, so a rule that reads
#      that header — CRS-920350, "Host header is a numeric IP address" — fires
#      on h2 for a request that carries no `Host` field at all.
#   5. `:authority` and `Host` disagreeing is REFUSED with 400, not resolved.
#      Neither `h2` 0.4.15 nor Pingora compares the two, so this is the only
#      thing between a mismatched pair and a request routed under one name and
#      served under the other. Agreement routes; disagreement is refused;
#      a second `Host` line is refused; and the refusal moves
#      `budget_events_total{subsystem="request_headers",limit="contradicted_authority"}`.
#
# Assertion 5 needs a client that will send a `Host` field beside `:authority`,
# which curl and every other well-behaved client refuse to do — they build one
# from the other. `h2raw.py` is that client: it speaks the wire directly, so it
# can send the pair no library will. It reads the verdict off the DATA frames
# rather than the HEADERS, which avoids needing an HPACK *decoder* for a test
# whose answers are already distinguishable by body: `Bad Request`,
# `Not Found`, `ORIGIN-REACHED`.
#
# Prerequisites:
#   - cargo build -p prx-waf   (or --release; set BIN=)
#   - curl (with nghttp2), openssl, psql, python3
#   - a reachable Postgres; the daemon migrates it itself
#
# Usage:
#   ./tests/e2e-tls-h2.sh
#   DATABASE_URL=postgresql://user:pw@host:5432/db ./tests/e2e-tls-h2.sh
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

BIN="${BIN:-target/debug/prx-waf}"
DATABASE_URL="${DATABASE_URL:-postgresql://prx_waf:prx_waf@127.0.0.1:15932/prx_waf}"
TLS_PORT="${TLS_PORT:-18743}"
HTTP_PORT="${HTTP_PORT:-18780}"
ORIGIN_PORT="${ORIGIN_PORT:-18799}"
API_PORT="${API_PORT:-19827}"
METRICS_PORT="${METRICS_PORT:-19828}"
HOSTNAME_UNDER_TEST="h2.test"
# The bot detector blocks `curl/*` outright and this test is about h2, not about
# bot detection.
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36'

PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

# ── Preconditions ─────────────────────────────────────────────────────────────
for tool in curl openssl psql python3; do
    command -v "$tool" >/dev/null || { echo "ERROR: $tool not found" >&2; exit 1; }
done
curl --version | head -1 | grep -q nghttp2 \
    || { echo "ERROR: this curl has no HTTP/2 support" >&2; exit 1; }
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

# ── Origin: plaintext HTTP, echoes what it was actually sent ─────────────────
cat > "$WORK/origin.py" <<'PY'
import http.server, sys

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def respond(self):
        body = ("ORIGIN-REACHED\nhost-header=%s\npath=%s\n"
                % (self.headers.get("Host"), self.path)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = respond

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self.respond()

    def log_message(self, fmt, *args):
        print("ORIGIN " + (fmt % args), flush=True)

http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY
python3 "$WORK/origin.py" "$ORIGIN_PORT" > "$WORK/origin.log" 2>&1 &
ORIGIN_PID=$!
# Otherwise the SIGKILL the cleanup trap sends is reported by the shell after
# the summary line, which reads like a failure and is not one.
disown || true

# ── A raw HTTP/2 client, because no polite one can send this ─────────────────
# Sends exactly the pseudo-headers and fields it is told to, in order, using
# HPACK "literal header field without indexing — new name" (RFC 7541 §6.2.2)
# with Huffman off, which needs no dynamic-table state on the encode side.
# Prints the negotiated ALPN protocol and everything the server sent as DATA.
cat > "$WORK/h2raw.py" <<'PY'
import socket, ssl, sys, json

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def hpack_literal(name, value):
    """Literal header field without indexing, new name, no Huffman."""
    def string(s):
        b = s.encode()
        # RFC 7541 §5.1 integer, 7-bit prefix, Huffman bit clear.
        if len(b) < 127:
            length = bytes([len(b)])
        else:
            rest, out = len(b) - 127, bytearray([127])
            while rest >= 128:
                out.append(rest % 128 + 128)
                rest //= 128
            out.append(rest)
            length = bytes(out)
        return length + b
    return b"\x00" + string(name) + string(value)


def frame(kind, flags, stream_id, payload):
    return (len(payload).to_bytes(3, "big") + bytes([kind, flags])
            + stream_id.to_bytes(4, "big") + payload)


def main():
    spec = json.loads(sys.argv[1])
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(spec.get("alpn", ["h2"]))

    raw = socket.create_connection((spec["ip"], spec["port"]), timeout=10)
    sock = ctx.wrap_socket(raw, server_hostname=spec.get("sni", "localhost"))
    negotiated = sock.selected_alpn_protocol()
    print("ALPN=%s" % negotiated)
    if negotiated != "h2":
        sock.close()
        return

    block = b"".join(hpack_literal(n, v) for n, v in spec["headers"])
    body = spec.get("body", "").encode()
    # END_HEADERS (0x4); END_STREAM (0x1) only when there is no body to follow.
    flags = 0x4 | (0x0 if body else 0x1)
    out = PREFACE + frame(0x4, 0, 0, b"") + frame(0x1, flags, 1, block)
    if body:
        out += frame(0x0, 0x1, 1, body)
    sock.sendall(out)

    sock.settimeout(10)
    buf, data, rst = b"", b"", None
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
            while len(buf) >= 9:
                length = int.from_bytes(buf[:3], "big")
                if len(buf) < 9 + length:
                    break
                kind, flags = buf[3], buf[4]
                payload = buf[9:9 + length]
                buf = buf[9 + length:]
                if kind == 0x0:                       # DATA
                    data += payload
                elif kind == 0x3:                     # RST_STREAM
                    rst = int.from_bytes(payload[:4], "big")
                elif kind == 0x7:                     # GOAWAY
                    rst = int.from_bytes(payload[4:8], "big")
                if kind in (0x0, 0x1) and flags & 0x1:
                    raise StopIteration
    except (StopIteration, socket.timeout, ssl.SSLError, ConnectionResetError):
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass

    if rst is not None:
        print("RESET=%d" % rst)
    print("DATA=%s" % data.decode("utf-8", "replace").replace("\n", "\\n"))


main()
PY

write_config() {
    cat > "$1" <<EOF
[proxy]
listen_addr = "127.0.0.1:$HTTP_PORT"
listen_addr_tls = "127.0.0.1:$TLS_PORT"
worker_threads = 2

[api]
listen_addr = "127.0.0.1:$API_PORT"

[metrics]
enabled = true
listen_addr = "127.0.0.1:$METRICS_PORT"

# CRS-920350 ("Host header is a numeric IP address") is a warning-severity rule,
# so at the shipped weights it scores 3 against a threshold of 5 and waits for a
# second rule instead of blocking alone. Test 4 needs one rule that reads the
# Host header to produce a visible verdict on its own, so the warning weight is
# raised to the threshold here. This changes how loudly that rule speaks, not
# which requests it matches, and it applies identically to both protocols — the
# assertion is that h2 and HTTP/1.1 get the SAME answer, whatever it is.
[owasp]
warning_anomaly_score = 5

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

# The router keys on host:port, so the HTTP/1.1 control requests need their own
# entry on the plaintext port. Same origin: a verdict that differs between the
# two is a difference in the protocol, not in the route.
[[hosts]]
host = "$HOSTNAME_UNDER_TEST"
port = $HTTP_PORT
ssl = false
upstream_ssl = false
remote_host = "127.0.0.1"
remote_port = $ORIGIN_PORT

# A numeric-IP vhost, so a request addressed to it is ROUTED and can then be
# judged by CRS-920350, which reads the Host request header. On h2 that header
# does not exist on the wire; the value has to have come from the authority.
# Both listeners, so the two protocols are compared like for like.
[[hosts]]
host = "127.0.0.1"
port = $TLS_PORT
ssl = true
upstream_ssl = false
remote_host = "127.0.0.1"
remote_port = $ORIGIN_PORT

[[hosts]]
host = "127.0.0.1"
port = $HTTP_PORT
ssl = false
upstream_ssl = false
remote_host = "127.0.0.1"
remote_port = $ORIGIN_PORT
EOF
}

start_daemon() {
    local cfg="$1" log="$2"
    JWT_SECRET="${JWT_SECRET:-e2e-tls-h2-secret-0123456789abcdef}" \
        "$BIN" --config "$cfg" run > "$log" 2>&1 &
    disown || true
    for _ in $(seq 1 60); do
        grep -q "Press Ctrl+C to stop" "$log" && { sleep 2; return 0; }
        sleep 1
    done
    return 1
}

origin_hits() { grep -c 'ORIGIN "' "$WORK/origin.log" || true; }

# `prxwaf_budget_events_total{subsystem=…,limit=…}` as an integer, 0 when absent.
budget() {
    curl -s --max-time 5 "http://127.0.0.1:$METRICS_PORT/metrics" 2>/dev/null \
        | awk -v pat="subsystem=\"$1\",limit=\"$2\"" \
              '$0 ~ /^prxwaf_budget_events_total\{/ && index($0, pat) { print $NF; found=1 }
               END { if (!found) print 0 }' \
        | head -1
}

# ── Certificate into the store, the way ACME leaves one there ────────────────
psql "$DATABASE_URL" -q -c 'DELETE FROM certificates' >/dev/null 2>&1 || true
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$WORK/store-key.pem" -out "$WORK/store-cert.pem" \
    -subj "/CN=$HOSTNAME_UNDER_TEST" -addext "subjectAltName=DNS:$HOSTNAME_UNDER_TEST" \
    >/dev/null 2>&1

write_config "$WORK/waf.toml"
if ! start_daemon "$WORK/waf.toml" "$WORK/waf-boot.log"; then
    echo "ERROR: the daemon never started; last lines:" >&2
    tail -30 "$WORK/waf-boot.log" >&2
    exit 1
fi
# The first boot only exists to migrate the database; the certificate goes in
# afterwards and the daemon is restarted to pick it up.
pkill -9 -f "$WORK/waf.toml" 2>/dev/null || true
for _ in $(seq 1 30); do
    ss -ltn 2>/dev/null | grep -q ":$TLS_PORT " || break
    sleep 1
done

psql "$DATABASE_URL" -q -v ON_ERROR_STOP=1 \
    -v cert="$(cat "$WORK/store-cert.pem")" \
    -v key="$(cat "$WORK/store-key.pem")" \
    -v domain="$HOSTNAME_UNDER_TEST" <<'SQL'
INSERT INTO certificates (host_code, domain, cert_pem, key_pem, status, not_after, issuer, subject)
VALUES ('e2eh2', :'domain', :'cert', :'key', 'active', NOW() + INTERVAL '1 day',
        'e2e-self-signed', :'domain');
SQL

if ! start_daemon "$WORK/waf.toml" "$WORK/waf.log"; then
    echo "ERROR: the daemon never restarted with a certificate; last lines:" >&2
    tail -30 "$WORK/waf.log" >&2
    exit 1
fi
grep -q "TLS termination active on 127.0.0.1:$TLS_PORT" "$WORK/waf.log" \
    || { echo "ERROR: the TLS listener is not active; nothing below can be measured" >&2
         grep -i tls "$WORK/waf.log" >&2; exit 1; }

# ═════════════════════════════════════════════════════════════════════════════
# Test 1: ALPN — what is offered, and whose preference decides
# ═════════════════════════════════════════════════════════════════════════════
echo "Test 1: ALPN advertises h2 ahead of http/1.1, at the server's preference"

alpn_pick() {
    echo | openssl s_client -connect "127.0.0.1:$TLS_PORT" -alpn "$1" \
        -servername "$HOSTNAME_UNDER_TEST" 2>/dev/null \
        | sed -n 's/^ALPN protocol: //p' | head -1
}

got="$(alpn_pick h2)"
echo "    client offers h2            -> ${got:-none}"
[ "$got" = "h2" ] && pass "h2 is advertised at all" || fail "h2 was not negotiated (got '${got:-none}')"

# The listener's list is ["h2", "http/1.1"] and rustls picks the first entry of
# the SERVER's list the client also offered. A client that would rather have
# HTTP/1.1 therefore still gets h2 — which is the documented order, measured
# rather than assumed.
got="$(alpn_pick 'http/1.1,h2')"
echo "    client offers http/1.1,h2   -> ${got:-none}"
[ "$got" = "h2" ] \
    && pass "the server's preference wins over the client's order" \
    || fail "the client's order decided the protocol (got '${got:-none}')"

got="$(alpn_pick 'http/1.1')"
echo "    client offers http/1.1 only -> ${got:-none}"
[ "$got" = "http/1.1" ] \
    && pass "an HTTP/1.1-only client is still served, not refused" \
    || fail "an HTTP/1.1-only client got '${got:-none}'"

# ═════════════════════════════════════════════════════════════════════════════
# Test 2: an h2 request is routed, and an unrouted one is still refused
# ═════════════════════════════════════════════════════════════════════════════
echo
echo "Test 2: h2 routes on :authority"
before="$(origin_hits)"
body="$(curl -s --http2 -A "$UA" --cacert "$WORK/store-cert.pem" \
    --resolve "$HOSTNAME_UNDER_TEST:$TLS_PORT:127.0.0.1" \
    -w '\nHTTP_STATUS=%{http_code}\nHTTP_VERSION=%{http_version}\n' \
    "https://$HOSTNAME_UNDER_TEST:$TLS_PORT/probe" || true)"
echo "$body" | sed 's/^/    /'
after="$(origin_hits)"

echo "$body" | grep -q 'HTTP_VERSION=2' \
    && pass "curl negotiated HTTP/2" \
    || fail "curl did not negotiate HTTP/2"
echo "$body" | grep -q 'HTTP_STATUS=200' \
    && pass "the h2 request was routed and answered 200, not the 404 an unrouted authority gets" \
    || fail "the h2 request was not routed"
echo "$body" | grep -q "host-header=$HOSTNAME_UNDER_TEST:$TLS_PORT" \
    && pass "the origin saw the authority as its HTTP/1.1 Host" \
    || fail "the origin did not see the client's authority"
[ "$after" -gt "$before" ] \
    && pass "the request actually reached the origin over plaintext" \
    || fail "nothing reached the origin"

# A 200 for everything would pass every assertion above. This is the control.
unrouted="$(curl -s -o /dev/null --http2 -A "$UA" -k --max-time 10 \
    --resolve "nosuch.test:$TLS_PORT:127.0.0.1" -w '%{http_code}' \
    "https://nosuch.test:$TLS_PORT/probe" || true)"
echo "    unrouted authority -> $unrouted"
[ "$unrouted" = "404" ] \
    && pass "an h2 request for an unconfigured authority is refused with 404" \
    || fail "an unconfigured authority got $unrouted, so the 200 above proves nothing"

# ═════════════════════════════════════════════════════════════════════════════
# Test 3: the detection chain runs on h2
# ═════════════════════════════════════════════════════════════════════════════
echo
echo "Test 3: detection on h2 agrees with detection on HTTP/1.1"
SQLI='id=1%27%20OR%20%271%27%3D%271%27%20--%20'

before="$(origin_hits)"
h2_sqli="$(curl -s -o /dev/null --http2 -A "$UA" --cacert "$WORK/store-cert.pem" \
    --resolve "$HOSTNAME_UNDER_TEST:$TLS_PORT:127.0.0.1" -w '%{http_code}' \
    "https://$HOSTNAME_UNDER_TEST:$TLS_PORT/probe?$SQLI" || true)"
after="$(origin_hits)"
echo "    h2 query SQLi -> $h2_sqli (origin hits $before -> $after)"
[ "$h2_sqli" = "403" ] \
    && pass "a SQLi in an h2 query is blocked with 403" \
    || fail "expected 403 for the h2 SQLi, got $h2_sqli"
[ "$before" = "$after" ] \
    && pass "the blocked h2 request never reached the origin" \
    || fail "the blocked h2 request was forwarded anyway"

h1_sqli="$(curl -s -o /dev/null --http1.1 -A "$UA" -H "Host: $HOSTNAME_UNDER_TEST:$HTTP_PORT" \
    -w '%{http_code}' "http://127.0.0.1:$HTTP_PORT/probe?$SQLI" || true)"
[ "$h1_sqli" = "$h2_sqli" ] \
    && pass "HTTP/1.1 and h2 agree on the query verdict ($h1_sqli)" \
    || fail "HTTP/1.1 said $h1_sqli and h2 said $h2_sqli"

# The body phase reads h2 DATA frames, which is a different code path in Pingora
# from an HTTP/1.1 chunked body.
h2_body="$(curl -s -o /dev/null --http2 -A "$UA" --cacert "$WORK/store-cert.pem" \
    --resolve "$HOSTNAME_UNDER_TEST:$TLS_PORT:127.0.0.1" -w '%{http_code}' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data "q=1' OR '1'='1' -- " \
    "https://$HOSTNAME_UNDER_TEST:$TLS_PORT/probe" || true)"
h1_body="$(curl -s -o /dev/null --http1.1 -A "$UA" -H "Host: $HOSTNAME_UNDER_TEST:$HTTP_PORT" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data "q=1' OR '1'='1' -- " -w '%{http_code}' \
    "http://127.0.0.1:$HTTP_PORT/probe" || true)"
echo "    h2 body SQLi -> $h2_body / http1.1 -> $h1_body"
[ "$h2_body" = "403" ] \
    && pass "a SQLi in an h2 request body is blocked with 403" \
    || fail "expected 403 for the h2 body SQLi, got $h2_body"
[ "$h1_body" = "$h2_body" ] \
    && pass "HTTP/1.1 and h2 agree on the body verdict ($h1_body)" \
    || fail "HTTP/1.1 said $h1_body and h2 said $h2_body for the same body"

# ═════════════════════════════════════════════════════════════════════════════
# Test 4: the detectors see the authority as the Host header
# ═════════════════════════════════════════════════════════════════════════════
echo
echo "Test 4: CRS-920350 reads the Host header, and h2 has none on the wire"
# curl over h2 sends `:authority: 127.0.0.1:PORT` and no `host` field at all.
# CRS-920350 matches a numeric-IP Host header. If the folded map did not carry
# the authority as `host`, this request would sail through on h2 while the
# identical HTTP/1.1 request is blocked — a protocol-shaped detection gap.
h2_numeric="$(curl -s -o /dev/null --http2 -k -A "$UA" --max-time 10 \
    -w '%{http_code}' "https://127.0.0.1:$TLS_PORT/probe" || true)"
h1_numeric="$(curl -s -o /dev/null --http1.1 -A "$UA" -H "Host: 127.0.0.1:$HTTP_PORT" \
    -w '%{http_code}' "http://127.0.0.1:$HTTP_PORT/probe" || true)"
echo "    numeric-IP authority: h2 -> $h2_numeric, http/1.1 -> $h1_numeric"
[ "$h1_numeric" = "403" ] \
    && pass "CRS-920350 blocks the numeric Host over HTTP/1.1 (the control)" \
    || fail "CRS-920350 did not fire over HTTP/1.1 ($h1_numeric); test 4 measures nothing"
[ "$h2_numeric" = "$h1_numeric" ] \
    && pass "the same rule fires on h2, so the detectors saw the authority as Host" \
    || fail "h2 said $h2_numeric where HTTP/1.1 said $h1_numeric — h2 bypasses a Host rule"

# ═════════════════════════════════════════════════════════════════════════════
# Test 5: :authority contradicting Host is refused, not resolved
# ═════════════════════════════════════════════════════════════════════════════
echo
echo "Test 5: a request that names two different sites is refused"

h2raw() { python3 "$WORK/h2raw.py" "$1" 2>&1; }

authority="$HOSTNAME_UNDER_TEST:$TLS_PORT"
# `--` in place of the authority builds a request with no `:authority` at all;
# every remaining argument is a `name=value` field appended after the pseudo
# headers. The browser user-agent is not decoration: the bot detector answers
# an agent-less request with 403 and every assertion below would read that
# instead of the routing verdict it is asking about.
req() {
    python3 - "$TLS_PORT" "$HOSTNAME_UNDER_TEST" "$UA" "$@" <<'PY'
import json, sys
port, sni, ua, authority = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
headers = [(":method", "GET"), (":scheme", "https")]
if authority != "--":
    headers.append((":authority", authority))
headers.append((":path", "/probe"))
headers.append(("user-agent", ua))
for extra in sys.argv[5:]:
    name, _, value = extra.partition("=")
    headers.append((name, value))
print(json.dumps({"ip": "127.0.0.1", "port": port, "sni": sni,
                  "alpn": ["h2"], "headers": headers}))
PY
}

before="$(origin_hits)"
out="$(h2raw "$(req "$authority")")"
echo "    :authority only                 -> $out"
echo "$out" | grep -q 'ORIGIN-REACHED' \
    && pass "the raw client's plain h2 request routes (the harness is not broken)" \
    || fail "the raw h2 client could not make an ordinary request work"

out="$(h2raw "$(req "$authority" "host=$authority")")"
echo "    :authority + agreeing host      -> $out"
echo "$out" | grep -q 'ORIGIN-REACHED' \
    && pass "an agreeing :authority/Host pair routes on the agreed value" \
    || fail "an agreeing pair was refused"

before="$(origin_hits)"
budget_before="$(budget request_headers contradicted_authority)"
out="$(h2raw "$(req "$authority" "host=evil.test:$TLS_PORT")")"
after="$(origin_hits)"
budget_after="$(budget request_headers contradicted_authority)"
echo "    :authority + disagreeing host   -> $out"
echo "    contradicted_authority $budget_before -> $budget_after, origin hits $before -> $after"
echo "$out" | grep -q 'Bad Request' \
    && pass "a disagreeing :authority/Host pair is refused with 400 Bad Request" \
    || fail "the disagreeing pair was not refused"
[ "$before" = "$after" ] \
    && pass "the refused request never reached the origin under either name" \
    || fail "the refused request was forwarded anyway"
[ "$((budget_after - budget_before))" -eq 1 ] \
    && pass "budget_events_total{request_headers,contradicted_authority} moved by exactly 1" \
    || fail "the contradiction counter moved by $((budget_after - budget_before)), not 1"
grep -q 'Rejecting request whose Host disagrees with the request authority' "$WORK/waf.log" \
    && pass "the refusal wrote a log line naming the disagreement" \
    || fail "the refusal is invisible in the log"
grep 'Rejecting request whose Host disagrees' "$WORK/waf.log" | grep -q 'action="block"' \
    && pass "the log line spells the metric's own action label" \
    || fail "the log line does not carry action=\"block\""

# Not the same defect, and it must not be swallowed by the new one: two `Host`
# lines are unroutable regardless of what `:authority` says, and that refusal
# runs first.
out="$(h2raw "$(req "$authority" "host=$authority" "host=$authority")")"
echo "    :authority + two host lines     -> $out"
echo "$out" | grep -q 'Bad Request' \
    && pass "a second Host line is still refused with 400" \
    || fail "a duplicated Host line was accepted"

# The `Host` alone must still route: an intermediary translating HTTP/1.1 to h2
# is allowed to send it without `:authority`.
out="$(h2raw "$(req -- "host=$authority")")"
echo "    host field, no :authority       -> $out"
echo "$out" | grep -q 'ORIGIN-REACHED' \
    && pass "an h2 request carrying only a Host field still routes" \
    || fail "a Host-only h2 request was not routed"

echo
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
