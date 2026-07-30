#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# HTTP/2 abuse-frame E2E: the frame-layer denial-of-service surface the TLS
# listener opened when it began advertising ALPN h2.
#
# The guards themselves live in the h2 crate, not in this repository — this test
# proves they are switched on for the real proxy, that [proxy.http2] can tighten
# them, and that the listener survives the storm. See docs/http2-attack-surface.md.
#
# What it asserts, against a running daemon configured with a deliberately tight
# [proxy.http2]:
#   1. the configured SETTINGS reach the wire (proof the config path is live);
#   2. a Rapid-Reset burst (CVE-2023-44487) is cut with GOAWAY(ENHANCE_YOUR_CALM)
#      at the configured reset ceiling, far below the shipped default;
#   3. a CONTINUATION flood (CVE-2024-27316) is cut with GOAWAY(ENHANCE_YOUR_CALM);
#   4. the listener still serves a normal request afterwards.
#
# Requires: openssl, psql, python3 (stdlib only), a reachable Postgres.
#   ./tests/e2e-h2-flood.sh
#   DATABASE_URL=postgresql://user:pw@host:5432/db ./tests/e2e-h2-flood.sh
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

BIN="${BIN:-target/debug/prx-waf}"
DATABASE_URL="${DATABASE_URL:-postgresql://prx_waf:prx_waf@127.0.0.1:15932/prx_waf}"
TLS_PORT="${TLS_PORT:-18944}"
HTTP_PORT="${HTTP_PORT:-18945}"
ORIGIN_PORT="${ORIGIN_PORT:-18946}"
API_PORT="${API_PORT:-18947}"
METRICS_PORT="${METRICS_PORT:-18948}"
HOST="h2flood.test"
HOSTCODE="e2ehf"

# The tight ceilings under test. The reset ceiling is far below h2's default of
# 20 so that "killed early" is unambiguous; the other two differ from
# default_h2_options's 100 / 65536 so that seeing them on the wire proves the
# table was read rather than ignored.
RESET_CEIL=5
CONC=42
HDR=16384

PASS=0
FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

for tool in openssl psql python3; do
    command -v "$tool" >/dev/null || { echo "ERROR: $tool not found" >&2; exit 1; }
done
[ -x "$BIN" ] || { echo "ERROR: $BIN not found; run: cargo build -p prx-waf" >&2; exit 1; }
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

WORK="$(mktemp -d)"
ORIGIN_PID=""
cleanup() {
    pkill -9 -f "$WORK/" 2>/dev/null || true
    [ -n "$ORIGIN_PID" ] && kill -9 "$ORIGIN_PID" 2>/dev/null || true
    psql "$DATABASE_URL" -q -c "DELETE FROM certificates WHERE host_code='$HOSTCODE'" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

psql "$DATABASE_URL" -c 'SELECT 1' >/dev/null 2>&1 \
    || { echo "ERROR: cannot reach $DATABASE_URL" >&2; exit 1; }

# ── origin: plaintext HTTP, so a served request is visibly distinct ──────────
cat > "$WORK/origin.py" <<'PY'
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        b = b"ORIGIN-REACHED\n"
        self.send_response(200); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def log_message(self, f, *a): print("ORIGIN " + (f % a), flush=True)
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
python3 "$WORK/origin.py" "$ORIGIN_PORT" > "$WORK/origin.log" 2>&1 &
ORIGIN_PID=$!
disown || true

# ── a raw h2 client: literal HPACK, no library would send these frames ───────
cat > "$WORK/h2flood.py" <<'PY'
import socket, ssl, sys, json

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def string(s):
    b = s.encode()
    if len(b) < 127:
        length = bytes([len(b)])
    else:
        rest, out = len(b) - 127, bytearray([127])
        while rest >= 128:
            out.append(rest % 128 + 128); rest //= 128
        out.append(rest); length = bytes(out)
    return length + b


def hpack(name, value):
    return b"\x00" + string(name) + string(value)


def frame(kind, flags, sid, payload):
    return (len(payload).to_bytes(3, "big") + bytes([kind, flags])
            + sid.to_bytes(4, "big") + payload)


def connect(spec):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    raw = socket.create_connection((spec["ip"], spec["port"]), timeout=10)
    sock = ctx.wrap_socket(raw, server_hostname=spec["sni"])
    print("ALPN=%s" % sock.selected_alpn_protocol())
    return sock


def headers(spec):
    return [(":method", spec.get("method", "GET")), (":scheme", "https"),
            (":authority", spec["authority"]), (":path", spec.get("path", "/")),
            ("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")]


def drain(sock, seconds):
    sock.settimeout(seconds)
    buf, goaway, closed = b"", None, False
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                closed = True; break
            buf += chunk
            while len(buf) >= 9:
                length = int.from_bytes(buf[:3], "big")
                if len(buf) < 9 + length:
                    break
                kind, payload = buf[3], buf[9:9 + length]
                buf = buf[9 + length:]
                if kind == 0x7 and goaway is None:
                    goaway = (int.from_bytes(payload[4:8], "big"),
                              payload[8:].decode("utf-8", "replace"),
                              int.from_bytes(payload[0:4], "big"))
    except (socket.timeout, ssl.SSLError, ConnectionResetError, OSError):
        pass
    if goaway:
        print("GOAWAY_CODE=%d" % goaway[0])
        print("GOAWAY_DEBUG=%s" % goaway[1])
        print("GOAWAY_LAST_STREAM=%d" % goaway[2])
    print("PEER_CLOSED=%s" % ("yes" if closed else "no"))


def settings(spec):
    sock = connect(spec)
    sock.sendall(PREFACE + frame(0x4, 0, 0, b""))
    sock.settimeout(6)
    names = {0x3: "MAX_CONCURRENT_STREAMS", 0x6: "MAX_HEADER_LIST_SIZE"}
    buf, done = b"", False
    try:
        while not done:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            while len(buf) >= 9:
                length = int.from_bytes(buf[:3], "big")
                if len(buf) < 9 + length:
                    break
                kind, payload = buf[3], buf[9:9 + length]
                buf = buf[9 + length:]
                if kind == 0x4 and payload:
                    for i in range(0, len(payload), 6):
                        pid = int.from_bytes(payload[i:i + 2], "big")
                        val = int.from_bytes(payload[i + 2:i + 6], "big")
                        if pid in names:
                            print("SETTING_%s=%d" % (names[pid], val))
                    done = True
    except (socket.timeout, ssl.SSLError, OSError):
        pass
    sock.close()


def rapid_reset(spec):
    sock = connect(spec)
    block = b"".join(hpack(k, v) for k, v in headers(spec))
    out = bytearray(PREFACE + frame(0x4, 0, 0, b""))
    sid = 1
    for _ in range(spec.get("streams", 200)):
        out += frame(0x1, 0x4 | 0x1, sid, block)
        out += frame(0x3, 0x0, sid, (0x8).to_bytes(4, "big"))
        sid += 2
    sock.sendall(out)
    drain(sock, spec.get("drain", 6))
    sock.close()


def continuation(spec):
    sock = connect(spec)
    sock.sendall(PREFACE + frame(0x4, 0, 0, b""))
    sock.sendall(frame(0x1, 0x0, 1, b"".join(hpack(k, v) for k, v in headers(spec))))
    filler = hpack("x-pad", "A" * 1024)
    try:
        for _ in range(spec.get("frames", 100)):
            sock.sendall(frame(0x9, 0x0, 1, filler))
    except (BrokenPipeError, ConnectionResetError, ssl.SSLError, OSError):
        pass
    drain(sock, spec.get("drain", 6))
    sock.close()


def baseline(spec):
    sock = connect(spec)
    sock.sendall(PREFACE + frame(0x4, 0, 0, b"")
                 + frame(0x1, 0x4 | 0x1, 1, b"".join(hpack(k, v) for k, v in headers(spec))))
    sock.settimeout(6)
    data, buf = b"", b""
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
                kind, flags, payload = buf[3], buf[4], buf[9:9 + length]
                buf = buf[9 + length:]
                if kind == 0x0:
                    data += payload
                if kind in (0x0, 0x1) and flags & 0x1:
                    raise StopIteration
    except (StopIteration, socket.timeout, ssl.SSLError, OSError):
        pass
    print("DATA=%s" % data.decode("utf-8", "replace").replace("\n", "\\n"))
    sock.close()


spec = json.loads(sys.argv[1])
{"settings": settings, "rapid-reset": rapid_reset,
 "continuation": continuation, "baseline": baseline}[spec["mode"]](spec)
PY

# ── config with a deliberately tight [proxy.http2] ───────────────────────────
cat > "$WORK/waf.toml" <<EOF
[proxy]
listen_addr = "127.0.0.1:$HTTP_PORT"
listen_addr_tls = "127.0.0.1:$TLS_PORT"
worker_threads = 2

[proxy.http2]
max_concurrent_streams = $CONC
max_header_list_size_bytes = $HDR
max_pending_accept_reset_streams = $RESET_CEIL

[api]
listen_addr = "127.0.0.1:$API_PORT"

[metrics]
enabled = true
listen_addr = "127.0.0.1:$METRICS_PORT"

[storage]
database_url = "$DATABASE_URL"
max_connections = 5

[[hosts]]
host = "$HOST"
port = $TLS_PORT
ssl = true
upstream_ssl = false
remote_host = "127.0.0.1"
remote_port = $ORIGIN_PORT
EOF

start_daemon() {
    JWT_SECRET="${JWT_SECRET:-e2e-h2-flood-secret-0123456789abcdef}" \
        "$BIN" --config "$WORK/waf.toml" run > "$1" 2>&1 &
    disown || true
    for _ in $(seq 1 60); do
        grep -q "Press Ctrl+C to stop" "$1" && { sleep 2; return 0; }
        sleep 1
    done
    return 1
}

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$WORK/k.pem" -out "$WORK/c.pem" \
    -subj "/CN=$HOST" -addext "subjectAltName=DNS:$HOST" >/dev/null 2>&1

# First boot migrates the schema; the cert goes in afterward and the daemon is
# restarted to pick it up — the same handshake the TLS test uses.
if ! start_daemon "$WORK/boot.log"; then
    echo "ERROR: the daemon never started; last lines:" >&2; tail -30 "$WORK/boot.log" >&2; exit 1
fi
pkill -9 -f "$WORK/waf.toml" 2>/dev/null || true
for _ in $(seq 1 30); do ss -ltn 2>/dev/null | grep -q ":$TLS_PORT " || break; sleep 1; done

psql "$DATABASE_URL" -q -v ON_ERROR_STOP=1 \
    -v cert="$(cat "$WORK/c.pem")" -v key="$(cat "$WORK/k.pem")" -v domain="$HOST" <<SQL
INSERT INTO certificates (host_code, domain, cert_pem, key_pem, status, not_after, issuer, subject)
VALUES ('$HOSTCODE', :'domain', :'cert', :'key', 'active', NOW() + INTERVAL '1 day',
        'e2e-h2-flood-self', :'domain');
SQL

if ! start_daemon "$WORK/waf.log"; then
    echo "ERROR: the daemon never restarted with a certificate; last lines:" >&2
    tail -30 "$WORK/waf.log" >&2; exit 1
fi
grep -q "TLS termination active on 127.0.0.1:$TLS_PORT" "$WORK/waf.log" \
    || { echo "ERROR: the TLS listener is not active" >&2; grep -i tls "$WORK/waf.log" >&2; exit 1; }

# Pingora's bootstrap forks; the "active" log line is written before the child
# has finished binding. Wait for the port to actually accept before probing it.
for _ in $(seq 1 30); do
    ss -ltn 2>/dev/null | grep -q ":$TLS_PORT " && break
    sleep 1
done
ss -ltn 2>/dev/null | grep -q ":$TLS_PORT " \
    || { echo "ERROR: TLS port $TLS_PORT never began listening" >&2; tail -20 "$WORK/waf.log" >&2; exit 1; }

COMMON="\"ip\":\"127.0.0.1\",\"port\":$TLS_PORT,\"sni\":\"$HOST\",\"authority\":\"$HOST:$TLS_PORT\""
run() { python3 "$WORK/h2flood.py" "{$COMMON,$1}"; }

# ═════════════════════════════════════════════════════════════════════════════
echo "Test 1: the configured [proxy.http2] SETTINGS reach the wire"
out="$(run '"mode":"settings"')"
echo "$out" | sed 's/^/    /'
echo "$out" | grep -q "ALPN=h2" && pass "h2 negotiated" || fail "h2 not negotiated"
echo "$out" | grep -q "SETTING_MAX_CONCURRENT_STREAMS=$CONC" \
    && pass "server advertises the configured max_concurrent_streams ($CONC, not the default 100)" \
    || fail "max_concurrent_streams was not the configured value"
echo "$out" | grep -q "SETTING_MAX_HEADER_LIST_SIZE=$HDR" \
    && pass "server advertises the configured max_header_list_size ($HDR, not the default 65536)" \
    || fail "max_header_list_size was not the configured value"

# ═════════════════════════════════════════════════════════════════════════════
echo
echo "Test 2: Rapid Reset (CVE-2023-44487) is cut at the configured ceiling"
out="$(run '"mode":"rapid-reset","streams":500')"
echo "$out" | sed 's/^/    /'
echo "$out" | grep -q "GOAWAY_CODE=11" \
    && pass "connection failed with GOAWAY(ENHANCE_YOUR_CALM)" \
    || fail "no ENHANCE_YOUR_CALM GOAWAY"
echo "$out" | grep -q "GOAWAY_DEBUG=too_many_resets" \
    && pass "the reason was too_many_resets" || fail "reason was not too_many_resets"
last="$(echo "$out" | sed -n 's/^GOAWAY_LAST_STREAM=//p')"
# The ceiling is RESET_CEIL, so the connection dies around the (RESET_CEIL+1)th
# stream — stream id ~2*(RESET_CEIL+1)-1. Well under what the default ceiling of
# 20 would allow (stream id 41). A generous upper bound tolerates accept races
# without letting a silently-raised ceiling through.
if [ -n "$last" ] && [ "$last" -ge 1 ] && [ "$last" -le 25 ]; then
    pass "killed early at stream $last — the tightened ceiling bit (default 20 would reach ~41)"
else
    fail "GOAWAY last-stream $last is not consistent with a ceiling of $RESET_CEIL"
fi

# ═════════════════════════════════════════════════════════════════════════════
echo
echo "Test 3: CONTINUATION flood (CVE-2024-27316) is cut"
out="$(run '"mode":"continuation","frames":200')"
echo "$out" | sed 's/^/    /'
echo "$out" | grep -q "GOAWAY_CODE=11" \
    && pass "connection failed with GOAWAY(ENHANCE_YOUR_CALM)" \
    || fail "no ENHANCE_YOUR_CALM GOAWAY"
echo "$out" | grep -q "GOAWAY_DEBUG=too_many_continuations" \
    && pass "the reason was too_many_continuations" || fail "reason was not too_many_continuations"

# ═════════════════════════════════════════════════════════════════════════════
echo
echo "Test 4: the listener still serves a normal request after the storm"
out="$(run '"mode":"baseline"')"
echo "$out" | sed 's/^/    /'
echo "$out" | grep -q "DATA=ORIGIN-REACHED" \
    && pass "a well-formed h2 request still reaches the origin" \
    || fail "the listener did not serve after the floods"

# ═════════════════════════════════════════════════════════════════════════════
echo
echo "──────────────────────────────────────────────"
echo "  PASSED: $PASS"
echo "  FAILED: $FAIL"
echo "──────────────────────────────────────────────"
[ "$FAIL" -eq 0 ]
